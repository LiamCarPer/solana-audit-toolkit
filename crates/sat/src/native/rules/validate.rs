//! R5 slice: SAT031 — Self-Referential Validation (the Cashio class).
//!
//! Cashio (Mar 2022, ~$48M) was drained because its deposit validation only
//! compared caller-supplied accounts to each other (`depositor_source.mint ==
//! collateral.mint`, `arrow.vendor_miner.mint == pool_mint`, …) and never
//! anchored the chain to canonical program state — so an attacker built a
//! fully self-consistent chain of fake accounts and minted ~2B CASH. See
//! `docs/EXPLOIT_CORPUS.md` for the verified-in-source root cause.
//!
//! This check rebuilds, per instruction, the graph of field-level equality
//! comparisons in the handler plus its called validation functions
//! (depth ≤ 2, including Vipers-style `impl Validate` methods via method-call
//! following), then flags connected components whose comparisons never touch a
//! canonical anchor: program-id / constant expressions, sysvars and program
//! accounts, literal-seed PDAs, and accounts whose `.owner` or `.key` is
//! compared against such an anchor (an owner/key check pins the account's
//! identity, making its data program-controlled — later comparisons against it
//! are anchored too).
//!
//! Two entry paths share one analyzer:
//! - **Native** (the pinned frontend model): instructions resolved from
//!   `entrypoint!`/`process_instruction`, account names from the frontend's
//!   account resolution.
//! - **Anchor fallback** (when no native marker exists): instructions from
//!   `#[program]` modules, accounts expanded from the `Context<Accounts>`
//!   struct (including nested Accounts bundles), validation wired through
//!   `#[access_control(ctx.accounts.validate())]` attributes and Vipers
//!   `impl Validate` methods. This is what makes the Cashio tree itself
//!   analyzable.
//!
//! Findings are heuristic leads, not proof: a chain of unanchored comparisons
//! is *shaped like* the Cashio bug, but whether one of the compared fields is
//! the load-bearing identity check requires manual confirmation.
//!
//! Title prefixes are load-bearing for SARIF classification (section 7 of
//! `docs/NATIVE_BACKEND.md`); do not rename them.

use std::collections::{HashMap, HashSet};

use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::{Expr, Pat};

use crate::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
use crate::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT031_TITLE: &str = "Self-Referential Validation:";

/// Guards whose *first two arguments* are an equality comparison between
/// expressions (`assert_keys_eq!(a.mint, b.mint)`). The Vipers family
/// (`assert_keys_eq!/assert_keys_neq!`) is the Cashio shape; the `require*`
/// and `assert_eq` families are native variants of the same check.
const EQUALITY_MACROS: &[&str] = &[
    "assert_keys_eq",
    "assert_keys_neq",
    "require_keys_eq",
    "require_keys_neq",
    "assert_eq",
    "require_eq",
    "debug_assert_eq",
    "check_eq",
];

/// Owner-validation call names whose first argument is the validated account
/// (`check_owner(a, &program_id)` style). Accounts passed to these are
/// canonical anchors.
const OWNER_CHECK_CALLS: &[&str] = &["check_owner", "assert_owned_by", "check_owned_by", "assert_owner"];

/// A resolved side of a comparison.
#[derive(Clone)]
enum Side {
    /// A literal, constant, or the program id — canonical by construction.
    Anchor,
    /// A field of a resolved account: `(account_index, field)`. The empty
    /// field marks a bare account expression (its pubkey identity).
    AccountField(usize, String),
    /// Unresolvable — neither an anchor nor an account field.
    Unknown,
}

/// One equality comparison with its resolved sides and graph nodes.
struct Comparison {
    left: Side,
    right: Side,
    left_node: Option<(usize, String)>,
    right_node: Option<(usize, String)>,
}

// ── Function + struct index over the parsed files ───────────────────────────

/// Free functions + impl methods (bare and `Type::method` qualified) across
/// the parsed files. Skip `#[cfg(test)]` items and `mod tests` bodies.
pub struct FnIndex<'a> {
    fns: HashMap<String, Vec<(&'a syn::Block, usize)>>,
    files: &'a [(syn::File, String)],
}

impl<'a> FnIndex<'a> {
    pub fn build(files: &'a [(syn::File, String)]) -> Self {
        let mut fns: HashMap<String, Vec<(&'a syn::Block, usize)>> = HashMap::new();
        for (i, (file, _)) in files.iter().enumerate() {
            collect_fns(&file.items, i, &mut fns);
        }
        FnIndex { fns, files }
    }

    /// Best candidate for `name`: a definition in `prefer_file` if one
    /// exists, otherwise the first definition overall.
    pub fn lookup(&self, name: &str, prefer_file: &str) -> Option<(&'a syn::Block, usize)> {
        let candidates = self.fns.get(name)?;
        candidates.iter().find(|(_, i)| self.files[*i].1 == prefer_file).or_else(|| candidates.first()).copied()
    }
}

fn is_test_item(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("test") || a.path().is_ident("cfg") && a.meta.to_token_stream().to_string().contains("test")
    })
}

fn collect_fns<'a>(items: &'a [syn::Item], file_idx: usize, out: &mut HashMap<String, Vec<(&'a syn::Block, usize)>>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                if !is_test_item(&f.attrs) {
                    out.entry(f.sig.ident.to_string()).or_default().push((&f.block, file_idx));
                }
            }
            syn::Item::Impl(im) => {
                let type_name = path_last_segment(&im.self_ty);
                for it in &im.items {
                    if let syn::ImplItem::Fn(f) = it {
                        if is_test_item(&f.attrs) {
                            continue;
                        }
                        let name = f.sig.ident.to_string();
                        out.entry(name.clone()).or_default().push((&f.block, file_idx));
                        if let Some(t) = &type_name {
                            out.entry(format!("{t}::{name}")).or_default().push((&f.block, file_idx));
                        }
                    }
                }
            }
            syn::Item::Mod(m) => {
                if m.ident == "tests" || is_test_item(&m.attrs) {
                    continue;
                }
                if let Some((_, items)) = &m.content {
                    collect_fns(items, file_idx, out);
                }
            }
            _ => {}
        }
    }
}

fn path_last_segment(ty: &syn::Type) -> Option<String> {
    if let syn::Type::Path(tp) = ty {
        return tp.path.segments.last().map(|s| s.ident.to_string());
    }
    None
}

/// One resolved struct field: `(name, leaf type ident, field attributes)`.
pub type StructField = (String, String, Vec<syn::Attribute>);

/// In-file struct field map: struct name → [`StructField`] list. Used by the
/// Anchor path to expand Accounts bundles, resolve
/// `self.common.crate_mint`-style chains, and scan
/// `#[account(constraint = ...)]` attributes on field definitions.
pub struct StructIndex {
    pub fields: HashMap<String, Vec<StructField>>,
}

impl StructIndex {
    pub fn build(files: &[(syn::File, String)]) -> Self {
        let mut fields = HashMap::new();
        for (file, _) in files {
            collect_structs(&file.items, &mut fields);
        }
        StructIndex { fields }
    }

    pub fn is_bundle(&self, type_ident: &str) -> bool {
        self.fields.contains_key(type_ident)
    }
}

fn collect_structs(items: &[syn::Item], out: &mut HashMap<String, Vec<StructField>>) {
    for item in items {
        match item {
            syn::Item::Struct(s) => {
                let mut field_list = Vec::new();
                for f in &s.fields {
                    if let syn::Field { ident: Some(ident), ty, attrs, .. } = f {
                        field_list.push((ident.to_string(), leaf_type_ident(ty), attrs.clone()));
                    }
                }
                out.entry(s.ident.to_string()).or_insert(field_list);
            }
            syn::Item::Mod(m) => {
                if m.ident == "tests" || is_test_item(&m.attrs) {
                    continue;
                }
                if let Some((_, items)) = &m.content {
                    collect_structs(items, out);
                }
            }
            _ => {}
        }
    }
}

/// The leaf type ident of a (possibly nested) type: `Box<Account<'info, Mint>>`
/// → `Mint`, `BrrrCommon<'info>` → `BrrrCommon`, `Context<PrintCash>` →
/// `PrintCash`. Lifetimes and `&` wrappers are ignored.
pub fn leaf_type_ident(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Reference(r) => leaf_type_ident(&r.elem),
        syn::Type::Path(tp) => {
            let Some(last) = tp.path.segments.last() else { return String::new() };
            let name = last.ident.to_string();
            if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                for arg in args.args.iter().rev() {
                    if let syn::GenericArgument::Type(t) = arg {
                        return leaf_type_ident(t);
                    }
                }
            }
            name
        }
        _ => String::new(),
    }
}

/// Bundle awareness for account resolution: which account names of an
/// instruction are themselves in-file Accounts bundles (so `bundle.field`
/// names another account slot).
pub struct Bundles {
    /// Account name → whether it is an in-file struct bundle.
    is_bundle: HashSet<String>,
}

impl Bundles {
    pub fn empty() -> Self {
        Bundles { is_bundle: HashSet::new() }
    }

    pub fn build(accounts: &[ResolvedAccount], account_types: &HashMap<String, String>, structs: &StructIndex) -> Self {
        let is_bundle = accounts
            .iter()
            .filter(|a| account_types.get(&a.name).is_some_and(|t| structs.is_bundle(t)))
            .map(|a| a.name.clone())
            .collect();
        Bundles { is_bundle }
    }

    pub fn contains(&self, account: &str) -> bool {
        self.is_bundle.contains(account)
    }
}

// ── Expression helpers ───────────────────────────────────────────────────────

/// Strip wrapper expressions (`(...)`, `&x`, `&mut x`, raw-address).
fn peel(e: &Expr) -> &Expr {
    match e {
        Expr::Paren(p) => peel(&p.expr),
        Expr::Group(g) => peel(&g.expr),
        Expr::Reference(r) => peel(&r.expr),
        Expr::RawAddr(r) => peel(&r.expr),
        _ => e,
    }
}

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(n) => n.to_string(),
        syn::Member::Unnamed(i) => i.index.to_string(),
    }
}

/// Parse a macro body as comma-separated expressions, when possible.
fn macro_exprs(mac: &syn::Macro) -> Vec<Expr> {
    mac.parse_body_with(Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        .map(|args| args.into_iter().collect())
        .unwrap_or_default()
}

/// Whether an expression is a canonical anchor by construction: literals,
/// arrays/repeats (discriminator byte arrays), the program id, and named
/// constants that pin an identity (`*_ID`, `*_MINT`, `*_ADDRESS`,
/// discriminator / tag / prefix / magic names).
fn is_anchor_expr(e: &Expr) -> bool {
    match peel(e) {
        Expr::Lit(_) => true,
        Expr::Array(_) | Expr::Repeat(_) => true,
        Expr::Tuple(t) => !t.elems.is_empty() && t.elems.iter().all(is_anchor_expr),
        Expr::Path(p) => {
            let last = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
            let trimmed = last.trim_start_matches('_');
            trimmed == "program_id"
                || trimmed == "ID"
                || trimmed == "PROGRAM_ID"
                || trimmed == "MINT"
                || last.ends_with("_ID")
                || last.ends_with("_MINT")
                || last.ends_with("_ADDRESS")
                || last.ends_with("_ADDR")
                || last.contains("discriminator")
                || last.contains("tag")
                || last.contains("prefix")
                || last.contains("magic")
        }
        _ => false,
    }
}

/// Resolve an expression to a [`Side`]. `aliases` maps local identifiers to
/// already-resolved sides (`let m = a.mint;` → `m` → `a.mint`).
fn resolve_side(e: &Expr, ix: &NativeInstruction, aliases: &HashMap<String, Side>, bundles: &Bundles) -> Side {
    if is_anchor_expr(e) {
        return Side::Anchor;
    }
    match peel(e) {
        Expr::Path(p) => {
            let Some(ident) = p.path.get_ident() else {
                return Side::Unknown;
            };
            let ident = ident.to_string();
            if let Some(side) = aliases.get(&ident) {
                return side.clone();
            }
            if let Some(acc) = account_index(ix, &ident) {
                // A bare account expression compares its pubkey identity.
                return Side::AccountField(acc, "key".to_string());
            }
            Side::Unknown
        }
        Expr::Field(f) => {
            // Walk the member chain down to a base identifier, resolving
            // `a.mint`, `self.a.mint`, `ctx.accounts.a.mint`, and aliased
            // bases (`m.mint` where `m` aliases `a`).
            let (base, mut fields) = field_chain_base(f);
            fields.push(member_name(&f.member));
            if base == "self" {
                // `self.<field>...` — the receiver is the Accounts struct; the
                // first member names an account variable (or bundle slot).
                if fields.is_empty() {
                    return Side::Unknown;
                }
                return resolve_chain(&fields[0], &fields[1..], ix, aliases, bundles);
            }
            if base == "ctx" && fields.first().map(String::as_str) == Some("accounts") {
                // `ctx.accounts.<field>...` — same as `self`, but anchored at
                // the handler's Context.
                if fields.len() < 2 {
                    return Side::Unknown;
                }
                return resolve_chain(&fields[1], &fields[2..], ix, aliases, bundles);
            }
            resolve_chain(&base, &fields, ix, aliases, bundles)
        }
        _ => Side::Unknown,
    }
}

/// Resolve `var.field1.field2...` where `var` is an account variable (directly
/// or through an alias). When `var` is a bundle account, the first field names
/// another account slot inside it.
fn resolve_chain(
    var: &str,
    fields: &[String],
    ix: &NativeInstruction,
    aliases: &HashMap<String, Side>,
    bundles: &Bundles,
) -> Side {
    let acc = if let Some(side) = aliases.get(var) {
        match side {
            Side::AccountField(acc, field) if field.is_empty() => *acc,
            Side::AccountField(acc, field) => {
                // `let m = a.mint;` then `m.key` — the alias already names an
                // account field; keep it.
                return Side::AccountField(*acc, field.clone());
            }
            _ => return Side::Unknown,
        }
    } else if let Some(acc) = account_index(ix, var) {
        acc
    } else {
        return Side::Unknown;
    };

    if bundles.contains(var) {
        // `var` is an in-file Accounts bundle: the first field names an
        // account slot inside it (`self.common.crate_mint` → `crate_mint`).
        let Some(slot) = fields.first() else {
            return Side::AccountField(acc, "key".to_string());
        };
        let Some(slot_acc) = account_index(ix, slot) else {
            return Side::Unknown;
        };
        return match fields.len() {
            1 => Side::AccountField(slot_acc, "key".to_string()),
            2 => Side::AccountField(slot_acc, fields[1].clone()),
            _ => Side::Unknown,
        };
    }

    match fields.len() {
        0 => Side::AccountField(acc, "key".to_string()),
        1 => Side::AccountField(acc, fields[0].clone()),
        _ => Side::Unknown,
    }
}

/// The base identifier of a field chain and the member names on the way down:
/// `self.a.mint` → (`self`, [a]); `a.mint` → (a, []); `x.y.mint` → (x, [y]).
fn field_chain_base(f: &syn::ExprField) -> (String, Vec<String>) {
    let mut members = Vec::new();
    let mut current = f;
    loop {
        match peel(&current.base) {
            Expr::Field(inner) => {
                members.push(member_name(&inner.member));
                current = inner;
            }
            Expr::Path(p) => {
                let base = p.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
                members.reverse();
                return (base, members);
            }
            _ => return (String::new(), members),
        }
    }
}

fn account_index(ix: &NativeInstruction, name: &str) -> Option<usize> {
    ix.accounts.iter().position(|a| a.name == name)
}

fn node_of(side: &Side) -> Option<(usize, String)> {
    match side {
        Side::AccountField(acc, field) => Some((*acc, field.clone())),
        _ => None,
    }
}

// ── Block scanning: aliases + comparisons ────────────────────────────────────

/// Walk a block in statement order, tracking `let` aliases and collecting
/// equality comparisons. Nested blocks (if/match/loop bodies) get a cloned
/// alias map so scoping stays sound.
fn scan_block(
    block: &syn::Block,
    aliases: &mut HashMap<String, Side>,
    ix: &NativeInstruction,
    bundles: &Bundles,
    out: &mut Vec<Comparison>,
) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    let init_expr = &init.expr;
                    if let Pat::Ident(pi) = &l.pat {
                        let side = resolve_side(init_expr, ix, aliases, bundles);
                        if !matches!(side, Side::Unknown) {
                            aliases.insert(pi.ident.to_string(), side);
                        }
                    }
                    scan_expr(init_expr, aliases, ix, bundles, out);
                }
            }
            syn::Stmt::Expr(e, _) => scan_expr(e, aliases, ix, bundles, out),
            syn::Stmt::Macro(m) => {
                let args = macro_exprs(&m.mac);
                if is_equality_macro(&m.mac) && args.len() >= 2 {
                    push_comparison(&args[0], &args[1], aliases, ix, bundles, out);
                } else {
                    for arg in &args {
                        scan_expr(arg, aliases, ix, bundles, out);
                    }
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn is_equality_macro(mac: &syn::Macro) -> bool {
    mac.path.segments.last().map(|s| s.ident.to_string()).is_some_and(|name| EQUALITY_MACROS.contains(&name.as_str()))
}

fn push_comparison(
    left: &Expr,
    right: &Expr,
    aliases: &HashMap<String, Side>,
    ix: &NativeInstruction,
    bundles: &Bundles,
    out: &mut Vec<Comparison>,
) {
    let left = resolve_side(left, ix, aliases, bundles);
    let right = resolve_side(right, ix, aliases, bundles);
    out.push(Comparison { left_node: node_of(&left), right_node: node_of(&right), left, right });
}

fn scan_expr(
    e: &Expr,
    aliases: &mut HashMap<String, Side>,
    ix: &NativeInstruction,
    bundles: &Bundles,
    out: &mut Vec<Comparison>,
) {
    match e {
        Expr::Binary(b) if matches!(b.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) => {
            push_comparison(&b.left, &b.right, aliases, ix, bundles, out);
        }
        Expr::Binary(b) => {
            scan_expr(&b.left, aliases, ix, bundles, out);
            scan_expr(&b.right, aliases, ix, bundles, out);
        }
        Expr::Block(b) => scan_block(&b.block, &mut aliases.clone(), ix, bundles, out),
        Expr::Unsafe(u) => scan_block(&u.block, &mut aliases.clone(), ix, bundles, out),
        Expr::Const(c) => scan_block(&c.block, &mut aliases.clone(), ix, bundles, out),
        Expr::Async(a) => scan_block(&a.block, &mut aliases.clone(), ix, bundles, out),
        Expr::TryBlock(tb) => scan_block(&tb.block, &mut aliases.clone(), ix, bundles, out),
        Expr::If(i) => {
            scan_expr(&i.cond, aliases, ix, bundles, out);
            scan_block(&i.then_branch, &mut aliases.clone(), ix, bundles, out);
            if let Some((_, else_expr)) = &i.else_branch {
                scan_expr(else_expr, aliases, ix, bundles, out);
            }
        }
        Expr::While(w) => {
            scan_expr(&w.cond, aliases, ix, bundles, out);
            scan_block(&w.body, &mut aliases.clone(), ix, bundles, out);
        }
        Expr::Loop(l) => scan_block(&l.body, &mut aliases.clone(), ix, bundles, out),
        Expr::ForLoop(fl) => scan_block(&fl.body, &mut aliases.clone(), ix, bundles, out),
        Expr::Match(m) => {
            scan_expr(&m.expr, aliases, ix, bundles, out);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    scan_expr(guard, aliases, ix, bundles, out);
                }
                scan_expr(&arm.body, aliases, ix, bundles, out);
            }
        }
        Expr::Call(c) => {
            scan_expr(&c.func, aliases, ix, bundles, out);
            for arg in &c.args {
                scan_expr(arg, aliases, ix, bundles, out);
            }
        }
        Expr::MethodCall(m) => {
            scan_expr(&m.receiver, aliases, ix, bundles, out);
            for arg in &m.args {
                scan_expr(arg, aliases, ix, bundles, out);
            }
        }
        Expr::Try(t) => scan_expr(&t.expr, aliases, ix, bundles, out),
        Expr::Paren(p) => scan_expr(&p.expr, aliases, ix, bundles, out),
        Expr::Group(g) => scan_expr(&g.expr, aliases, ix, bundles, out),
        Expr::Reference(r) => scan_expr(&r.expr, aliases, ix, bundles, out),
        Expr::RawAddr(r) => scan_expr(&r.expr, aliases, ix, bundles, out),
        Expr::Unary(u) => scan_expr(&u.expr, aliases, ix, bundles, out),
        Expr::Await(a) => scan_expr(&a.base, aliases, ix, bundles, out),
        Expr::Yield(y) => {
            if let Some(x) = &y.expr {
                scan_expr(x, aliases, ix, bundles, out);
            }
        }
        Expr::Let(l) => scan_expr(&l.expr, aliases, ix, bundles, out),
        Expr::Assign(a) => {
            scan_expr(&a.left, aliases, ix, bundles, out);
            scan_expr(&a.right, aliases, ix, bundles, out);
        }
        Expr::Index(i) => {
            scan_expr(&i.expr, aliases, ix, bundles, out);
            scan_expr(&i.index, aliases, ix, bundles, out);
        }
        Expr::Tuple(t) => {
            for el in &t.elems {
                scan_expr(el, aliases, ix, bundles, out);
            }
        }
        Expr::Array(a) => {
            for el in &a.elems {
                scan_expr(el, aliases, ix, bundles, out);
            }
        }
        Expr::Struct(s) => {
            for f in &s.fields {
                scan_expr(&f.expr, aliases, ix, bundles, out);
            }
        }
        Expr::Closure(c) => scan_expr(&c.body, aliases, ix, bundles, out),
        Expr::Cast(c) => scan_expr(&c.expr, aliases, ix, bundles, out),
        Expr::Range(r) => {
            if let Some(start) = &r.start {
                scan_expr(start, aliases, ix, bundles, out);
            }
            if let Some(end) = &r.end {
                scan_expr(end, aliases, ix, bundles, out);
            }
        }
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                scan_expr(x, aliases, ix, bundles, out);
            }
        }
        Expr::Break(br) => {
            if let Some(x) = &br.expr {
                scan_expr(x, aliases, ix, bundles, out);
            }
        }
        Expr::Macro(m) => {
            let args = macro_exprs(&m.mac);
            if is_equality_macro(&m.mac) && args.len() >= 2 {
                push_comparison(&args[0], &args[1], aliases, ix, bundles, out);
            } else {
                for arg in &args {
                    scan_expr(arg, aliases, ix, bundles, out);
                }
            }
        }
        _ => {}
    }
}

// ── Helper call graph (handler + validation functions) ───────────────────────

fn is_known_builtin(name: &str) -> bool {
    matches!(
        name,
        "next_account_info"
            | "iter"
            | "into_iter"
            | "as_ref"
            | "as_mut"
            | "clone"
            | "unwrap"
            | "expect"
            | "is_signer"
            | "try_borrow_mut"
            | "try_borrow"
            | "borrow_mut"
            | "borrow"
            | "contains"
            | "starts_with"
            | "len"
            | "is_empty"
            | "get"
            | "copy_from_slice"
            | "realloc"
    )
}

/// Distinct callees of a block: plain calls (`validate(...)`) and method
/// calls (`self.accounts.validate()?`), restricted to names that resolve in
/// the file index. Impl methods are indexed bare by `collect_fns`, so a
/// `self.x.validate()` call is found.
fn collect_callees_in_block(block: &syn::Block, index: &FnIndex, out: &mut Vec<String>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => walk_for_callees(e, index, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    walk_for_callees(&init.expr, index, out);
                }
            }
            syn::Stmt::Macro(m) => {
                for arg in macro_exprs(&m.mac) {
                    walk_for_callees(&arg, index, out);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn walk_for_callees(e: &Expr, index: &FnIndex, out: &mut Vec<String>) {
    match e {
        Expr::Call(c) => {
            if let Expr::Path(p) = &*c.func {
                let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if !is_known_builtin(&name)
                    && !matches!(name.as_str(), "msg" | "Ok" | "Err")
                    && index.fns.contains_key(&name)
                {
                    out.push(name);
                }
            }
            for arg in &c.args {
                walk_for_callees(arg, index, out);
            }
        }
        Expr::MethodCall(m) => {
            let name = m.method.to_string();
            if index.fns.contains_key(&name) {
                out.push(name);
            }
            walk_for_callees(&m.receiver, index, out);
            for arg in &m.args {
                walk_for_callees(arg, index, out);
            }
        }
        Expr::Block(b) => walk_for_callees_block(&b.block, index, out),
        Expr::Unsafe(u) => walk_for_callees_block(&u.block, index, out),
        Expr::Async(a) => walk_for_callees_block(&a.block, index, out),
        Expr::Const(c) => walk_for_callees_block(&c.block, index, out),
        Expr::TryBlock(tb) => walk_for_callees_block(&tb.block, index, out),
        Expr::If(i) => {
            walk_for_callees(&i.cond, index, out);
            walk_for_callees_block(&i.then_branch, index, out);
            if let Some((_, else_expr)) = &i.else_branch {
                walk_for_callees(else_expr, index, out);
            }
        }
        Expr::While(w) => {
            walk_for_callees(&w.cond, index, out);
            walk_for_callees_block(&w.body, index, out);
        }
        Expr::Loop(l) => walk_for_callees_block(&l.body, index, out),
        Expr::ForLoop(fl) => walk_for_callees_block(&fl.body, index, out),
        Expr::Match(m) => {
            walk_for_callees(&m.expr, index, out);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    walk_for_callees(guard, index, out);
                }
                walk_for_callees(&arm.body, index, out);
            }
        }
        Expr::Try(t) => walk_for_callees(&t.expr, index, out),
        Expr::Paren(p) => walk_for_callees(&p.expr, index, out),
        Expr::Group(g) => walk_for_callees(&g.expr, index, out),
        Expr::Reference(r) => walk_for_callees(&r.expr, index, out),
        Expr::RawAddr(r) => walk_for_callees(&r.expr, index, out),
        Expr::Unary(u) => walk_for_callees(&u.expr, index, out),
        Expr::Await(a) => walk_for_callees(&a.base, index, out),
        Expr::Closure(c) => walk_for_callees(&c.body, index, out),
        Expr::Binary(b) => {
            walk_for_callees(&b.left, index, out);
            walk_for_callees(&b.right, index, out);
        }
        Expr::Assign(a) => {
            walk_for_callees(&a.left, index, out);
            walk_for_callees(&a.right, index, out);
        }
        Expr::Index(i) => {
            walk_for_callees(&i.expr, index, out);
            walk_for_callees(&i.index, index, out);
        }
        Expr::Tuple(t) => {
            for el in &t.elems {
                walk_for_callees(el, index, out);
            }
        }
        Expr::Array(a) => {
            for el in &a.elems {
                walk_for_callees(el, index, out);
            }
        }
        Expr::Struct(s) => {
            for f in &s.fields {
                walk_for_callees(&f.expr, index, out);
            }
        }
        Expr::Cast(c) => walk_for_callees(&c.expr, index, out),
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                walk_for_callees(x, index, out);
            }
        }
        Expr::Break(br) => {
            if let Some(x) = &br.expr {
                walk_for_callees(x, index, out);
            }
        }
        Expr::Macro(m) => {
            for arg in macro_exprs(&m.mac) {
                walk_for_callees(&arg, index, out);
            }
        }
        _ => {}
    }
}

fn walk_for_callees_block(block: &syn::Block, index: &FnIndex, out: &mut Vec<String>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => walk_for_callees(e, index, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    walk_for_callees(&init.expr, index, out);
                }
            }
            syn::Stmt::Macro(m) => {
                for arg in macro_exprs(&m.mac) {
                    walk_for_callees(&arg, index, out);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

/// The handler body plus its helper call graph (depth ≤ 2, cycle-guarded).
/// Unlike the other slices, method calls are followed too so that
/// Vipers-style `self.accounts.validate()?` calls join the graph. The visited
/// set is keyed by `(file, name)` so several impls sharing a method name
/// (e.g. `validate` on different Accounts structs) are all followed.
/// `extra_roots` (handler attribute expressions like `#[access_control(
/// ctx.accounts.validate())]`) are scanned for callees at depth 0.
pub fn collect_blocks<'a>(
    block: &'a syn::Block,
    index: &'a FnIndex<'a>,
    visited: &mut HashSet<(usize, String)>,
    depth: usize,
    out: &mut Vec<&'a syn::Block>,
    extra_roots: &[Expr],
) {
    out.push(block);
    if depth >= 2 {
        return;
    }
    let mut callees = Vec::new();
    collect_callees_in_block(block, index, &mut callees);
    if depth == 0 {
        for root in extra_roots {
            walk_for_callees(root, index, &mut callees);
        }
    }
    callees.sort();
    callees.dedup();
    for name in callees {
        let Some(candidates) = index.fns.get(&name) else { continue };
        for (candidate, candidate_file) in candidates {
            if !visited.insert((*candidate_file, name.clone())) {
                continue;
            }
            collect_blocks(candidate, index, visited, depth + 1, out, &[]);
        }
    }
}

// ── Canonical-anchor resolution ──────────────────────────────────────────────

/// Accounts treated as canonical from the start: sysvars, program and
/// system-program accounts, and literal-seed PDAs.
fn seed_canonical(ix: &NativeInstruction) -> HashSet<usize> {
    let mut out = HashSet::new();
    for (i, acc) in ix.accounts.iter().enumerate() {
        let builtin = matches!(acc.kind, AccountKind::Sysvar | AccountKind::Program | AccountKind::SystemProgram);
        let literal_pda = acc.is_pda && acc.seeds.iter().all(|s| is_literal_seed(s));
        if builtin || literal_pda {
            out.insert(i);
        }
    }
    out
}

/// A seed expression is literal when it is a quoted string / byte string /
/// number and carries no identifier.
fn is_literal_seed(seed: &str) -> bool {
    let trimmed = seed.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut in_string = false;
    let mut quote = '\0';
    for c in trimmed.chars() {
        if c == '\'' || c == '"' {
            if !in_string {
                in_string = true;
                quote = c;
            } else if c == quote {
                in_string = false;
            }
        } else if !in_string && (c.is_alphabetic() || c == '_') {
            return false;
        }
    }
    true
}

/// Accounts passed as the first argument of an owner-validation call
/// (`check_owner(a, &program_id)` style), scanned across the flattened blocks.
fn owner_checked_accounts(blocks: &[&syn::Block], ix: &NativeInstruction) -> HashSet<usize> {
    let mut out = HashSet::new();
    for block in blocks {
        scan_owner_checks(block, ix, &mut out);
    }
    out
}

fn scan_owner_checks(block: &syn::Block, ix: &NativeInstruction, out: &mut HashSet<usize>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => scan_owner_checks_expr(e, ix, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    scan_owner_checks_expr(&init.expr, ix, out);
                }
            }
            syn::Stmt::Macro(m) => {
                for arg in macro_exprs(&m.mac) {
                    scan_owner_checks_expr(&arg, ix, out);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn scan_owner_checks_expr(e: &Expr, ix: &NativeInstruction, out: &mut HashSet<usize>) {
    match e {
        Expr::Call(c) => {
            if let Expr::Path(p) = &*c.func {
                let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if OWNER_CHECK_CALLS.contains(&name.as_str())
                    && let Some(first) = c.args.first()
                    && let Some(acc) = account_of_expr(first, ix)
                {
                    out.insert(acc);
                }
            }
            for arg in &c.args {
                scan_owner_checks_expr(arg, ix, out);
            }
        }
        Expr::MethodCall(m) => {
            scan_owner_checks_expr(&m.receiver, ix, out);
            for arg in &m.args {
                scan_owner_checks_expr(arg, ix, out);
            }
        }
        Expr::Block(b) => scan_owner_checks(&b.block, ix, out),
        Expr::Unsafe(u) => scan_owner_checks(&u.block, ix, out),
        Expr::Async(a) => scan_owner_checks(&a.block, ix, out),
        Expr::Const(c) => scan_owner_checks(&c.block, ix, out),
        Expr::TryBlock(tb) => scan_owner_checks(&tb.block, ix, out),
        Expr::If(i) => {
            scan_owner_checks_expr(&i.cond, ix, out);
            scan_owner_checks(&i.then_branch, ix, out);
            if let Some((_, else_expr)) = &i.else_branch {
                scan_owner_checks_expr(else_expr, ix, out);
            }
        }
        Expr::While(w) => {
            scan_owner_checks_expr(&w.cond, ix, out);
            scan_owner_checks(&w.body, ix, out);
        }
        Expr::Loop(l) => scan_owner_checks(&l.body, ix, out),
        Expr::ForLoop(fl) => scan_owner_checks(&fl.body, ix, out),
        Expr::Match(m) => {
            scan_owner_checks_expr(&m.expr, ix, out);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    scan_owner_checks_expr(guard, ix, out);
                }
                scan_owner_checks_expr(&arm.body, ix, out);
            }
        }
        Expr::Try(t) => scan_owner_checks_expr(&t.expr, ix, out),
        Expr::Paren(p) => scan_owner_checks_expr(&p.expr, ix, out),
        Expr::Group(g) => scan_owner_checks_expr(&g.expr, ix, out),
        Expr::Reference(r) => scan_owner_checks_expr(&r.expr, ix, out),
        Expr::RawAddr(r) => scan_owner_checks_expr(&r.expr, ix, out),
        Expr::Unary(u) => scan_owner_checks_expr(&u.expr, ix, out),
        Expr::Await(a) => scan_owner_checks_expr(&a.base, ix, out),
        Expr::Closure(c) => scan_owner_checks_expr(&c.body, ix, out),
        Expr::Binary(b) => {
            scan_owner_checks_expr(&b.left, ix, out);
            scan_owner_checks_expr(&b.right, ix, out);
        }
        Expr::Assign(a) => {
            scan_owner_checks_expr(&a.left, ix, out);
            scan_owner_checks_expr(&a.right, ix, out);
        }
        Expr::Macro(m) => {
            for arg in macro_exprs(&m.mac) {
                scan_owner_checks_expr(&arg, ix, out);
            }
        }
        _ => {}
    }
}

/// The account an expression names, when it is exactly an account variable
/// (wrappers allowed).
fn account_of_expr(e: &Expr, ix: &NativeInstruction) -> Option<usize> {
    match peel(e) {
        Expr::Path(p) => {
            let ident = p.path.get_ident()?.to_string();
            account_index(ix, &ident)
        }
        _ => None,
    }
}

/// Fixed point: an account becomes canonical when its `.owner` or `.key` is
/// compared against an anchor (constant / program id) or against the key of an
/// already-canonical account, since that pins the account's identity and makes
/// its data program-controlled. Iterates until stable (bounded).
fn reachable_canonical(comparisons: &[Comparison], seeded: HashSet<usize>) -> HashSet<usize> {
    let mut canonical = seeded;
    for _ in 0..8 {
        let mut changed = false;
        for c in comparisons {
            let pairs = [
                ((&c.left, &c.left_node), (&c.right, &c.right_node)),
                ((&c.right, &c.right_node), (&c.left, &c.left_node)),
            ];
            for ((_side, node), (other, other_node)) in pairs {
                let Some((acc, field)) = node else { continue };
                if canonical.contains(acc) || !matches!(field.as_str(), "owner" | "key") {
                    continue;
                }
                let pinned = matches!(other, Side::Anchor)
                    || other_node.as_ref().is_some_and(|(other_acc, _)| canonical.contains(other_acc));
                if pinned {
                    changed |= canonical.insert(*acc);
                }
            }
        }
        if !changed {
            break;
        }
    }
    canonical
}

// ── Chain graph ──────────────────────────────────────────────────────────────

/// Union-find over (account, field) nodes with per-component bookkeeping.
struct UnionFind {
    parent: Vec<usize>,
    node_count: Vec<usize>,
    anchored: Vec<bool>,
    account: Vec<usize>,
    field: Vec<String>,
}

impl UnionFind {
    fn new(nodes: Vec<(usize, String)>) -> Self {
        let n = nodes.len();
        UnionFind {
            parent: (0..n).collect(),
            node_count: vec![1; n],
            anchored: vec![false; n],
            account: nodes.iter().map(|(a, _)| *a).collect(),
            field: nodes.iter().map(|(_, f)| f.clone()).collect(),
        }
    }

    fn find(&mut self, i: usize) -> usize {
        if self.parent[i] != i {
            self.parent[i] = self.find(self.parent[i]);
        }
        self.parent[i]
    }

    fn union(&mut self, a: usize, b: usize) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent[rb] = ra;
            self.node_count[ra] += self.node_count[rb];
            self.anchored[ra] |= self.anchored[rb];
        }
    }

    fn mark_anchored(&mut self, i: usize) {
        let r = self.find(i);
        self.anchored[r] = true;
    }
}

fn location(ix: &NativeInstruction) -> String {
    format!("{}:{} ({})", ix.file, ix.line, ix.name)
}

// ── Anchor path: `#[program]` modules → instructions ─────────────────────────

/// Whether any parsed file carries an Anchor `#[program]` module.
pub fn has_anchor_program(files: &[(syn::File, String)]) -> bool {
    files.iter().any(|(file, _)| {
        file.items.iter().any(|item| match item {
            syn::Item::Mod(m) => m.attrs.iter().any(|a| a.path().is_ident("program")),
            _ => false,
        })
    })
}

/// One Anchor instruction extracted from a `#[program]` module.
pub struct AnchorInstruction {
    pub name: String,
    pub handler: String,
    pub file: String,
    pub line: usize,
    /// Root Accounts struct name (the `Context<X>` type).
    pub root_struct: String,
    /// The handler fn item (to scan attributes like `#[access_control(...)]`).
    pub attrs: Vec<syn::Attribute>,
}

/// Build the Anchor instruction list from `#[program]` modules.
pub fn anchor_instructions(files: &[(syn::File, String)]) -> Vec<AnchorInstruction> {
    let mut out = Vec::new();
    for (file, path) in files {
        collect_program_instructions(&file.items, path, &mut out);
    }
    out
}

fn collect_program_instructions(items: &[syn::Item], path: &str, out: &mut Vec<AnchorInstruction>) {
    for item in items {
        if let syn::Item::Mod(m) = item
            && m.attrs.iter().any(|a| a.path().is_ident("program"))
            && let Some((_, mod_items)) = &m.content
        {
            for f in mod_items.iter().filter_map(|i| match i {
                syn::Item::Fn(f) => Some(f),
                _ => None,
            }) {
                let Some(root_struct) = context_root_struct(&f.sig) else { continue };
                out.push(AnchorInstruction {
                    name: f.sig.ident.to_string(),
                    handler: f.sig.ident.to_string(),
                    file: path.to_string(),
                    line: f.sig.ident.span().start().line,
                    root_struct,
                    attrs: f.attrs.clone(),
                });
            }
        }
    }
}

/// The `X` of the `ctx: Context<X>` (or `ctx: &Context<X>`) handler parameter.
fn context_root_struct(sig: &syn::Signature) -> Option<String> {
    for input in &sig.inputs {
        let ty = match input {
            syn::FnArg::Typed(t) => &t.ty,
            syn::FnArg::Receiver(_) => continue,
        };
        let inner = match ty.as_ref() {
            syn::Type::Reference(r) => &*r.elem,
            t => t,
        };
        if let syn::Type::Path(tp) = inner {
            let last = tp.path.segments.last()?;
            if last.ident != "Context" {
                continue;
            }
            if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                for arg in args.args.iter().rev() {
                    if let syn::GenericArgument::Type(t) = arg {
                        return Some(leaf_type_ident(t));
                    }
                }
            }
        }
    }
    None
}

/// Expand the account slots of an Accounts struct (recursively through
/// in-file bundle types). Returns `(account_name, type_ident)` pairs in
/// declaration order, root fields first, deduplicated by name.
fn expand_accounts(root: &str, structs: &StructIndex) -> (Vec<(String, String)>, HashMap<String, String>) {
    let mut slots = Vec::new();
    let mut seen = HashSet::new();
    expand_into(root, structs, 0, &mut seen, &mut slots);
    let account_types = slots.iter().map(|(n, t)| (n.clone(), t.clone())).collect();
    (slots, account_types)
}

fn expand_into(
    struct_name: &str,
    structs: &StructIndex,
    depth: usize,
    seen: &mut HashSet<String>,
    out: &mut Vec<(String, String)>,
) {
    if depth > 3 {
        return;
    }
    let Some(fields) = structs.fields.get(struct_name) else { return };
    for (fname, fty, _attrs) in fields {
        if seen.insert(fname.clone()) {
            out.push((fname.clone(), fty.clone()));
        }
        if structs.is_bundle(fty) && !fty.is_empty() {
            expand_into(fty, structs, depth + 1, seen, out);
        }
    }
}

/// Name-based kind inference for the Anchor path (no frontend model).
fn infer_kind(name: &str) -> AccountKind {
    let lower = name.to_ascii_lowercase();
    if lower == "system_program" {
        AccountKind::SystemProgram
    } else if matches!(
        lower.as_str(),
        "clock" | "rent" | "epoch_schedule" | "slot_history" | "recent_blockhashes" | "instructions" | "sysvar"
    ) {
        AccountKind::Sysvar
    } else if lower.ends_with("_program") {
        AccountKind::Program
    } else {
        AccountKind::Unchecked
    }
}

/// Expression roots from a handler's attributes: `#[access_control(
/// ctx.accounts.validate())]`-style list attributes are scanned as part of the
/// handler body.
fn attr_expr_roots(attrs: &[syn::Attribute]) -> Vec<Expr> {
    let mut out = Vec::new();
    for attr in attrs {
        if attr.path().is_ident("cfg") || attr.path().is_ident("doc") || attr.path().is_ident("derive") {
            continue;
        }
        if let syn::Meta::List(list) = &attr.meta
            && let Ok(expr) = syn::parse2::<Expr>(list.tokens.clone())
        {
            out.push(expr);
        }
    }
    out
}

/// Constraint expressions from `#[account(...)]` attributes on Accounts-struct
/// FIELD definitions: `#[account(mut, constraint = author_fees.mint ==
/// collateral.mint)]` yields the `author_fees.mint == collateral.mint`
/// comparison (the post-fix Cashio shape). These join the SAT031 graph like
/// handler-level roots.
pub fn account_constraint_exprs(attrs: &[syn::Attribute]) -> Vec<Expr> {
    use syn::punctuated::Punctuated;

    let mut out = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }
        let syn::Meta::List(list) = &attr.meta else { continue };
        let metas =
            syn::parse::Parser::parse2(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated, list.tokens.clone());
        let Ok(metas) = metas else { continue };
        for meta in metas {
            if let syn::Meta::NameValue(nv) = meta
                && nv.path.is_ident("constraint")
            {
                out.push(nv.value);
            }
        }
    }
    out
}

// ── Shared per-instruction analysis ──────────────────────────────────────────

/// The comparison graph collected for one instruction: flattened handler +
/// helper blocks, the equality comparisons, and the reachable canonical
/// accounts. Shared by the SAT031 chain detection and the SAT033
/// unanchored-token-mint check.
struct InstructionGraph<'a> {
    blocks: Vec<&'a syn::Block>,
    comparisons: Vec<Comparison>,
    canonical: HashSet<usize>,
}

fn analyze_instruction_graph<'a>(
    ix: &NativeInstruction,
    index: &'a FnIndex<'a>,
    bundles: &Bundles,
    attr_roots: &[Expr],
) -> Option<InstructionGraph<'a>> {
    let (handler, file_idx) = index.lookup(&ix.handler, &ix.file)?;

    let mut blocks: Vec<&'a syn::Block> = Vec::new();
    let mut visited = HashSet::new();
    visited.insert((file_idx, ix.handler.clone()));
    collect_blocks(handler, index, &mut visited, 0, &mut blocks, attr_roots);

    // Alias seed: the handler's `program_id` parameter is an anchor.
    let mut aliases = HashMap::new();
    aliases.insert("program_id".to_string(), Side::Anchor);

    let mut comparisons = Vec::new();
    for block in &blocks {
        let mut block_aliases = aliases.clone();
        scan_block(block, &mut block_aliases, ix, bundles, &mut comparisons);
    }
    for root in attr_roots {
        let mut block_aliases = aliases.clone();
        scan_expr(root, &mut block_aliases, ix, bundles, &mut comparisons);
    }

    let mut canonical = reachable_canonical(&comparisons, seed_canonical(ix));
    canonical.extend(owner_checked_accounts(&blocks, ix));

    Some(InstructionGraph { blocks, comparisons, canonical })
}

fn analyze_instruction(
    ix: &NativeInstruction,
    index: &FnIndex,
    bundles: &Bundles,
    attr_roots: &[Expr],
) -> Vec<Finding> {
    let Some(graph) = analyze_instruction_graph(ix, index, bundles, attr_roots) else {
        return Vec::new();
    };
    sat031_findings(ix, &graph)
}

/// SAT031: one finding per unanchored (account, field) component with ≥ 2
/// distinct nodes. Components made solely of `key`-field nodes (e.g.
/// `a.key == b.key`) are identity-pinning idioms, not data-validation
/// chains — the SAT019/021 slices own that pattern, so they are suppressed.
fn sat031_findings(ix: &NativeInstruction, graph: &InstructionGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let comparisons = &graph.comparisons;

    // Build the graph over (account, field) nodes.
    let mut nodes: Vec<(usize, String)> = Vec::new();
    let mut node_index: HashMap<(usize, String), usize> = HashMap::new();
    for c in comparisons {
        for n in [&c.left_node, &c.right_node].into_iter().flatten() {
            if !node_index.contains_key(n) {
                node_index.insert(n.clone(), nodes.len());
                nodes.push(n.clone());
            }
        }
    }
    let mut uf = UnionFind::new(nodes);
    for c in comparisons {
        let (Some(l), Some(r)) = (&c.left_node, &c.right_node) else { continue };
        let li = node_index[l];
        let ri = node_index[r];
        let anchored = matches!(c.left, Side::Anchor)
            || matches!(c.right, Side::Anchor)
            || graph.canonical.contains(&l.0)
            || graph.canonical.contains(&r.0);
        if anchored {
            uf.mark_anchored(li);
            uf.mark_anchored(ri);
        } else {
            uf.union(li, ri);
        }
    }

    let roots: Vec<usize> = (0..uf.parent.len()).map(|i| uf.find(i)).collect();
    let mut seen_roots = HashSet::new();
    for root in &roots {
        if !seen_roots.insert(*root) {
            continue;
        }
        if uf.anchored[*root] || uf.node_count[*root] < 2 || component_is_all_keys(&uf, &roots, *root) {
            continue;
        }
        let account = uf.account[*root];
        let name = ix.accounts[account].name.clone();
        findings.push(Finding {
            id: String::new(),
            title: format!("{SAT031_TITLE} `{name}`"),
            severity: Severity::High,
            description: format!(
                "Validation in instruction `{}` compares only caller-supplied accounts to each \
                 other ({}) and never anchors the chain to canonical program state (program id, \
                 constants, owner checks, or literal-seed PDAs). An attacker who controls every \
                 account in the chain can make the validation self-consistent with fabricated \
                 data — the Cashio class (EXPLOIT_CORPUS.md). Manually confirm whether one of \
                 the compared fields is the load-bearing identity check.",
                ix.name,
                chain_summary(ix, &uf, *root)
            ),
            location: Some(location(ix)),
            suggestion: Some(format!(
                "Anchor the validation to canonical state: compare at least one field in the \
                 chain against a constant / the program id / a registry or authority account \
                 whose owner is verified, e.g. `if {}.owner != program_id {{ return Err(...) }}`.",
                name
            )),
        });
    }

    findings
}

/// Whether every node of a component is a `key`-field node (identity pinning).
fn component_is_all_keys(uf: &UnionFind, roots: &[usize], root: usize) -> bool {
    for (i, r) in roots.iter().enumerate() {
        if *r == root && uf.field[i] != "key" {
            return false;
        }
    }
    true
}

/// Human-readable chain summary: `` `a`.mint == `b`.key; `` per component.
/// `parent` is fully flattened (the caller precomputes all roots).
fn chain_summary(ix: &NativeInstruction, uf: &UnionFind, root: usize) -> String {
    let mut parts = Vec::new();
    for (i, p) in uf.parent.iter().enumerate() {
        if *p == root {
            let acc = &ix.accounts[uf.account[i]].name;
            parts.push(format!("`{acc}`.{}", uf.field[i]));
        }
    }
    parts.join(", ")
}

// ── SAT033: unanchored token mint ────────────────────────────────────────────

/// The source field of a token-CPI accounts struct, and whether the pinned
/// node is the token account's `.mint` (`true`) or the mint account's
/// identity (`false`). Covers the anchor-spl transfer/mint/burn shapes.
fn transfer_source_field(name: &str) -> Option<(&str, bool)> {
    match name {
        "Transfer" | "TransferChecked" | "Burn" | "BurnChecked" => Some(("from", true)),
        "MintTo" | "MintToChecked" => Some(("mint", false)),
        _ => None,
    }
}

/// Strips `to_account_info()`/`clone()`-style wrapper calls from an
/// expression (`self.depositor_source.to_account_info()` →
/// `self.depositor_source`).
fn strip_wrapper_calls(e: &Expr) -> &Expr {
    match e {
        Expr::MethodCall(m)
            if matches!(m.method.to_string().as_str(), "to_account_info" | "clone" | "as_ref" | "key") =>
        {
            strip_wrapper_calls(&m.receiver)
        }
        _ => e,
    }
}

/// SAT033: a token transfer/mint CPI whose SOURCE token account's `.mint`
/// (or the mint account's identity) is never compared against anything at all
/// in the instruction's validation graph. SAT031 owns chains that ARE
/// compared but unanchored; this fires only when the mint is never touched,
/// keeping the two checks complementary.
fn sat033_findings(ix: &NativeInstruction, graph: &InstructionGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut sources: Vec<(usize, bool)> = Vec::new();
    let mut seen = HashSet::new();
    for block in &graph.blocks {
        collect_transfer_sources(block, ix, &mut sources, &mut seen);
    }

    for (acc_idx, is_mint_field) in sources {
        let compared = graph.comparisons.iter().any(|c| {
            [&c.left_node, &c.right_node]
                .into_iter()
                .flatten()
                .any(|(a, f)| *a == acc_idx && (is_mint_field && f == "mint" || !is_mint_field && f == "key"))
        });
        if compared {
            continue;
        }
        let name = ix.accounts[acc_idx].name.clone();
        let (source_label, target_label) =
            if is_mint_field { ("source token account", "`.mint`") } else { ("mint account", "identity (`.key`)") };
        findings.push(Finding {
            id: String::new(),
            title: format!("Unanchored Token Mint: `{name}`"),
            severity: Severity::High,
            description: format!(
                "Instruction `{}` performs a token transfer/mint CPI whose {source_label} `{name}` \
                 {target_label} is never compared against canonical state (a constant, the program \
                 id, an owner-checked account, or a pinned registry). An attacker can supply a \
                 token account (or mint) with an arbitrary mint, and the program has no visible \
                 anchoring check to catch it — the Cashio-class shape focused on transfer paths. \
                 Confirm whether the handler validates the mint elsewhere.",
                ix.name
            ),
            location: Some(location(ix)),
            suggestion: Some(format!(
                "Anchor the {source_label}'s mint identity before the CPI, e.g. \
                 `assert_keys_eq!({name}.mint, EXPECTED_MINT)` or an \
                 `#[account(constraint = {name}.mint == EXPECTED_MINT)]` on the Accounts field."
            )),
        });
    }

    findings
}

fn collect_transfer_sources(
    block: &syn::Block,
    ix: &NativeInstruction,
    out: &mut Vec<(usize, bool)>,
    seen: &mut HashSet<(usize, bool)>,
) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => walk_transfer_sources(e, ix, out, seen),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    walk_transfer_sources(&init.expr, ix, out, seen);
                }
            }
            syn::Stmt::Macro(m) => {
                for arg in macro_exprs(&m.mac) {
                    walk_transfer_sources(&arg, ix, out, seen);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn walk_transfer_sources(
    e: &Expr,
    ix: &NativeInstruction,
    out: &mut Vec<(usize, bool)>,
    seen: &mut HashSet<(usize, bool)>,
) {
    match e {
        Expr::Struct(s) => {
            let struct_name = s.path.segments.last().map(|seg| seg.ident.to_string()).unwrap_or_default();
            if let Some((field, is_mint_field)) = transfer_source_field(&struct_name)
                && let Some(source_field) =
                    s.fields.iter().find(|f| matches!(&f.member, syn::Member::Named(n) if n == field))
                && let Side::AccountField(acc, _) =
                    resolve_side(strip_wrapper_calls(&source_field.expr), ix, &HashMap::new(), &Bundles::empty())
                && seen.insert((acc, is_mint_field))
            {
                out.push((acc, is_mint_field));
            }
            for f in &s.fields {
                walk_transfer_sources(&f.expr, ix, out, seen);
            }
        }
        Expr::Call(c) => {
            walk_transfer_sources(&c.func, ix, out, seen);
            for arg in &c.args {
                walk_transfer_sources(arg, ix, out, seen);
            }
        }
        Expr::MethodCall(m) => {
            walk_transfer_sources(&m.receiver, ix, out, seen);
            for arg in &m.args {
                walk_transfer_sources(arg, ix, out, seen);
            }
        }
        Expr::Block(b) => collect_transfer_sources(&b.block, ix, out, seen),
        Expr::Unsafe(u) => collect_transfer_sources(&u.block, ix, out, seen),
        Expr::Const(c) => collect_transfer_sources(&c.block, ix, out, seen),
        Expr::Async(a) => collect_transfer_sources(&a.block, ix, out, seen),
        Expr::TryBlock(tb) => collect_transfer_sources(&tb.block, ix, out, seen),
        Expr::If(i) => {
            walk_transfer_sources(&i.cond, ix, out, seen);
            collect_transfer_sources(&i.then_branch, ix, out, seen);
            if let Some((_, else_expr)) = &i.else_branch {
                walk_transfer_sources(else_expr, ix, out, seen);
            }
        }
        Expr::While(w) => {
            walk_transfer_sources(&w.cond, ix, out, seen);
            collect_transfer_sources(&w.body, ix, out, seen);
        }
        Expr::Loop(l) => collect_transfer_sources(&l.body, ix, out, seen),
        Expr::ForLoop(fl) => collect_transfer_sources(&fl.body, ix, out, seen),
        Expr::Match(m) => {
            walk_transfer_sources(&m.expr, ix, out, seen);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    walk_transfer_sources(guard, ix, out, seen);
                }
                walk_transfer_sources(&arm.body, ix, out, seen);
            }
        }
        Expr::Try(t) => walk_transfer_sources(&t.expr, ix, out, seen),
        Expr::Paren(p) => walk_transfer_sources(&p.expr, ix, out, seen),
        Expr::Group(g) => walk_transfer_sources(&g.expr, ix, out, seen),
        Expr::Reference(r) => walk_transfer_sources(&r.expr, ix, out, seen),
        Expr::RawAddr(r) => walk_transfer_sources(&r.expr, ix, out, seen),
        Expr::Unary(u) => walk_transfer_sources(&u.expr, ix, out, seen),
        Expr::Await(a) => walk_transfer_sources(&a.base, ix, out, seen),
        Expr::Closure(c) => walk_transfer_sources(&c.body, ix, out, seen),
        Expr::Binary(b) => {
            walk_transfer_sources(&b.left, ix, out, seen);
            walk_transfer_sources(&b.right, ix, out, seen);
        }
        Expr::Assign(a) => {
            walk_transfer_sources(&a.left, ix, out, seen);
            walk_transfer_sources(&a.right, ix, out, seen);
        }
        Expr::Index(i) => {
            walk_transfer_sources(&i.expr, ix, out, seen);
            walk_transfer_sources(&i.index, ix, out, seen);
        }
        Expr::Tuple(t) => {
            for el in &t.elems {
                walk_transfer_sources(el, ix, out, seen);
            }
        }
        Expr::Array(a) => {
            for el in &a.elems {
                walk_transfer_sources(el, ix, out, seen);
            }
        }
        Expr::Cast(c) => walk_transfer_sources(&c.expr, ix, out, seen),
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                walk_transfer_sources(x, ix, out, seen);
            }
        }
        Expr::Break(br) => {
            if let Some(x) = &br.expr {
                walk_transfer_sources(x, ix, out, seen);
            }
        }
        Expr::Macro(m) => {
            for arg in macro_exprs(&m.mac) {
                walk_transfer_sources(&arg, ix, out, seen);
            }
        }
        _ => {}
    }
}

/// SAT031: flag instructions whose validation compares only caller-supplied
/// accounts to each other. Native model first; when the workspace has no
/// native marker but has Anchor `#[program]` modules, an Anchor fallback path
/// extracts the instructions, Accounts bundles and `validate` chains from
/// source (this is what makes the Cashio tree analyzable).
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let index = FnIndex::build(parsed);
    let structs = StructIndex::build(parsed);

    if !program.instructions.is_empty() {
        let mut findings = Vec::new();
        for ix in &program.instructions {
            let bundles = Bundles::empty();
            findings.extend(analyze_instruction(ix, &index, &bundles, &[]));
        }
        return findings;
    }

    if !has_anchor_program(parsed) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for anchor in anchor_instructions(parsed) {
        let (slots, account_types) = expand_accounts(&anchor.root_struct, &structs);
        if slots.is_empty() {
            continue;
        }
        let accounts = slots
            .into_iter()
            .map(|(name, _)| {
                let kind = infer_kind(&name);
                ResolvedAccount { name, kind, ..ResolvedAccount::default() }
            })
            .collect();
        let ix = NativeInstruction {
            name: anchor.name,
            discriminator: None,
            handler: anchor.handler,
            file: anchor.file,
            line: anchor.line,
            accounts,
        };
        let bundles = Bundles::build(&ix.accounts, &account_types, &structs);

        // Handler attribute roots (`#[access_control(...)]`) plus the
        // `#[account(constraint = ...)]` comparisons on the Accounts struct's
        // field definitions.
        let mut roots = attr_expr_roots(&anchor.attrs);
        if let Some(fields) = structs.fields.get(&anchor.root_struct) {
            for (_fname, _fty, attrs) in fields {
                roots.extend(account_constraint_exprs(attrs));
            }
        }

        let Some(graph) = analyze_instruction_graph(&ix, &index, &bundles, &roots) else {
            continue;
        };
        findings.extend(sat031_findings(&ix, &graph));
        findings.extend(sat033_findings(&ix, &graph));
    }
    findings
}
