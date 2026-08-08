//! R4 slice: CPI rules SAT028, SAT029 and SAT030.
//!
//! These rules look inside the raw syntax trees (the `parsed` file pairs) for
//! `invoke`/`invoke_signed` call sites inside each instruction handler (and
//! its helper call graph, depth ≤ 2, cycle-guarded — same semantics as
//! `docs/NATIVE_BACKEND.md` section 6), and correlate the CPI's authority
//! account with the resolved model (`crate::native::model`):
//!
//! - SAT028 — a token-program CPI (transfer/mint_to/burn/set_authority) whose
//!   authority account is neither signer-checked nor key-compared, or a PDA
//!   signed with plain `invoke` instead of `invoke_signed`.
//! - SAT029 — a CPI whose `program_id` is the program's own declared id
//!   (self-invocation / sub-dispatch re-entry).
//! - SAT030 — a state account written by ≥ 2 instructions where at least one
//!   writer lacks an init/discriminator guard.
//!
//! CPI shapes understood:
//! - `invoke(&Instruction { program_id, accounts, data }, &[...])` struct
//!   literals (also `let`-bound, resolved through one level of top-level
//!   bindings), including `Instruction::new_with_borsh`/`new_with_bytes`.
//! - token instruction builders: `spl_token::instruction::transfer(...)`-style
//!   calls (path contains `token`, or the op name is token-distinctive:
//!   `transfer_checked`/`mint_to`/`burn`/`set_authority`; bare `transfer`
//!   without a `token` path segment is excluded as ambiguous, mirroring
//!   `crate::token_cpi`).
//! - `Instruction`-enum data variants named Transfer/TransferChecked/MintTo/
//!   Burn/SetAuthority in the `data` field (e.g.
//!   `TokenInstruction::Transfer { .. }.pack()`).
//!
//! Not mapped (silently skipped, never panics): CPIs built through helper
//! functions that assemble `Instruction` values (bindings are only resolved at
//! top level of the block that contains the call), `AccountMeta` pubkeys that
//! do not resolve to an instruction account by variable name, and invoke
//! calls hidden inside macros (opaque token streams).

use std::collections::{HashMap, HashSet};

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

use crate::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
use crate::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7 (load-bearing
/// for SARIF classification — do not rename).
const SAT028_TITLE: &str = "Token CPI Unverified Authority:";
const SAT029_TITLE: &str = "Self-Invocation:";
const SAT030_TITLE: &str = "Cross-Instruction State Reuse:";

/// The SPL Token and Token-2022 program ids.
const TOKEN_PROGRAM_IDS: [&str; 2] =
    ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"];

/// Token operations SAT028 reasons over.
const TOKEN_OPS: [&str; 5] = ["transfer", "transfer_checked", "mint_to", "burn", "set_authority"];

/// Token ops distinctive enough to match even without a `token` path segment.
const DISTINCTIVE_OPS: [&str; 4] = ["transfer_checked", "mint_to", "burn", "set_authority"];

const INVOKE_NAMES: [&str; 3] = ["invoke", "invoke_signed", "invoke_signed_unchecked"];

// ── Expression helpers ──────────────────────────────────────────────────────

/// Compact key of an expression: `spl_token::id()`, `token_program.key`,
/// `*program_id`, string-literal values, etc. Used for cheap pattern checks.
fn expr_key(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => Some(p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")),
        syn::Expr::Call(c) => expr_key(&c.func),
        syn::Expr::MethodCall(m) => Some(format!("{}.{}", expr_key(&m.receiver).unwrap_or_default(), m.method)),
        syn::Expr::Field(f) => Some(format!("{}.{}", expr_key(&f.base).unwrap_or_default(), member_name(&f.member))),
        syn::Expr::Reference(r) => expr_key(&r.expr),
        syn::Expr::Paren(p) => expr_key(&p.expr),
        syn::Expr::Group(g) => expr_key(&g.expr),
        syn::Expr::Unary(u) => expr_key(&u.expr),
        syn::Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        _ => None,
    }
}

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(i) => i.to_string(),
        syn::Member::Unnamed(i) => i.index.to_string(),
    }
}

/// Base identifier of an account-pubkey expression: `&authority.key()` ->
/// `authority`, `*program_id` -> `program_id`, `accs.authority.key()` ->
/// `authority` (struct-field access), `state.data.borrow()[0..8]` -> `state`.
fn base_ident(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Reference(r) => base_ident(&r.expr),
        syn::Expr::Paren(p) => base_ident(&p.expr),
        syn::Expr::Group(g) => base_ident(&g.expr),
        syn::Expr::Unary(u) => base_ident(&u.expr),
        syn::Expr::MethodCall(m) => base_ident(&m.receiver),
        syn::Expr::Index(i) => base_ident(&i.expr),
        syn::Expr::Field(f) => {
            // Struct-field access (`accs.authority`) yields the field name;
            // AccountInfo members (`key`, `data`) resolve to the base account.
            if let syn::Member::Named(member) = &f.member
                && !matches!(member.to_string().as_str(), "key" | "data")
                && matches!(&*f.base, syn::Expr::Path(_))
            {
                return Some(member.to_string());
            }
            base_ident(&f.base)
        }
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// Peel reference/paren/group/deref/try wrappers off an expression.
fn peel(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Reference(r) => peel(&r.expr),
        syn::Expr::Paren(p) => peel(&p.expr),
        syn::Expr::Group(g) => peel(&g.expr),
        syn::Expr::Unary(u) => peel(&u.expr),
        syn::Expr::Try(t) => peel(&t.expr),
        _ => e,
    }
}

fn bool_lit(e: &syn::Expr) -> Option<bool> {
    let syn::Expr::Lit(lit) = e else { return None };
    let syn::Lit::Bool(b) = &lit.lit else { return None };
    Some(b.value)
}

/// Authority names mirrored from `rules/auth.rs` (kept local: auth is owned by
/// another slice).
fn is_authority_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXACT: [&str; 9] =
        ["authority", "owner", "admin", "payer", "creator", "manager", "operator", "governor", "signer"];
    EXACT.contains(&lower.as_str())
        || lower.ends_with("_authority")
        || lower.ends_with("_admin")
        || lower.ends_with("_owner")
        || lower.ends_with("_signer")
}

fn is_known_builtin(name: &str) -> bool {
    matches!(
        name,
        "next_account_info"
            | "find_program_address"
            | "create_program_address"
            | "invoke"
            | "invoke_signed"
            | "invoke_signed_unchecked"
    )
}

// ── Generic expression walker ───────────────────────────────────────────────

/// Walk every expression (nested blocks, match arms, closures, guard macros
/// such as `require!`/`assert!`) and every `let` local of a block. `on_expr`
/// is called for each expression, `on_local` for each `let` binding.
fn walk_block_all(block: &syn::Block, on_expr: &mut dyn FnMut(&syn::Expr), on_local: &mut dyn FnMut(&syn::Local)) {
    for stmt in &block.stmts {
        walk_stmt_all(stmt, on_expr, on_local);
    }
}

fn walk_stmt_all(stmt: &syn::Stmt, on_expr: &mut dyn FnMut(&syn::Expr), on_local: &mut dyn FnMut(&syn::Local)) {
    match stmt {
        syn::Stmt::Expr(e, _) => walk_expr_all(e, on_expr, on_local),
        syn::Stmt::Local(l) => {
            on_local(l);
            if let Some(init) = &l.init {
                walk_expr_all(&init.expr, on_expr, on_local);
            }
        }
        syn::Stmt::Macro(_) | syn::Stmt::Item(_) => {}
    }
}

fn walk_expr_all(e: &syn::Expr, on_expr: &mut dyn FnMut(&syn::Expr), on_local: &mut dyn FnMut(&syn::Local)) {
    on_expr(e);
    match e {
        syn::Expr::Call(c) => {
            walk_expr_all(&c.func, on_expr, on_local);
            for arg in &c.args {
                walk_expr_all(arg, on_expr, on_local);
            }
        }
        syn::Expr::MethodCall(m) => {
            walk_expr_all(&m.receiver, on_expr, on_local);
            for arg in &m.args {
                walk_expr_all(arg, on_expr, on_local);
            }
        }
        syn::Expr::Block(b) => walk_block_all(&b.block, on_expr, on_local),
        syn::Expr::Unsafe(u) => walk_block_all(&u.block, on_expr, on_local),
        syn::Expr::Async(a) => walk_block_all(&a.block, on_expr, on_local),
        syn::Expr::Const(c) => walk_block_all(&c.block, on_expr, on_local),
        syn::Expr::If(i) => {
            walk_expr_all(&i.cond, on_expr, on_local);
            walk_block_all(&i.then_branch, on_expr, on_local);
            if let Some((_, else_expr)) = &i.else_branch {
                walk_expr_all(else_expr, on_expr, on_local);
            }
        }
        syn::Expr::Match(m) => {
            walk_expr_all(&m.expr, on_expr, on_local);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    walk_expr_all(guard, on_expr, on_local);
                }
                walk_expr_all(&arm.body, on_expr, on_local);
            }
        }
        syn::Expr::While(w) => {
            walk_expr_all(&w.cond, on_expr, on_local);
            walk_block_all(&w.body, on_expr, on_local);
        }
        syn::Expr::Loop(l) => walk_block_all(&l.body, on_expr, on_local),
        syn::Expr::ForLoop(fl) => walk_block_all(&fl.body, on_expr, on_local),
        syn::Expr::Try(t) => walk_expr_all(&t.expr, on_expr, on_local),
        syn::Expr::Paren(p) => walk_expr_all(&p.expr, on_expr, on_local),
        syn::Expr::Group(g) => walk_expr_all(&g.expr, on_expr, on_local),
        syn::Expr::Reference(r) => walk_expr_all(&r.expr, on_expr, on_local),
        syn::Expr::Unary(u) => walk_expr_all(&u.expr, on_expr, on_local),
        syn::Expr::Let(l) => walk_expr_all(&l.expr, on_expr, on_local),
        syn::Expr::Binary(b) => {
            walk_expr_all(&b.left, on_expr, on_local);
            walk_expr_all(&b.right, on_expr, on_local);
        }
        syn::Expr::Assign(a) => {
            walk_expr_all(&a.left, on_expr, on_local);
            walk_expr_all(&a.right, on_expr, on_local);
        }
        syn::Expr::Index(i) => {
            walk_expr_all(&i.expr, on_expr, on_local);
            walk_expr_all(&i.index, on_expr, on_local);
        }
        syn::Expr::Field(f) => walk_expr_all(&f.base, on_expr, on_local),
        syn::Expr::Tuple(t) => {
            for el in &t.elems {
                walk_expr_all(el, on_expr, on_local);
            }
        }
        syn::Expr::Array(a) => {
            for el in &a.elems {
                walk_expr_all(el, on_expr, on_local);
            }
        }
        syn::Expr::Repeat(r) => {
            walk_expr_all(&r.expr, on_expr, on_local);
            walk_expr_all(&r.len, on_expr, on_local);
        }
        syn::Expr::Struct(s) => {
            for field in &s.fields {
                walk_expr_all(&field.expr, on_expr, on_local);
            }
        }
        syn::Expr::Closure(c) => walk_expr_all(&c.body, on_expr, on_local),
        syn::Expr::Cast(c) => walk_expr_all(&c.expr, on_expr, on_local),
        syn::Expr::Range(r) => {
            if let Some(start) = &r.start {
                walk_expr_all(start, on_expr, on_local);
            }
            if let Some(end) = &r.end {
                walk_expr_all(end, on_expr, on_local);
            }
        }
        syn::Expr::Return(r) => {
            if let Some(x) = &r.expr {
                walk_expr_all(x, on_expr, on_local);
            }
        }
        syn::Expr::Break(b) => {
            if let Some(x) = &b.expr {
                walk_expr_all(x, on_expr, on_local);
            }
        }
        syn::Expr::Await(a) => walk_expr_all(&a.base, on_expr, on_local),
        syn::Expr::Macro(m) => {
            // Guard macros carry conditions/assertions as expression args;
            // other macros (vec!, msg!) are opaque token streams.
            if is_guard_macro(&m.mac) {
                let Ok(args) = m.mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) else {
                    return;
                };
                for arg in args {
                    walk_expr_all(&arg, on_expr, on_local);
                }
            }
        }
        syn::Expr::Path(_) | syn::Expr::Lit(_) | syn::Expr::Continue(_) => {}
        _ => {}
    }
}

fn is_guard_macro(mac: &syn::Macro) -> bool {
    matches!(
        mac.path.segments.last().map(|s| s.ident.to_string()).as_deref(),
        Some(
            "require"
                | "require_keys_eq"
                | "require_keys_neq"
                | "require_eq"
                | "assert"
                | "assert_eq"
                | "invariant"
                | "debug_assert"
                | "debug_assert_eq"
                | "check"
                | "check_eq"
        )
    )
}

/// Distinct local-function callees of a block (used for the helper call
/// graph). Only names that resolve to functions in the file index are kept.
fn collect_callees_in_block(block: &syn::Block, index: &FnIndex, out: &mut Vec<String>) {
    walk_block_all(
        block,
        &mut |e| {
            if let syn::Expr::Call(c) = e {
                let key = expr_key(&c.func).unwrap_or_default();
                let last = key.rsplit("::").next().unwrap_or(&key);
                if !is_known_builtin(last) && !matches!(last, "msg" | "Ok" | "Err") && index.fns.contains_key(last) {
                    out.push(last.to_string());
                }
            }
        },
        &mut |_| {},
    );
}

// ── Function index over the parsed files ────────────────────────────────────

struct FnIndex<'a> {
    fns: HashMap<String, Vec<(&'a syn::ItemFn, usize)>>,
    files: &'a [(syn::File, String)],
}

impl<'a> FnIndex<'a> {
    fn build(files: &'a [(syn::File, String)]) -> Self {
        let mut fns: HashMap<String, Vec<(&'a syn::ItemFn, usize)>> = HashMap::new();
        for (i, (file, _)) in files.iter().enumerate() {
            collect_fns(&file.items, i, &mut fns);
        }
        FnIndex { fns, files }
    }

    /// Best candidate for `name`: a definition in `prefer_file` if one
    /// exists, otherwise the first definition overall.
    fn lookup(&self, name: &str, prefer_file: &str) -> Option<(&'a syn::ItemFn, usize)> {
        let candidates = self.fns.get(name)?;
        candidates.iter().find(|(_, i)| self.files[*i].1 == prefer_file).or_else(|| candidates.first()).copied()
    }
}

fn collect_fns<'a>(items: &'a [syn::Item], file_idx: usize, out: &mut HashMap<String, Vec<(&'a syn::ItemFn, usize)>>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => out.entry(f.sig.ident.to_string()).or_default().push((f, file_idx)),
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_fns(items, file_idx, out);
                }
            }
            _ => {}
        }
    }
}

/// The handler block plus its helper call graph (depth ≤ 2, cycle-guarded).
fn handler_blocks<'a>(handler: &'a syn::ItemFn, file_idx: usize, index: &FnIndex<'a>) -> Vec<(&'a syn::Block, usize)> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    visited.insert(handler.sig.ident.to_string());
    collect_blocks(&handler.block, file_idx, index, &mut visited, 0, &mut out);
    out
}

fn collect_blocks<'a>(
    block: &'a syn::Block,
    file_idx: usize,
    index: &FnIndex<'a>,
    visited: &mut HashSet<String>,
    depth: usize,
    out: &mut Vec<(&'a syn::Block, usize)>,
) {
    out.push((block, file_idx));
    if depth >= 2 {
        return;
    }
    let mut callees = Vec::new();
    collect_callees_in_block(block, index, &mut callees);
    callees.sort();
    callees.dedup();
    for name in callees {
        if !visited.insert(name.clone()) {
            continue;
        }
        if let Some((f, idx)) = index.lookup(&name, "") {
            collect_blocks(&f.block, idx, index, visited, depth + 1, out);
        }
    }
}

// ── Invoke call sites ───────────────────────────────────────────────────────

/// One `invoke`/`invoke_signed`/`invoke_signed_unchecked` call site.
struct InvokeSite {
    callee: String,
    args: Vec<syn::Expr>,
    file: String,
    line: usize,
}

impl InvokeSite {
    /// True when the call provides seeds (`invoke_signed*`), so a PDA
    /// authority can actually sign.
    fn is_signed(&self) -> bool {
        self.callee != "invoke"
    }
}

fn collect_sites_in_block(block: &syn::Block, file: &str, out: &mut Vec<InvokeSite>) {
    walk_block_all(
        block,
        &mut |e| {
            if let syn::Expr::Call(c) = e {
                let callee = expr_key(&c.func).unwrap_or_default();
                let last = callee.rsplit("::").next().unwrap_or(&callee);
                if INVOKE_NAMES.contains(&last) {
                    out.push(InvokeSite {
                        callee: last.to_string(),
                        args: c.args.iter().cloned().collect(),
                        file: file.to_string(),
                        line: c.span().start().line,
                    });
                }
            }
        },
        &mut |_| {},
    );
}

/// Collect all invoke sites of the handler expansion together with the
/// top-level `let` bindings of the block that contains each site.
fn collect_sites(
    blocks: &[(&syn::Block, usize)],
    files: &[(syn::File, String)],
) -> Vec<(InvokeSite, HashMap<String, syn::Expr>)> {
    let mut out = Vec::new();
    for (block, file_idx) in blocks {
        let bindings = collect_bindings(block);
        let mut sites = Vec::new();
        collect_sites_in_block(block, &files[*file_idx].1, &mut sites);
        for site in sites {
            out.push((site, bindings.clone()));
        }
    }
    out
}

/// Top-level `let` bindings of a block, used to resolve
/// `let ix = Instruction { .. }; invoke(&ix, ..)`.
fn collect_bindings(block: &syn::Block) -> HashMap<String, syn::Expr> {
    let mut map = HashMap::new();
    for stmt in &block.stmts {
        if let syn::Stmt::Local(local) = stmt
            && let Some(init) = &local.init
            && let syn::Pat::Ident(pat) = &local.pat
        {
            map.insert(pat.ident.to_string(), (*init.expr).clone());
        }
    }
    map
}

/// Resolve the instruction expression passed to `invoke` through `let`
/// bindings and wrapper expressions.
fn resolve_invoke_target(e: &syn::Expr, bindings: &HashMap<String, syn::Expr>) -> syn::Expr {
    match e {
        syn::Expr::Reference(r) => resolve_invoke_target(&r.expr, bindings),
        syn::Expr::Paren(p) => resolve_invoke_target(&p.expr, bindings),
        syn::Expr::Group(g) => resolve_invoke_target(&g.expr, bindings),
        syn::Expr::Try(t) => resolve_invoke_target(&t.expr, bindings),
        syn::Expr::Path(p) => match p.path.get_ident().map(|i| i.to_string()) {
            Some(name) => match bindings.get(&name) {
                Some(bound) => resolve_invoke_target(bound, bindings),
                None => e.clone(),
            },
            None => e.clone(),
        },
        _ => e.clone(),
    }
}

/// Recovered shape of the instruction passed to `invoke`.
struct InstrInfo {
    /// Token op when this is a token CPI: the builder/variant op name
    /// (`transfer`, ...) or the generic label `token cpi`.
    token_op: Option<String>,
    /// The `program_id` expression (struct literal field / builder first arg).
    program_id: Option<syn::Expr>,
    /// The `accounts` collection expression (AccountMeta list), if present.
    accounts: Option<syn::Expr>,
    /// Full argument list for token instruction-builder calls
    /// (`spl_token::instruction::transfer(...)`); the authority sits at a
    /// fixed position.
    builder_args: Option<Vec<syn::Expr>>,
}

fn inspect_instruction(e: &syn::Expr, bindings: &HashMap<String, syn::Expr>) -> Option<InstrInfo> {
    let e = resolve_invoke_target(e, bindings);
    match &e {
        syn::Expr::Struct(s) => {
            let mut program_id = None;
            let mut accounts = None;
            let mut data = None;
            for field in &s.fields {
                let syn::Member::Named(member) = &field.member else { continue };
                match member.to_string().as_str() {
                    "program_id" => program_id = Some(field.expr.clone()),
                    "accounts" => accounts = Some(field.expr.clone()),
                    "data" => data = Some(field.expr.clone()),
                    _ => {}
                }
            }
            // `data: TokenInstruction::Transfer { .. }.pack()`-style variants.
            let variant_op = data.as_ref().and_then(token_variant_op);
            let token_op = variant_op.or_else(|| {
                program_id.as_ref().filter(|pid| is_token_program_id(pid)).map(|_| "token cpi".to_string())
            });
            Some(InstrInfo { token_op, program_id, accounts, builder_args: None })
        }
        syn::Expr::Call(c) => {
            let callee = expr_key(&c.func).unwrap_or_default();
            let last = callee.rsplit("::").next().unwrap_or(&callee).to_string();
            if matches!(last.as_str(), "new_with_borsh" | "new_with_bytes") {
                let program_id = c.args.iter().next().cloned();
                let accounts = c.args.iter().nth(2).cloned();
                let token_op =
                    program_id.as_ref().filter(|pid| is_token_program_id(pid)).map(|_| "token cpi".to_string());
                Some(InstrInfo { token_op, program_id, accounts, builder_args: None })
            } else {
                token_op_from_callee(&callee).map(|op| InstrInfo {
                    token_op: Some(op.to_string()),
                    program_id: c.args.iter().next().cloned(),
                    accounts: None,
                    builder_args: Some(c.args.iter().cloned().collect()),
                })
            }
        }
        _ => None,
    }
}

/// The token op of an instruction-builder callee, when it is a token CPI.
fn token_op_from_callee(callee: &str) -> Option<&'static str> {
    let lower = callee.to_ascii_lowercase();
    let last = lower.rsplit("::").next().unwrap_or(&lower);
    if !TOKEN_OPS.contains(&last) {
        return None;
    }
    // Bare `transfer` without a `token` path segment is ambiguous
    // (e.g. `system_program::transfer`) — exclude it, like `token_cpi.rs`.
    if lower.contains("token") {
        TOKEN_OPS.iter().find(|op| **op == last).copied()
    } else {
        DISTINCTIVE_OPS.iter().find(|op| **op == last).copied()
    }
}

/// First `Instruction`-enum variant path named Transfer/TransferChecked/
/// MintTo/Burn/SetAuthority in an expression (token-ish path only).
fn token_variant_op(e: &syn::Expr) -> Option<String> {
    let mut found = None;
    walk_variant_paths(e, &mut |path| {
        if found.is_some() {
            return;
        }
        let last = path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if TOKEN_OPS.contains(&last.as_str()) {
            let full = path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
            let lower = full.to_ascii_lowercase();
            if lower.contains("token") || lower.contains("instruction") {
                found = Some(last);
            }
        }
    });
    found
}

fn walk_variant_paths(e: &syn::Expr, f: &mut dyn FnMut(&syn::Path)) {
    match e {
        syn::Expr::Path(p) => f(&p.path),
        syn::Expr::Struct(s) => {
            f(&s.path);
            for field in &s.fields {
                walk_variant_paths(&field.expr, f);
            }
        }
        syn::Expr::Call(c) => {
            walk_variant_paths(&c.func, f);
            for arg in &c.args {
                walk_variant_paths(arg, f);
            }
        }
        syn::Expr::MethodCall(m) => {
            walk_variant_paths(&m.receiver, f);
            for arg in &m.args {
                walk_variant_paths(arg, f);
            }
        }
        syn::Expr::Reference(r) => walk_variant_paths(&r.expr, f),
        syn::Expr::Paren(p) => walk_variant_paths(&p.expr, f),
        syn::Expr::Group(g) => walk_variant_paths(&g.expr, f),
        syn::Expr::Try(t) => walk_variant_paths(&t.expr, f),
        syn::Expr::Unary(u) => walk_variant_paths(&u.expr, f),
        syn::Expr::Tuple(t) => {
            for el in &t.elems {
                walk_variant_paths(el, f);
            }
        }
        syn::Expr::Array(a) => {
            for el in &a.elems {
                walk_variant_paths(el, f);
            }
        }
        _ => {}
    }
}

/// True when the expression denotes the SPL Token / Token-2022 program:
/// a base58 string literal, or a `token`-named path/variable
/// (`token_program`, `spl_token::id()`, `solana_program::token::ID`).
/// `token_account.key`-style account keys are excluded.
fn is_token_program_id(e: &syn::Expr) -> bool {
    let e = peel(e);
    if let syn::Expr::Lit(l) = e
        && let syn::Lit::Str(s) = &l.lit
    {
        return TOKEN_PROGRAM_IDS.iter().any(|id| s.value() == *id);
    }
    expr_key(e).is_some_and(|k| is_token_program_key(&k))
}

fn is_token_program_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token") && !lower.contains("account")
}

// ── SAT028/029: authority mapping ───────────────────────────────────────────

/// One `AccountMeta` recovered from an `accounts` list.
struct MetaInfo {
    pubkey: syn::Expr,
    signer: bool,
}

/// Authority position of `spl_token::instruction::<op>(program_id,
/// <accounts..>, signers, amount)` — the last account argument in every
/// standard layout (transfer: source/dest/authority; transfer_checked:
/// source/mint/dest/authority; burn: account/mint/authority; mint_to:
/// mint/dest/authority; set_authority: account/new_authority/authority).
fn authority_arg_index(op: &str) -> usize {
    match op {
        "transfer_checked" => 4,
        _ => 3,
    }
}

fn collect_metas(e: &syn::Expr, bindings: &HashMap<String, syn::Expr>, out: &mut Vec<MetaInfo>) {
    let e = resolve_meta_collection(e, bindings);
    match &e {
        syn::Expr::Macro(m) if m.mac.path.segments.last().is_some_and(|s| s.ident == "vec") => {
            if let Ok(metas) = m.mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
                for meta in metas {
                    if let Some(info) = meta_from_expr(&meta) {
                        out.push(info);
                    }
                }
            }
        }
        syn::Expr::Array(a) => {
            for el in &a.elems {
                if let Some(info) = meta_from_expr(el) {
                    out.push(info);
                }
            }
        }
        _ => {}
    }
}

fn resolve_meta_collection(e: &syn::Expr, bindings: &HashMap<String, syn::Expr>) -> syn::Expr {
    if let syn::Expr::Path(p) = e
        && let Some(name) = p.path.get_ident()
        && let Some(bound) = bindings.get(&name.to_string())
    {
        return resolve_meta_collection(bound, bindings);
    }
    e.clone()
}

fn meta_from_expr(e: &syn::Expr) -> Option<MetaInfo> {
    match e {
        syn::Expr::Call(c) => {
            let key = expr_key(&c.func).unwrap_or_default();
            let last = key.rsplit("::").next().unwrap_or(&key);
            if key.contains("AccountMeta") && matches!(last, "new" | "new_readonly") {
                let pubkey = c.args.iter().next()?.clone();
                let signer = c.args.iter().nth(1).and_then(bool_lit).unwrap_or(false);
                return Some(MetaInfo { pubkey, signer });
            }
            None
        }
        syn::Expr::Struct(s) if s.path.segments.last().is_some_and(|seg| seg.ident == "AccountMeta") => {
            let mut pubkey = None;
            let mut signer = false;
            for field in &s.fields {
                let syn::Member::Named(member) = &field.member else { continue };
                match member.to_string().as_str() {
                    "pubkey" => pubkey = Some(field.expr.clone()),
                    "is_signer" => signer = bool_lit(&field.expr).unwrap_or(false),
                    _ => {}
                }
            }
            Some(MetaInfo { pubkey: pubkey?, signer })
        }
        _ => None,
    }
}

/// The authority pubkey of a token CPI: for builder calls the fixed argument
/// position of the op; for `Instruction` literals the last `AccountMeta`
/// whose pubkey expression names an authority (standard layouts put the
/// authority last; `set_authority` has `new_authority` before `authority`).
fn cpi_authority(info: &InstrInfo, bindings: &HashMap<String, syn::Expr>) -> Option<(syn::Expr, bool)> {
    if let Some(args) = &info.builder_args {
        let idx = authority_arg_index(info.token_op.as_deref().unwrap_or_default());
        return args.get(idx).cloned().map(|e| (e, false));
    }
    let mut metas = Vec::new();
    if let Some(accounts) = &info.accounts {
        collect_metas(accounts, bindings, &mut metas);
    }
    metas
        .iter()
        .rev()
        .find(|m| base_ident(&m.pubkey).is_some_and(|b| is_authority_named(&b)))
        .map(|m| (m.pubkey.clone(), m.signer))
}

/// True when the authority account is the program itself (`program_id`
/// parameter or its `id()` getter), which signs via `invoke_signed` seeds.
fn is_program_self(expr: &syn::Expr, base: &str) -> bool {
    base == "program_id" || matches!(expr_key(expr).as_deref(), Some("id" | "crate::id"))
}

/// Strip quotes/whitespace from a base58 id for literal comparison.
fn normalize_id(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// True when the `program_id` expression targets the program itself: a
/// literal equal to the declared id, the `id()`/`crate::id()` getter
/// (resolved to the declared id), or the entrypoint's `program_id` parameter
/// (which the runtime always sets to the current program's id).
fn is_self_invocation(program_id: &syn::Expr, declared: Option<&str>) -> bool {
    let e = peel(program_id);
    if let syn::Expr::Lit(l) = e
        && let syn::Lit::Str(s) = &l.lit
    {
        let normalized = normalize_id(&s.value());
        return declared.is_some_and(|d| normalize_id(d) == normalized);
    }
    let key = expr_key(e).unwrap_or_default();
    if matches!(key.as_str(), "id" | "crate::id") {
        return declared.is_some();
    }
    key == "program_id"
}

fn sat028_finding(ix: &NativeInstruction, site: &InvokeSite, op: &str, acc_name: &str, pda: bool) -> Finding {
    let op_label = if op == "token cpi" { "a token-program CPI".to_string() } else { format!("a token `{op}` CPI") };
    let (description, suggestion) = if pda {
        (
            format!(
                "The instruction `{}` performs {} whose authority account `{acc_name}` is a program-derived \
                 address, but the call at {}:{} uses plain `invoke` instead of `invoke_signed`. The PDA can \
                 never supply a signature, so the token program rejects the CPI (denial of service) — and if \
                 the program is changed to sign with seeds derived from attacker-influenced inputs, the \
                 authority check is bypassed entirely and arbitrary transfers are authorized.",
                ix.name, op_label, site.file, site.line
            ),
            format!(
                "Sign the CPI with `invoke_signed` using the same fixed seeds used in \
                 `find_program_address` for `{acc_name}` — never derive seeds from user-controlled input."
            ),
        )
    } else {
        (
            format!(
                "The instruction `{}` performs {} whose authority account `{acc_name}` is not constrained as \
                 a signer (`is_signer_checked = false`), never compared against a stored or derived key \
                 (`key_checked = false`), and the CPI's AccountMeta does not mark it as a signer either. The \
                 token program requires the authority's signature on this operation, so without a signer or \
                 key constraint the caller can name any account as the authority: an attacker supplying their \
                 own key for `{acc_name}` inherits every privileged transition gated on it (moving tokens out \
                 of accounts the program controls), or the CPI fails at runtime (denial of service).",
                ix.name, op_label
            ),
            format!(
                "Constrain the authority before the CPI: `if !{acc_name}.is_signer {{ return \
                 Err(ProgramError::MissingRequiredSignature); }}`, or compare `{acc_name}.key` against the \
                 stored/derived key; for a PDA use `invoke_signed` with fixed seeds."
            ),
        )
    };
    Finding {
        id: String::new(),
        title: format!("{SAT028_TITLE} `{acc_name}` in `{}` ({op})", ix.name),
        severity: Severity::High,
        description,
        location: Some(format!("{}:{} ({})", site.file, site.line, ix.name)),
        suggestion: Some(suggestion),
    }
}

fn sat029_finding(ix: &NativeInstruction, site: &InvokeSite, declared: Option<&str>) -> Finding {
    let target = declared
        .map(|d| format!(" its declared program id (`{d}`)"))
        .unwrap_or_else(|| " the entrypoint's own `program_id`".to_string());
    Finding {
        id: String::new(),
        title: format!("{SAT029_TITLE} `{}` re-enters its own program id", ix.name),
        severity: Severity::Medium,
        description: format!(
            "The instruction `{}` issues an `{}` whose `program_id` is{} — a self-invocation at {}:{}. \
             Self-invocations re-enter the program's own dispatch with instruction data the caller \
             controls, so entrypoint-level validation can be bypassed by routing through an internal \
             path, recursion can compound reentrancy, and funds can move through handlers that were only \
             meant to be reachable from a guarded outer instruction.",
            ix.name, site.callee, target, site.file, site.line
        ),
        location: Some(format!("{}:{} ({})", site.file, site.line, ix.name)),
        suggestion: Some(
            "Replace the self-invocation with an internal function call, or — if the sub-dispatch is \
             intentional — validate the re-entered instruction's accounts and data exactly as you would \
             at the entrypoint."
                .to_string(),
        ),
    }
}

/// SAT028 + SAT029 for one instruction: both consume the invoke call sites.
fn sat028_029(
    ix: &NativeInstruction,
    sites: &[(InvokeSite, HashMap<String, syn::Expr>)],
    declared: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (site, bindings) in sites {
        if site.args.is_empty() {
            continue;
        }
        let target = resolve_invoke_target(&site.args[0], bindings);
        let Some(info) = inspect_instruction(&target, bindings) else { continue };

        // SAT029: the CPI targets the program's own id.
        if let Some(pid) = &info.program_id
            && is_self_invocation(pid, declared)
        {
            findings.push(sat029_finding(ix, site, declared));
        }

        // SAT028: token CPI with an unverified (or PDA-but-unsigned) authority.
        let Some(op) = &info.token_op else { continue };
        let Some((authority_expr, meta_signer)) = cpi_authority(&info, bindings) else { continue };
        let Some(base) = base_ident(&authority_expr) else { continue };
        // FP filter: the program is its own authority (signs via seeds).
        if is_program_self(&authority_expr, &base) {
            continue;
        }
        let Some(account) = ix.accounts.iter().find(|a| a.name == base) else { continue };
        if account.is_pda && !site.is_signed() {
            findings.push(sat028_finding(ix, site, op, &account.name, true));
        } else if !account.is_signer_checked && !account.key_checked && !meta_signer {
            findings.push(sat028_finding(ix, site, op, &account.name, false));
        }
    }
    findings
}

// ── SAT030: cross-instruction state reuse ───────────────────────────────────

/// Whether the account is plausibly program state: `kind == State` by type,
/// or a state-suggesting name (the frontend leaves plain `AccountInfo`
/// variables `Unchecked`, so the name heuristic is what covers the dominant
/// native pattern). Grouping is name-based per program — documented
/// approximation: two instructions' identically-named accounts are assumed to
/// be the same state account.
fn is_stateish(account: &ResolvedAccount) -> bool {
    if account.kind == AccountKind::State {
        return true;
    }
    let name = account.name.to_ascii_lowercase();
    const EXACT: [&str; 4] = ["state", "config", "registry", "data"];
    EXACT.contains(&name.as_str())
        || name.ends_with("_state")
        || name.ends_with("_config")
        || name.ends_with("_registry")
        || name.ends_with("_storage")
}

/// True when the handler expansion contains an init/discriminator guard for
/// the account: `data_is_empty()`, a `data[0..8] == DISCRIMINATOR`-style
/// comparison, an `is_initialized` flag check, a `realloc`-on-account call,
/// or a discriminator/init-field comparison on a local deserialized from the
/// account's data (`let s = State::try_from_slice(&data)?;` then
/// `s.discriminator != STATE_DISCRIMINATOR`). Presence-based and
/// order-insensitive (same semantics as section 6).
fn has_init_guard(blocks: &[(&syn::Block, usize)], acc: &str) -> bool {
    blocks.iter().any(|(block, _)| block_has_init_guard(block, acc))
}

fn block_has_init_guard(block: &syn::Block, acc: &str) -> bool {
    let derived = collect_derived_locals(block, acc);
    let deser = collect_deserialized_locals(block, acc);
    let mut found = false;
    walk_block_all(
        block,
        &mut |e| {
            if found {
                return;
            }
            match e {
                syn::Expr::MethodCall(m) => {
                    let name = m.method.to_string();
                    let base = base_ident(&m.receiver).unwrap_or_default();
                    if matches!(name.as_str(), "data_is_empty" | "realloc" | "is_initialized")
                        && (base == acc || derived.contains(&base))
                    {
                        found = true;
                    }
                }
                syn::Expr::Field(f) => {
                    if let syn::Member::Named(member) = &f.member
                        && member == "is_initialized"
                        && let Some(base) = base_ident(&f.base)
                        && (base == acc || derived.contains(&base))
                    {
                        found = true;
                    }
                }
                syn::Expr::Binary(b)
                    if matches!(b.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
                        && (is_discriminator_compare(&b.left, &b.right, acc, &derived)
                            || is_discriminator_compare(&b.right, &b.left, acc, &derived)
                            || is_deser_field_compare(&b.left, &b.right, &deser)
                            || is_deser_field_compare(&b.right, &b.left, &deser)) =>
                {
                    found = true;
                }
                _ => {}
            }
        },
        &mut |_| {},
    );
    found
}

/// Locals bound from the account (`let data = state.data.borrow();`,
/// `let loaded = State::load(&state)?;`) so guards written on the deserialized
/// value are attributed to the account.
fn collect_derived_locals(block: &syn::Block, acc: &str) -> HashSet<String> {
    let mut derived = HashSet::new();
    walk_block_all(block, &mut |_| {}, &mut |local| {
        let Some(init) = &local.init else { return };
        if let syn::Pat::Ident(pat) = &local.pat
            && expr_mentions_ident(&init.expr, acc)
        {
            derived.insert(pat.ident.to_string());
        }
    });
    derived
}

fn expr_mentions_ident(e: &syn::Expr, ident: &str) -> bool {
    let mut found = false;
    walk_expr_all(
        e,
        &mut |e| {
            if let syn::Expr::Path(p) = e
                && p.path.get_ident().is_some_and(|i| i == ident)
            {
                found = true;
            }
        },
        &mut |_| {},
    );
    found
}

/// Base account variable an expression ultimately derives from, following
/// references/derefs, field and method access, indexing, and calls
/// (`State::load(&state)` → `state`, `try_from_slice(&data)` → `data`).
/// Struct-field access (`accs.state`) yields the field name (the model names
/// struct-style accounts by their field); the AccountInfo members `key`/`data`
/// resolve to the base account.
fn expr_account_base(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Reference(r) => expr_account_base(&r.expr),
        syn::Expr::Paren(p) => expr_account_base(&p.expr),
        syn::Expr::Group(g) => expr_account_base(&g.expr),
        syn::Expr::Try(t) => expr_account_base(&t.expr),
        syn::Expr::Unary(u) => expr_account_base(&u.expr),
        syn::Expr::MethodCall(m) => expr_account_base(&m.receiver),
        syn::Expr::Index(i) => expr_account_base(&i.expr),
        syn::Expr::Field(f) => {
            if let syn::Member::Named(member) = &f.member
                && !matches!(member.to_string().as_str(), "key" | "data")
                && matches!(&*f.base, syn::Expr::Path(_))
            {
                return Some(member.to_string());
            }
            expr_account_base(&f.base)
        }
        syn::Expr::Call(c) => c.args.first().and_then(expr_account_base),
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// True when the binding is a deserialization call on a byte slice
/// (`try_from_slice`/`try_from_slice_unchecked`/`unpack`/`unpack_unchecked`).
fn is_deserialization_call(e: &syn::Expr) -> bool {
    let e = peel(e);
    let syn::Expr::Call(c) = e else { return false };
    let callee = expr_key(&c.func).unwrap_or_default();
    let last = callee.rsplit("::").next().unwrap_or(&callee);
    matches!(last, "try_from_slice" | "try_from_slice_unchecked" | "unpack" | "unpack_unchecked")
}

/// Locals deserialized from the account's data — `let s =
/// State::try_from_slice(&data)?;` — resolved through `let` chains in source
/// order (`let data = state.data.borrow();` / `let bytes = &data[..];` then
/// the deserialization). Only the account whose data feeds the deserialization
/// gets the guard attributed to it.
///
/// Resolution is deliberately single-pass and order-sensitive: a fixpoint
/// would let a *later* shadowing binding (e.g. a second `let data = ...`
/// bound from a different account) retroactively re-attribute earlier
/// deserializations to the wrong account, which the per-account attribution
/// requirement forbids. Shadowing with an account switch is a documented
/// blind spot (the first attribution wins).
fn collect_deserialized_locals(block: &syn::Block, acc: &str) -> HashSet<String> {
    let mut from_acc: HashSet<String> = HashSet::new();
    let mut deser: HashSet<String> = HashSet::new();
    walk_block_all(block, &mut |_| {}, &mut |local| {
        let Some(init) = &local.init else { return };
        let syn::Pat::Ident(pat) = &local.pat else { return };
        let name = pat.ident.to_string();
        if from_acc.contains(&name) {
            // Shadowed binding: keep the first attribution (conservative).
            return;
        }
        let Some(base) = expr_account_base(&init.expr) else { return };
        if base != acc && !from_acc.contains(&base) && !deser.contains(&base) {
            return;
        }
        from_acc.insert(name.clone());
        if is_deserialization_call(&init.expr) || deser.contains(&base) {
            deser.insert(name);
        }
    });
    deser
}

/// Discriminator/init fields of a deserialized state struct that identify
/// whether the account was initialized.
const DESER_FIELD_NAMES: [&str; 5] = ["discriminator", "version", "tag", "is_initialized", "state"];

/// One side of a comparison is a discriminator/init field of a local
/// deserialized from the account's data (`s.discriminator`, `s.version`,
/// `s.tag`, `s.is_initialized`, `s.state`).
fn is_deser_field(e: &syn::Expr, deser: &HashSet<String>) -> bool {
    let e = peel(e);
    let syn::Expr::Field(f) = e else { return false };
    let syn::Member::Named(member) = &f.member else { return false };
    if !DESER_FIELD_NAMES.contains(&member.to_string().as_str()) {
        return false;
    }
    base_ident(&f.base).is_some_and(|b| deser.contains(&b))
}

/// `s.<field> ==/<!= <constant>` where `s` is a local deserialized from the
/// account's data and the other side is a literal/array/constant path.
fn is_deser_field_compare(a: &syn::Expr, b: &syn::Expr, deser: &HashSet<String>) -> bool {
    is_deser_field(a, deser) && is_literal_like(b)
}

/// One side of a comparison is an index into the account's data
/// (`data[0..8]`, `state.data.borrow()[0..8]`).
fn is_data_index(e: &syn::Expr, acc: &str, derived: &HashSet<String>) -> bool {
    let e = peel(e);
    if let syn::Expr::Index(i) = e {
        let base = base_ident(&i.expr).unwrap_or_default();
        return base == acc || derived.contains(&base);
    }
    false
}

/// The other side is a literal, byte array, or constant path
/// (`DISCRIMINATOR`, `[9u8; 8]`, `0`).
fn is_literal_like(e: &syn::Expr) -> bool {
    matches!(peel(e), syn::Expr::Lit(_) | syn::Expr::Array(_) | syn::Expr::Repeat(_) | syn::Expr::Path(_))
}

fn is_discriminator_compare(a: &syn::Expr, b: &syn::Expr, acc: &str, derived: &HashSet<String>) -> bool {
    is_data_index(a, acc, derived) && is_literal_like(b)
}

fn sat030_finding(name: &str, writers: &[(&NativeInstruction, bool)]) -> Finding {
    let all: Vec<&str> = writers.iter().map(|(ix, _)| ix.name.as_str()).collect();
    let unguarded: Vec<&NativeInstruction> =
        writers.iter().filter_map(|(ix, guarded)| (!guarded).then_some(*ix)).collect();
    let first = unguarded[0];
    let unguarded_names: Vec<&str> = unguarded.iter().map(|ix| ix.name.as_str()).collect();
    Finding {
        id: String::new(),
        title: format!("{SAT030_TITLE} `{name}` written by {} instructions", writers.len()),
        severity: Severity::Medium,
        description: format!(
            "The state account `{name}` is written by {} instructions ({}) but `{}` writes it without any \
             init or discriminator guard (`data_is_empty()`, a `data[0..8] == DISCRIMINATOR`-style compare, \
             an `is_initialized` flag check, or a realloc-plus-init pattern). A previously initialized, \
             closed-and-recreated, or attacker-funded account is accepted and overwritten as if it were \
             fresh, so invariants the other writers establish (ownership, authority, initialization state) \
             can be clobbered or reused across instructions.",
            writers.len(),
            all.join(", "),
            unguarded_names.join(", ")
        ),
        location: Some(format!("{}:{} ({})", first.file, first.line, first.name)),
        suggestion: Some(format!(
            "Guard every writer of `{name}`: `if !{name}.data_is_empty() {{ return \
             Err(ProgramError::AccountAlreadyInitialized); }}` on the init path, or compare \
             `{name}.data.borrow()[0..8]` against the account's discriminator before writing."
        )),
    }
}

fn sat030(program: &NativeProgram, index: &FnIndex) -> Vec<Finding> {
    let mut groups: HashMap<String, Vec<(&NativeInstruction, bool)>> = HashMap::new();
    for ix in &program.instructions {
        let Some((handler, file_idx)) = index.lookup(&ix.handler, &ix.file) else { continue };
        let blocks = handler_blocks(handler, file_idx, index);
        for account in &ix.accounts {
            if account.written && is_stateish(account) {
                let guarded = has_init_guard(&blocks, &account.name);
                groups.entry(account.name.clone()).or_default().push((ix, guarded));
            }
        }
    }
    let mut findings = Vec::new();
    for (name, writers) in groups {
        // FP filter: skip when every writer carries an init/discriminator guard.
        if writers.len() < 2 || writers.iter().all(|(_, guarded)| *guarded) {
            continue;
        }
        findings.push(sat030_finding(&name, &writers));
    }
    findings
}

// ── Entry point ─────────────────────────────────────────────────────────────

/// Run SAT028 / SAT029 / SAT030 over every instruction of `program`.
///
/// At most one finding per (rule, instruction, call site / state account);
/// findings are never merged across instructions. Instructions whose handler
/// cannot be located in the parsed files are skipped silently.
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let index = FnIndex::build(parsed);
    let mut findings = Vec::new();
    for ix in &program.instructions {
        let Some((handler, file_idx)) = index.lookup(&ix.handler, &ix.file) else { continue };
        let blocks = handler_blocks(handler, file_idx, &index);
        let sites = collect_sites(&blocks, parsed);
        findings.extend(sat028_029(ix, &sites, program.program_id.as_deref()));
    }
    findings.extend(sat030(program, &index));
    findings
}
