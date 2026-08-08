//! R3 slice: lifecycle rules SAT024–SAT027.
//!
//! These rules target the account-lifecycle class of native Solana bugs:
//! closing an account that other instructions write without a re-init guard
//! (SAT024, the reinit-after-close class), deserializing account data without
//! an owner check or discriminator validation (SAT025), unchecked integer
//! arithmetic (SAT026 — a port of the Anchor backend's SAT012 walker), and
//! declaring runtime builtins (programs/sysvars) as writable (SAT027).
//!
//! SAT024/SAT025/SAT027 consume the resolved model (`crate::native::model`)
//! plus the parsed syntax trees: the model provides the per-account flags
//! (`written`, `owner_checked`, `key_checked`), the syntax trees provide the
//! close sites, deserialization call sites and guard expressions. SAT026 is
//! syntax-only, like its Anchor counterpart.
//!
//! Order-sensitivity of re-init guards (a guard anywhere in the handler or its
//! depth-≤1 helpers suppresses the finding) is a documented approximation —
//! see `docs/NATIVE_BACKEND.md` section 6. Title prefixes are load-bearing for
//! SARIF classification (section 7); do not rename them.

use std::collections::{HashMap, HashSet};

use syn::spanned::Spanned;

use crate::native::model::{NativeInstruction, NativeProgram, ResolvedAccount};
use crate::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT024_TITLE: &str = "Account Reinit After Close:";
const SAT025_TITLE: &str = "Unchecked Deserialization:";
const SAT026_TITLE: &str = "Unsafe Arithmetic:";
const SAT027_TITLE: &str = "Writable Builtin Account:";

/// Deserialization operations SAT025 watches for (spec section 7).
const DESER_OPS: [&str; 3] = ["try_from_slice", "try_from_slice_unchecked", "unpack"];

/// Local functions the frontend treats as builtin; helper scanning must not
/// try to resolve them.
const KNOWN_BUILTINS: [&str; 6] = [
    "next_account_info",
    "find_program_address",
    "create_program_address",
    "invoke",
    "invoke_signed",
    "invoke_signed_unchecked",
];

/// Known builtin program/sysvar addresses (base58) and their display labels,
/// matched against string literals that reference an account (SAT027).
const BUILTIN_ADDRS: [(&str, &str); 7] = [
    ("11111111111111111111111111111111", "the system program"),
    ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "the token program"),
    ("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "token-2022"),
    ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "the associated token program"),
    ("ComputeBudget111111111111111111111111111111", "the compute budget program"),
    ("SysvarC1ock11111111111111111111111111111111", "the clock sysvar"),
    ("SysvarRent111111111111111111111111111111111", "the rent sysvar"),
];

// ── Syntax tree index ────────────────────────────────────────────────────────

/// All functions of a parsed workspace, keyed by name (file preferred).
struct FnIndex<'a> {
    fns: Vec<(&'a syn::ItemFn, &'a str)>,
}

impl<'a> FnIndex<'a> {
    fn build(parsed: &'a [(syn::File, String)]) -> Self {
        let mut fns = Vec::new();
        for (file, path) in parsed {
            collect_fns(&file.items, path, &mut fns);
        }
        FnIndex { fns }
    }

    /// Look up a function by name, preferring a definition in `file`.
    fn find(&self, name: &str, file: &str) -> Option<(&'a syn::ItemFn, &'a str)> {
        self.fns
            .iter()
            .copied()
            .find(|(f, ffile)| f.sig.ident == name && *ffile == file)
            .or_else(|| self.fns.iter().copied().find(|(f, _)| f.sig.ident == name))
    }
}

/// Collect every free function: top-level and inside `mod` bodies. Native
/// handlers are free functions; `impl` methods are out of scope.
fn collect_fns<'a>(items: &'a [syn::Item], file: &'a str, out: &mut Vec<(&'a syn::ItemFn, &'a str)>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => out.push((f, file)),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_fns(inner, file, out);
                }
            }
            _ => {}
        }
    }
}

// ── Generic expression visitors ──────────────────────────────────────────────

/// Visit every expression of a block, including nested control flow.
fn walk_block(block: &syn::Block, f: &mut impl FnMut(&syn::Expr)) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => walk_expr(e, f),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    walk_expr(&init.expr, f);
                }
            }
            _ => {}
        }
    }
}

fn walk_expr(e: &syn::Expr, f: &mut impl FnMut(&syn::Expr)) {
    f(e);
    match e {
        syn::Expr::Binary(b) => {
            walk_expr(&b.left, f);
            walk_expr(&b.right, f);
        }
        syn::Expr::Unary(u) => walk_expr(&u.expr, f),
        syn::Expr::Paren(p) => walk_expr(&p.expr, f),
        syn::Expr::Group(g) => walk_expr(&g.expr, f),
        syn::Expr::Try(t) => walk_expr(&t.expr, f),
        syn::Expr::Reference(r) => walk_expr(&r.expr, f),
        syn::Expr::Cast(c) => walk_expr(&c.expr, f),
        syn::Expr::Field(fe) => walk_expr(&fe.base, f),
        syn::Expr::Index(i) => {
            walk_expr(&i.expr, f);
            walk_expr(&i.index, f);
        }
        syn::Expr::MethodCall(m) => {
            walk_expr(&m.receiver, f);
            for a in &m.args {
                walk_expr(a, f);
            }
        }
        syn::Expr::Call(c) => {
            walk_expr(&c.func, f);
            for a in &c.args {
                walk_expr(a, f);
            }
        }
        syn::Expr::Block(be) => walk_block(&be.block, f),
        syn::Expr::If(ie) => {
            walk_expr(&ie.cond, f);
            walk_block(&ie.then_branch, f);
            if let Some((_, other)) = &ie.else_branch {
                walk_expr(other, f);
            }
        }
        syn::Expr::Match(me) => {
            walk_expr(&me.expr, f);
            for arm in &me.arms {
                if let Some((_, guard)) = &arm.guard {
                    walk_expr(guard, f);
                }
                walk_expr(&arm.body, f);
            }
        }
        syn::Expr::While(w) => {
            walk_expr(&w.cond, f);
            walk_block(&w.body, f);
        }
        syn::Expr::Loop(l) => walk_block(&l.body, f),
        syn::Expr::ForLoop(fl) => walk_block(&fl.body, f),
        syn::Expr::Return(r) => {
            if let Some(x) = &r.expr {
                walk_expr(x, f);
            }
        }
        syn::Expr::Break(br) => {
            if let Some(x) = &br.expr {
                walk_expr(x, f);
            }
        }
        syn::Expr::Let(le) => walk_expr(&le.expr, f),
        syn::Expr::Assign(a) => {
            walk_expr(&a.left, f);
            walk_expr(&a.right, f);
        }
        syn::Expr::Closure(cl) => walk_expr(&cl.body, f),
        syn::Expr::Array(ar) => {
            for x in &ar.elems {
                walk_expr(x, f);
            }
        }
        syn::Expr::Tuple(t) => {
            for x in &t.elems {
                walk_expr(x, f);
            }
        }
        syn::Expr::Struct(s) => {
            for fl in &s.fields {
                walk_expr(&fl.expr, f);
            }
        }
        syn::Expr::Repeat(r) => {
            walk_expr(&r.expr, f);
            walk_expr(&r.len, f);
        }
        syn::Expr::Range(r) => {
            if let Some(start) = &r.start {
                walk_expr(start, f);
            }
            if let Some(end) = &r.end {
                walk_expr(end, f);
            }
        }
        _ => {}
    }
}

/// Symbols of an expression: identifier segments and string literal values.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sym {
    Ident(String),
    Str(String),
}

/// Collect the identifier segments and string literals of an expression
/// subtree (paths, fields, methods, callees, and their arguments).
fn collect_syms(e: &syn::Expr, out: &mut Vec<Sym>) {
    match e {
        syn::Expr::Path(p) => {
            out.extend(p.path.segments.iter().map(|s| Sym::Ident(s.ident.to_string())));
        }
        syn::Expr::Lit(l) => {
            if let syn::Lit::Str(s) = &l.lit {
                out.push(Sym::Str(s.value()));
            }
        }
        syn::Expr::Field(f) => {
            collect_syms(&f.base, out);
            if let syn::Member::Named(n) = &f.member {
                out.push(Sym::Ident(n.to_string()));
            }
        }
        syn::Expr::MethodCall(m) => {
            collect_syms(&m.receiver, out);
            out.push(Sym::Ident(m.method.to_string()));
            for a in &m.args {
                collect_syms(a, out);
            }
        }
        syn::Expr::Call(c) => {
            collect_syms(&c.func, out);
            for a in &c.args {
                collect_syms(a, out);
            }
        }
        syn::Expr::Index(i) => {
            collect_syms(&i.expr, out);
            collect_syms(&i.index, out);
        }
        syn::Expr::Reference(r) => collect_syms(&r.expr, out),
        syn::Expr::Paren(p) => collect_syms(&p.expr, out),
        syn::Expr::Group(g) => collect_syms(&g.expr, out),
        syn::Expr::Try(t) => collect_syms(&t.expr, out),
        syn::Expr::Unary(u) => collect_syms(&u.expr, out),
        syn::Expr::Binary(b) => {
            collect_syms(&b.left, out);
            collect_syms(&b.right, out);
        }
        syn::Expr::Assign(a) => {
            collect_syms(&a.left, out);
            collect_syms(&a.right, out);
        }
        syn::Expr::Cast(c) => collect_syms(&c.expr, out),
        syn::Expr::Array(ar) => {
            for x in &ar.elems {
                collect_syms(x, out);
            }
        }
        syn::Expr::Tuple(t) => {
            for x in &t.elems {
                collect_syms(x, out);
            }
        }
        syn::Expr::Struct(s) => {
            for fl in &s.fields {
                collect_syms(&fl.expr, out);
            }
        }
        syn::Expr::Repeat(r) => {
            collect_syms(&r.expr, out);
            collect_syms(&r.len, out);
        }
        syn::Expr::Range(r) => {
            if let Some(start) = &r.start {
                collect_syms(start, out);
            }
            if let Some(end) = &r.end {
                collect_syms(end, out);
            }
        }
        syn::Expr::Closure(cl) => collect_syms(&cl.body, out),
        _ => {}
    }
}

/// Last segment of a callable expression (`State::try_from_slice` → `try_from_slice`).
fn callee_ident(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        syn::Expr::Call(c) => callee_ident(&c.func),
        syn::Expr::Paren(p) => callee_ident(&p.expr),
        _ => None,
    }
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(pi) => Some(pi.ident.to_string()),
        // `let mut s: State = ...` parses the pattern as a type-ascription.
        syn::Pat::Type(t) => pat_ident(&t.pat),
        syn::Pat::Reference(r) => pat_ident(&r.pat),
        syn::Pat::Paren(p) => pat_ident(&p.pat),
        _ => None,
    }
}

// ── Data-flow taint (local variable → account) ───────────────────────────────

/// Local names derived from an account's data/identity, mapped back to the
/// account's variable name. `let data = &state.data.borrow_mut();` maps
/// `data → state`; `let s = State::try_from_slice(&data)?` maps `s → state`.
type Taint = HashMap<String, String>;

fn build_taint(block: &syn::Block, accounts: &[String]) -> Taint {
    let mut taint = Taint::new();
    for stmt in &block.stmts {
        let syn::Stmt::Local(l) = stmt else { continue };
        let Some(init) = &l.init else { continue };
        let Some(name) = pat_ident(&l.pat) else { continue };
        let mut syms = Vec::new();
        collect_syms(&init.expr, &mut syms);
        let mapped = syms.iter().find_map(|s| match s {
            Sym::Ident(id) => {
                if accounts.iter().any(|a| a == id) {
                    Some(id.clone())
                } else {
                    taint.get(id).cloned()
                }
            }
            Sym::Str(_) => None,
        });
        if let Some(acc) = mapped {
            taint.insert(name, acc);
        }
    }
    taint
}

/// Whether the expression subtree mentions the account (directly or through a
/// tainted local).
fn references(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    let mut syms = Vec::new();
    collect_syms(e, &mut syms);
    syms.iter().any(|s| match s {
        Sym::Ident(id) => id == acc || taint.get(id).is_some_and(|a| a == acc),
        Sym::Str(_) => false,
    })
}

// ── Literal helpers ──────────────────────────────────────────────────────────

fn is_zero_lit(e: &syn::Expr) -> bool {
    matches!(e, syn::Expr::Lit(l) if matches!(&l.lit, syn::Lit::Int(i) if i.base10_digits() == "0"))
}

/// Whether `e` is an integer literal (optionally with a specific value).
fn is_int_lit(e: &syn::Expr, want: Option<u64>) -> bool {
    let syn::Expr::Lit(l) = e else { return false };
    let syn::Lit::Int(i) = &l.lit else { return false };
    let Ok(v) = i.base10_digits().parse::<u64>() else { return false };
    want.is_none_or(|w| v == w)
}

/// Whether the index expression selects the first bytes of the data buffer:
/// `data[0..8]`, `data[..8]`, `data[0..]`, or `data[0]`.
fn is_first_bytes_index(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Range(r) => {
            let start_ok = r.start.as_ref().is_none_or(|s| is_int_lit(s, Some(0)));
            let end_ok = r.end.as_ref().is_none_or(|e| is_int_lit(e, Some(8)));
            start_ok && end_ok
        }
        syn::Expr::Lit(_) => is_int_lit(e, Some(0)),
        _ => false,
    }
}

/// A constant or known discriminator: literals, byte arrays, and
/// discriminator/tag/prefix/magic-named constants.
fn is_constant_like(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Lit(_) | syn::Expr::Array(_) => true,
        syn::Expr::Path(p) => {
            let last = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
            let lower = last.to_ascii_lowercase();
            lower.contains("discriminator")
                || lower.contains("tag")
                || lower.contains("prefix")
                || lower.contains("magic")
        }
        syn::Expr::Reference(r) => is_constant_like(&r.expr),
        syn::Expr::Paren(p) => is_constant_like(&p.expr),
        syn::Expr::Group(g) => is_constant_like(&g.expr),
        syn::Expr::Unary(u) => is_constant_like(&u.expr),
        syn::Expr::Cast(c) => is_constant_like(&c.expr),
        _ => false,
    }
}

// ── SAT024: account close sites and re-init guards ───────────────────────────

/// `account.realloc(0, ..)` — zero-length realloc closes the account.
fn is_realloc_zero(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    let syn::Expr::MethodCall(m) = e else { return false };
    m.method == "realloc" && m.args.first().is_some_and(is_zero_lit) && references(&m.receiver, acc, taint)
}

/// `account.assign(&system_program)` — re-assigning ownership to the system
/// program closes the account.
fn is_assign_system(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    let syn::Expr::MethodCall(m) = e else { return false };
    if m.method != "assign" || !references(&m.receiver, acc, taint) {
        return false;
    }
    let mut syms = Vec::new();
    for a in &m.args {
        collect_syms(a, &mut syms);
    }
    syms.iter().any(|s| match s {
        Sym::Ident(id) => id == "system_program",
        Sym::Str(v) => v == "11111111111111111111111111111111",
    })
}

/// `account.data.borrow_mut().set_len(0)` / `try_borrow_mut_data()?.set_len(0)`.
fn is_data_set_len_zero(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    let syn::Expr::MethodCall(m) = e else { return false };
    if m.method != "set_len" || !m.args.first().is_some_and(is_zero_lit) || !references(&m.receiver, acc, taint) {
        return false;
    }
    let mut syms = Vec::new();
    collect_syms(&m.receiver, &mut syms);
    syms.iter().any(|s| matches!(s, Sym::Ident(id) if id.contains("data")))
}

/// `*account.lamports = 0` / `**account.try_borrow_mut_lamports()? = 0` —
/// draining the lamport balance closes the account.
fn is_lamports_zero(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    let syn::Expr::Assign(a) = e else { return false };
    is_zero_lit(&a.right) && lamports_target(&a.left, acc, taint)
}

fn lamports_target(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    match e {
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => lamports_target(&u.expr, acc, taint),
        syn::Expr::Try(t) => lamports_target(&t.expr, acc, taint),
        syn::Expr::Paren(p) => lamports_target(&p.expr, acc, taint),
        syn::Expr::Field(f) => {
            matches!(f.member, syn::Member::Named(ref n) if n == "lamports") && references(&f.base, acc, taint)
        }
        syn::Expr::MethodCall(m) => m.method == "try_borrow_mut_lamports" && references(&m.receiver, acc, taint),
        _ => false,
    }
}

/// Re-init guard on an account: `data_is_empty()`, an `is_initialized` flag,
/// or a `data[0..8] == CONSTANT` discriminator comparison.
fn is_reinit_guard(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    if let syn::Expr::MethodCall(m) = e
        && (m.method == "data_is_empty" || m.method == "is_initialized")
        && references(&m.receiver, acc, taint)
    {
        return true;
    }
    if let syn::Expr::Field(f) = e
        && matches!(f.member, syn::Member::Named(ref n) if n == "is_initialized")
        && references(&f.base, acc, taint)
    {
        return true;
    }
    is_discriminator_check(e, acc, taint)
}

fn is_discriminator_check(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    let syn::Expr::Binary(b) = e else { return false };
    if !matches!(b.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
        return false;
    }
    (is_data_prefix(&b.left, acc, taint) && is_constant_like(&b.right))
        || (is_data_prefix(&b.right, acc, taint) && is_constant_like(&b.left))
}

fn is_data_prefix(e: &syn::Expr, acc: &str, taint: &Taint) -> bool {
    match e {
        syn::Expr::Index(i) => references(&i.expr, acc, taint) && is_first_bytes_index(&i.index),
        syn::Expr::Reference(r) => is_data_prefix(&r.expr, acc, taint),
        syn::Expr::Paren(p) => is_data_prefix(&p.expr, acc, taint),
        syn::Expr::Group(g) => is_data_prefix(&g.expr, acc, taint),
        syn::Expr::Try(t) => is_data_prefix(&t.expr, acc, taint),
        _ => false,
    }
}

/// Account-agnostic guard used when scanning helpers (their parameters have
/// different names than the caller's accounts).
fn is_reinit_guard_generic(e: &syn::Expr) -> bool {
    if let syn::Expr::MethodCall(m) = e
        && (m.method == "data_is_empty" || m.method == "is_initialized")
    {
        return true;
    }
    if let syn::Expr::Field(f) = e
        && matches!(f.member, syn::Member::Named(ref n) if n == "is_initialized")
    {
        return true;
    }
    let syn::Expr::Binary(b) = e else { return false };
    if !matches!(b.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
        return false;
    }
    (is_data_prefix_generic(&b.left) && is_constant_like(&b.right))
        || (is_data_prefix_generic(&b.right) && is_constant_like(&b.left))
}

fn is_data_prefix_generic(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Index(i) => is_first_bytes_index(&i.index),
        syn::Expr::Reference(r) => is_data_prefix_generic(&r.expr),
        syn::Expr::Paren(p) => is_data_prefix_generic(&p.expr),
        syn::Expr::Group(g) => is_data_prefix_generic(&g.expr),
        syn::Expr::Try(t) => is_data_prefix_generic(&t.expr),
        _ => false,
    }
}

/// Depth-≤1 helper functions called from the handler body.
fn collect_helpers<'a>(block: &syn::Block, index: &'a FnIndex) -> Vec<&'a syn::ItemFn> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk_block(block, &mut |e| {
        let syn::Expr::Call(c) = e else { return };
        let Some(name) = callee_ident(&c.func) else { return };
        if KNOWN_BUILTINS.contains(&name.as_str()) || matches!(name.as_str(), "msg" | "Ok" | "Err" | "try_from") {
            return;
        }
        if !seen.insert(name.clone()) {
            return;
        }
        if let Some((f, _)) = index.find(&name, "") {
            out.push(f);
        }
    });
    out
}

// ── SAT025: deserialization sites ────────────────────────────────────────────

/// First `try_from_slice`/`unpack`/`try_from_slice_unchecked` call whose
/// receiver/argument references the account; returns `(op, line)`.
fn deser_site(block: &syn::Block, acc: &str, taint: &Taint) -> Option<(String, usize)> {
    let mut found = None;
    walk_block(block, &mut |e| {
        if found.is_some() {
            return;
        }
        match e {
            syn::Expr::MethodCall(m) => {
                let op = m.method.to_string();
                if DESER_OPS.contains(&op.as_str()) && references(&m.receiver, acc, taint) {
                    found = Some((op, e.span().start().line));
                }
            }
            syn::Expr::Call(c) => {
                if let Some(op) = callee_ident(&c.func)
                    && DESER_OPS.contains(&op.as_str())
                    && c.args.first().is_some_and(|a| references(a, acc, taint))
                {
                    found = Some((op, e.span().start().line));
                }
            }
            _ => {}
        }
    });
    found
}

// ── SAT027: builtin name matching ────────────────────────────────────────────

/// Split a variable name on separators and camelCase boundaries:
/// `system_program` → `[system, program]`, `sysvarClock` → `[sysvar, clock]`.
fn name_tokens(name: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            cur.push(ch.to_ascii_lowercase());
            prev_lower = ch.is_ascii_lowercase();
        } else if !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
            prev_lower = false;
        } else {
            prev_lower = false;
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Display label when the account name matches a known builtin (program or
/// sysvar name heuristic from `docs/NATIVE_BACKEND.md` section 7).
fn builtin_label(name: &str) -> Option<&'static str> {
    let tokens = name_tokens(name);
    let has = |t: &str| tokens.iter().any(|x| x == t);
    if has("system") && has("program") {
        return Some("the system program");
    }
    if tokens.iter().any(|t| t == "token2022") {
        return Some("token-2022");
    }
    if has("associated") && has("token") {
        return Some("the associated token program");
    }
    if has("token") && has("2022") {
        return Some("token-2022");
    }
    if has("token") && has("program") {
        return Some("the token program");
    }
    if has("ata") && has("program") {
        return Some("the associated token program");
    }
    if has("compute") && has("budget") {
        return Some("the compute budget program");
    }
    if has("clock") {
        return Some("the clock sysvar");
    }
    if has("rent") {
        return Some("the rent sysvar");
    }
    if has("epoch") && has("schedule") {
        return Some("the epoch schedule sysvar");
    }
    if has("fees") {
        return Some("the fees sysvar");
    }
    if has("recent") && has("blockhashes") {
        return Some("the recent blockhashes sysvar");
    }
    if has("stake") && has("history") {
        return Some("the stake history sysvar");
    }
    if has("instructions") {
        return Some("the instructions sysvar");
    }
    None
}

/// Display label when the handler compares the account against a literal
/// builtin address string.
fn builtin_addr_label(block: &syn::Block, acc: &str) -> Option<&'static str> {
    let mut found = None;
    walk_block(block, &mut |e| {
        if found.is_some() {
            return;
        }
        let mut syms = Vec::new();
        collect_syms(e, &mut syms);
        if !syms.iter().any(|s| matches!(s, Sym::Ident(id) if id == acc)) {
            return;
        }
        for (addr, label) in BUILTIN_ADDRS {
            if syms.iter().any(|s| matches!(s, Sym::Str(v) if v == addr)) {
                found = Some(label);
                return;
            }
        }
    });
    found
}

// ── Findings ─────────────────────────────────────────────────────────────────

fn sat024_finding(ix: &NativeInstruction, name: &str, line: usize, file: &str) -> Finding {
    Finding {
        id: String::new(),
        title: format!("{SAT024_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "Instruction `{}` closes the account `{name}` (zero-length realloc, system-program \
             assign, lamports drain, or data truncation) while other instructions of the same \
             program write it, and the write path carries no re-init guard. After the close the \
             account is re-created (its lamports were drained; the next writer must top them up \
             again), so the writer can re-initialize it from stale or attacker-influenced bytes, \
             breaking the program's initialization invariants. Exploit: call `{}` to close \
             `{name}`, then trigger the writer instruction, which treats the re-created account \
             as its own state and writes attacker-controlled parameters into it.",
            ix.name, ix.name
        ),
        location: Some(format!("{file}:{line} ({})", ix.name)),
        suggestion: Some(format!(
            "Before writing `{name}`, verify it is initialized: \
             `if data[0..8] != DISCRIMINATOR {{ return Err(ProgramError::InvalidAccountData); }}` \
             or `if {name}.data_is_empty() {{ return Err(ProgramError::UninitializedAccount); }}`, \
             and skip writes to closed accounts."
        )),
    }
}

fn sat025_finding(ix: &NativeInstruction, acc: &ResolvedAccount, op: &str, line: usize, file: &str) -> Finding {
    let name = &acc.name;
    Finding {
        id: String::new(),
        title: format!("{SAT025_TITLE} `{name}`"),
        severity: Severity::Medium,
        description: format!(
            "`{name}` is deserialized with `{op}` in `{}` while the account's owner is never \
             verified (`owner_checked = false`) and its data's discriminator is never validated. \
             Any account owned by any program can be passed here, so `{op}` runs over \
             attacker-controlled bytes and every later check operates on fabricated state. \
             Exploit: supply an account owned by a malicious program with a forged layout; the \
             program deserializes it as its own state and writes derived data, which the \
             attacker influenced.",
            ix.name
        ),
        location: Some(format!("{file}:{line} ({})", ix.name)),
        suggestion: Some(format!(
            "Verify the owner before deserializing: \
             `if {name}.owner != program_id {{ return Err(ProgramError::IllegalOwner); }}`, and \
             validate the discriminator: \
             `if data[0..8] != DISCRIMINATOR {{ return Err(ProgramError::InvalidAccountData); }}`."
        )),
    }
}

fn sat027_finding(ix: &NativeInstruction, acc: &ResolvedAccount, label: &str, file: &str) -> Finding {
    let name = &acc.name;
    Finding {
        id: String::new(),
        title: format!("{SAT027_TITLE} `{name}`"),
        severity: Severity::Medium,
        description: format!(
            "`{name}` resolves to {label}, a runtime builtin whose data is owned by the runtime, \
             yet instruction `{}` declares it writable and borrows its data mutably. Writing a \
             builtin account fails at runtime (the runtime refuses modification of system-owned \
             data), so the instruction hard-fails whenever the write path is reached, and \
             marking the account writable forces the client to fund an unnecessary writable \
             slot. Impact: the instruction is unusable or behaves unpredictably.",
            ix.name
        ),
        location: Some(format!("{file}:{} ({})", ix.line, ix.name)),
        suggestion: Some(format!(
            "Declare `{name}` read-only (`writable = false` in the `AccountMeta` / drop the \
             mutable borrow) — builtin programs and sysvars must never be written by the program."
        )),
    }
}

// ── Rules ────────────────────────────────────────────────────────────────────

/// SAT024: an instruction closes an account while another instruction of the
/// same program writes it, without a reachable re-init guard. One finding per
/// (closing instruction, closed account).
fn sat024(program: &NativeProgram, index: &FnIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, ix) in program.instructions.iter().enumerate() {
        let Some((handler, file)) = index.find(&ix.handler, &ix.file) else { continue };
        let names: Vec<String> = ix.accounts.iter().map(|a| a.name.clone()).collect();
        let taint = build_taint(&handler.block, &names);
        let helpers = collect_helpers(&handler.block, index);

        let mut closed: HashMap<String, usize> = HashMap::new();
        walk_block(&handler.block, &mut |e| {
            for acc in &ix.accounts {
                if closed.contains_key(&acc.name) {
                    continue;
                }
                let is_close = is_realloc_zero(e, &acc.name, &taint)
                    || is_assign_system(e, &acc.name, &taint)
                    || is_data_set_len_zero(e, &acc.name, &taint)
                    || is_lamports_zero(e, &acc.name, &taint);
                if is_close {
                    closed.insert(acc.name.clone(), e.span().start().line);
                }
            }
        });

        for (name, line) in closed {
            let written_elsewhere = program
                .instructions
                .iter()
                .enumerate()
                .any(|(j, other)| j != i && other.accounts.iter().any(|a| a.name == name && a.written));
            if !written_elsewhere {
                continue;
            }
            if has_validation_guard(handler, &name, &taint, &helpers) {
                continue;
            }
            findings.push(sat024_finding(ix, &name, line, file));
        }
    }
    findings
}

/// SAT025: a `try_from_slice`/`unpack`/`try_from_slice_unchecked` call on an
/// account whose owner is never checked and whose data is never discriminator-
/// validated. One finding per (instruction, account).
fn sat025(program: &NativeProgram, index: &FnIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ix in &program.instructions {
        let Some((handler, file)) = index.find(&ix.handler, &ix.file) else { continue };
        let names: Vec<String> = ix.accounts.iter().map(|a| a.name.clone()).collect();
        let taint = build_taint(&handler.block, &names);
        let helpers = collect_helpers(&handler.block, index);

        for acc in ix.accounts.iter().filter(|a| !a.owner_checked) {
            let Some((op, line)) = deser_site(&handler.block, &acc.name, &taint) else { continue };
            if has_validation_guard(handler, &acc.name, &taint, &helpers) {
                continue;
            }
            findings.push(sat025_finding(ix, acc, &op, line, file));
        }
    }
    findings
}

/// SAT027: a known builtin (program/sysvar) account declared writable in an
/// instruction's account list. The `written` flag doubles as the FP filter —
/// accounts whose data is never touched are not reported.
fn sat027(program: &NativeProgram, index: &FnIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ix in &program.instructions {
        let Some((handler, file)) = index.find(&ix.handler, &ix.file) else { continue };
        for acc in ix.accounts.iter().filter(|a| a.written) {
            let label = builtin_label(&acc.name).or_else(|| builtin_addr_label(&handler.block, &acc.name));
            let Some(label) = label else { continue };
            findings.push(sat027_finding(ix, acc, label, file));
        }
    }
    findings
}

// ── SAT026 (port of the Anchor backend's SAT012 walker) ──────────────────────

fn is_security_relevant_arithmetic(lhs: &str, rhs: &str, is_assign: bool) -> bool {
    let joined = format!("{} {}", lhs.to_lowercase(), rhs.to_lowercase());
    let keywords = [
        "amount",
        "balance",
        "deposit",
        "withdraw",
        "supply",
        "total",
        "vault",
        "fee",
        "reward",
        "share",
        "price",
        "lamport",
        "debt",
        "collateral",
        "liquidity",
        "reserve",
    ];
    (is_assign && lhs.contains('.')) || keywords.iter().any(|keyword| joined.contains(keyword))
}

fn expr_to_string_v2(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(expr_path) => {
            expr_path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
        }
        syn::Expr::Field(field) => {
            let base = expr_to_string_v2(&field.base);
            let member = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            format!("{base}.{member}")
        }
        syn::Expr::Lit(lit) => lit_to_string(&lit.lit),
        syn::Expr::Paren(paren) => format!("({})", expr_to_string_v2(&paren.expr)),
        syn::Expr::Binary(binary) => {
            format!("{} {:?} {}", expr_to_string_v2(&binary.left), binary.op, expr_to_string_v2(&binary.right))
        }
        syn::Expr::Unary(unary) => format!("{:?}{}", unary.op, expr_to_string_v2(&unary.expr)),
        syn::Expr::MethodCall(method) => format!("{}.{}()", expr_to_string_v2(&method.receiver), method.method),
        syn::Expr::Cast(cast) => format!("{} as {}", expr_to_string_v2(&cast.expr), type_to_string(&cast.ty)),
        _ => format!("{expr:?}"),
    }
}

fn lit_to_string(lit: &syn::Lit) -> String {
    match lit {
        syn::Lit::Str(s) => s.value(),
        syn::Lit::ByteStr(b) => String::from_utf8_lossy(&b.value()).to_string(),
        syn::Lit::Byte(b) => (b.value() as char).to_string(),
        syn::Lit::Char(c) => c.value().to_string(),
        syn::Lit::Int(i) => i.base10_digits().to_string(),
        syn::Lit::Float(f) => f.base10_digits().to_string(),
        syn::Lit::Bool(b) => b.value().to_string(),
        _ => "{lit}".to_string(),
    }
}

fn type_to_string(ty: &syn::Type) -> String {
    use quote::ToTokens;
    ty.to_token_stream().to_string()
}

/// SAT026: port of the Anchor backend's `check_unsafe_arithmetic` — raw
/// `+ - * / %` on security-relevant operands, walked over every function of
/// every parsed file. Same titles and severities as SAT012 (the multiplication
/// variant stays `Medium`/`Unsafe Multiplication:`), plus the `/` and `%`
/// operators the native spec lists.
fn sat026(parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (file, path) in parsed {
        let mut fns = Vec::new();
        collect_fns(&file.items, path, &mut fns);
        for (f, _) in fns {
            let fn_name = f.sig.ident.to_string();
            find_unsafe_ops_in_block(&f.block, &fn_name, path, &mut findings);
        }
    }
    findings
}

fn find_unsafe_ops_in_block(block: &syn::Block, fn_name: &str, file: &str, findings: &mut Vec<Finding>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                find_unsafe_ops_in_expr(expr, fn_name, file, findings);
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    find_unsafe_ops_in_expr(&init.expr, fn_name, file, findings);
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_lines)]
fn find_unsafe_ops_in_expr(expr: &syn::Expr, fn_name: &str, file: &str, findings: &mut Vec<Finding>) {
    match expr {
        syn::Expr::Binary(binary) => {
            let line = binary.span().start().line;
            let is_sub_assign = matches!(binary.op, syn::BinOp::SubAssign(_));
            let is_add_assign = matches!(binary.op, syn::BinOp::AddAssign(_));
            let is_sub = matches!(binary.op, syn::BinOp::Sub(_));
            let is_add = matches!(binary.op, syn::BinOp::Add(_));
            let is_div = matches!(binary.op, syn::BinOp::Div(_));
            let is_rem = matches!(binary.op, syn::BinOp::Rem(_));
            let is_div_assign = matches!(binary.op, syn::BinOp::DivAssign(_));
            let is_rem_assign = matches!(binary.op, syn::BinOp::RemAssign(_));
            let is_mul = matches!(binary.op, syn::BinOp::Mul(_));
            let is_mul_assign = matches!(binary.op, syn::BinOp::MulAssign(_));

            let lhs_str = expr_to_string_v2(&binary.left);
            let rhs_str = expr_to_string_v2(&binary.right);

            if is_sub_assign || is_add_assign || is_sub || is_add || is_div || is_rem || is_div_assign || is_rem_assign
            {
                let (op_str, checked) = if is_sub_assign || is_sub {
                    ("-", "checked_sub")
                } else if is_div_assign || is_div {
                    ("/", "checked_div")
                } else if is_rem_assign || is_rem {
                    ("%", "checked_rem")
                } else {
                    ("+", "checked_add")
                };
                let op_form = if is_sub_assign || is_add_assign || is_div_assign || is_rem_assign { "=" } else { "" };
                let is_assign = is_sub_assign || is_add_assign || is_div_assign || is_rem_assign;

                if !is_security_relevant_arithmetic(&lhs_str, &rhs_str, is_assign) {
                    find_unsafe_ops_in_expr(&binary.left, fn_name, file, findings);
                    find_unsafe_ops_in_expr(&binary.right, fn_name, file, findings);
                    return;
                }

                findings.push(Finding {
                    id: String::new(),
                    title: format!("{SAT026_TITLE} `{op_str}{op_form}` in `{fn_name}` — use checked_*() instead"),
                    severity: Severity::High,
                    description: format!(
                        "The expression `{lhs_str}` uses `{op_str}{op_form}` on a field in `{fn_name}`. \
                         In release mode (optimized builds), Rust arithmetic wraps on overflow instead \
                         of panicking. Use `{checked}()`, or `overflow-checks = true` instead.",
                    ),
                    location: Some(format!("{file}:{line} ({fn_name})")),
                    suggestion: Some(if is_assign {
                        format!(
                            "Replace with `.{checked}(amount).ok_or(Error::Underflow)?` or \
                             `.{checked}(amount).ok_or(Error::Overflow)?`."
                        )
                    } else {
                        format!("Use `{checked}()` instead of the raw operator.")
                    }),
                });
            }

            if (is_mul || is_mul_assign)
                && !lhs_str.is_empty()
                && !rhs_str.is_empty()
                && is_security_relevant_arithmetic(&lhs_str, &rhs_str, is_mul_assign)
            {
                findings.push(Finding {
                    id: String::new(),
                    title: format!("Unsafe Multiplication: possible overflow in `{fn_name}`"),
                    severity: Severity::Medium,
                    description: format!(
                        "The expression `{lhs_str}` in `{fn_name}` may overflow if both operands are \
                         large. Use `checked_mul()` and chain with `checked_div()`."
                    ),
                    location: Some(format!("{file}:{line} ({fn_name})")),
                    suggestion: Some(
                        "Use `.checked_mul(other)?.checked_div(10000)?` for fee calculations, \
                         or upcast to u128 for intermediate results."
                            .to_string(),
                    ),
                });
            }

            find_unsafe_ops_in_expr(&binary.left, fn_name, file, findings);
            find_unsafe_ops_in_expr(&binary.right, fn_name, file, findings);
        }
        syn::Expr::If(if_expr) => {
            find_unsafe_ops_in_expr(&if_expr.cond, fn_name, file, findings);
            find_unsafe_ops_in_block(&if_expr.then_branch, fn_name, file, findings);
            if let Some((_, else_expr)) = &if_expr.else_branch {
                find_unsafe_ops_in_expr(else_expr, fn_name, file, findings);
            }
        }
        syn::Expr::Block(block_expr) => {
            find_unsafe_ops_in_block(&block_expr.block, fn_name, file, findings);
        }
        syn::Expr::ForLoop(for_loop) => {
            find_unsafe_ops_in_block(&for_loop.body, fn_name, file, findings);
        }
        syn::Expr::While(while_loop) => {
            find_unsafe_ops_in_expr(&while_loop.cond, fn_name, file, findings);
            find_unsafe_ops_in_block(&while_loop.body, fn_name, file, findings);
        }
        syn::Expr::Loop(loop_expr) => {
            find_unsafe_ops_in_block(&loop_expr.body, fn_name, file, findings);
        }
        syn::Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                if let Some((_, guard_expr)) = &arm.guard {
                    find_unsafe_ops_in_expr(guard_expr, fn_name, file, findings);
                }
                find_unsafe_ops_in_expr(&arm.body, fn_name, file, findings);
            }
        }
        syn::Expr::Call(call) => {
            for arg in &call.args {
                find_unsafe_ops_in_expr(arg, fn_name, file, findings);
            }
        }
        // `x = a + b` / `x = a * b` — descend into plain assignments so the
        // arithmetic inside them is still walked.
        syn::Expr::Assign(assign) => {
            find_unsafe_ops_in_expr(&assign.left, fn_name, file, findings);
            find_unsafe_ops_in_expr(&assign.right, fn_name, file, findings);
        }
        _ => {}
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Run SAT024/SAT025/SAT026/SAT027 over the program and its parsed files.
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let index = FnIndex::build(parsed);
    let mut findings = sat024(program, &index);
    findings.extend(sat025(program, &index));
    findings.extend(sat026(parsed));
    findings.extend(sat027(program, &index));
    findings
}

/// Shared guard check: a re-init/discriminator guard reachable in the handler
/// or in any depth-≤1 helper suppresses SAT024 and SAT025 findings.
fn has_validation_guard(handler: &syn::ItemFn, acc: &str, taint: &Taint, helpers: &[&syn::ItemFn]) -> bool {
    let mut found = false;
    walk_block(&handler.block, &mut |e| {
        if is_reinit_guard(e, acc, taint) {
            found = true;
        }
    });
    if found {
        return true;
    }
    for h in helpers {
        walk_block(&h.block, &mut |e| {
            if is_reinit_guard_generic(e) {
                found = true;
            }
        });
    }
    found
}
