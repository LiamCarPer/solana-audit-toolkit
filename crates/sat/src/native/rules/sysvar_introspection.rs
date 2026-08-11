//! R7 slice: SAT032 — Sysvar-Introspection Misuse (the Wormhole bridge class).
//!
//! This is a pure syntax-tree rule (no `NativeProgram` model dependency): it
//! walks every function of every parsed file and looks for calls to the
//! *unchecked* `sysvar::instructions` introspection family
//! (`load_current_index`, `load_instruction_at`, `load_instruction`) whose
//! account-data argument is a borrow expression over a caller-supplied local
//! account (`x.try_borrow_mut_data()`, `x.try_borrow_data()`, `x.data.borrow()`,
//! `x.data.borrow_mut()`, `x.try_borrow_mut()`, or any `<local>.borrow*()`
//! rooted at a plain identifier — struct-bundle fields such as
//! `accs.instruction_acc.try_borrow_mut_data()` included).
//!
//! The unchecked helpers parse the raw bytes they are given with NO sysvar
//! address check; the `_checked` variants begin with `check_id` and refuse to
//! parse unless the account really is the instructions sysvar. Passing a
//! caller-supplied account's bytes to the unchecked helpers makes every
//! introspection result (the "current instruction index", the "instruction at
//! index") attacker-controlled. This is the exact Wormhole bridge (Solana
//! side) pattern of 2022-02-02 (~$320M, `docs/EXPLOIT_CORPUS.md`): the bridge
//! read its verification state from a fabricated caller-supplied account
//! instead of the real instructions sysvar.
//!
//! Non-triggers:
//! - the `_checked` variants (`load_instruction_at_checked`, ...) — never in
//!   the family set, and their plain `&AccountInfo` argument is not a borrow
//!   expression;
//! - `Clock::get()` / `Sysvar::get()`-style accessors — callee `get` is not in
//!   the family;
//! - data arguments rooted at a call (`sysvar::instructions::id()`) or a
//!   literal — not a borrow over a plain identifier.
//!
//! The title prefix is load-bearing for SARIF classification (the
//! `Sysvar-Introspection` arm must sit above the generic `Sysvar` arm in
//! `crate::sarif::classify_finding_rule`); do not rename it.

use syn::spanned::Spanned;

use crate::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7 (load-bearing
/// for SARIF classification — do not rename).
const SAT032_TITLE: &str = "Sysvar-Introspection Misuse:";

/// The unchecked `sysvar::instructions` introspection helpers. The `_checked`
/// variants (`load_instruction_at_checked`) are deliberately absent: they
/// validate the account before parsing.
const UNCHECKED_INTROSPECTION: [&str; 3] = ["load_current_index", "load_instruction_at", "load_instruction"];

/// Position of the account-data argument per helper. `load_current_index`
/// takes only the data; the `load_instruction*` helpers take
/// `(index, data)`.
fn data_arg_position(callee: &str) -> Option<usize> {
    match callee {
        "load_current_index" => Some(0),
        "load_instruction_at" | "load_instruction" => Some(1),
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

/// The plain identifier an expression chain is rooted at, following field
/// accesses (`accs.instruction_acc` → `accs`), method receivers
/// (`x.data.borrow()` → `x`) and indexing. `None` when the root is a call
/// (`sysvar::instructions::id()`), a literal, or a multi-segment path.
fn root_ident(e: &syn::Expr) -> Option<String> {
    match peel(e) {
        syn::Expr::Path(p) => (p.path.segments.len() == 1).then(|| p.path.segments[0].ident.to_string()),
        syn::Expr::Field(f) => root_ident(&f.base),
        syn::Expr::MethodCall(m) => root_ident(&m.receiver),
        syn::Expr::Index(i) => root_ident(&i.expr),
        _ => None,
    }
}

/// True when the argument is a borrow expression over a local account:
/// `x.try_borrow_mut_data()`, `x.try_borrow_data()`, `x.data.borrow()`,
/// `x.data.borrow_mut()`, `x.try_borrow_mut()`, or any `<local>.borrow*()`
/// rooted at a plain identifier (`accs.instruction_acc.try_borrow_mut_data()`).
/// False for literals, `&AccountInfo` arguments (the checked form), and
/// receivers rooted at calls such as `sysvar::instructions::id()`.
fn is_borrow_over_local(arg: &syn::Expr) -> bool {
    let syn::Expr::MethodCall(m) = peel(arg) else { return false };
    if !m.method.to_string().contains("borrow") {
        return false;
    }
    root_ident(&m.receiver).is_some()
}

/// `a::b::c` key of a callable path expression.
fn path_key(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => Some(p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")),
        _ => None,
    }
}

// ── Generic expression walker (mirrors `rules/lifecycle.rs`) ─────────────────

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
        syn::Expr::Unsafe(u) => walk_block(&u.block, f),
        syn::Expr::Async(a) => walk_block(&a.block, f),
        syn::Expr::Const(c) => walk_block(&c.block, f),
        syn::Expr::TryBlock(tb) => walk_block(&tb.block, f),
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
        syn::Expr::Await(a) => walk_expr(&a.base, f),
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
        syn::Expr::Lit(_) | syn::Expr::Path(_) | syn::Expr::Continue(_) | syn::Expr::Infer(_) => {}
        _ => {}
    }
}

// ── Function collection ───────────────────────────────────────────────────────

/// One function body of a parsed file (free fn, `mod` member, or `impl`
/// method) with the file path it lives in.
struct FnBody<'a> {
    name: &'a syn::Ident,
    file: &'a str,
    block: &'a syn::Block,
}

fn collect_fn_bodies<'a>(items: &'a [syn::Item], file: &'a str, out: &mut Vec<FnBody<'a>>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => out.push(FnBody { name: &f.sig.ident, file, block: &f.block }),
            syn::Item::Impl(imp) => {
                for member in &imp.items {
                    if let syn::ImplItem::Fn(f) = member {
                        out.push(FnBody { name: &f.sig.ident, file, block: &f.block });
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_fn_bodies(inner, file, out);
                }
            }
            _ => {}
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run SAT032 (Sysvar-Introspection Misuse) over the parsed files.
///
/// One HIGH finding per call site of an unchecked introspection helper whose
/// account-data argument is a borrow over a caller-supplied local account.
/// File-level AST scan: independent of the resolved `NativeProgram` model, so
/// it also fires on corpora whose dispatch (e.g. `solitaire!`) resolves no
/// accounts.
pub fn check(parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (file, path) in parsed_files {
        let mut fns = Vec::new();
        collect_fn_bodies(&file.items, path, &mut fns);
        for f in fns {
            let mut sites: Vec<(String, usize)> = Vec::new();
            walk_block(f.block, &mut |e| {
                let syn::Expr::Call(c) = e else { return };
                let Some(callee) = path_key(&c.func) else { return };
                let last = callee.rsplit("::").next().unwrap_or(&callee);
                // Defensive: the family set never ends in `_checked`; keep the
                // guard explicit so a future variant cannot slip through.
                if last.ends_with("_checked") || !UNCHECKED_INTROSPECTION.contains(&last) {
                    return;
                }
                let Some(pos) = data_arg_position(last) else { return };
                let Some(arg) = c.args.iter().nth(pos) else { return };
                if is_borrow_over_local(arg) {
                    sites.push((last.to_string(), e.span().start().line));
                }
            });
            for (call, line) in sites {
                // Only `load_instruction_at` has a `_checked` variant in
                // `solana_program::sysvar::instructions`; for the others the
                // fix is the explicit sysvar-address validation.
                let checked_tip = if call == "load_instruction_at" {
                    "use the checked variant `load_instruction_at_checked` (it begins with a \
                     `check_id` and rejects non-sysvar accounts), or"
                        .to_string()
                } else {
                    "the `_checked` variant only exists for `load_instruction_at`, so".to_string()
                };
                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "{SAT032_TITLE} `{call}` parses caller-supplied account data without a sysvar \
                         address check"
                    ),
                    severity: Severity::High,
                    description: format!(
                        "Function `{}` calls the unchecked sysvar-introspection helper `{call}` with a \
                         borrow of a caller-supplied account's raw data. The unchecked helpers parse \
                         arbitrary bytes with no sysvar-address check; the `_checked` variants begin by \
                         validating that the account is the real `sysvar::instructions` account. Passing \
                         attacker-supplied bytes here makes the introspection result (the \"current \
                         instruction index\" or the \"instruction at index\") attacker-controlled: an \
                         attacker can fabricate an account that spoofs the instruction list, which is \
                         how the Wormhole bridge (Feb 2022, ~$320M) forged a guardian-approved \
                         signature-verification state (see `docs/EXPLOIT_CORPUS.md`).",
                        f.name
                    ),
                    location: Some(format!("{}:{line} ({})", f.file, f.name)),
                    suggestion: Some(format!(
                        "Before parsing, {checked_tip} validate the account is the real instructions \
                         sysvar: `if acc.key != &solana_program::sysvar::instructions::id() {{ return \
                         Err(ProgramError::InvalidAccountData); }}` and verify \
                         `acc.owner == &solana_program::sysvar::ID`."
                    )),
                });
            }
        }
    }
    findings
}
