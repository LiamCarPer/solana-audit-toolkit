//! R2 slice: SAT022 (PDA seed derivation mismatch) and SAT023 (state write
//! after CPI) for the native backend.
//!
//! SAT022 ports the Anchor backend's `pda::check_pda_seed_mismatch` to
//! statement-level analysis: per `is_pda` account with recorded
//! `find_program_address` seeds (source text), every `invoke_signed` call
//! site in the instruction's handler is inspected and its signer seed lists
//! (`&[&[&[u8]]]`, the third argument) are compared element-wise after
//! string normalization (strip `&`, `.as_ref()`, `.to_bytes()`, `.key()`,
//! whitespace). SAT023 ports `analyzer::check_cei_ordering`: statements are
//! walked in program order; once an external call has run unconditionally,
//! later mutations of `written` accounts are reported unless the account was
//! closed or re-created in between.
//!
//! Documented approximations (manual review still required):
//! - SAT022 only compares call sites whose third argument is an inline
//!   `&[&[...]]` literal. Seeds passed through a variable are not visible:
//!   the call site is skipped (the spec's FP filter), never flagged.
//! - A trailing `&[bump]`-shaped signer element is dropped before comparison
//!   (the bump is *returned* by `find_program_address`, so it never appears
//!   in the recorded seed list). Bump-like = a single identifier containing
//!   "bump" inside a (possibly referenced) one-element array.
//! - `invoke_signed` calls inside helper functions are not inspected; only
//!   the handler body is (recursively, including nested control flow).
//! - SAT023 treats `invoke`/`invoke_signed` and any call whose path contains
//!   `spl_token`, `spl_associated_token_account`, `system_instruction` or a
//!   `token::transfer`-style helper as an interaction. Instruction
//!   *construction* via `spl_token::instruction::transfer(...)` therefore
//!   counts as an interaction too — a deliberate over-approximation the
//!   spec's helper list implies; the actual external call is the
//!   `invoke(...)` around it.
//! - Local variables bound from `<account>.data.borrow[_mut]()`,
//!   `try_from_slice(&...data...)`, `load()`/`load_mut()` are tracked so
//!   later field assignments, `serialize`, `copy_from_slice` etc. can be
//!   attributed to the account. Writes inside branch bodies are found, but a
//!   CPI inside one branch never leaks to sibling branches or following
//!   statements (branch isolation, as in the Anchor check).
//! - The close/re-create FP filter scans statements between the last
//!   unconditional CPI and the write for `realloc(0)`/`realloc_zeroed(0)` or
//!   a lamports-to-zero assignment on the account. Ownership transfers
//!   (`assign`) are not part of the filter.

use crate::native::model::{NativeInstruction, NativeProgram};
use crate::types::{Finding, Severity};
use std::collections::{HashMap, HashSet};
use syn::spanned::Spanned;

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT022_TITLE: &str = "Seed Derivation Mismatch:";
const SAT023_TITLE: &str = "State Write After CPI:";

/// `"{file}:{line} ({instruction_name})"` — same shape as the Anchor backend.
fn finding_location(file: &str, line: usize, ix_name: &str) -> String {
    format!("{file}:{line} ({ix_name})")
}

/// Run SAT022 and SAT023 over every instruction of `program`.
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = sat022(program, parsed);
    findings.extend(sat023(program, parsed));
    findings
}

// ── SAT022: PDA seed derivation mismatch ─────────────────────────────────────

/// SAT022: an `is_pda` account whose `invoke_signed` seeds (per call site in
/// the handler) differ from its `find_program_address` seeds.
fn sat022(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ix in &program.instructions {
        let Some((handler, file)) = find_handler(parsed, ix) else { continue };

        // Every `invoke_signed` call site with a visible inline seed array:
        // (line, signer seed lists).
        let mut sites: Vec<(usize, Vec<Vec<String>>)> = Vec::new();
        collect_invoke_signed_sites(&handler.block, &mut sites);
        // FP filter: no `invoke_signed` seeds visible for this handler.
        if sites.is_empty() {
            continue;
        }

        for account in &ix.accounts {
            if !account.is_pda || account.seeds.is_empty() {
                continue;
            }
            // The account is signed with the right seeds at a call site when
            // ANY signer seed list of that site matches its derivation. The
            // first site with no matching list is the mismatch. At most one
            // finding per (instruction, account).
            let mismatch = sites.iter().find(|(_, sets)| !sets.iter().any(|set| seeds_match(&account.seeds, set)));
            let Some((line, sets)) = mismatch else { continue };
            let signing = sets.first().cloned().unwrap_or_default();
            findings.push(sat022_finding(ix, &account.name, &account.seeds, &signing, *line, file));
        }
    }
    findings
}

/// Recursively collect `invoke_signed` call sites inside a block.
fn collect_invoke_signed_sites(block: &syn::Block, sites: &mut Vec<(usize, Vec<Vec<String>>)>) {
    for stmt in &block.stmts {
        collect_stmt_invoke_signed(stmt, sites);
    }
}

fn collect_stmt_invoke_signed(stmt: &syn::Stmt, sites: &mut Vec<(usize, Vec<Vec<String>>)>) {
    match stmt {
        syn::Stmt::Expr(expr, _) => collect_expr_invoke_signed(expr, sites),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                collect_expr_invoke_signed(&init.expr, sites);
            }
        }
        _ => {}
    }
}

fn collect_expr_invoke_signed(expr: &syn::Expr, sites: &mut Vec<(usize, Vec<Vec<String>>)>) {
    match expr {
        syn::Expr::Try(t) => collect_expr_invoke_signed(&t.expr, sites),
        syn::Expr::Paren(p) => collect_expr_invoke_signed(&p.expr, sites),
        syn::Expr::Group(g) => collect_expr_invoke_signed(&g.expr, sites),
        syn::Expr::Reference(r) => collect_expr_invoke_signed(&r.expr, sites),
        syn::Expr::Call(c) => {
            if callee_is_invoke_signed(&c.func) {
                if let Some(sets) = signers_seeds_of(&c.args) {
                    sites.push((c.span().start().line, sets));
                }
                return;
            }
            for arg in &c.args {
                collect_expr_invoke_signed(arg, sites);
            }
        }
        syn::Expr::MethodCall(mc) => {
            collect_expr_invoke_signed(&mc.receiver, sites);
            for arg in &mc.args {
                collect_expr_invoke_signed(arg, sites);
            }
        }
        syn::Expr::Block(b) => collect_invoke_signed_sites(&b.block, sites),
        syn::Expr::If(ei) => {
            collect_expr_invoke_signed(&ei.cond, sites);
            collect_invoke_signed_sites(&ei.then_branch, sites);
            if let Some((_, else_expr)) = &ei.else_branch {
                collect_expr_invoke_signed(else_expr, sites);
            }
        }
        syn::Expr::Match(em) => {
            collect_expr_invoke_signed(&em.expr, sites);
            for arm in &em.arms {
                if let Some((_, guard)) = &arm.guard {
                    collect_expr_invoke_signed(guard, sites);
                }
                collect_expr_invoke_signed(&arm.body, sites);
            }
        }
        syn::Expr::ForLoop(fl) => {
            collect_expr_invoke_signed(&fl.expr, sites);
            collect_invoke_signed_sites(&fl.body, sites);
        }
        syn::Expr::While(wl) => {
            collect_expr_invoke_signed(&wl.cond, sites);
            collect_invoke_signed_sites(&wl.body, sites);
        }
        syn::Expr::Loop(l) => collect_invoke_signed_sites(&l.body, sites),
        syn::Expr::Let(le) => collect_expr_invoke_signed(&le.expr, sites),
        syn::Expr::Unary(u) => collect_expr_invoke_signed(&u.expr, sites),
        _ => {}
    }
}

fn callee_is_invoke_signed(callee: &syn::Expr) -> bool {
    let text = expr_text(callee);
    text == "invoke_signed" || text.ends_with("::invoke_signed")
}

/// Extract the signer seed sets from the third argument of `invoke_signed`
/// (`&[&[&[u8]]]`). Returns `None` when the argument is not an inline
/// literal array — the seeds are not visible, and the call site is skipped
/// rather than flagged (spec FP filter).
fn signers_seeds_of(args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>) -> Option<Vec<Vec<String>>> {
    let arg = args.iter().nth(2)?;
    let syn::Expr::Array(outer) = unwrap_expr(arg) else { return None };
    let mut sets = Vec::new();
    for elem in &outer.elems {
        let syn::Expr::Array(inner) = unwrap_expr(elem) else { return None };
        let seeds: Vec<String> = inner.elems.iter().map(expr_text).collect();
        if !seeds.is_empty() {
            sets.push(seeds);
        }
    }
    if sets.is_empty() { None } else { Some(sets) }
}

/// Compare the account's `find_program_address` seeds against one signer
/// seed list. Both sides are string-normalized (strip `&`, `.as_ref()`,
/// `.to_bytes()`, `.key()`, whitespace) and compared element-wise; a
/// trailing bump-shaped element on the signing side is dropped first.
fn seeds_match(derived: &[String], signing: &[String]) -> bool {
    let derived: Vec<String> = derived.iter().map(|s| normalize_seed(s)).collect();
    let mut signing: Vec<String> = signing.iter().map(|s| normalize_seed(s)).collect();
    if signing.len() == derived.len() + 1 && is_bump_like(signing.last().expect("len > 0")) {
        signing.pop();
    }
    derived.len() == signing.len() && derived.iter().zip(&signing).all(|(a, b)| a == b)
}

/// Normalize a seed expression's source text: drop `&`, whitespace, and the
/// common `&[u8]`-coercion suffixes (`&[u8]` slices and pubkey byte access).
fn normalize_seed(text: &str) -> String {
    let mut s: String = text.chars().filter(|c| *c != '&' && !c.is_whitespace()).collect();
    for pat in [".as_ref()", ".to_bytes_le()", ".to_bytes_be()", ".to_bytes()", ".key()", ".key"] {
        s = s.replace(pat, "");
    }
    s
}

/// `&[bump]`-shaped signer element: a (possibly referenced) one-element
/// array whose content is a bump-like identifier. `find_program_address`
/// seed lists never contain nested arrays, so this shape only appears when
/// signing.
fn is_bump_like(text: &str) -> bool {
    let trimmed = text.trim();
    let inner = trimmed.strip_prefix('&').unwrap_or(trimmed);
    let Some(core) = inner.strip_prefix('[').and_then(|t| t.strip_suffix(']')) else {
        return false;
    };
    let core = core.trim();
    core.contains("bump") && core.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn sat022_finding(
    ix: &NativeInstruction,
    account: &str,
    derived: &[String],
    signing: &[String],
    line: usize,
    file: &str,
) -> Finding {
    let derived_list = derived.join(", ");
    let signing_list = signing.join(", ");
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT022_TITLE} `{account}`"),
        severity: Severity::High,
        description: format!(
            "Instruction `{ix_name}` signs a CPI with seeds `[{signing_list}]` for PDA \
             account `{account}`, which this instruction validated as \
             `find_program_address(&[{derived_list}], program_id)`. The seeds differ, so the \
             CPI signs as a DIFFERENT PDA than the one that was derived and checked. When the \
             differing seed is attacker-influenced (e.g. a caller-supplied key in the seed \
             list), the attacker can derive the signing PDA themselves: the program then \
             authorizes withdrawals or transfers under a PDA the attacker controls, silently \
             bypassing the ownership checks that the validated account was supposed to carry. \
             Exploit: call the instruction with an attacker key in the seed position and let \
             the program sign the token transfer with the attacker-derived PDA."
        ),
        location: Some(finding_location(file, line, ix_name)),
        suggestion: Some(
            "Sign with exactly the seeds used for the `find_program_address` derivation \
             (including the returned bump as the final `&[bump]` element), and derive the \
             PDA in the same code path that builds the signer seeds."
                .to_string(),
        ),
    }
}

// ── SAT023: state write after CPI ────────────────────────────────────────────

/// Shared context for the CEI walk: the instruction, the file it lives in,
/// and the resolved account names / `written` flags from the model.
struct Ctx<'a> {
    ix: &'a NativeInstruction,
    file: &'a str,
    account_names: &'a HashSet<String>,
    written: &'a HashSet<String>,
}

/// SAT023: mutation of a `written` state account after an external call in
/// the same handler. One finding per (instruction, account) — the earliest
/// write statement after the first unconditional CPI.
fn sat023(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ix in &program.instructions {
        let Some((handler, file)) = find_handler(parsed, ix) else { continue };
        let account_names: HashSet<String> = ix.accounts.iter().map(|a| a.name.clone()).collect();
        let written: HashSet<String> = ix.accounts.iter().filter(|a| a.written).map(|a| a.name.clone()).collect();
        if written.is_empty() {
            continue;
        }
        let ctx = Ctx { ix, file, account_names: &account_names, written: &written };
        let mut env: HashMap<String, String> = HashMap::new();
        let mut reported: HashSet<String> = HashSet::new();
        let _ = walk_block(&handler.block, &ctx, &mut env, &mut reported, &mut findings);
    }
    findings
}

/// Walk a block in program order, tracking whether an unconditional external
/// call has been seen. Returns `(found, cpi_escapes)`: `found` means a
/// violation was already reported inside a nested construct (the enclosing
/// walk can stop), `cpi_escapes` means the sequential flow ends with an
/// unconditional interaction (the caller must set its own flag).
fn walk_block(
    block: &syn::Block,
    ctx: &Ctx<'_>,
    env: &mut HashMap<String, String>,
    reported: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> (bool, bool) {
    let mut cpi_seen = false;
    let mut cpi_idx = 0usize;
    for (idx, stmt) in block.stmts.iter().enumerate() {
        if cpi_seen {
            // A CPI ran before this statement: any write anywhere inside it —
            // no matter how deeply nested — is a post-interaction write.
            let mut writes = Vec::new();
            collect_stmt_writes(stmt, env, ctx, &mut writes);
            for account in writes {
                if !reported.insert(account.clone()) {
                    continue;
                }
                // FP filter: skip when the account was closed or re-created
                // between the call and the write (fresh state leaks nothing).
                let closed = (cpi_idx + 1..idx).any(|i| stmt_closes_account(&block.stmts[i], &account, ctx));
                if !closed && ctx.written.contains(&account) {
                    let line = stmt_line(stmt).unwrap_or(ctx.ix.line);
                    findings.push(sat023_finding(ctx, &account, line));
                }
            }
            continue;
        }
        update_env_stmt(stmt, env, ctx);
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                let (found, escapes) = walk_expr(expr, ctx, env, reported, findings);
                if found {
                    return (true, true);
                }
                if escapes {
                    cpi_seen = true;
                    cpi_idx = idx;
                }
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    let (found, escapes) = walk_expr(&init.expr, ctx, env, reported, findings);
                    if found {
                        return (true, true);
                    }
                    if escapes {
                        cpi_seen = true;
                        cpi_idx = idx;
                    }
                }
            }
            _ => {}
        }
    }
    (false, cpi_seen)
}

/// Walk an expression looking for violations inside its nested constructs.
/// Branch isolation mirrors the Anchor check: each branch/arm/loop body is
/// entered from the pre-construct flag state, so a CPI in one branch never
/// leaks into siblings or into the statements that follow the construct.
fn walk_expr(
    expr: &syn::Expr,
    ctx: &Ctx<'_>,
    env: &mut HashMap<String, String>,
    reported: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> (bool, bool) {
    match expr {
        syn::Expr::Call(call) => {
            if is_external_call(&expr_text(&call.func)) {
                // The call arguments evaluate before the call, so nothing in
                // this statement writes "after" the interaction.
                return (false, true);
            }
            let mut found = false;
            let mut escapes = false;
            for arg in &call.args {
                let (f, e) = walk_expr(arg, ctx, env, reported, findings);
                found |= f;
                escapes |= e;
            }
            (found, escapes)
        }
        syn::Expr::MethodCall(mc) => {
            let mut found = false;
            let mut escapes = false;
            let (f, e) = walk_expr(&mc.receiver, ctx, env, reported, findings);
            found |= f;
            escapes |= e;
            for arg in &mc.args {
                let (f, e) = walk_expr(arg, ctx, env, reported, findings);
                found |= f;
                escapes |= e;
            }
            (found, escapes)
        }
        // A bare block always executes: a CPI inside it propagates to the
        // statements that follow.
        syn::Expr::Block(be) => walk_block(&be.block, ctx, env, reported, findings),
        syn::Expr::If(ei) => {
            let (found, _) = walk_expr(&ei.cond, ctx, env, reported, findings);
            if found {
                return (true, false);
            }
            let (found, _) = walk_block(&ei.then_branch, ctx, env, reported, findings);
            if found {
                return (true, false);
            }
            if let Some((_, else_expr)) = &ei.else_branch {
                let (found, _) = walk_expr(else_expr, ctx, env, reported, findings);
                if found {
                    return (true, false);
                }
            }
            (false, false)
        }
        syn::Expr::Match(em) => {
            let (found, _) = walk_expr(&em.expr, ctx, env, reported, findings);
            if found {
                return (true, false);
            }
            for arm in &em.arms {
                if let Some((_, guard)) = &arm.guard {
                    let (found, _) = walk_expr(guard, ctx, env, reported, findings);
                    if found {
                        return (true, false);
                    }
                }
                let (found, _) = walk_expr(&arm.body, ctx, env, reported, findings);
                if found {
                    return (true, false);
                }
            }
            (false, false)
        }
        syn::Expr::ForLoop(fl) => {
            let (found, _) = walk_expr(&fl.expr, ctx, env, reported, findings);
            if found {
                return (true, false);
            }
            // The body is entered with the pre-loop state; a CPI inside it
            // never escapes to the statements after the loop.
            let (found, _) = walk_block(&fl.body, ctx, env, reported, findings);
            (found, false)
        }
        syn::Expr::While(wl) => {
            let (found, _) = walk_expr(&wl.cond, ctx, env, reported, findings);
            if found {
                return (true, false);
            }
            let (found, _) = walk_block(&wl.body, ctx, env, reported, findings);
            (found, false)
        }
        syn::Expr::Loop(l) => {
            let (found, _) = walk_block(&l.body, ctx, env, reported, findings);
            (found, false)
        }
        syn::Expr::Try(t) => walk_expr(&t.expr, ctx, env, reported, findings),
        syn::Expr::Paren(p) => walk_expr(&p.expr, ctx, env, reported, findings),
        syn::Expr::Group(g) => walk_expr(&g.expr, ctx, env, reported, findings),
        syn::Expr::Reference(r) => walk_expr(&r.expr, ctx, env, reported, findings),
        syn::Expr::Unary(u) => walk_expr(&u.expr, ctx, env, reported, findings),
        syn::Expr::Let(le) => walk_expr(&le.expr, ctx, env, reported, findings),
        syn::Expr::Cast(c) => walk_expr(&c.expr, ctx, env, reported, findings),
        syn::Expr::Binary(b) => {
            let (f1, e1) = walk_expr(&b.left, ctx, env, reported, findings);
            let (f2, e2) = walk_expr(&b.right, ctx, env, reported, findings);
            (f1 || f2, e1 || e2)
        }
        syn::Expr::Assign(a) => {
            let (f1, e1) = walk_expr(&a.left, ctx, env, reported, findings);
            let (f2, e2) = walk_expr(&a.right, ctx, env, reported, findings);
            (f1 || f2, e1 || e2)
        }
        _ => (false, false),
    }
}

/// `invoke`, `invoke_signed`, or a known CPI helper path (`spl_token::...`,
/// `token::transfer`-style, `system_instruction::...`).
fn is_external_call(callee: &str) -> bool {
    const CPI_HELPERS: [&str; 10] = [
        "token::transfer",
        "token::transfer_checked",
        "token::mint_to",
        "token::mint_to_checked",
        "token::burn",
        "token::burn_checked",
        "token::set_authority",
        "token::set_authority_checked",
        "token::approve",
        "token::revoke",
    ];
    callee.contains("invoke")
        || callee.contains("spl_token")
        || callee.contains("spl_associated_token_account")
        || callee.contains("system_instruction")
        || CPI_HELPERS.iter().any(|h| callee.contains(h))
}

// ── Local-variable tracking (write attribution) ──────────────────────────────

/// Track local bindings that carry an account's data or deserialized state,
/// so later writes can be attributed to the account.
fn update_env_stmt(stmt: &syn::Stmt, env: &mut HashMap<String, String>, ctx: &Ctx<'_>) {
    let syn::Stmt::Local(local) = stmt else { return };
    let Some(init) = &local.init else { return };
    let Some(name) = pat_ident(&local.pat) else { return };
    if let Some(account) = binding_account(&init.expr, env, ctx) {
        env.insert(name, account);
    }
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    let syn::Pat::Ident(p) = pat else { return None };
    Some(p.ident.to_string())
}

/// The account a local binding is derived from: mutable/immutable data
/// borrows, `load`/`load_mut` accessors, and `try_from_slice`/`unpack`
/// deserialization of an account's data.
fn binding_account(expr: &syn::Expr, env: &HashMap<String, String>, ctx: &Ctx<'_>) -> Option<String> {
    match unwrap_expr(expr) {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if matches!(
                method.as_str(),
                "borrow"
                    | "borrow_mut"
                    | "try_borrow_data"
                    | "try_borrow_mut_data"
                    | "try_borrow"
                    | "try_borrow_mut"
                    | "load"
                    | "load_mut"
                    | "deserialize"
                    | "deserialize_mut"
                    | "try_from_slice_mut"
                    | "unpack_mut"
            ) {
                account_of(&mc.receiver, env, ctx)
            } else {
                None
            }
        }
        syn::Expr::Call(c) => {
            let callee = expr_text(&c.func);
            let last = callee.rsplit("::").next().unwrap_or(&callee);
            if matches!(last, "try_from_slice" | "unpack" | "load" | "load_mut") {
                c.args.first().and_then(|a| account_of(a, env, ctx))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Map an expression to an account name: the root variable is a resolved
/// account, a tracked local, or the member of a `try_from`-struct variable
/// (`accs.vault.data.borrow_mut()` → `vault`).
fn account_of(expr: &syn::Expr, env: &HashMap<String, String>, ctx: &Ctx<'_>) -> Option<String> {
    let root = root_ident(expr)?;
    if ctx.account_names.contains(&root) {
        return Some(root);
    }
    if let Some(account) = env.get(&root) {
        return Some(account.clone());
    }
    if let syn::Expr::Field(f) = unwrap_expr(expr)
        && let syn::Member::Named(member) = &f.member
    {
        let member = member.to_string();
        if ctx.account_names.contains(&member) {
            return Some(member);
        }
    }
    None
}

/// The root identifier of an expression (`state.data.borrow_mut()` → `state`).
fn root_ident(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::MethodCall(mc) => root_ident(&mc.receiver),
        syn::Expr::Field(f) => root_ident(&f.base),
        syn::Expr::Index(i) => root_ident(&i.expr),
        syn::Expr::Reference(r) => root_ident(&r.expr),
        syn::Expr::Paren(p) => root_ident(&p.expr),
        syn::Expr::Group(g) => root_ident(&g.expr),
        syn::Expr::Try(t) => root_ident(&t.expr),
        syn::Expr::Unary(u) => root_ident(&u.expr),
        syn::Expr::Cast(c) => root_ident(&c.expr),
        _ => None,
    }
}

// ── Write detection ──────────────────────────────────────────────────────────

/// Collect the accounts written by a statement, recursing into nested blocks
/// and control flow, and tracking local bindings along the way.
fn collect_stmt_writes(stmt: &syn::Stmt, env: &mut HashMap<String, String>, ctx: &Ctx<'_>, writes: &mut Vec<String>) {
    update_env_stmt(stmt, env, ctx);
    match stmt {
        syn::Stmt::Expr(expr, _) => collect_expr_writes(expr, env, ctx, writes),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                collect_expr_writes(&init.expr, env, ctx, writes);
            }
        }
        _ => {}
    }
}

fn collect_expr_writes(expr: &syn::Expr, env: &mut HashMap<String, String>, ctx: &Ctx<'_>, writes: &mut Vec<String>) {
    match expr {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            // Direct account-data mutation: `state.data.borrow_mut()`,
            // `state.load_mut::<T>()`, `state.try_borrow_mut_data()`,
            // `state.data.deserialize_mut()`.
            if matches!(method.as_str(), "borrow_mut" | "load_mut" | "deserialize_mut" | "try_borrow_mut_data")
                && let Some(account) = account_of(&mc.receiver, env, ctx)
            {
                push_unique(writes, account);
            }
            // Persisting or mutating a tracked deserialized/buffer local:
            // `state_data.serialize(&mut data)`, `data.copy_from_slice(...)`.
            if matches!(
                method.as_str(),
                "serialize" | "serialize_into" | "copy_from_slice" | "extend_from_slice" | "write_all"
            ) && let Some(account) = account_of(&mc.receiver, env, ctx)
            {
                push_unique(writes, account);
            }
            collect_expr_writes(&mc.receiver, env, ctx, writes);
            for arg in &mc.args {
                collect_expr_writes(arg, env, ctx, writes);
            }
        }
        syn::Expr::Call(c) => {
            let callee = expr_text(&c.func);
            // Free `serialize_into(&mut buf, &state)`: the account whose
            // data buffer is written.
            if callee.contains("serialize_into")
                && let Some(account) = c.args.iter().find_map(|a| account_of(a, env, ctx))
            {
                push_unique(writes, account);
            }
            for arg in &c.args {
                collect_expr_writes(arg, env, ctx, writes);
            }
        }
        syn::Expr::Assign(a) => {
            // `state_data.amount = x`, `data[0] = x`.
            if let Some(account) = account_of(&a.left, env, ctx) {
                push_unique(writes, account);
            }
            collect_expr_writes(&a.left, env, ctx, writes);
            collect_expr_writes(&a.right, env, ctx, writes);
        }
        syn::Expr::Binary(b) => {
            // Compound assignments: `state_data.amount += x`.
            if matches!(
                b.op,
                syn::BinOp::AddAssign(_)
                    | syn::BinOp::SubAssign(_)
                    | syn::BinOp::MulAssign(_)
                    | syn::BinOp::DivAssign(_)
                    | syn::BinOp::RemAssign(_)
                    | syn::BinOp::BitXorAssign(_)
                    | syn::BinOp::BitAndAssign(_)
                    | syn::BinOp::BitOrAssign(_)
                    | syn::BinOp::ShlAssign(_)
                    | syn::BinOp::ShrAssign(_)
            ) && let Some(account) = account_of(&b.left, env, ctx)
            {
                push_unique(writes, account);
            }
            collect_expr_writes(&b.left, env, ctx, writes);
            collect_expr_writes(&b.right, env, ctx, writes);
        }
        syn::Expr::Block(be) => {
            for stmt in &be.block.stmts {
                collect_stmt_writes(stmt, env, ctx, writes);
            }
        }
        syn::Expr::If(ei) => {
            collect_expr_writes(&ei.cond, env, ctx, writes);
            for stmt in &ei.then_branch.stmts {
                collect_stmt_writes(stmt, env, ctx, writes);
            }
            if let Some((_, else_expr)) = &ei.else_branch {
                collect_expr_writes(else_expr, env, ctx, writes);
            }
        }
        syn::Expr::Match(em) => {
            collect_expr_writes(&em.expr, env, ctx, writes);
            for arm in &em.arms {
                if let Some((_, guard)) = &arm.guard {
                    collect_expr_writes(guard, env, ctx, writes);
                }
                collect_expr_writes(&arm.body, env, ctx, writes);
            }
        }
        syn::Expr::ForLoop(fl) => {
            collect_expr_writes(&fl.expr, env, ctx, writes);
            for stmt in &fl.body.stmts {
                collect_stmt_writes(stmt, env, ctx, writes);
            }
        }
        syn::Expr::While(wl) => {
            collect_expr_writes(&wl.cond, env, ctx, writes);
            for stmt in &wl.body.stmts {
                collect_stmt_writes(stmt, env, ctx, writes);
            }
        }
        syn::Expr::Loop(l) => {
            for stmt in &l.body.stmts {
                collect_stmt_writes(stmt, env, ctx, writes);
            }
        }
        syn::Expr::Try(t) => collect_expr_writes(&t.expr, env, ctx, writes),
        syn::Expr::Paren(p) => collect_expr_writes(&p.expr, env, ctx, writes),
        syn::Expr::Group(g) => collect_expr_writes(&g.expr, env, ctx, writes),
        syn::Expr::Reference(r) => collect_expr_writes(&r.expr, env, ctx, writes),
        syn::Expr::Unary(u) => collect_expr_writes(&u.expr, env, ctx, writes),
        syn::Expr::Cast(c) => collect_expr_writes(&c.expr, env, ctx, writes),
        syn::Expr::Let(le) => collect_expr_writes(&le.expr, env, ctx, writes),
        syn::Expr::Index(i) => {
            collect_expr_writes(&i.expr, env, ctx, writes);
            collect_expr_writes(&i.index, env, ctx, writes);
        }
        syn::Expr::Field(f) => collect_expr_writes(&f.base, env, ctx, writes),
        syn::Expr::Tuple(t) => {
            for elem in &t.elems {
                collect_expr_writes(elem, env, ctx, writes);
            }
        }
        syn::Expr::Array(a) => {
            for elem in &a.elems {
                collect_expr_writes(elem, env, ctx, writes);
            }
        }
        syn::Expr::Struct(s) => {
            for field in &s.fields {
                collect_expr_writes(&field.expr, env, ctx, writes);
            }
        }
        _ => {}
    }
}

fn push_unique(writes: &mut Vec<String>, account: String) {
    if !writes.contains(&account) {
        writes.push(account);
    }
}

// ── Close / re-create FP filter ──────────────────────────────────────────────

/// FP filter for SAT023: `true` when the statement closes or re-creates
/// `account` — `realloc(0)`/`realloc_zeroed(0)` on it, or its lamports set
/// to zero. Receivers that resolve to no account count (conservative:
/// prefer skipping the finding over a false positive).
fn stmt_closes_account(stmt: &syn::Stmt, account: &str, ctx: &Ctx<'_>) -> bool {
    let mut closed = false;
    match stmt {
        syn::Stmt::Expr(expr, _) => expr_closes_account(expr, account, ctx, &mut closed),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                expr_closes_account(&init.expr, account, ctx, &mut closed);
            }
        }
        _ => {}
    }
    closed
}

fn expr_closes_account(expr: &syn::Expr, account: &str, ctx: &Ctx<'_>, closed: &mut bool) {
    if *closed {
        return;
    }
    match expr {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if (method == "realloc" || method == "realloc_zeroed")
                && first_arg_is_zero(&mc.args)
                && account_name_of(&mc.receiver, ctx.account_names).is_none_or(|a| a == account)
            {
                *closed = true;
                return;
            }
            if mc.method == "try_borrow_mut_lamports"
                && account_name_of(&mc.receiver, ctx.account_names).is_none_or(|a| a == account)
            {
                // The lamports borrow itself only signals a close when the
                // borrowed value is zeroed — handled by the Assign arm below;
                // keep scanning for the zeroing assignment.
                expr_closes_account(&mc.receiver, account, ctx, closed);
                return;
            }
            expr_closes_account(&mc.receiver, account, ctx, closed);
            for arg in &mc.args {
                expr_closes_account(arg, account, ctx, closed);
            }
        }
        syn::Expr::Assign(a) => {
            if rhs_is_zero_lit(&a.right) && expr_zeroes_lamports(&a.left, account, ctx) {
                *closed = true;
                return;
            }
            expr_closes_account(&a.left, account, ctx, closed);
            expr_closes_account(&a.right, account, ctx, closed);
        }
        syn::Expr::Call(c) => {
            for arg in &c.args {
                expr_closes_account(arg, account, ctx, closed);
            }
        }
        syn::Expr::Try(t) => expr_closes_account(&t.expr, account, ctx, closed),
        syn::Expr::Paren(p) => expr_closes_account(&p.expr, account, ctx, closed),
        syn::Expr::Group(g) => expr_closes_account(&g.expr, account, ctx, closed),
        syn::Expr::Reference(r) => expr_closes_account(&r.expr, account, ctx, closed),
        syn::Expr::Unary(u) => expr_closes_account(&u.expr, account, ctx, closed),
        syn::Expr::Field(f) => expr_closes_account(&f.base, account, ctx, closed),
        syn::Expr::Index(i) => {
            expr_closes_account(&i.expr, account, ctx, closed);
            expr_closes_account(&i.index, account, ctx, closed);
        }
        syn::Expr::Binary(b) => {
            expr_closes_account(&b.left, account, ctx, closed);
            expr_closes_account(&b.right, account, ctx, closed);
        }
        syn::Expr::Block(be) => {
            for stmt in &be.block.stmts {
                stmt_closes_account(stmt, account, ctx);
            }
        }
        _ => {}
    }
}

/// `true` when the expression contains a lamports manipulation that zeroes
/// the account's balance (`**a.try_borrow_mut_lamports()? = 0`,
/// `a.lamports = 0`).
fn expr_zeroes_lamports(expr: &syn::Expr, account: &str, ctx: &Ctx<'_>) -> bool {
    match expr {
        syn::Expr::MethodCall(mc) => {
            if mc.method == "try_borrow_mut_lamports"
                && account_name_of(&mc.receiver, ctx.account_names).is_none_or(|a| a == account)
            {
                return true;
            }
            expr_zeroes_lamports(&mc.receiver, account, ctx)
                || mc.args.iter().any(|a| expr_zeroes_lamports(a, account, ctx))
        }
        syn::Expr::Field(f) => {
            if matches!(f.member, syn::Member::Named(ref i) if i == "lamports")
                && account_name_of(&f.base, ctx.account_names).is_none_or(|a| a == account)
            {
                return true;
            }
            expr_zeroes_lamports(&f.base, account, ctx)
        }
        syn::Expr::Try(t) => expr_zeroes_lamports(&t.expr, account, ctx),
        syn::Expr::Paren(p) => expr_zeroes_lamports(&p.expr, account, ctx),
        syn::Expr::Group(g) => expr_zeroes_lamports(&g.expr, account, ctx),
        syn::Expr::Reference(r) => expr_zeroes_lamports(&r.expr, account, ctx),
        syn::Expr::Unary(u) => expr_zeroes_lamports(&u.expr, account, ctx),
        syn::Expr::Index(i) => {
            expr_zeroes_lamports(&i.expr, account, ctx) || expr_zeroes_lamports(&i.index, account, ctx)
        }
        syn::Expr::Call(c) => c.args.iter().any(|a| expr_zeroes_lamports(a, account, ctx)),
        _ => false,
    }
}

/// `realloc(0, ...)`-style: first argument unwraps to the integer literal 0.
fn first_arg_is_zero(args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>) -> bool {
    args.first().is_some_and(|a| {
        if let syn::Expr::Lit(l) = unwrap_expr(a)
            && let syn::Lit::Int(i) = &l.lit
        {
            i.base10_digits() == "0"
        } else {
            false
        }
    })
}

fn rhs_is_zero_lit(expr: &syn::Expr) -> bool {
    if let syn::Expr::Lit(l) = unwrap_expr(expr)
        && let syn::Lit::Int(i) = &l.lit
    {
        i.base10_digits() == "0"
    } else {
        false
    }
}

/// Resolve an expression to a direct account name (no local tracking): the
/// close filter only looks at statements that touch the account itself.
fn account_name_of(expr: &syn::Expr, account_names: &HashSet<String>) -> Option<String> {
    let root = root_ident(expr)?;
    if account_names.contains(&root) { Some(root) } else { None }
}

fn sat023_finding(ctx: &Ctx<'_>, account: &str, line: usize) -> Finding {
    let ix_name = ctx.ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT023_TITLE} `{account}`"),
        severity: Severity::High,
        description: format!(
            "Instruction `{ix_name}` writes the state of account `{account}` AFTER an \
             external call (invoke / invoke_signed / CPI helper) in the same handler, \
             violating Checks-Effects-Interactions ordering. The called program can \
             re-enter this instruction during the CPI callback and observe the STALE \
             pre-write state, so invariants enforced before the call (balances, ownership, \
             limits) can be violated on re-entry — the vulnerability class behind the \
             Wormhole $320M bridge exploit. The write is at or after line {line}."
        ),
        location: Some(finding_location(ctx.file, line, ix_name)),
        suggestion: Some(
            "Move the state write BEFORE the external call (Checks → Effects → \
             Interactions), or re-validate the account state after the interaction \
             (reentrancy guard or re-check invariants)."
                .to_string(),
        ),
    }
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Find the instruction's handler function in the parsed files, scoped to
/// the instruction's own file (a same-named function in another file does
/// not qualify). Falls back to any file when the recorded file does not
/// match any parsed pair.
fn find_handler<'a>(parsed: &'a [(syn::File, String)], ix: &NativeInstruction) -> Option<(syn::ItemFn, &'a str)> {
    let scoped = parsed
        .iter()
        .filter(|(_, path)| path == &ix.file)
        .find_map(|(file, path)| find_fn_in_items(&file.items, &ix.handler).map(|f| (f, path.as_str())));
    if scoped.is_some() {
        return scoped;
    }
    parsed.iter().find_map(|(file, path)| find_fn_in_items(&file.items, &ix.handler).map(|f| (f, path.as_str())))
}

fn find_fn_in_items(items: &[syn::Item], name: &str) -> Option<syn::ItemFn> {
    for item in items {
        match item {
            syn::Item::Fn(f) if f.sig.ident == name => return Some(f.clone()),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content
                    && let Some(f) = find_fn_in_items(inner, name)
                {
                    return Some(f);
                }
            }
            syn::Item::Impl(imp) => {
                for member in &imp.items {
                    if let syn::ImplItem::Fn(f) = member
                        && f.sig.ident == name
                    {
                        return Some(syn::ItemFn {
                            attrs: f.attrs.clone(),
                            vis: f.vis.clone(),
                            sig: f.sig.clone(),
                            block: Box::new(f.block.clone()),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn stmt_line(stmt: &syn::Stmt) -> Option<usize> {
    match stmt {
        syn::Stmt::Expr(expr, _) => Some(expr.span().start().line),
        syn::Stmt::Local(local) => Some(local.span().start().line),
        _ => None,
    }
}

fn unwrap_expr(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Try(t) => unwrap_expr(&t.expr),
        syn::Expr::Paren(p) => unwrap_expr(&p.expr),
        syn::Expr::Group(g) => unwrap_expr(&g.expr),
        syn::Expr::Reference(r) => unwrap_expr(&r.expr),
        _ => e,
    }
}

/// Render an expression as compact source text (used for callee paths and
/// seeds). `quote`'s token stream inserts spaces between tokens
/// (`other . key ()`); they are removed here so text comparisons and the
/// normalization in [`normalize_seed`] are stable.
fn expr_text(e: &syn::Expr) -> String {
    quote::quote!(#e).to_string().split_whitespace().collect()
}
