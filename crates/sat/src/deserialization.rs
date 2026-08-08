//! Manual deserialization audit — flags account data deserialized by hand
//! instead of through Anchor's typed `Account<'info, T>` wrappers, bypassing
//! the owner/discriminator validation Anchor applies.

use std::collections::HashMap;

use syn::spanned::Spanned;

use crate::analyzer::{AccountField, AccountsStruct, type_to_string};
use crate::types::{Finding, Severity};

const DESER_OPS: &[&str] = &[
    "try_from_slice",
    "try_from_slice_unchecked",
    "try_from_slice_checked",
    "try_deserialize",
    "try_borrow_data",
    "borrow_data",
];
const UNCHECKED_OPS: &[&str] = &["try_from_slice_unchecked", "try_deserialize"];
const BORROW_OPS: &[&str] = &["try_borrow_data", "borrow_data"];

fn is_deser_op(name: &str) -> Option<&'static str> {
    let last = name.rsplit("::").next().unwrap_or(name);
    DESER_OPS.iter().find(|op| **op == last).copied()
}

fn call_path(func: &syn::Expr) -> String {
    match func {
        syn::Expr::Path(path) => path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"),
        syn::Expr::Call(call) => call_path(&call.func),
        _ => String::new(),
    }
}

fn handler_ctx_type(func: &syn::ItemFn) -> Option<String> {
    let first = func.sig.inputs.iter().find_map(|input| match input {
        syn::FnArg::Typed(pat) => Some(pat),
        _ => None,
    })?;
    let ty = type_to_string(&first.ty);
    let rest = ty.strip_prefix("Context<")?.strip_suffix('>')?;
    Some(rest.to_string())
}

/// True when `expr` is exactly the `ctx.accounts` field reference.
fn is_ctx_accounts(expr: &syn::Expr) -> bool {
    if let syn::Expr::Field(f) = expr {
        let syn::Member::Named(member) = &f.member else { return false };
        if member != "accounts" {
            return false;
        }
        return matches!(&*f.base, syn::Expr::Path(p) if p.path.is_ident("ctx"));
    }
    false
}

/// Finds the first `ctx.accounts.<name>` field reference anywhere in an
/// expression tree (handles `.data.borrow()` chains, references, indexes,
/// casts, and call arguments).
fn find_account_field(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Field(f) => {
            if is_ctx_accounts(&f.base)
                && let syn::Member::Named(ident) = &f.member
            {
                return Some(ident.to_string());
            }
            find_account_field(&f.base)
        }
        // `ctx.accounts.<name>...` chains parse as paths when every segment is
        // an identifier — the account field is the segment after `accounts`.
        syn::Expr::Path(p) => {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if segs.len() >= 3 && segs[0].eq_ignore_ascii_case("ctx") && segs[1].eq_ignore_ascii_case("accounts") {
                segs.get(2).cloned()
            } else {
                None
            }
        }
        syn::Expr::MethodCall(mc) => find_account_field(&mc.receiver),
        syn::Expr::Index(i) => find_account_field(&i.expr),
        syn::Expr::Reference(r) => find_account_field(&r.expr),
        syn::Expr::Paren(p) => find_account_field(&p.expr),
        syn::Expr::Cast(c) => find_account_field(&c.expr),
        syn::Expr::Try(t) => find_account_field(&t.expr),
        syn::Expr::Unary(u) => find_account_field(&u.expr),
        syn::Expr::Call(c) => c.args.iter().find_map(find_account_field),
        _ => None,
    }
}

// ── AST traversal ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DeserHit {
    op: String,
    line: usize,
    field: String,
}

fn scan_fn(block: &syn::Block) -> Vec<DeserHit> {
    let mut hits = Vec::new();
    scan_stmts(&block.stmts, &mut hits);
    hits
}

fn scan_stmts(stmts: &[syn::Stmt], out: &mut Vec<DeserHit>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => scan_expr(expr, out),
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    scan_expr(&init.expr, out);
                }
            }
            _ => {}
        }
    }
}

fn scan_expr(expr: &syn::Expr, out: &mut Vec<DeserHit>) {
    match expr {
        syn::Expr::Call(call) => {
            let callee = call_path(&call.func);
            if let Some(op) = is_deser_op(&callee)
                && let Some(field) = call.args.iter().find_map(find_account_field)
            {
                out.push(DeserHit { op: op.to_string(), line: call.span().start().line, field });
            }
            for arg in &call.args {
                scan_expr(arg, out);
            }
            scan_expr(&call.func, out);
        }
        syn::Expr::MethodCall(mc) => {
            if let Some(op) = is_deser_op(&mc.method.to_string())
                && let Some(field) = find_account_field(&mc.receiver)
            {
                out.push(DeserHit { op: op.to_string(), line: mc.span().start().line, field });
            }
            scan_expr(&mc.receiver, out);
            for arg in &mc.args {
                scan_expr(arg, out);
            }
        }
        syn::Expr::Block(be) => scan_stmts(&be.block.stmts, out),
        syn::Expr::If(ei) => {
            scan_expr(&ei.cond, out);
            scan_stmts(&ei.then_branch.stmts, out);
            if let Some((_, else_expr)) = &ei.else_branch {
                scan_expr(else_expr, out);
            }
        }
        syn::Expr::Match(em) => {
            scan_expr(&em.expr, out);
            for arm in &em.arms {
                scan_expr(&arm.body, out);
            }
        }
        syn::Expr::Try(t) => scan_expr(&t.expr, out),
        syn::Expr::Unary(u) => scan_expr(&u.expr, out),
        syn::Expr::Paren(p) => scan_expr(&p.expr, out),
        syn::Expr::Let(el) => scan_expr(&el.expr, out),
        syn::Expr::Reference(r) => scan_expr(&r.expr, out),
        syn::Expr::Index(i) => scan_expr(&i.expr, out),
        _ => {}
    }
}

// ── Classification ───────────────────────────────────────────────────────────

fn classify(
    field: &AccountField,
    hit: &DeserHit,
    fn_name: &str,
    struct_name: &str,
) -> Option<(Severity, String, String)> {
    let raw = field.is_account_info || field.is_unchecked_account;

    if raw && !field.has_owner {
        let ty = if field.is_unchecked_account { "UncheckedAccount" } else { "AccountInfo" };
        return Some((
            Severity::High,
            format!(
                "Manual Deserialization: `{}::{}` data is deserialized in `{}` without an owner constraint",
                struct_name, field.name, fn_name
            ),
            format!(
                "The field `{}` in `{}` is typed as `{}` and its data is deserialized in `{}` without an owner \
                 constraint. An attacker can supply an account owned by their own program with fabricated data \
                 (account spoofing). Use a typed `Account<'info, T>`, add `#[account(owner = ...)]`, or verify \
                 the discriminator before trusting the data.",
                field.name, struct_name, ty, fn_name
            ),
        ));
    }

    if UNCHECKED_OPS.contains(&hit.op.as_str()) {
        return Some((
            Severity::Medium,
            format!(
                "Manual Deserialization: `{}` uses `{}` on `{}::{}` bypassing Anchor validation",
                fn_name, hit.op, struct_name, field.name
            ),
            format!(
                "`{}` skips the owner and discriminator checks Anchor applies to typed accounts. Verify the \
                 account owner and discriminator manually before deserializing its data.",
                hit.op
            ),
        ));
    }

    if BORROW_OPS.contains(&hit.op.as_str()) && !raw {
        return Some((
            Severity::Medium,
            format!(
                "Manual Deserialization: `{}` borrows data from typed account `{}::{}` bypassing the discriminator check",
                fn_name, struct_name, field.name
            ),
            format!(
                "The typed account `{}::{}` is accessed via `{}`, bypassing Anchor's discriminator and owner \
                 validation. Use the typed accessors (`ctx.accounts.{}.field`) or re-verify the discriminator.",
                struct_name, field.name, hit.op, field.name
            ),
        ));
    }

    if (hit.op == "try_from_slice" || hit.op == "try_from_slice_checked") && !raw {
        return Some((
            Severity::Medium,
            format!(
                "Manual Deserialization: `{}` uses `{}` on `{}::{}` bypassing Anchor validation",
                fn_name, hit.op, struct_name, field.name
            ),
            format!(
                "The typed account `{}::{}` is deserialized with `{}`, which does not verify Anchor's \
                 discriminator. Use the typed `Account<'info, T>` accessors or check the discriminator first.",
                struct_name, field.name, hit.op
            ),
        ));
    }

    None
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn check_manual_deserialization(accounts: &[AccountsStruct], parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    // (fn, field) → index of the finding currently kept for that pair.
    let mut best: HashMap<(String, String), usize> = HashMap::new();

    for (file, path_str) in parsed_files {
        for item in &file.items {
            let syn::Item::Mod(item_mod) = item else { continue };
            if !item_mod.attrs.iter().any(|a| a.path().is_ident("program")) {
                continue;
            }
            let Some((_, items)) = &item_mod.content else { continue };
            for mod_item in items {
                let syn::Item::Fn(func) = mod_item else { continue };
                if !matches!(func.vis, syn::Visibility::Public(_)) {
                    continue;
                }
                let fn_name = func.sig.ident.to_string();
                let Some(ctx_type) = handler_ctx_type(func) else { continue };
                // Match the accounts struct within the SAME file: struct names
                // collide across files in multi-file workspaces.
                let Some(accts) = accounts
                    .iter()
                    .find(|a| a.name.eq_ignore_ascii_case(&ctx_type) && a.file.to_string_lossy() == path_str.as_str())
                else {
                    continue;
                };

                for hit in scan_fn(&func.block) {
                    let Some(field) = accts.fields.iter().find(|f| f.name.eq_ignore_ascii_case(&hit.field)) else {
                        continue;
                    };
                    let Some((severity, title, description)) = classify(field, &hit, &fn_name, &accts.name) else {
                        continue;
                    };
                    let key = (fn_name.clone(), field.name.clone());
                    let location = format!("{path_str}:{} ({fn_name})", hit.line);
                    let suggestion =
                        "Use `Account<'info, T>::try_from(&info)` for typed access, or verify the account \
                         owner and discriminator before deserializing its data."
                            .to_string();
                    let build = || Finding {
                        id: String::new(),
                        title,
                        severity,
                        description,
                        location: Some(location),
                        suggestion: Some(suggestion),
                    };
                    match best.get(&key) {
                        // Keep the existing entry when it is at least as severe.
                        Some(&idx) if findings[idx].severity <= severity => {}
                        Some(&idx) => findings[idx] = build(),
                        None => {
                            best.insert(key, findings.len());
                            findings.push(build());
                        }
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_field_name_from_receiver_chain() {
        let expr: syn::Expr = syn::parse_str("ctx.accounts.user.try_borrow_data()").unwrap();
        assert_eq!(find_account_field(&expr).as_deref(), Some("user"));
        let expr: syn::Expr = syn::parse_str("ctx.accounts.state.data.borrow()").unwrap();
        assert_eq!(find_account_field(&expr).as_deref(), Some("state"));
        let expr: syn::Expr = syn::parse_str("&ctx.accounts.user.data.borrow()[..]").unwrap();
        assert_eq!(find_account_field(&expr).as_deref(), Some("user"));
    }

    #[test]
    fn ignores_non_account_receivers() {
        let expr: syn::Expr = syn::parse_str("instruction.data").unwrap();
        assert_eq!(find_account_field(&expr), None);
        let expr: syn::Expr = syn::parse_str("data").unwrap();
        assert_eq!(find_account_field(&expr), None);
    }
}
