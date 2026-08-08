//! Token-CPI verification — flags token transfer/set_authority CPIs whose
//! authority account is not constrained as a signer (or a seeded PDA signer).
//!
//! The token program requires the authority to sign a transfer unless the
//! calling program signs via `invoke_signed`. When the authority is declared
//! as an unconstrained `AccountInfo`/`Account`, the CPI either fails at
//! runtime (DoS) or — if the program signs with seeds derived from
//! attacker-influenced inputs — authorizes arbitrary transfers.

use std::collections::HashMap;

use syn::spanned::Spanned;

use crate::analyzer::{AccountField, AccountsStruct, type_to_string};
use crate::types::{Finding, Severity};

/// Token operations that move value or change ownership.
const TOKEN_OPS: &[&str] = &[
    "transfer",
    "transfer_checked",
    "transfer_checked_with_fee",
    "set_authority",
    "mint_to",
    "burn",
    "approve",
    "revoke",
    "freeze_account",
    "thaw_account",
    "close_account",
];

/// Ops distinctive enough to match even without a `token` path segment.
const DISTINCTIVE_OPS: &[&str] = &[
    "transfer_checked",
    "transfer_checked_with_fee",
    "mint_to",
    "burn",
    "set_authority",
    "approve",
    "freeze_account",
    "thaw_account",
];

/// Authority field names accepted in CPI accounts struct literals.
const AUTHORITY_FIELD_NAMES: &[&str] = &["authority", "current_authority"];

fn is_token_op_call(callee: &str) -> Option<&'static str> {
    let lower = callee.to_lowercase();
    let last = lower.rsplit("::").next().unwrap_or(&lower);
    // Bare `transfer` without a `token` path segment is ambiguous
    // (e.g. system_program::transfer) — exclude it.
    if last == "transfer" && !lower.contains("token") {
        return None;
    }
    if !lower.contains("token") && !DISTINCTIVE_OPS.contains(&last) {
        return None;
    }
    TOKEN_OPS.iter().find(|op| **op == last).copied()
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

// ── Local data flow (let-bound CPI structs) ──────────────────────────────────
// Anchor code typically binds the CPI accounts struct to a `let` first
// (`let cpi_accounts = TransferChecked { ... }; CpiContext::new(..., cpi_accounts)`),
// so bindings are collected and resolved before inspecting the call.

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

fn resolve(expr: &syn::Expr, bindings: &HashMap<String, syn::Expr>) -> syn::Expr {
    if let syn::Expr::Path(path) = expr
        && let Some(ident) = path.path.get_ident()
        && let Some(bound) = bindings.get(&ident.to_string())
    {
        return resolve(bound, bindings);
    }
    expr.clone()
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

/// Extracts the accounts-field name from `ctx.accounts.<name>...` expressions.
fn account_name_from_expr(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::MethodCall(mc) => account_name_from_expr(&mc.receiver),
        syn::Expr::Field(f) => {
            if is_ctx_accounts(&f.base)
                && let syn::Member::Named(ident) = &f.member
            {
                return Some(ident.to_string());
            }
            account_name_from_expr(&f.base)
        }
        // `ctx.accounts.<name>` chains parse as paths when every segment is an
        // identifier — the account field is the segment after `accounts`.
        syn::Expr::Path(p) => {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if segs.len() >= 3 && segs[0].eq_ignore_ascii_case("ctx") && segs[1].eq_ignore_ascii_case("accounts") {
                segs.get(2).cloned()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_authority_name(call: &syn::ExprCall, bindings: &HashMap<String, syn::Expr>) -> Option<String> {
    let ctx_arg = call.args.first()?;
    let cpi_call = resolve(ctx_arg, bindings);
    let syn::Expr::Call(cpi_call) = cpi_call else { return None };
    let callee = call_path(&cpi_call.func);
    if !callee.contains("CpiContext") {
        return None;
    }
    let accounts_arg = cpi_call.args.iter().nth(1)?;
    let lit = resolve(accounts_arg, bindings);
    let syn::Expr::Struct(struct_lit) = lit else { return None };
    for field in &struct_lit.fields {
        let name = match &field.member {
            syn::Member::Named(ident) => ident.to_string(),
            _ => continue,
        };
        if AUTHORITY_FIELD_NAMES.contains(&name.as_str()) {
            return account_name_from_expr(&field.expr);
        }
    }
    None
}

fn authority_is_constrained(field: &AccountField) -> bool {
    field.is_signer_type || field.has_signer || field.has_seeds
}

// ── AST traversal ────────────────────────────────────────────────────────────

fn collect_token_calls(block: &syn::Block) -> Vec<(String, syn::ExprCall)> {
    let mut calls = Vec::new();
    collect_token_calls_in_stmts(&block.stmts, &mut calls);
    calls
}

fn collect_token_calls_in_stmts(stmts: &[syn::Stmt], out: &mut Vec<(String, syn::ExprCall)>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => collect_token_calls_in_expr(expr, out),
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    collect_token_calls_in_expr(&init.expr, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_token_calls_in_expr(expr: &syn::Expr, out: &mut Vec<(String, syn::ExprCall)>) {
    match expr {
        syn::Expr::Call(call) => {
            let callee = call_path(&call.func);
            if let Some(op) = is_token_op_call(&callee) {
                out.push((op.to_string(), call.clone()));
            }
            for arg in &call.args {
                collect_token_calls_in_expr(arg, out);
            }
            collect_token_calls_in_expr(&call.func, out);
        }
        syn::Expr::Block(be) => collect_token_calls_in_stmts(&be.block.stmts, out),
        syn::Expr::If(ei) => {
            collect_token_calls_in_expr(&ei.cond, out);
            collect_token_calls_in_stmts(&ei.then_branch.stmts, out);
            if let Some((_, else_expr)) = &ei.else_branch {
                collect_token_calls_in_expr(else_expr, out);
            }
        }
        syn::Expr::Match(em) => {
            collect_token_calls_in_expr(&em.expr, out);
            for arm in &em.arms {
                collect_token_calls_in_expr(&arm.body, out);
            }
        }
        syn::Expr::Try(t) => collect_token_calls_in_expr(&t.expr, out),
        syn::Expr::Unary(u) => collect_token_calls_in_expr(&u.expr, out),
        syn::Expr::Paren(p) => collect_token_calls_in_expr(&p.expr, out),
        syn::Expr::Let(el) => collect_token_calls_in_expr(&el.expr, out),
        syn::Expr::Reference(r) => collect_token_calls_in_expr(&r.expr, out),
        syn::Expr::MethodCall(mc) => {
            collect_token_calls_in_expr(&mc.receiver, out);
            for arg in &mc.args {
                collect_token_calls_in_expr(arg, out);
            }
        }
        _ => {}
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn check_token_cpi(accounts: &[AccountsStruct], parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

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

                let bindings = collect_bindings(&func.block);
                for (op, call) in collect_token_calls(&func.block) {
                    let Some(authority_name) = extract_authority_name(&call, &bindings) else { continue };
                    let Some(field) = accts.fields.iter().find(|f| f.name.eq_ignore_ascii_case(&authority_name)) else {
                        continue;
                    };
                    if authority_is_constrained(field) {
                        continue;
                    }

                    let is_ownership = matches!(op.as_str(), "set_authority" | "approve" | "revoke");
                    let line = call.span().start().line;
                    let description = if is_ownership {
                        format!(
                            "The instruction `{}` calls `{}` with `{}::{}` as the authority, but that field is \
                             not constrained as a signer (`Signer<'info>`, `#[account(signer)]`, or a seeded \
                             PDA). For `set_authority`/`approve` this can let an attacker change token account \
                             ownership or approve spends they should not control.",
                            fn_name, op, accts.name, field.name
                        )
                    } else {
                        format!(
                            "The instruction `{}` calls `{}` with `{}::{}` as the transfer authority, but that \
                             field is not constrained as a signer. The token program requires the authority to \
                             sign unless the program signs via `invoke_signed` — if the signing seeds are \
                             derived from attacker-influenced inputs this authorizes arbitrary transfers; \
                             otherwise the CPI fails at runtime (denial of service).",
                            fn_name, op, accts.name, field.name
                        )
                    };

                    findings.push(Finding {
                        id: String::new(),
                        title: format!(
                            "Token Transfer CPI: `{}` calls `{}` with authority `{}::{}` not constrained as signer",
                            fn_name, op, accts.name, field.name
                        ),
                        severity: Severity::High,
                        description,
                        location: Some(format!("{path_str}:{line} ({fn_name})")),
                        suggestion: Some(
                            "Constrain the authority with `#[account(signer)]` / `Signer<'info>`, or derive it \
                             as a PDA from fixed seeds and sign via `invoke_signed`."
                                .to_string(),
                        ),
                    });
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
    fn classifies_token_ops() {
        assert_eq!(is_token_op_call("spl_token::transfer"), Some("transfer"));
        assert_eq!(is_token_op_call("token_2022::transfer_checked"), Some("transfer_checked"));
        assert_eq!(is_token_op_call("anchor_spl::token::transfer_checked_with_fee"), Some("transfer_checked_with_fee"));
        assert_eq!(is_token_op_call("transfer_checked"), Some("transfer_checked"));
        assert_eq!(is_token_op_call("spl_token::set_authority"), Some("set_authority"));
    }

    #[test]
    fn excludes_non_token_transfers() {
        assert_eq!(is_token_op_call("system_program::transfer"), None);
        assert_eq!(is_token_op_call("solana_program::system_instruction::transfer"), None);
        assert_eq!(is_token_op_call("update"), None);
    }

    #[test]
    fn extracts_account_name_from_receiver_chain() {
        let expr: syn::Expr = syn::parse_str("ctx.accounts.authority.to_account_info()").unwrap();
        assert_eq!(account_name_from_expr(&expr).as_deref(), Some("authority"));
        let expr: syn::Expr = syn::parse_str("ctx.accounts.authority.key()").unwrap();
        assert_eq!(account_name_from_expr(&expr).as_deref(), Some("authority"));
    }
}
