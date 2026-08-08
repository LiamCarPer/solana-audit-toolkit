//! `init_if_needed` audit — flags `#[account(init_if_needed)]` on
//! authority-bearing accounts whose handlers lack an initialization guard.
//!
//! `init_if_needed` is Anchor's most-exploited footgun: any caller can
//! create the account first, so an attacker front-runs the initialization
//! transaction and plants attacker-chosen authority fields. The legitimate
//! handler then writes state assuming fresh initialization (or overwrites
//! attacker-planted values), enabling authority takeover and state
//! overwrite.

use std::collections::HashMap;

use quote::quote;

use crate::analyzer::{AccountsStruct, type_to_string};
use crate::types::{Finding, Severity};

// ── Re-parsed accounts metadata ──────────────────────────────────────────────
// `AccountField` only records `has_init`, not whether the init variant is
// `init_if_needed`, so the attributes are re-parsed here (the `pda.rs`
// pattern).

#[derive(Debug, Clone, Default)]
struct FieldAttrs {
    has_init_if_needed: bool,
}

#[derive(Debug, Clone, Default)]
struct ParsedAccountsStruct {
    fields: HashMap<String, FieldAttrs>,
}

fn parse_accounts_attrs(parsed_files: &[(syn::File, String)]) -> HashMap<(String, String), ParsedAccountsStruct> {
    let mut out = HashMap::new();
    for (file, path_str) in parsed_files {
        for item in &file.items {
            let syn::Item::Struct(item_struct) = item else { continue };
            if !has_accounts_derive(item_struct) {
                continue;
            }
            let mut parsed = ParsedAccountsStruct::default();
            for field in &item_struct.fields {
                let Some(name) = field.ident.as_ref().map(|i| i.to_string()) else { continue };
                let mut attrs = FieldAttrs::default();
                for attr in &field.attrs {
                    if !attr.path().is_ident("account") {
                        continue;
                    }
                    let _ = attr.parse_nested_meta(|meta| {
                        if meta.path.get_ident().map(|i| i.to_string()).as_deref() == Some("init_if_needed") {
                            attrs.has_init_if_needed = true;
                        }
                        Ok(())
                    });
                }
                parsed.fields.insert(name, attrs);
            }
            // Keyed by (file, struct name): struct names collide across files in
            // multi-file workspaces and a name-only map would mix them up.
            out.insert((path_str.clone(), item_struct.ident.to_string()), parsed);
        }
    }
    out
}

fn has_accounts_derive(item_struct: &syn::ItemStruct) -> bool {
    item_struct.attrs.iter().any(|attr| {
        let path = attr.path();
        if let Some(ident) = path.get_ident()
            && ident == "derive"
            && let Ok(nested) =
                attr.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        {
            return nested.iter().any(|meta| meta.path().is_ident("Accounts"));
        }
        false
    })
}

// ── Storage struct classification ────────────────────────────────────────────

fn storage_field_names(parsed_files: &[(syn::File, String)]) -> HashMap<(String, String), Vec<String>> {
    let mut out = HashMap::new();
    for (file, path_str) in parsed_files {
        for item in &file.items {
            let syn::Item::Struct(item_struct) = item else { continue };
            let is_storage = item_struct.attrs.iter().any(|a| a.path().is_ident("account"));
            if !is_storage {
                continue;
            }
            let fields: Vec<String> = item_struct
                .fields
                .iter()
                .filter_map(|f| f.ident.as_ref().map(|i| i.to_string().to_lowercase()))
                .collect();
            out.insert((path_str.clone(), item_struct.ident.to_string()), fields);
        }
    }
    out
}

fn inner_account_type(ty_name: &str) -> Option<String> {
    for prefix in ["Account<", "AccountLoader<"] {
        if let Some(rest) = ty_name.strip_prefix(prefix) {
            let inner = rest.strip_suffix('>').unwrap_or(rest);
            let last = inner.split(',').next_back().map(|p| p.trim().to_string()).unwrap_or_default();
            return if last.is_empty() { None } else { Some(last) };
        }
    }
    None
}

fn is_state_like(ty_name: &str, struct_path: &str, storage: &HashMap<(String, String), Vec<String>>) -> bool {
    let Some(inner) = inner_account_type(ty_name) else { return false };
    let inner_lower = inner.to_lowercase();
    if ["tokenaccount", "mint", "systemaccount"].iter().any(|e| inner_lower == *e) {
        return false;
    }
    let Some(fields) = storage.get(&(struct_path.to_string(), inner)) else { return false };
    let authority_keys = ["authority", "admin", "owner", "creator", "governor", "manager", "operator"];
    if fields.iter().any(|f| authority_keys.contains(&f.as_str())) {
        return true;
    }
    fields.iter().any(|f| f.contains("state") || f.contains("config") || f.contains("vault") || f.contains("pool"))
}

// ── Handler guard analysis ───────────────────────────────────────────────────

fn handler_ctx_type(func: &syn::ItemFn) -> Option<String> {
    let first = func.sig.inputs.iter().find_map(|input| match input {
        syn::FnArg::Typed(pat) => Some(pat),
        _ => None,
    })?;
    let ty = type_to_string(&first.ty);
    let rest = ty.strip_prefix("Context<")?.strip_suffix('>')?;
    Some(rest.to_string())
}

fn stmt_mentions_initialized(stmt: &syn::Stmt) -> bool {
    let s = quote!(#stmt).to_string().to_lowercase();
    s.contains("is_initialized") || s.contains("initialized")
}

const AUTHORITY_MEMBERS: &[&str] = &["authority", "admin", "owner", "creator", "governor", "manager", "operator"];

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

/// Whether a write target references state: an authority-like member anywhere
/// in the chain, or a `ctx.accounts.<name>` reference (which may then carry
/// further fields such as `.authority` or `.value`).
fn lhs_is_state_write(lhs: &syn::Expr) -> bool {
    match lhs {
        syn::Expr::Field(f) => {
            let member = match &f.member {
                syn::Member::Named(ident) => ident.to_string().to_lowercase(),
                _ => return false,
            };
            if AUTHORITY_MEMBERS.contains(&member.as_str()) || is_ctx_accounts(&f.base) {
                return true;
            }
            lhs_is_state_write(&f.base)
        }
        syn::Expr::Path(p) => {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            let lower: Vec<String> = segs.iter().map(|s| s.to_lowercase()).collect();
            if lower.iter().any(|s| AUTHORITY_MEMBERS.contains(&s.as_str())) {
                return true;
            }
            lower.len() >= 3 && lower[0] == "ctx" && lower[1] == "accounts"
        }
        _ => false,
    }
}

fn stmt_writes_state(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(expr, _) => expr_writes_state(expr),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                expr_writes_state(&init.expr)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn expr_writes_state(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Assign(assign) => lhs_is_state_write(&assign.left),
        syn::Expr::Binary(binary)
            if matches!(
                binary.op,
                syn::BinOp::AddAssign(_)
                    | syn::BinOp::SubAssign(_)
                    | syn::BinOp::MulAssign(_)
                    | syn::BinOp::DivAssign(_)
            ) =>
        {
            lhs_is_state_write(&binary.left)
        }
        syn::Expr::Block(be) => be.block.stmts.iter().any(stmt_writes_state),
        syn::Expr::If(ei) => {
            expr_writes_state(&ei.cond)
                || ei.then_branch.stmts.iter().any(stmt_writes_state)
                || ei.else_branch.as_ref().is_some_and(|(_, e)| expr_writes_state(e))
        }
        syn::Expr::Match(em) => em.arms.iter().any(|arm| expr_writes_state(&arm.body)),
        syn::Expr::Paren(paren) => expr_writes_state(&paren.expr),
        _ => false,
    }
}

/// Returns `Some(true)` when an initialization guard appears before the first
/// state write, `Some(false)` when a write happens with no guard, and `None`
/// when no matching handler or no state write could be found (uncertain).
/// Handlers are matched within the struct's own file to avoid struct-name
/// collisions across files.
fn scan_handler_guards(parsed_files: &[(syn::File, String)], struct_name: &str, struct_path: &str) -> Option<bool> {
    for (file, path_str) in parsed_files {
        if path_str != struct_path {
            continue;
        }
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
                let Some(ctx_type) = handler_ctx_type(func) else { continue };
                if !ctx_type.eq_ignore_ascii_case(struct_name) {
                    continue;
                }
                let mut guard_seen = false;
                let mut wrote = false;
                for stmt in &func.block.stmts {
                    if !guard_seen && stmt_mentions_initialized(stmt) {
                        guard_seen = true;
                    }
                    if stmt_writes_state(stmt) {
                        wrote = true;
                        if !guard_seen {
                            return Some(false);
                        }
                    }
                }
                if wrote {
                    return Some(true);
                }
            }
        }
    }
    None
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn check_init_if_needed(accounts: &[AccountsStruct], parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let parsed = parse_accounts_attrs(parsed_files);
    let storage = storage_field_names(parsed_files);

    for accts in accounts {
        let struct_key = (accts.file.display().to_string(), accts.name.clone());
        let Some(attrs) = parsed.get(&struct_key) else { continue };
        for field in &accts.fields {
            let Some(fa) = attrs.fields.get(&field.name) else { continue };
            if !fa.has_init_if_needed {
                continue;
            }
            if !is_state_like(&field.ty_name, &struct_key.0, &storage) {
                continue;
            }

            let guarded = scan_handler_guards(parsed_files, &accts.name, &struct_key.0);
            let (severity, guard_label, guard_note) = match guarded {
                Some(false) => (
                    Severity::High,
                    "without an initialization guard",
                    "No initialization guard was found before the state writes.",
                ),
                _ => (
                    Severity::Medium,
                    "with an initialization guard",
                    "An is_initialized guard appears before the state writes — verify it covers every write path.",
                ),
            };

            let inner = inner_account_type(&field.ty_name).unwrap_or_default();
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Reinitialization Risk: `{}::{}` uses init_if_needed on authority-bearing account `{}` {}",
                    accts.name, field.name, inner, guard_label
                ),
                severity,
                description: format!(
                    "The field `{}` in `{}` is declared with `#[account(init_if_needed)]` and its storage type \
                     `{}` holds authority-like fields. `init_if_needed` lets ANY caller create the account \
                     first: an attacker can front-run the initialization and plant their own authority, and \
                     the handler then writes state without a fresh-initialization guarantee, enabling \
                     authority takeover and state overwrite. {}",
                    field.name, accts.name, inner, guard_note
                ),
                location: Some(format!("{}:{} ({}::{})", accts.file.display(), field.line, accts.name, field.name)),
                suggestion: Some(format!(
                    "Use `#[account(init, payer = ..., space = ...)]` when the account must be fresh, or guard \
                     the handler with `if !state.is_initialized {{ ... }}` before writing authority fields on \
                     `{}`. Never seed authority fields from attacker-controlled inputs.",
                    field.name
                )),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(fields: &[&str]) -> HashMap<(String, String), Vec<String>> {
        let mut m = HashMap::new();
        m.insert(("test.rs".to_string(), "State".to_string()), fields.iter().map(|s| s.to_string()).collect());
        m
    }

    #[test]
    fn classifies_state_like_storage() {
        let s = storage(&["authority", "total_deposits"]);
        assert!(is_state_like("Account<State>", "test.rs", &s));
        assert!(is_state_like("Account<'info, State>", "test.rs", &s));
        assert!(is_state_like("AccountLoader<State>", "test.rs", &s));
    }

    #[test]
    fn excludes_token_and_non_authority_types() {
        let s = storage(&["authority"]);
        assert!(!is_state_like("Account<TokenAccount>", "test.rs", &s));
        assert!(!is_state_like("Account<'info, Mint>", "test.rs", &s));
        let s2 = storage(&["value", "counter"]);
        assert!(!is_state_like("Account<State>", "test.rs", &s2));
    }
}
