use crate::analyzer::AccountsStruct;
use crate::cpi::expr_to_string_expr;
use crate::types::{Finding, Severity};
use std::collections::{HashMap, HashSet};

// ── Sysvar misuse detection ───────────────────────────────────────────────────

struct SysvarDef {
    pubkey: &'static str,
    accessor_type: &'static str,
    name: &'static str,
}

const KNOWN_SYSVARS: &[SysvarDef] = &[
    SysvarDef { pubkey: "SysvarRent111111111111111111111111111111111", accessor_type: "Rent", name: "rent" },
    SysvarDef { pubkey: "SysvarC1ock11111111111111111111111111111111", accessor_type: "Clock", name: "clock" },
    SysvarDef {
        pubkey: "SysvarEpochSchedu1e111111111111111111111111",
        accessor_type: "EpochSchedule",
        name: "epoch_schedule",
    },
    SysvarDef { pubkey: "SysvarFees111111111111111111111111111111111", accessor_type: "Fees", name: "fees" },
    SysvarDef {
        pubkey: "SysvarRecentB1ockHashes11111111111111111111",
        accessor_type: "RecentBlockhashes",
        name: "recent_blockhashes",
    },
    SysvarDef {
        pubkey: "SysvarStakeHistory1111111111111111111111111",
        accessor_type: "StakeHistory",
        name: "stake_history",
    },
    SysvarDef {
        pubkey: "SysvarInstruction1111111111111111111111111",
        accessor_type: "Instructions",
        name: "instructions",
    },
    SysvarDef {
        pubkey: "SysvarS1otHashes111111111111111111111111111",
        accessor_type: "SlotHashes",
        name: "slot_hashes",
    },
    SysvarDef {
        pubkey: "SysvarS1otHistory11111111111111111111111111",
        accessor_type: "SlotHistory",
        name: "slot_history",
    },
];

/// A recorded use of a sysvar inside an instruction body or an
/// `#[account(...)]` constraint.
///
/// `is_accessor` is `true` when the use is a plain accessor call
/// (`<Type>::get()`, `<Type>::get_or_create_account()`, `Sysvar::get()`).
/// Accessor calls read the sysvar at its well-known fixed address and work
/// WITHOUT a declared account (Jito's live tip-distribution `claim` handler
/// and Anchor's own generated seeds constraints both call `Clock::get()` with
/// no `clock` field declared). Any non-accessor reference (e.g.
/// `ctx.accounts.clock`, a bare `clock` inside a `#[account(...)]`
/// constraint) refers to an Accounts-struct field and is a genuine Anchor
/// constraint failure when undeclared.
#[derive(Debug, Clone)]
struct SysvarUse {
    name: String,
    is_accessor: bool,
}

pub fn check_sysvar_misuse(parsed_files: &[(syn::File, String)], accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut sysvar_declared: HashMap<String, Vec<String>> = HashMap::new();
    let mut sysvar_writable: HashSet<String> = HashSet::new();

    for accts in accounts {
        for field in &accts.fields {
            let ty_lower = field.ty_name.to_lowercase();
            for sysvar in KNOWN_SYSVARS {
                if ty_lower.contains(&sysvar.accessor_type.to_lowercase())
                    || ty_lower.contains(&format!("sysvar::{}", sysvar.name))
                    || field.name.to_lowercase() == sysvar.name
                {
                    sysvar_declared.entry(sysvar.accessor_type.to_string()).or_default().push(accts.name.clone());

                    if field.has_mut {
                        sysvar_writable.insert(sysvar.accessor_type.to_string());
                    }
                }
            }
        }
    }

    let mut sysvar_used_in_body: HashMap<String, Vec<String>> = HashMap::new();
    // Sysvars referenced from a non-accessor context. Only those are genuine
    // Anchor failures when undeclared; accessor-only usage is legal without a
    // declared field.
    let mut sysvar_non_accessor: HashSet<String> = HashSet::new();

    for (file, _file_path) in parsed_files {
        for item in &file.items {
            let functions = find_functions_with_sysvar_calls(item);
            for (fn_name, sysvars) in functions {
                for use_ in sysvars {
                    sysvar_used_in_body.entry(use_.name.clone()).or_default().push(fn_name.clone());
                    if !use_.is_accessor {
                        sysvar_non_accessor.insert(use_.name.clone());
                    }
                }
            }
            scan_account_attrs_for_sysvar(item, &mut sysvar_used_in_body, &mut sysvar_non_accessor);
        }
    }

    for sysvar in KNOWN_SYSVARS {
        if let Some(used_in) = sysvar_used_in_body.get(sysvar.accessor_type)
            && !sysvar_declared.contains_key(sysvar.accessor_type)
            && sysvar_non_accessor.contains(sysvar.accessor_type)
        {
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Missing Sysvar Account: `{}::get()` used but `{}` not declared in any Accounts struct",
                    sysvar.accessor_type, sysvar.name
                ),
                severity: Severity::High,
                description: format!(
                    "Instructions {:?} call `{}::get()` or `Sysvar::get()` but the `{}` sysvar \
                         account is not declared in any `#[derive(Accounts)]` struct. This will cause \
                         the sysvar accessor to fail at runtime because Anchor needs an explicit sysvar \
                         account in the accounts list to provide the sysvar data to the instruction.",
                    used_in, sysvar.accessor_type, sysvar.name
                ),
                location: Some(format!("Sysvar: {} ({})", sysvar.name, sysvar.pubkey)),
                suggestion: Some(format!(
                    "Add `pub {}: Sysvar<{}>` to each `#[derive(Accounts)]` struct that is used \
                         by instructions calling `{}::get()`.",
                    sysvar.name, sysvar.accessor_type, sysvar.accessor_type
                )),
            });
        }
    }

    for sysvar in KNOWN_SYSVARS {
        if sysvar_writable.contains(sysvar.accessor_type) {
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Writable Sysvar: `{}` is declared with `#[account(mut)]` but sysvars are read-only",
                    sysvar.name
                ),
                severity: Severity::High,
                description: format!(
                    "The `{}` sysvar account (pubkey: `{}`) is declared with `#[account(mut)]` in an \
                         Accounts struct. Sysvars are inherently read-only; marking them writable is a \
                         common fee-locking attack vector where a malicious actor could cause the runtime \
                         to attempt deducting lamports from a non-writable sysvar, locking user funds.",
                    sysvar.name, sysvar.pubkey
                ),
                location: Some(format!("Sysvar: {} ({})", sysvar.name, sysvar.pubkey)),
                suggestion: Some(format!(
                    "Remove `#[account(mut)]` from the `{}` field. Sysvars should be declared as \
                         read-only accounts.",
                    sysvar.name
                )),
            });
        }
    }

    findings
}

fn find_functions_with_sysvar_calls(item: &syn::Item) -> Vec<(String, Vec<SysvarUse>)> {
    let mut results = Vec::new();

    if let syn::Item::Mod(item_mod) = item
        && let Some((_, items)) = &item_mod.content
    {
        for mod_item in items {
            if let syn::Item::Fn(func) = mod_item {
                let sysvars = scan_for_sysvar_calls(&func.block);
                if !sysvars.is_empty() {
                    results.push((func.sig.ident.to_string(), sysvars));
                }
            }
        }
    }

    results
}

fn scan_for_sysvar_calls(block: &syn::Block) -> Vec<SysvarUse> {
    // Name -> accessor-only flag; `false` (a non-accessor use) wins when a
    // sysvar is referenced both ways.
    let mut found: HashMap<String, bool> = HashMap::new();
    scan_stmts_for_sysvar(&block.stmts, &mut found);
    found.into_iter().map(|(name, is_accessor)| SysvarUse { name, is_accessor }).collect()
}

/// Record a sysvar use, keeping the accessor flag `false` once any
/// non-accessor reference has been seen.
fn record_sysvar_use(found: &mut HashMap<String, bool>, accessor_type: &str, is_accessor: bool) {
    found
        .entry(accessor_type.to_string())
        .and_modify(|accessor_only| {
            *accessor_only = *accessor_only && is_accessor;
        })
        .or_insert(is_accessor);
}

/// Render a field-access chain as a dotted string (`ctx.accounts`,
/// `ctx.accounts.clock`, ...). Returns `None` for non-path-like expressions.
fn expr_accounts_base(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => {
            let segments = path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
            Some(segments)
        }
        syn::Expr::Field(field) => {
            let base = expr_accounts_base(&field.base)?;
            let member = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            Some(format!("{base}.{member}"))
        }
        _ => None,
    }
}

fn scan_stmts_for_sysvar(stmts: &[syn::Stmt], found: &mut HashMap<String, bool>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => scan_expr_for_sysvar(expr, found),
            syn::Stmt::Local(local) => {
                if let Some(ref init) = local.init {
                    scan_expr_for_sysvar(&init.expr, found);
                }
            }
            _ => {}
        }
    }
}

fn scan_expr_for_sysvar(expr: &syn::Expr, found: &mut HashMap<String, bool>) {
    match expr {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if method == "get" || method == "get_or_create_account" {
                let receiver = expr_to_string_expr(&mc.receiver);
                for sysvar in KNOWN_SYSVARS {
                    if receiver == sysvar.accessor_type || receiver.ends_with(&format!("::{}", sysvar.accessor_type)) {
                        record_sysvar_use(found, sysvar.accessor_type, true);
                    }
                }
            }
            scan_expr_for_sysvar(&mc.receiver, found);
        }
        syn::Expr::Block(be) => scan_stmts_for_sysvar(&be.block.stmts, found),
        syn::Expr::If(ei) => {
            scan_expr_for_sysvar(&ei.cond, found);
            scan_stmts_for_sysvar(&ei.then_branch.stmts, found);
            if let Some((_, else_branch)) = &ei.else_branch {
                scan_expr_for_sysvar(else_branch, found);
            }
        }
        syn::Expr::Match(em) => {
            for arm in &em.arms {
                scan_expr_for_sysvar(&arm.body, found);
            }
        }
        syn::Expr::Try(et) => scan_expr_for_sysvar(&et.expr, found),
        syn::Expr::Call(ec) => {
            // `Clock::get()` parses as a call of the path `Clock::get`, not as a
            // method call — inspect the callee path as well as the arguments.
            if let syn::Expr::Path(path) = &*ec.func {
                let name = path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
                for sysvar in KNOWN_SYSVARS {
                    let get_call = format!("{}::get", sysvar.accessor_type);
                    let get_or_create_call = format!("{}::get_or_create_account", sysvar.accessor_type);
                    if name == get_call
                        || name == get_or_create_call
                        || name.ends_with(&format!("::{get_call}"))
                        || name.ends_with(&format!("::{get_or_create_call}"))
                    {
                        record_sysvar_use(found, sysvar.accessor_type, true);
                    }
                }
            }
            for arg in &ec.args {
                scan_expr_for_sysvar(arg, found);
            }
        }
        syn::Expr::Let(el) => scan_expr_for_sysvar(&el.expr, found),
        syn::Expr::Field(ef) => {
            // A non-accessor reference to a sysvar account field
            // (`ctx.accounts.clock`, `&ctx.accounts.clock`, ...) requires a
            // declared `clock` field in the Accounts struct — a genuine Anchor
            // failure when undeclared. Only the direct
            // `<...>.accounts.<sysvar>` shape is matched; a nested field such
            // as `ctx.accounts.config.clock` reads a custom account's data and
            // needs no sysvar.
            if let Some(base_str) = expr_accounts_base(&ef.base)
                && (base_str == "accounts" || base_str.ends_with(".accounts"))
                && let syn::Member::Named(member) = &ef.member
            {
                let member_name = member.to_string();
                if let Some(sysvar) = KNOWN_SYSVARS.iter().find(|s| s.name == member_name) {
                    record_sysvar_use(found, sysvar.accessor_type, false);
                }
            }
            scan_expr_for_sysvar(&ef.base, found);
        }
        syn::Expr::Reference(er) => scan_expr_for_sysvar(&er.expr, found),
        syn::Expr::Array(arr) => {
            for elem in &arr.elems {
                scan_expr_for_sysvar(elem, found);
            }
        }
        syn::Expr::Paren(ep) => scan_expr_for_sysvar(&ep.expr, found),
        _ => {}
    }
}

/// Scan `#[account(...)]` constraint attributes on `#[derive(Accounts)]`
/// struct fields for sysvar references.
///
/// `Clock::get()` inside a constraint (e.g. a seeds expression, as emitted by
/// Anchor's own generated code) is an accessor call and needs no declared
/// field; any other reference (e.g. a bare `clock` in a `constraint` /
/// `has_one` expression) names an Accounts-struct field and is a genuine
/// Anchor failure when undeclared.
fn scan_account_attrs_for_sysvar(
    item: &syn::Item,
    used_in: &mut HashMap<String, Vec<String>>,
    non_accessor: &mut HashSet<String>,
) {
    let syn::Item::Struct(item_struct) = item else { return };
    if !has_accounts_derive(item_struct) {
        return;
    }
    let owner = item_struct.ident.to_string();
    for field in &item_struct.fields {
        for attr in &field.attrs {
            if !attr.path().is_ident("account") {
                continue;
            }
            let Ok(list) = attr.meta.require_list() else { continue };
            scan_attr_tokens(list.tokens.clone(), &owner, used_in, non_accessor);
        }
    }
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

fn scan_attr_tokens(
    tokens: proc_macro2::TokenStream,
    owner: &str,
    used_in: &mut HashMap<String, Vec<String>>,
    non_accessor: &mut HashSet<String>,
) {
    let mut iter = tokens.into_iter();
    while let Some(tt) = iter.next() {
        match tt {
            proc_macro2::TokenTree::Ident(ident) => {
                let ident_str = ident.to_string();
                for sysvar in KNOWN_SYSVARS {
                    if ident_str == sysvar.accessor_type {
                        // Accessor-call shape: `<Type> :: get[_or_create_account]`.
                        let mut look = iter.clone();
                        let is_accessor = matches!(
                            (look.next(), look.next(), look.next()),
                            (
                                Some(proc_macro2::TokenTree::Punct(p1)),
                                Some(proc_macro2::TokenTree::Punct(p2)),
                                Some(proc_macro2::TokenTree::Ident(fn_ident)),
                            ) if p1.as_char() == ':' && p2.as_char() == ':'
                                && (fn_ident == "get" || fn_ident == "get_or_create_account")
                        );
                        record_attr_use(owner, sysvar.accessor_type, is_accessor, used_in, non_accessor);
                        break;
                    }
                    if ident_str == sysvar.name {
                        // A bare sysvar name in a constraint refers to an
                        // Accounts-struct field, never an accessor call.
                        record_attr_use(owner, sysvar.accessor_type, false, used_in, non_accessor);
                        break;
                    }
                }
            }
            proc_macro2::TokenTree::Group(group) => {
                scan_attr_tokens(group.stream(), owner, used_in, non_accessor);
            }
            _ => {}
        }
    }
}

fn record_attr_use(
    owner: &str,
    accessor_type: &str,
    is_accessor: bool,
    used_in: &mut HashMap<String, Vec<String>>,
    non_accessor: &mut HashSet<String>,
) {
    used_in.entry(accessor_type.to_string()).or_default().push(owner.to_string());
    if !is_accessor {
        non_accessor.insert(accessor_type.to_string());
    }
}
