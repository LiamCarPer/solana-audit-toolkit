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

pub(crate) fn check_sysvar_misuse(parsed_files: &[(syn::File, String)], accounts: &[AccountsStruct]) -> Vec<Finding> {
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

    for (file, _file_path) in parsed_files {
        for item in &file.items {
            let functions = find_functions_with_sysvar_calls(item);
            for (fn_name, sysvars) in functions {
                for sv in sysvars {
                    sysvar_used_in_body.entry(sv).or_default().push(fn_name.clone());
                }
            }
        }
    }

    for sysvar in KNOWN_SYSVARS {
        if let Some(used_in) = sysvar_used_in_body.get(sysvar.accessor_type)
            && !sysvar_declared.contains_key(sysvar.accessor_type)
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

fn find_functions_with_sysvar_calls(item: &syn::Item) -> Vec<(String, Vec<String>)> {
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

fn scan_for_sysvar_calls(block: &syn::Block) -> Vec<String> {
    let mut found = HashSet::new();
    scan_stmts_for_sysvar(&block.stmts, &mut found);
    found.into_iter().collect()
}

fn scan_stmts_for_sysvar(stmts: &[syn::Stmt], found: &mut HashSet<String>) {
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

fn scan_expr_for_sysvar(expr: &syn::Expr, found: &mut HashSet<String>) {
    match expr {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if method == "get" || method == "get_or_create_account" {
                let receiver = expr_to_string_expr(&mc.receiver);
                for sysvar in KNOWN_SYSVARS {
                    if receiver == sysvar.accessor_type || receiver.ends_with(&format!("::{}", sysvar.accessor_type)) {
                        found.insert(sysvar.accessor_type.to_string());
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
            for arg in &ec.args {
                scan_expr_for_sysvar(arg, found);
            }
        }
        syn::Expr::Let(el) => scan_expr_for_sysvar(&el.expr, found),
        _ => {}
    }
}
