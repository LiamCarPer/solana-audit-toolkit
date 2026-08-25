//! Known external-crate validator recognition.
//!
//! Production Solana programs delegate validation to external-crate helpers
//! (`load_signer`, `check_admin`, `Ncn::load`, …) that perform signer, owner,
//! and authority checks behind an abstraction layer. Static analysis cannot
//! see through these calls — but the checks ARE there. This module provides a
//! registry of known validation function patterns so the rule slices can
//! suppress findings when recognized validators are present.
//!
//! Design: each [`KnownValidator`] maps callee last-segment patterns to
//! argument positions holding the validated account. Resolution is
//! conservative: only exact function-name matches are recognized (no fuzzy
//! matching), and argument indices map positionally to resolved accounts.
//!
//! This is NOT a comprehensive list. Programs with custom validation wrappers
//! not listed here will still produce FPs — that's a documented limitation.
//! Adding new entries requires knowing the external crate's API.

use std::collections::HashSet;

use syn::Expr;

use crate::native::model::NativeInstruction;

/// What kind of proof a known-validator call provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationKind {
    /// The account signed the transaction.
    Signer,
    /// The account is owned by this program (PDA check).
    Owner,
    /// The caller matches a stored authority key.
    Authority,
    /// A valid SPL token account with matching mint/owner.
    TokenAccount,
    /// A known program or sysvar identity check.
    Builtin,
    /// A bound/threshold check on the value (staleness gate, pause check).
    BoundCheck,
}

/// A known external-crate validation function pattern.
struct KnownValidator {
    /// Last path segment(s) to match against the callee ident.
    names: &'static [&'static str],
    /// Which call-argument positions hold the validated accounts.
    arg_positions: &'static [usize],
    kind: ValidationKind,
}

/// Registry of known external-crate validation functions.
///
/// Sources: jito_jsm_core, jito_vault_sdk, anchor_lang loaders, and common
/// Solana ecosystem patterns. Extend as new crates are encountered.
static KNOWN_VALIDATORS: &[KnownValidator] = &[
    // ── jito_jsm_core::loader ────────────────────────────────────────────────
    KnownValidator { names: &["load_signer"], arg_positions: &[0], kind: ValidationKind::Signer },
    KnownValidator { names: &["load_signer_writable"], arg_positions: &[0], kind: ValidationKind::Signer },
    KnownValidator { names: &["load_token_mint"], arg_positions: &[0], kind: ValidationKind::TokenAccount },
    KnownValidator { names: &["load_token_account"], arg_positions: &[0], kind: ValidationKind::TokenAccount },
    KnownValidator {
        names: &["load_associated_token_account"],
        arg_positions: &[0],
        kind: ValidationKind::TokenAccount,
    },
    KnownValidator {
        names: &["load_token_program", "load_system_program"],
        arg_positions: &[0],
        kind: ValidationKind::Builtin,
    },
    // ── jito_bytemuck / program-specific loaders (XxxAccount::load) ────────
    KnownValidator { names: &["load"], arg_positions: &[1], kind: ValidationKind::Owner },
    // ── authority / admin checks (method calls on account structs) ──────────
    KnownValidator {
        names: &["check_admin", "check_delegate_admin", "check_slasher_admin", "check_owner", "check_secondary_admin"],
        arg_positions: &[0],
        kind: ValidationKind::Authority,
    },
    // ── bound / threshold / state checks ────────────────────────────────────
    KnownValidator {
        names: &[
            "check_update_state_ok",
            "check_is_paused",
            "check_vrt_mint",
            "check_reward_fee_effective_rate",
            "check_mint_burn_admin",
        ],
        arg_positions: &[],
        kind: ValidationKind::BoundCheck,
    },
];

/// What a matched known-validator call proves about specific accounts.
pub struct ValidatedAccounts {
    pub kind: ValidationKind,
    pub account_indices: Vec<usize>,
}

/// Scans a call expression for known-validator matches. Returns the validated
/// accounts when the callee matches a known pattern.
fn match_known_validator(
    callee: &str,
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    ix: &NativeInstruction,
) -> Option<ValidatedAccounts> {
    for kv in KNOWN_VALIDATORS {
        if kv.names.contains(&callee) && !kv.arg_positions.is_empty() {
            let mut account_indices = Vec::new();
            for pos in kv.arg_positions {
                if let Some(arg) = args.get(*pos) {
                    resolve_arg_accounts(arg, ix, &mut account_indices);
                }
            }
            if !account_indices.is_empty() {
                return Some(ValidatedAccounts { kind: kv.kind, account_indices });
            }
        }
        // Zero-arg validators (BoundCheck) still count as validation gates.
        if kv.names.contains(&callee) && kv.arg_positions.is_empty() {
            return Some(ValidatedAccounts { kind: kv.kind, account_indices: vec![] });
        }
    }
    None
}

/// Resolve an expression to account indices (direct idents, receiver chains).
fn resolve_arg_accounts(e: &Expr, ix: &NativeInstruction, out: &mut Vec<usize>) {
    match e {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                let ident = ident.to_string();
                if let Some(idx) = ix.accounts.iter().position(|a| a.name == ident) {
                    out.push(idx);
                }
            }
        }
        Expr::Field(f) => resolve_arg_accounts(&f.base, ix, out),
        Expr::Reference(r) => resolve_arg_accounts(&r.expr, ix, out),
        Expr::Paren(p) => resolve_arg_accounts(&p.expr, ix, out),
        Expr::Group(g) => resolve_arg_accounts(&g.expr, ix, out),
        _ => {}
    }
}

/// Scan all expressions in a block for known-validator calls. Returns every
/// `(kind, account_index)` pair proven by recognized validation calls.
pub fn scan_known_validators(blocks: &[&syn::Block], ix: &NativeInstruction) -> HashSet<(ValidationKind, usize)> {
    let mut out = HashSet::new();
    for block in blocks {
        scan_block_validators(block, ix, &mut out);
    }
    out
}

fn scan_block_validators(block: &syn::Block, ix: &NativeInstruction, out: &mut HashSet<(ValidationKind, usize)>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => scan_validator_expr(e, ix, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    scan_validator_expr(&init.expr, ix, out);
                }
            }
            syn::Stmt::Macro(m) => {
                for arg in macro_args(&m.mac) {
                    scan_validator_expr(&arg, ix, out);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn scan_validator_expr(e: &Expr, ix: &NativeInstruction, out: &mut HashSet<(ValidationKind, usize)>) {
    match e {
        Expr::Call(c) => {
            let callee = match &*c.func {
                syn::Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                _ => String::new(),
            };
            if let Some(validated) = match_known_validator(&callee, &c.args, ix) {
                for idx in &validated.account_indices {
                    out.insert((validated.kind, *idx));
                }
            }
            for arg in &c.args {
                scan_validator_expr(arg, ix, out);
            }
        }
        Expr::MethodCall(m) => {
            let name = m.method.to_string();
            for kv in KNOWN_VALIDATORS {
                if kv.names.contains(&name.as_str()) && !kv.arg_positions.is_empty() {
                    // Method-call validators: the RECEIVER is the validated
                    // account (e.g. `ncn.check_admin(key)` → ncn).
                    if let Some(acc_idx) = resolve_receiver_account(&m.receiver, ix) {
                        out.insert((kv.kind, acc_idx));
                    }
                }
            }
            scan_validator_expr(&m.receiver, ix, out);
            for arg in &m.args {
                scan_validator_expr(arg, ix, out);
            }
        }
        Expr::Binary(b) => {
            scan_validator_expr(&b.left, ix, out);
            scan_validator_expr(&b.right, ix, out);
        }
        Expr::Unary(u) => scan_validator_expr(&u.expr, ix, out),
        Expr::Reference(r) => scan_validator_expr(&r.expr, ix, out),
        Expr::Paren(p) => scan_validator_expr(&p.expr, ix, out),
        Expr::Group(g) => scan_validator_expr(&g.expr, ix, out),
        Expr::Try(t) => scan_validator_expr(&t.expr, ix, out),
        Expr::If(i) => {
            scan_validator_expr(&i.cond, ix, out);
            scan_block_validators(&i.then_branch, ix, out);
            if let Some((_, else_expr)) = &i.else_branch {
                scan_validator_expr(else_expr, ix, out);
            }
        }
        Expr::Block(b) => scan_block_validators(&b.block, ix, out),
        _ => {}
    }
}

/// Resolve a method-call receiver chain root to an account index.
fn resolve_receiver_account(receiver: &Expr, ix: &NativeInstruction) -> Option<usize> {
    let mut cur = receiver;
    loop {
        match cur {
            Expr::Path(p) => {
                let ident = p.path.get_ident()?.to_string();
                return ix.accounts.iter().position(|a| a.name == ident);
            }
            Expr::Field(f) => cur = &f.base,
            Expr::Reference(r) => cur = &r.expr,
            Expr::Paren(p) => cur = &p.expr,
            Expr::Group(g) => cur = &g.expr,
            Expr::MethodCall(m) => cur = &m.receiver,
            _ => return None,
        }
    }
}

fn macro_args(mac: &syn::Macro) -> Vec<syn::Expr> {
    use syn::parse::Parser;
    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
        .parse2(mac.tokens.clone())
        .map(|args| args.into_iter().collect())
        .unwrap_or_default()
}
