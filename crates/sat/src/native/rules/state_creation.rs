//! R6 slice: SAT032 — Permissionless State Creation.
//!
//! The second half of the Cashio story: `bankman::new_bank` is permissionless.
//! Any caller can create a bank account and record *unverified* authority
//! keys (`admin`, `brrr_issue_authority`, `burn_withdraw_authority`) as the
//! bank's curators — the "false bank" that made the fabricated validation
//! chain possible. The authority slots are `UncheckedAccount` fields with
//! `CHECK:` doc comments, so the SAT001/002 missing-signer/owner checks
//! downgrade them to LOW; the *permissionless-creation* angle is the bug
//! itself, which is what this rule targets.
//!
//! Detection (Anchor path only): an instruction whose Accounts struct has at
//! least one `#[account(init ...)]`/`#[account(init_if_needed ...)]` field
//! (it CREATES state) and an authority-named slot that is neither
//! `Signer<'info>`-typed nor `#[account(signer)]`-constrained. Unlike
//! SAT001/002, a `CHECK:` doc comment does NOT suppress the finding: the
//! documented manual validation cannot help when the recorded authority is a
//! caller-chosen key and the state is created permissionlessly.
//!
//! Two standard Anchor patterns are NOT caller-chosen and therefore do not
//! fire, even when the slot is authority-named and unsigner-pinned:
//! - `#[account(seeds = [...], bump = ...)]` slots are program-derived
//!   addresses: the program fully determines the recorded key (the Marinade
//!   `stake_deposit_authority` / `stake_withdraw_authority` class).
//! - the `init` + `payer = <Signer>` + `system_program` wiring (the payer is
//!   signer-pinned and only pays rent; the created state does not record it
//!   as an authority).
//!
//! Findings are leads: a legitimate open-registration contract (staking
//! vaults, protocol registries) may intentionally accept caller-chosen
//! authorities — confirm whether any privileged transition depends on the
//! recorded key before escalating.
//!
//! Title prefixes are load-bearing for SARIF classification (section 7 of
//! `docs/NATIVE_BACKEND.md`); do not rename them.

use syn::punctuated::Punctuated;

use crate::native::model::NativeProgram;
use crate::native::rules::validate::{StructIndex, anchor_instructions, has_anchor_program};
use crate::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT032_TITLE: &str = "Permissionless State Creation:";

/// Authority-named slot heuristics (mirrors the Anchor backend's list plus
/// the Cashio `new_bank` shapes: the recorded `admin` and crate authorities).
/// `bank`/`curator` are deliberately NOT in the list: the created state
/// account is often itself named `bank` (Cashio's `Bank`), and the recorded
/// authority slot is the `admin`-style field.
fn is_authority_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXACT: &[&str] = &[
        "authority",
        "admin",
        "owner",
        "payer",
        "creator",
        "manager",
        "operator",
        "governor",
        "governance_authority",
        "vault_authority",
        "pool_admin",
        "controller",
        "principal",
    ];
    EXACT.contains(&lower.as_str())
        || lower.ends_with("_authority")
        || lower.ends_with("_admin")
        || lower.ends_with("_owner")
        || lower.ends_with("_signer")
}

/// Parses an `#[account(...)]` attribute's inner metas.
///
/// `#[account(mut, ...)]` opens with the `mut` keyword, which syn's `Meta`
/// parser rejects — the keyword (and its trailing comma) is filtered out so
/// the remaining metas (`init`, `seeds`, `signer`, ...) are readable
/// (Marinade writes `#[account(mut, init, ...)]`-style attributes).
fn account_metas(attrs: &[syn::Attribute]) -> Vec<syn::Meta> {
    let mut out = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }
        let syn::Meta::List(list) = &attr.meta else { continue };
        let tokens = strip_mut_meta_keyword(list.tokens.clone());
        if let Ok(metas) = syn::parse::Parser::parse2(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated, tokens)
        {
            out.extend(metas);
        }
    }
    out
}

/// Removes a leading `mut` keyword (and its separating comma) from an
/// `#[account(...)]` attribute's token stream so syn's `Meta` parser can
/// read the rest.
fn strip_mut_meta_keyword(tokens: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    let raw: Vec<proc_macro2::TokenTree> = tokens.into_iter().collect();
    let mut filtered = Vec::new();
    let mut drop_next_comma = false;
    for tt in raw {
        if matches!(&tt, proc_macro2::TokenTree::Ident(i) if i == "mut") {
            drop_next_comma = true;
            continue;
        }
        if drop_next_comma && matches!(&tt, proc_macro2::TokenTree::Punct(p) if p.as_char() == ',') {
            drop_next_comma = false;
            continue;
        }
        drop_next_comma = false;
        filtered.push(tt);
    }
    filtered.into_iter().collect()
}

/// Whether any `#[account(...)]` attribute contains an `init` or
/// `init_if_needed` meta (the field CREATES state).
fn field_creates_state(attrs: &[syn::Attribute]) -> bool {
    account_metas(attrs).iter().any(|meta| meta.path().is_ident("init") || meta.path().is_ident("init_if_needed"))
}

/// Whether the field is pinned as a signer by construction.
fn field_is_signer(attrs: &[syn::Attribute], type_ident: &str) -> bool {
    type_ident == "Signer" || account_metas(attrs).iter().any(|meta| meta.path().is_ident("signer"))
}

/// Whether the field is a program-derived address by construction
/// (`#[account(seeds = ..., bump = ...)]`). A PDA slot is NOT a caller-chosen
/// key: the program fully determines its address, so recording it in freshly
/// created state cannot forge a "false bank" (the Marinade
/// `stake_deposit_authority` class — the Cashio `admin` slots carry no
/// `seeds` and keep firing).
fn field_is_pda(attrs: &[syn::Attribute]) -> bool {
    account_metas(attrs).iter().any(|meta| meta.path().is_ident("seeds"))
}

/// SAT032: flag creation instructions that record unverified authority keys
/// into freshly created state. Anchor path only — native creation flows are
/// covered by SAT019/020/021.
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    if !program.instructions.is_empty() || !has_anchor_program(parsed) {
        return Vec::new();
    }

    let structs = StructIndex::build(parsed);
    let mut findings = Vec::new();

    for anchor in anchor_instructions(parsed) {
        let Some(fields) = structs.fields.get(&anchor.root_struct) else {
            continue;
        };
        let creates_state = fields.iter().any(|(_name, _ty, attrs)| field_creates_state(attrs));
        if !creates_state {
            continue;
        }

        for (name, type_ident, attrs) in fields {
            if !is_authority_named(name) || field_is_signer(attrs, type_ident) || field_is_pda(attrs) {
                continue;
            }
            findings.push(Finding {
                id: String::new(),
                title: format!("{SAT032_TITLE} `{name}`"),
                severity: Severity::High,
                description: format!(
                    "Instruction `{}` creates state (an `#[account(init ...)]` field) and records the \
                     caller-chosen key `{name}` as an authority without requiring its signature. \
                     Anyone can therefore create a fully legitimate-looking state account carrying \
                     their own authority key — the permissionless false-bank pattern from the Cashio \
                     exploit (EXPLOIT_CORPUS.md), where `new_bank` recorded unverified `admin`/`bank` \
                     keys. A `CHECK:` comment does not help here: the documented manual validation \
                     cannot pin a caller-chosen key. Confirm whether any privileged transition depends \
                     on the recorded key before escalating.",
                    anchor.name
                ),
                location: Some(format!("{}:{} ({})", anchor.file, anchor.line, anchor.name)),
                suggestion: Some(format!(
                    "Make `{name}` a `Signer<'info>` (or add `#[account(signer)]`) on the creation \
                     instruction, or pin it to a fixed key / program-derived address."
                )),
            });
        }
    }

    findings
}
