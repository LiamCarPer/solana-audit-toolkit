//! R1 slice: authentication rules SAT019, SAT020 and SAT021.
//!
//! These rules target the missing-auth class of native Solana exploits (the
//! Amulet/Cypher incidents in `EXPLOIT_CORPUS.md`): privileged accounts used
//! without verifying their signature, their owner, or their expected key.
//!
//! The frontend model (`crate::native::model`) pre-resolves, per account and
//! per instruction, whether a signer guard, an owner-equality guard, or a
//! key-equality guard is reachable in the handler body or its helper call
//! graph (depth ≤ 2). These checks only consume that resolved model; they do
//! not re-read the syntax trees. Order-sensitivity of guards and
//! cross-instruction reasoning are documented approximations (see
//! `docs/NATIVE_BACKEND.md` section 6) — manual steps cover them.
//!
//! Title prefixes are load-bearing for SARIF classification (section 7);
//! do not rename them.

use crate::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
use crate::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT019_TITLE: &str = "Unverified Signer Account:";
const SAT020_TITLE: &str = "Unverified Owner Account:";
const SAT021_TITLE: &str = "Unchecked Authority Key:";

/// Whether the account name marks it as privileged. Mirrors the Anchor
/// backend's `check_missing_signer` name list plus the spec's suffix rules
/// (`_authority`/`_admin`/`_owner`/`_signer`).
fn is_authority_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXACT: [&str; 12] = [
        "authority",
        "owner",
        "admin",
        "payer",
        "creator",
        "manager",
        "operator",
        "governor",
        "signer",
        "upgrade_authority",
        "mint_authority",
        "freeze_authority",
    ];
    EXACT.contains(&lower.as_str())
        || lower.ends_with("_authority")
        || lower.ends_with("_admin")
        || lower.ends_with("_owner")
        || lower.ends_with("_signer")
}

/// Builtin accounts whose identity is fixed by the runtime; owner checks are
/// meaningless for them and would only produce false positives.
fn is_builtin(kind: AccountKind) -> bool {
    matches!(kind, AccountKind::Sysvar | AccountKind::Program | AccountKind::SystemProgram)
}

/// `"{file}:{line} ({instruction_name})"` — same shape as the Anchor backend.
fn location(ix: &NativeInstruction) -> String {
    let file = ix.file.as_str();
    let name = ix.name.as_str();
    format!("{file}:{} ({name})", ix.line)
}

/// SAT019: authority-named account used without any reachable `is_signer`
/// check. Skipped when the account is a `Signer` by construction (its
/// signature is guaranteed by the runtime) or when its key is pinned (fixed
/// key / PDA derivation makes the signer irrelevant).
fn sat019(ix: &NativeInstruction, account: &ResolvedAccount) -> Finding {
    let name = account.name.as_str();
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT019_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "The account `{name}` is used in instruction `{ix_name}` without any reachable \
             `is_signer` check. Its name identifies it as an authority, yet its signature is \
             never verified, so the runtime guarantees nothing about who supplied it. Exploit: \
             an attacker calls `{ix_name}` passing their own public key for `{name}` and the \
             victim's data accounts; every privileged transition gated on this account \
             (withdrawals, ownership changes, minting) is then authorized under the attacker's \
             identity."
        ),
        location: Some(location(ix)),
        suggestion: Some(format!(
            "Verify the signature before using the account, e.g. \
             `if !{name}.is_signer {{ return Err(ProgramError::MissingRequiredSignature); }}`, \
             or pin the account to a fixed key / PDA derivation."
        )),
    }
}

/// SAT020: stateful or written account whose owner is never verified and
/// whose key is not pinned. Skipped for runtime-builtin kinds (sysvars,
/// programs, system program).
fn sat020(ix: &NativeInstruction, account: &ResolvedAccount) -> Finding {
    let name = account.name.as_str();
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT020_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "The account `{name}` carries state or is written by instruction `{ix_name}` but is \
             never checked against the program's owner (`owner_checked = false`) and its key is \
             not pinned (`key_checked = false`). Any account owned by any program can be passed \
             here, so data the program treats as its own state can be substituted with an \
             attacker-crafted account owned by a malicious program. Exploit: supply a look-alike \
             account owned by a program the attacker controls, with forged data, and the \
             program's discriminator/state checks operate on attacker-controlled bytes."
        ),
        location: Some(location(ix)),
        suggestion: Some(format!(
            "Add an owner check before reading or writing the account, e.g. \
             `if {name}.owner != program_id {{ return Err(ProgramError::IllegalOwner); }}`."
        )),
    }
}

/// SAT021: authority-named account that is never compared to a stored/derived
/// key and is not signer-checked either, so the program cannot tell the real
/// authority apart from an arbitrary caller-supplied public key.
fn sat021(ix: &NativeInstruction, account: &ResolvedAccount) -> Finding {
    let name = account.name.as_str();
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT021_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "The authority-named account `{name}` is used in instruction `{ix_name}` without \
             ever being compared to a stored or derived key (`key_checked = false`) and without \
             a signer check (`is_signer_checked = false`). Access control based on \"is this \
             the authority account?\" therefore degenerates to \"is this any account?\". \
             Exploit: pass any public key the program will accept for `{name}` and inherit the \
             authority role the account's name implies."
        ),
        location: Some(location(ix)),
        suggestion: Some(format!(
            "Compare the account key against the expected value before use, e.g. \
             `if {name}.key != expected_authority {{ return Err(ProgramError::InvalidAccountData); }}`, \
             or derive it with `find_program_address` and compare; alternatively require \
             `{name}.is_signer`."
        )),
    }
}

/// Run SAT019/SAT020/SAT021 over every instruction of `program`.
///
/// At most one finding per (rule, instruction, account): deduplication is
/// inherent to the iteration, and findings are never merged across
/// instructions even when they refer to the same account name.
pub fn check(program: &NativeProgram, _parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ix in &program.instructions {
        for account in &ix.accounts {
            let authority_named = is_authority_named(&account.name);
            let stateful = matches!(account.kind, AccountKind::State | AccountKind::TokenAccount | AccountKind::Mint);

            // SAT019: authority-named, signature never verified, not a
            // `Signer` by construction, key not pinned.
            if authority_named
                && !account.is_signer_checked
                && account.kind != AccountKind::Signer
                && !account.key_checked
            {
                findings.push(sat019(ix, account));
            }

            // SAT020: stateful or written account, owner never verified, key
            // not pinned, not a runtime builtin.
            if !is_builtin(account.kind)
                && (stateful || account.written)
                && !account.owner_checked
                && !account.key_checked
            {
                findings.push(sat020(ix, account));
            }

            // SAT021: authority-named, key never compared, signature never
            // verified.
            if authority_named && !account.key_checked && !account.is_signer_checked {
                findings.push(sat021(ix, account));
            }
        }
    }
    findings
}
