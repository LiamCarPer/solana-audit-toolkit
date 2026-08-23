//! R9 slice tests: SAT039 — Accounting Drift, exercised through the public
//! `sat::accounting` module against the parsed files from
//! `sat::native::analyze_source_and_files_for_test`.

use sat::accounting;

use sat::native::model::NativeProgram;
use sat::types::Finding;

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT039: &str = "Accounting Drift:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/accounting/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = accounting::check(&program, &files);
    (program, findings)
}

// ── Model sanity ─────────────────────────────────────────────────────────────

#[test]
fn vuln_fixture_resolves_accounts() {
    let (program, _) = run(&fixture_source("vuln.rs"));
    assert!(!program.instructions.is_empty(), "native program must resolve");
    for name in ["user_token_account", "vault_token_account", "state"] {
        assert!(program.instructions[0].accounts.iter().any(|a| a.name == name), "account `{name}` must resolve");
    }
}

// ── Finding shape ────────────────────────────────────────────────────────────

#[test]
fn vuln_fixture_fires_accounting_drift() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    assert!(!findings.is_empty(), "drift shapes must fire: {findings:#?}");
    for f in &findings {
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(f.title.starts_with(SAT039), "{}", f.title);
        assert!(!f.description.is_empty());
        assert!(f.suggestion.is_some());
    }
}

#[test]
fn stale_balance_shape_fires_medium() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    let dest = next_account_info(accounts_iter)?;

    let balance_before = u64::from_le_bytes(vault.data.borrow()[64..72].try_into().unwrap());

    token_transfer(vault, dest, 100)?;

    msg!("previous balance was {}", balance_before);
    Ok(())
}

fn token_transfer(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    msg!("moving {}", amount);
    Ok(())
}
"#;
    let (_, findings) = run(source);
    let flagged =
        findings.iter().filter(|f| f.title.contains("stale") || f.description.contains("never re-read")).count();
    assert!(flagged >= 1, "stale-balance shape must fire Medium: {findings:#?}");
}

// ── Clean gate ───────────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_drift_findings() {
    let (_, findings) = run(&fixture_source("clean.rs"));
    assert!(findings.is_empty(), "post-CPI re-read must not fire: {findings:#?}");
}

// ── FP filters (inline sources) ──────────────────────────────────────────────

/// No token CPI → no drift analysis at all.
#[test]
fn no_token_cpi_no_findings() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;

    let balance_before = u64::from_le_bytes(vault.data.borrow()[64..72].try_into().unwrap());
    msg!("balance {}", balance_before);
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "no CPI means no drift: {findings:#?}");
}
