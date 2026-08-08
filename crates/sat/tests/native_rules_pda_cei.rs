//! R2 slice tests: SAT022 (PDA seed derivation mismatch) and SAT023 (state
//! write after CPI) for native programs, exercised via `pda_cei::check`
//! directly on the pinned model + parsed files.
//!
//! `crates/sat/src/native/rules/mod.rs` is owned by the integration slice and
//! does not wire `pda_cei` in yet, so this test crate includes the rule file
//! itself with `#[path]` and bridges the `crate::native` / `crate::types`
//! paths it uses. Once the integration slice lands `pub mod pda_cei;` in
//! `rules/mod.rs`, this shim can be dropped in favor of
//! `sat::native::rules::pda_cei::check`.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{NativeInstruction, NativeProgram};
    }
}

#[path = "../src/native/rules/pda_cei.rs"]
mod pda_cei;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT022: &str = "Seed Derivation Mismatch:";
const SAT023: &str = "State Write After CPI:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/pda_cei/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the PDA/CEI rules.
fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = pda_cei::check(&program, &files);
    (program, findings)
}

fn run_fixture(name: &str) -> (NativeProgram, Vec<Finding>) {
    run(&fixture_source(name))
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

fn by_rule_account<'a>(findings: &'a [Finding], prefix: &str, account: &str) -> Vec<&'a Finding> {
    let ticked = format!("`{account}`");
    findings.iter().filter(|f| f.title.starts_with(prefix) && f.title.contains(&ticked)).collect()
}

fn account<'a>(ix: &'a sat::native::model::NativeInstruction, name: &str) -> &'a sat::native::model::ResolvedAccount {
    ix.accounts
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("account `{name}` not resolved (have: {:?})", ix.accounts))
}

/// 1-based line of the first source line containing `needle`.
fn line_of(source: &str, needle: &str) -> usize {
    source.lines().position(|l| l.contains(needle)).map(|i| i + 1).unwrap_or(0)
}

// ── Model sanity: guards against vacuous rule tests ─────────────────────────

#[test]
fn vuln_fixture_resolves_pda_and_written_flags() {
    let (program, _) = run_fixture("vuln.rs");
    assert_eq!(program.instructions.len(), 1);
    let ix = &program.instructions[0];
    assert_eq!(ix.name, "process_instruction");

    let escrow = account(ix, "escrow");
    assert!(escrow.is_pda, "vuln: escrow is a PDA");
    assert_eq!(
        escrow.seeds,
        vec!["b\"escrow\"".to_string(), "owner.key()".to_string()],
        "vuln: find_program_address seeds recorded as source text"
    );

    let state = account(ix, "state");
    assert!(state.written, "vuln: state is written after the CPI");
    assert!(!account(ix, "vault").written && !account(ix, "token_program").written);
}

#[test]
fn clean_fixture_resolves_pda_and_written_flags() {
    let (program, _) = run_fixture("clean.rs");
    assert_eq!(program.instructions.len(), 1);
    let ix = &program.instructions[0];

    assert!(account(ix, "escrow").is_pda, "clean: escrow is a PDA");
    assert_eq!(account(ix, "escrow").seeds, vec!["b\"escrow\"".to_string(), "owner.key()".to_string()]);
    assert!(account(ix, "state").written, "clean: state is written (before the CPI)");
}

// ── Rule firing on the vulnerable fixture ───────────────────────────────────

#[test]
fn vuln_yields_sat022_and_sat023_findings() {
    let (_, findings) = run_fixture("vuln.rs");
    assert_eq!(by_rule(&findings, SAT022).len(), 1, "SAT022 fires for the mismatched PDA");
    assert_eq!(by_rule(&findings, SAT023).len(), 1, "SAT023 fires for the write after the CPI");
    assert_eq!(findings.len(), 2, "no duplicate (rule, instruction, account) pairs: {findings:?}");
}

#[test]
fn vuln_findings_target_the_expected_accounts() {
    let (_, findings) = run_fixture("vuln.rs");
    assert_eq!(by_rule_account(&findings, SAT022, "escrow").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT023, "state").len(), 1);
}

#[test]
fn vuln_findings_are_high_severity_with_shaped_locations() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    let sat022_loc = format!("test.rs:{} (process_instruction)", line_of(&source, "invoke_signed("));
    let sat023_loc =
        format!("test.rs:{} (process_instruction)", line_of(&source, "let mut data = state.data.borrow_mut();"));

    assert!(!findings.is_empty());
    for f in &findings {
        assert_eq!(f.severity, Severity::High, "spec section 7: both rules are High — got {}", f.title);
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(!f.description.is_empty(), "description: what, why, exploit sketch");
        assert!(f.suggestion.is_some(), "suggestion: how to fix");
    }
    let sat022 = by_rule(&findings, SAT022)[0];
    assert_eq!(sat022.location.as_deref(), Some(sat022_loc.as_str()), "SAT022 at the invoke_signed call site");
    assert!(
        sat022.description.contains("[b\"escrow\", owner.key()]") && sat022.description.contains("other.key()"),
        "SAT022 description reports both seed lists: {}",
        sat022.description
    );
    let sat023 = by_rule(&findings, SAT023)[0];
    assert_eq!(sat023.location.as_deref(), Some(sat023_loc.as_str()), "SAT023 at the write statement");
}

#[test]
fn vuln_findings_use_only_the_two_rule_prefixes() {
    let (_, findings) = run_fixture("vuln.rs");
    for f in &findings {
        assert!(f.title.starts_with(SAT022) || f.title.starts_with(SAT023), "unexpected title prefix: {}", f.title);
    }
}

// ── Clean fixture ───────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_pda_cei_findings() {
    let (_, findings) = run_fixture("clean.rs");
    assert!(findings.is_empty(), "clean.rs must produce zero findings: {findings:?}");
}

// ── FP filters (inline sources) ─────────────────────────────────────────────

/// SAT022: a trailing `&[bump]` signer element is the returned bump, not a
/// seed difference.
#[test]
fn bump_only_difference_is_not_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            program_error::ProgramError,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let escrow = next_account_info(accounts_iter)?;
            let vault = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;

            let (pda, bump) = Pubkey::find_program_address(&[b"escrow"], program_id);
            if escrow.key != &pda {
                return Err(ProgramError::InvalidSeeds);
            }
            let transfer_ix = spl_token::instruction::transfer(
                token_program.key, vault.key, escrow.key, escrow.key, &[], 100,
            )?;
            invoke_signed(
                &transfer_ix,
                &[vault.clone(), escrow.clone(), token_program.clone()],
                &[&[b"escrow", &[bump]]],
            )?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

/// SAT022 FP filter: no `invoke_signed` seeds visible in the handler.
#[test]
fn handler_without_invoke_signed_is_not_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            program_error::ProgramError,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let escrow = next_account_info(accounts_iter)?;
            let owner = next_account_info(accounts_iter)?;

            let (pda, _bump) = Pubkey::find_program_address(&[b"escrow", owner.key()], program_id);
            if escrow.key != &pda {
                return Err(ProgramError::InvalidSeeds);
            }
            msg!("no CPI in this instruction: {}", escrow.key);
            Ok(())
        }
    "#;
    let (program, findings) = run(src);
    assert!(program.instructions[0].accounts[0].is_pda, "frontend must still resolve the PDA");
    assert!(findings.is_empty(), "{findings:?}");
}

/// SAT022: seeds passed through a variable are not visible — skipped, never
/// flagged.
#[test]
fn variable_seeds_call_site_is_skipped() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            program_error::ProgramError,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let escrow = next_account_info(accounts_iter)?;
            let vault = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;

            let (pda, bump) = Pubkey::find_program_address(&[b"escrow"], program_id);
            if escrow.key != &pda {
                return Err(ProgramError::InvalidSeeds);
            }
            let signer_seeds = [&[b"escrow"][..], &[bump]];
            let transfer_ix = spl_token::instruction::transfer(
                token_program.key, vault.key, escrow.key, escrow.key, &[], 100,
            )?;
            invoke_signed(
                &transfer_ix,
                &[vault.clone(), escrow.clone(), token_program.clone()],
                &[signer_seeds],
            )?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

/// SAT023 FP filter: the account is closed (`realloc(0)`) between the call
/// and the write — the write touches fresh state.
#[test]
fn state_closed_between_cpi_and_write_is_not_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let vault = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;

            let transfer_ix = spl_token::instruction::transfer(
                token_program.key, vault.key, state.key, state.key, &[], 100,
            )?;
            invoke(
                &transfer_ix,
                &[vault.clone(), state.clone(), token_program.clone()],
            )?;

            // Close the state account after the call, then write to the
            // re-created one: nothing leaks to the CPI.
            state.realloc(0, false)?;
            state.realloc(1, false)?;
            let mut data = state.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

/// SAT023 branch isolation: a CPI inside an `if` branch must not leak to
/// statements that follow the `if`.
#[test]
fn cpi_inside_branch_does_not_leak_to_following_writes() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let vault = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;

            if instruction_data[0] == 1 {
                let transfer_ix = spl_token::instruction::transfer(
                    token_program.key, vault.key, state.key, state.key, &[], 100,
                )?;
                invoke(
                    &transfer_ix,
                    &[vault.clone(), state.clone(), token_program.clone()],
                )?;
            }

            // The branch may not have run — this write is not unconditionally
            // after a CPI.
            let mut data = state.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

/// SAT023 does fire for a write inside a branch that itself follows the CPI
/// in the same branch (sequential order inside the branch is still checked).
#[test]
fn write_inside_branch_after_cpi_is_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let vault = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;

            if instruction_data[0] == 1 {
                let transfer_ix = spl_token::instruction::transfer(
                    token_program.key, vault.key, state.key, state.key, &[], 100,
                )?;
                invoke(
                    &transfer_ix,
                    &[vault.clone(), state.clone(), token_program.clone()],
                )?;
                let mut data = state.data.borrow_mut();
                data[0] = 1;
            }
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT023), "{}", findings[0].title);
    assert_eq!(findings[0].severity, Severity::High);
}
