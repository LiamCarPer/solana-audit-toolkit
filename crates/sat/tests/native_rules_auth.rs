//! R1 slice tests: SAT019 / SAT020 / SAT021 — authentication rules for native
//! programs, exercised via `auth::check` directly on the pinned model.
//!
//! `crates/sat/src/native/rules/mod.rs` is owned by the integration slice and
//! does not wire `auth` in yet, so this test crate includes the rule file
//! itself with `#[path]` and bridges the `crate::native` / `crate::types`
//! paths it uses. Once the integration slice lands `pub mod auth;` in
//! `rules/mod.rs`, this shim can be dropped in favor of
//! `sat::native::rules::auth::check`.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
    }
}

#[path = "../src/native/rules/auth.rs"]
mod auth;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT019: &str = "Unverified Signer Account:";
const SAT020: &str = "Unverified Owner Account:";
const SAT021: &str = "Unchecked Authority Key:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/auth/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the auth rules.
fn run_auth(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = auth::check(&program, &files);
    (program, findings)
}

fn run_auth_fixture(name: &str) -> (NativeProgram, Vec<Finding>) {
    run_auth(&fixture_source(name))
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

fn fn_line(source: &str) -> usize {
    source.lines().position(|l| l.contains("pub fn process_instruction")).map(|i| i + 1).unwrap_or(0)
}

// ── Model sanity: guards against vacuous rule tests ─────────────────────────

#[test]
fn vuln_fixture_resolves_unverified_flags() {
    let source = fixture_source("vuln.rs");
    let (program, _) = run_auth(&source);
    assert_eq!(program.instructions.len(), 1);
    let ix = &program.instructions[0];
    assert_eq!(ix.name, "process_instruction");

    let authority = account(ix, "authority");
    assert!(!authority.is_signer_checked, "vuln: authority has no signer guard");
    assert!(!authority.key_checked, "vuln: authority key is not pinned");
    assert_eq!(authority.kind, sat::native::model::AccountKind::Unchecked);

    let state = account(ix, "state");
    assert!(state.written, "vuln: state data is written");
    assert!(!state.owner_checked, "vuln: state has no owner guard");
    assert!(!state.key_checked, "vuln: state key is not pinned");

    let owner = account(ix, "owner");
    assert!(!owner.key_checked, "vuln: owner is never key-compared");
    assert!(!owner.is_signer_checked, "vuln: owner is not signer-checked");
}

#[test]
fn clean_fixture_resolves_all_guards() {
    let source = fixture_source("clean.rs");
    let (program, _) = run_auth(&source);
    assert_eq!(program.instructions.len(), 1);
    let ix = &program.instructions[0];

    assert!(account(ix, "authority").is_signer_checked, "clean: authority signer guard");
    assert!(account(ix, "state").owner_checked, "clean: state owner guard");
    assert!(account(ix, "owner").key_checked, "clean: owner key compare");
    assert!(account(ix, "expected_owner").key_checked, "clean: expected_owner pinned by the compare");
}

// ── Rule firing on the vulnerable fixture ───────────────────────────────────

#[test]
fn vuln_yields_all_three_authentication_findings() {
    let (_, findings) = run_auth_fixture("vuln.rs");
    assert_eq!(by_rule(&findings, SAT019).len(), 2, "SAT019 fires for `authority` and `owner`");
    assert_eq!(by_rule(&findings, SAT020).len(), 1, "SAT020 fires for the written `state` account");
    assert_eq!(by_rule(&findings, SAT021).len(), 2, "SAT021 fires for `authority` and `owner`");
}

#[test]
fn vuln_findings_target_the_expected_accounts() {
    let (_, findings) = run_auth_fixture("vuln.rs");

    assert_eq!(by_rule_account(&findings, SAT019, "authority").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT019, "owner").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT020, "state").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT021, "authority").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT021, "owner").len(), 1);

    // Dedup: exactly one finding per (rule, instruction, account).
    assert_eq!(findings.len(), 5, "no duplicate (rule, instruction, account) pairs: {findings:?}");
}

#[test]
fn vuln_findings_are_high_severity_with_shaped_locations() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run_auth(&source);
    let expected_loc = format!("test.rs:{} (process_instruction)", fn_line(&source));

    assert!(!findings.is_empty());
    for f in &findings {
        assert_eq!(f.severity, Severity::High, "spec section 7: all three rules are High — got {}", f.title);
        assert_eq!(f.location.as_deref(), Some(expected_loc.as_str()), "location format `file:line (name)`");
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(!f.description.is_empty(), "description: what, why, exploit sketch");
        assert!(f.suggestion.is_some(), "suggestion: the guard to add");
    }
}

#[test]
fn vuln_findings_use_only_the_three_rule_prefixes() {
    let (_, findings) = run_auth_fixture("vuln.rs");
    for f in &findings {
        assert!(
            f.title.starts_with(SAT019) || f.title.starts_with(SAT020) || f.title.starts_with(SAT021),
            "unexpected title prefix: {}",
            f.title
        );
    }
}

// ── Clean fixture ───────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_authentication_findings() {
    let (_, findings) = run_auth_fixture("clean.rs");
    assert!(findings.is_empty(), "clean.rs must produce zero findings: {findings:?}");
}

// ── FP filters (inline sources) ─────────────────────────────────────────────

#[test]
fn cpi_passed_only_fixture_resolves_the_token_account() {
    // Model sanity: the suppression test must not be vacuous — the account
    // really is a stateful token account with no owner/key check.
    let source = fixture_source("cpi_passed_only.rs");
    let (program, _) = run_auth(&source);
    assert_eq!(program.instructions.len(), 1);
    let ix = &program.instructions[0];
    assert_eq!(ix.accounts.len(), 3);
    let ta = account(ix, "token_account");
    assert_eq!(ta.kind, sat::native::model::AccountKind::TokenAccount);
    assert!(!ta.owner_checked && !ta.key_checked, "SAT020 trigger conditions hold");
}

#[test]
fn cpi_passed_only_token_account_is_not_reported() {
    // SAT020 suppression: the account is only passed to an SPL Token
    // `invoke_signed` (through a helper, like Mango's `invoke_transfer`); the
    // token program validates ownership at runtime.
    let (_, findings) = run_auth_fixture("cpi_passed_only.rs");
    assert!(findings.is_empty(), "CPI-passed-only account must not fire SAT020: {findings:?}");
}

#[test]
fn cpi_passed_only_control_with_data_read_is_reported() {
    // Same shape plus a `try_from_slice` on the account's data: the data read
    // is a program use, so SAT020 fires (delist-path shape).
    let (_, findings) = run_auth_fixture("cpi_passed_only_control.rs");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT020), "{}", findings[0].title);
    assert!(findings[0].title.contains("`token_account`"), "{}", findings[0].title);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn cpi_to_unknown_program_is_reported() {
    // Unknown callee: a dex-style invoke whose program_id is `dex_program.key`
    // with no known-program check — the account must keep firing.
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let dex_program = next_account_info(accounts_iter)?;
            let token_account = next_account_info(accounts_iter)?;
            let ix = Instruction {
                program_id: *dex_program.key,
                accounts: vec![AccountMeta::new(*token_account.key, false)],
                data: vec![],
            };
            invoke(&ix, &[dex_program.clone(), token_account.clone()])
        }
    "#;
    let (_, findings) = run_auth(src);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT020), "{}", findings[0].title);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn cpi_with_token_program_base58_literal_is_not_reported() {
    // The program id literal resolves to the SPL Token program: the account
    // passed to this CPI is suppressed.
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::Instruction,
            program::invoke,
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
            let token_account = next_account_info(accounts_iter)?;
            let ix = Instruction {
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".parse().unwrap(),
                accounts: vec![],
                data: vec![],
            };
            invoke(&ix, &[vault.clone(), token_account.clone()])
        }
    "#;
    let (_, findings) = run_auth(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn signer_checked_authority_is_not_reported() {
    // SAT021 skips when `is_signer_checked`; SAT019 requires `!is_signer_checked`.
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
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let authority = next_account_info(accounts_iter)?;
            if !authority.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn key_pinned_authority_is_not_reported() {
    // SAT019 skips when `key_checked` (fixed key); SAT021 requires `!key_checked`.
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
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let authority = next_account_info(accounts_iter)?;
            let expected = Pubkey::new_from_array([7u8; 32]);
            if authority.key != &expected {
                return Err(ProgramError::InvalidAccountData);
            }
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn written_sysvar_is_not_reported_as_unverified_owner() {
    // SAT020 skips runtime-builtin kinds (Sysvar here, from the name `clock`).
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
            let clock = next_account_info(accounts_iter)?;
            let mut data = clock.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn written_unchecked_account_without_owner_check_is_reported() {
    // SAT020 also covers `written` accounts whose kind stays Unchecked.
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
            let config = next_account_info(accounts_iter)?;
            let mut data = config.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT020), "{}", findings[0].title);
    assert_eq!(findings[0].severity, Severity::High);
}

// ── Helper-guard recognition (SAT019/SAT020/SAT021 FP filter) ───────────────

#[test]
fn helper_guarded_fixture_resolves_unguarded_flags() {
    // Model sanity: the helper-guard suppression must not be vacuous — the
    // frontend resolves all three accounts as unguarded (no signer check, no
    // owner check, no key pinning), so without the helper layer the fixture
    // would fire all three rules.
    let (program, _) = run_auth_fixture("helper_guarded.rs");
    assert_eq!(program.instructions.len(), 1);
    let ix = &program.instructions[0];

    let admin = account(ix, "admin");
    assert!(!admin.is_signer_checked, "helper_guarded: frontend sees no signer guard");
    assert!(!admin.key_checked, "helper_guarded: frontend sees no key pin");

    let state = account(ix, "state");
    assert!(state.written, "helper_guarded: state data is written");
    assert!(!state.owner_checked, "helper_guarded: frontend sees no owner guard");

    let config = account(ix, "config");
    assert!(config.written, "helper_guarded: config data is written");
    assert!(!config.owner_checked && !config.key_checked, "helper_guarded: frontend sees no owner guard");
}

#[test]
fn helper_guarded_fixture_is_clean() {
    // `load_signer(admin, ..)` + `load_system_account(state, ..)` +
    // `Config::load(program_id, config, ..)` in the handler body suppress
    // SAT019 / SAT020 / SAT021 for those accounts.
    let (_, findings) = run_auth_fixture("helper_guarded.rs");
    assert!(findings.is_empty(), "helper-guarded accounts must not fire: {findings:?}");
}

#[test]
fn no_helper_fixture_fires_all_three_rules() {
    // Same accounts without the helper calls: SAT019 / SAT020 / SAT021 fire.
    let (_, findings) = run_auth_fixture("no_helper.rs");
    assert_eq!(by_rule(&findings, SAT019).len(), 1, "{findings:?}");
    assert_eq!(by_rule(&findings, SAT020).len(), 2, "{findings:?}");
    assert_eq!(by_rule(&findings, SAT021).len(), 1, "{findings:?}");
    assert_eq!(by_rule_account(&findings, SAT019, "admin").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT020, "state").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT020, "config").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT021, "admin").len(), 1);
    assert_eq!(findings.len(), 4, "{findings:?}");
}

#[test]
fn mango_shape_load_checked_is_not_a_guard() {
    // Regression control (Mango RecoveryWithdraw* shape):
    // `TokenAccount::load_checked(token_account)` checks nothing, so SAT020
    // must still fire — the curated whitelist never treats bare
    // `load`/`load_checked` as an owner check.
    let (_, findings) = run_auth_fixture("mango_shape_control.rs");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT020), "{}", findings[0].title);
    assert!(findings[0].title.contains("`token_account`"), "{}", findings[0].title);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn state_load_on_token_kind_account_is_not_a_guard() {
    // Pattern-3 kind gate: `<Type>::load` on an account the frontend
    // classified `TokenAccount` must not be treated as an owner check
    // (Mango `Loadable::load`-style shapes on token accounts keep firing).
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let token_account = next_account_info(accounts_iter)?;
            TokenThing::load(program_id, token_account)?;
            let mut data = token_account.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT020), "{}", findings[0].title);
    assert!(findings[0].title.contains("`token_account`"), "{}", findings[0].title);
}

#[test]
fn authority_key_helper_pins_the_authority_key() {
    // Pattern 4: `state.check_admin(admin.key)` is an authority-key equality
    // helper — SAT021 (and SAT019) must not fire for `admin`. SAT020 still
    // fires for the written, owner-unchecked `state`.
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
            let admin = next_account_info(accounts_iter)?;
            let mut data = state.data.borrow_mut();
            let state = State::try_from_slice_unchecked_mut(&mut data)?;
            state.check_admin(admin.key)?;
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.starts_with(SAT020), "{}", findings[0].title);
    assert!(findings[0].title.contains("`state`"), "{}", findings[0].title);
    assert!(by_rule_account(&findings, SAT021, "admin").is_empty());
    assert!(by_rule_account(&findings, SAT019, "admin").is_empty());
}

#[test]
fn helper_guards_are_exact_name_matches() {
    // `load_signer_extra` is NOT in the whitelist: SAT019 / SAT021 must still
    // fire for `admin` (exact callee-name matching, no prefix fuzz).
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            msg,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let admin = next_account_info(accounts_iter)?;
            load_signer_extra(admin, true)?;
            msg!("admin: {}", admin.key);
            Ok(())
        }
    "#;
    let (_, findings) = run_auth(src);
    assert_eq!(by_rule_account(&findings, SAT019, "admin").len(), 1, "{findings:?}");
    assert_eq!(by_rule_account(&findings, SAT021, "admin").len(), 1, "{findings:?}");
}
