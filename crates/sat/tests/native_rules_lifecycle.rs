//! R3 slice tests: SAT024 / SAT025 / SAT026 / SAT027 — lifecycle rules for
//! native programs (account close/reinit, unchecked deserialization, unsafe
//! arithmetic, writable builtins), exercised via `lifecycle::check` directly
//! on the pinned model plus the parsed files.
//!
//! `crates/sat/src/native/rules/mod.rs` is owned by the integration slice and
//! does not wire `lifecycle` in yet, so this test crate includes the rule file
//! itself with `#[path]` and bridges the `crate::native` / `crate::types`
//! paths it uses (same shim as `native_rules_auth.rs`). Once the integration
//! slice lands `pub mod lifecycle;` in `rules/mod.rs`, this shim can be
//! dropped in favor of `sat::native::rules::lifecycle::check`.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{NativeInstruction, NativeProgram, ResolvedAccount};
    }
}

#[path = "../src/native/rules/lifecycle.rs"]
mod lifecycle;

use sat::native::model::NativeInstruction;
use sat::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT024: &str = "Account Reinit After Close:";
const SAT025: &str = "Unchecked Deserialization:";
const SAT026: &str = "Unsafe Arithmetic:";
const SAT027: &str = "Writable Builtin Account:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/lifecycle/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the lifecycle rules.
fn run_lifecycle(source: &str) -> (sat::native::model::NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = lifecycle::check(&program, &files);
    (program, findings)
}

fn run_lifecycle_fixture(name: &str) -> (sat::native::model::NativeProgram, Vec<Finding>) {
    run_lifecycle(&fixture_source(name))
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

fn by_rule_account<'a>(findings: &'a [Finding], prefix: &str, account: &str) -> Vec<&'a Finding> {
    let ticked = format!("`{account}`");
    findings.iter().filter(|f| f.title.starts_with(prefix) && f.title.contains(&ticked)).collect()
}

fn account<'a>(ix: &'a NativeInstruction, name: &str) -> &'a sat::native::model::ResolvedAccount {
    ix.accounts
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("account `{name}` not resolved (have: {:?})", ix.accounts))
}

fn instruction<'a>(program: &'a sat::native::model::NativeProgram, handler: &str) -> &'a NativeInstruction {
    program
        .instructions
        .iter()
        .find(|ix| ix.handler == handler)
        .unwrap_or_else(|| panic!("instruction `{handler}` not resolved (have: {:?})", program.instructions))
}

/// 1-based line of the first line containing `needle`.
fn line_of(source: &str, needle: &str) -> usize {
    source.lines().position(|l| l.contains(needle)).map(|i| i + 1).unwrap_or_else(|| panic!("`{needle}` not found"))
}

// ── Model sanity: guards against vacuous rule tests ─────────────────────────

#[test]
fn vuln_fixture_resolves_lifecycle_flags() {
    let source = fixture_source("vuln.rs");
    let (program, _) = run_lifecycle(&source);
    assert_eq!(program.instructions.len(), 3);

    let close = instruction(&program, "process_close");
    let state = account(close, "state");
    assert!(state.written, "vuln: realloc(0) marks `state` written");
    assert!(!state.owner_checked, "vuln: `state` has no owner guard");

    let deposit = instruction(&program, "process_deposit");
    let state = account(deposit, "state");
    assert!(state.written, "vuln: `state` data is written");
    assert!(!state.owner_checked, "vuln: `state` is not owner-checked");

    let tick = instruction(&program, "process_tick");
    let clock = account(tick, "clock");
    assert!(clock.written, "vuln: `clock` data is borrowed mutably");
    assert_eq!(clock.kind, sat::native::model::AccountKind::Sysvar);
}

#[test]
fn clean_fixture_resolves_all_guards() {
    let source = fixture_source("clean.rs");
    let (program, _) = run_lifecycle(&source);
    assert_eq!(program.instructions.len(), 3);

    let deposit = instruction(&program, "process_deposit");
    assert!(account(deposit, "state").owner_checked, "clean: owner guard on `state`");

    let tick = instruction(&program, "process_tick");
    assert!(!account(tick, "clock").written, "clean: `clock` is never borrowed mutably");
}

// ── Rule firing on the vulnerable fixture ───────────────────────────────────

#[test]
fn vuln_yields_all_four_lifecycle_findings() {
    let (_, findings) = run_lifecycle_fixture("vuln.rs");
    assert_eq!(by_rule(&findings, SAT024).len(), 1, "SAT024: one closing instruction: {findings:?}");
    assert_eq!(by_rule(&findings, SAT025).len(), 1, "SAT025: one unchecked deserialization: {findings:?}");
    assert_eq!(by_rule(&findings, SAT026).len(), 1, "SAT026: one raw `+=`: {findings:?}");
    assert_eq!(by_rule(&findings, SAT027).len(), 1, "SAT027: one writable builtin: {findings:?}");
}

#[test]
fn vuln_findings_target_the_expected_accounts() {
    let (_, findings) = run_lifecycle_fixture("vuln.rs");
    assert_eq!(by_rule_account(&findings, SAT024, "state").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT025, "state").len(), 1);
    assert_eq!(by_rule_account(&findings, SAT027, "clock").len(), 1);

    // Dedup: exactly one finding per (rule, instruction, account).
    assert_eq!(findings.len(), 4, "no duplicate (rule, instruction, account) pairs: {findings:?}");
}

#[test]
fn vuln_findings_have_spec_severities_and_shaped_locations() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run_lifecycle(&source);

    let sat024 = by_rule(&findings, SAT024);
    let sat025 = by_rule(&findings, SAT025);
    let sat026 = by_rule(&findings, SAT026);
    let sat027 = by_rule(&findings, SAT027);
    assert_eq!(sat024[0].severity, Severity::High, "spec: SAT024 is High");
    assert_eq!(sat025[0].severity, Severity::Medium, "spec: SAT025 is Medium");
    assert_eq!(sat026[0].severity, Severity::High, "spec: SAT026 is High");
    assert_eq!(sat027[0].severity, Severity::Medium, "spec: SAT027 is Medium");

    // Location shape `"{file}:{line} ({instruction_name})"` (SAT026 uses the
    // function name, which equals the instruction name for a dispatched
    // handler).
    let close_line = line_of(&source, "state.realloc(0, false)?;");
    assert_eq!(sat024[0].location.as_deref(), Some(format!("test.rs:{close_line} (process_close)").as_str()));

    let deser_line = line_of(&source, "State::try_from_slice");
    assert_eq!(sat025[0].location.as_deref(), Some(format!("test.rs:{deser_line} (process_deposit)").as_str()));

    let arith_line = line_of(&source, "s.total += amount;");
    assert_eq!(sat026[0].location.as_deref(), Some(format!("test.rs:{arith_line} (process_deposit)").as_str()));

    let arm_line = line_of(&source, "=> process_tick");
    assert_eq!(sat027[0].location.as_deref(), Some(format!("test.rs:{arm_line} (process_tick)").as_str()));

    for f in &findings {
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(!f.description.is_empty(), "description: what, why, exploit sketch");
        assert!(f.suggestion.is_some(), "suggestion: the guard to add");
    }
}

#[test]
fn vuln_findings_use_only_the_four_rule_prefixes() {
    let (_, findings) = run_lifecycle_fixture("vuln.rs");
    for f in &findings {
        assert!(
            f.title.starts_with(SAT024)
                || f.title.starts_with(SAT025)
                || f.title.starts_with(SAT026)
                || f.title.starts_with(SAT027),
            "unexpected title prefix: {}",
            f.title
        );
    }
}

// ── Clean fixture ───────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_lifecycle_findings() {
    let (_, findings) = run_lifecycle_fixture("clean.rs");
    assert!(findings.is_empty(), "clean.rs must produce zero findings: {findings:?}");
}

// ── Inline helper sources ───────────────────────────────────────────────────

/// Two-instruction program: `process_close` (tag 1) and `process_write`
/// (tag 2, always writes `state`). Used to exercise SAT024 close variants.
fn two_ix_source(close_body: &str, write_body: &str) -> String {
    format!(
        r#"
        use solana_program::{{
            account_info::{{next_account_info, AccountInfo}},
            entrypoint,
            entrypoint::ProgramResult,
            program_error::ProgramError,
            pubkey::Pubkey,
        }};
        entrypoint!(process_instruction);
        const STATE_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            instruction_data: &[u8],
        ) -> ProgramResult {{
            match instruction_data[0] {{
                1 => process_close(_program_id, accounts, instruction_data),
                2 => process_write(_program_id, accounts, instruction_data),
                _ => Err(ProgramError::InvalidInstructionData),
            }}
        }}
        pub fn process_close(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {{
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            {close_body}
            Ok(())
        }}
        pub fn process_write(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {{
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            {write_body}
            Ok(())
        }}
        "#
    )
}

const WRITE_BODY: &str = "let mut data = state.data.borrow_mut();\n        data[0] = 1;";

/// A single-instruction program with the given handler body.
fn one_ix_source(body: &str) -> String {
    format!(
        r#"
        use solana_program::{{
            account_info::{{next_account_info, AccountInfo}},
            entrypoint,
            entrypoint::ProgramResult,
            program_error::ProgramError,
            pubkey::Pubkey,
        }};
        entrypoint!(process_instruction);
        const STATE_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        struct State {{
            total: u64,
        }}
        pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {{
            let accounts_iter = &mut accounts.iter();
            {body}
            Ok(())
        }}
        "#
    )
}

// ── SAT026 fixed-point (Mango I80F48) FP regression ─────────────────────────

#[test]
fn fixed_point_fixture_yields_no_sat026_findings() {
    let (_, findings) = run_lifecycle_fixture("fixed_point.rs");
    assert!(by_rule(&findings, SAT026).is_empty(), "fixed-point arithmetic must not fire: {findings:?}");
}

#[test]
fn typed_fixed_point_local_suppresses_sat026() {
    // (a) explicit non-primitive type annotation.
    let src = one_ix_source("let mut total: FixedPoint = FixedPoint::zero();\n        total += 1;");
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT026).is_empty(), "{findings:?}");
}

#[test]
fn constructor_initialized_local_suppresses_sat026() {
    // (b) non-primitive constructor call.
    let src = one_ix_source("let mut total = FixedPoint::from_num(1.0);\n        total += 1;");
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT026).is_empty(), "{findings:?}");
}

#[test]
fn fixed_point_parameter_suppresses_sat026() {
    // (c) non-primitive parameter type, plus a struct field on a non-primitive
    // receiver (d).
    let src = r#"
        use solana_program::{{
            account_info::{{next_account_info, AccountInfo}},
            entrypoint,
            entrypoint::ProgramResult,
            pubkey::Pubkey,
        }};
        entrypoint!(process_instruction);
        pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {{
            let accounts_iter = &mut accounts.iter();
            let market = next_account_info(accounts_iter)?;
            apply_fees(market);
            Ok(())
        }}
        struct Market {{
            fees_accrued: FixedPoint,
        }}
        struct FixedPoint(i128);
        fn apply_fees(market: &mut Market) {{
            let ref_fee_rate: FixedPoint = FixedPoint::from_num(0.0001);
            market.fees_accrued += ref_fee_rate;
        }}
        "#;
    let (_, findings) = run_lifecycle(src);
    assert!(by_rule(&findings, SAT026).is_empty(), "{findings:?}");
}

#[test]
fn primitive_local_arithmetic_still_fires() {
    // `u64::from_le_bytes` is not a constructor, so `total` stays u64 and the
    // raw `+=` keeps firing; the index/cast operand is never classified.
    let src = one_ix_source(
        "let bytes = [0u8; 16];\n        let mut total = u64::from_le_bytes(bytes[0..8].try_into().unwrap());\n        total += bytes[8] as u64;",
    );
    let (_, findings) = run_lifecycle(&src);
    let hits = by_rule(&findings, SAT026);
    assert_eq!(hits.len(), 1, "{findings:?}");
    assert_eq!(hits[0].severity, Severity::High);
}

#[test]
fn primitive_constructor_local_still_fires() {
    // `u64::from(..)` resolves to primitive: (b) must not suppress it.
    let src = one_ix_source("let mut total = u64::from(7u8);\n        total += 1;");
    let (_, findings) = run_lifecycle(&src);
    assert_eq!(by_rule(&findings, SAT026).len(), 1, "{findings:?}");
}

// ── SAT024 close variants and FP filters ────────────────────────────────────

#[test]
fn sat024_fires_for_realloc_zero_close() {
    let src = two_ix_source("state.realloc(0, false)?;", WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    let hits = by_rule(&findings, SAT024);
    assert_eq!(hits.len(), 1, "realloc(0) close without guard: {findings:?}");
    assert_eq!(hits[0].severity, Severity::High);
}

#[test]
fn sat024_fires_for_system_program_assign_close() {
    let src = two_ix_source("state.assign(&system_program);", WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    assert_eq!(by_rule(&findings, SAT024).len(), 1, "assign(&system_program) close: {findings:?}");
}

#[test]
fn sat024_fires_for_data_set_len_zero_close() {
    let src = two_ix_source("state.data.borrow_mut().set_len(0);", WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    assert_eq!(by_rule(&findings, SAT024).len(), 1, "data set_len(0) close: {findings:?}");
}

#[test]
fn sat024_fires_for_lamports_zero_close() {
    let src = two_ix_source("**state.try_borrow_mut_lamports()? = 0;", WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    assert_eq!(by_rule(&findings, SAT024).len(), 1, "lamports zeroing close: {findings:?}");
}

#[test]
fn sat024_is_silent_without_a_writer_instruction() {
    // The closing instruction is the only one; no other instruction writes.
    let src = one_ix_source("state.realloc(0, false)?;");
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT024).is_empty(), "close without other writer: {findings:?}");
}

#[test]
fn sat024_is_suppressed_by_data_is_empty_guard() {
    let close = "if state.data_is_empty() { return Err(ProgramError::UninitializedAccount); }\n        state.realloc(0, false)?;";
    let src = two_ix_source(close, WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT024).is_empty(), "data_is_empty guard before close: {findings:?}");
}

#[test]
fn sat024_is_suppressed_by_discriminator_guard() {
    let close = "let data = &state.data.borrow();\n        if data[0..8] != STATE_DISCRIMINATOR { return Err(ProgramError::InvalidAccountData); }\n        drop(data);\n        state.realloc(0, false)?;";
    let src = two_ix_source(close, WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT024).is_empty(), "discriminator guard before close: {findings:?}");
}

#[test]
fn sat024_is_suppressed_by_is_initialized_flag_guard() {
    let close = "let mut data = state.data.borrow_mut();\n        let mut s: State = State::try_from_slice(&data)?;\n        if !s.is_initialized { return Err(ProgramError::UninitializedAccount); }\n        drop(data);\n        state.realloc(0, false)?;";
    let src = two_ix_source(close, WRITE_BODY);
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT024).is_empty(), "is_initialized flag guard: {findings:?}");
}

// ── SAT025 FP filters ───────────────────────────────────────────────────────

#[test]
fn sat025_fires_on_owner_unchecked_deserialization() {
    let src = one_ix_source(
        "let state = next_account_info(accounts_iter)?;\n        let mut data = state.data.borrow_mut();\n        let _s: State = State::try_from_slice(&data)?;\n        data[0] = 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    let hits = by_rule(&findings, SAT025);
    assert_eq!(hits.len(), 1, "{findings:?}");
    assert_eq!(hits[0].severity, Severity::Medium);
}

#[test]
fn sat025_is_suppressed_by_owner_check() {
    let src = one_ix_source(
        "if state.owner != program_id { return Err(ProgramError::IllegalOwner); }\n        let mut data = state.data.borrow_mut();\n        let _s: State = State::try_from_slice(&data)?;\n        data[0] = 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT025).is_empty(), "owner-checked deserialization: {findings:?}");
}

#[test]
fn sat025_is_suppressed_by_discriminator_check() {
    let src = one_ix_source(
        "let mut data = state.data.borrow_mut();\n        if data[0..8] != STATE_DISCRIMINATOR { return Err(ProgramError::InvalidAccountData); }\n        let _s: State = State::try_from_slice(&data)?;\n        data[0] = 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT025).is_empty(), "discriminator-validated deserialization: {findings:?}");
}

// ── SAT026 FP filters ───────────────────────────────────────────────────────

#[test]
fn sat026_fires_on_raw_add_of_a_balance() {
    let src = one_ix_source(
        "let state = next_account_info(accounts_iter)?;\n        let mut data = state.data.borrow_mut();\n        let mut s: State = State::try_from_slice(&data)?;\n        s.total = s.total + 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    let hits = by_rule(&findings, SAT026);
    assert_eq!(hits.len(), 1, "{findings:?}");
    assert_eq!(hits[0].severity, Severity::High);
    assert!(hits[0].title.contains("`+` in `process_instruction`"), "{}", hits[0].title);
}

#[test]
fn sat026_is_silent_with_checked_add() {
    let src = one_ix_source(
        "let state = next_account_info(accounts_iter)?;\n        let mut data = state.data.borrow_mut();\n        let mut s: State = State::try_from_slice(&data)?;\n        s.total = s.total.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;",
    );
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT026).is_empty(), "checked_add must not fire: {findings:?}");
}

// ── SAT027 ──────────────────────────────────────────────────────────────────

#[test]
fn sat027_fires_for_writable_token_program() {
    let src = one_ix_source(
        "let token_program = next_account_info(accounts_iter)?;\n        let mut data = token_program.data.borrow_mut();\n        data[0] = 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    let hits = by_rule_account(&findings, SAT027, "token_program");
    assert_eq!(hits.len(), 1, "{findings:?}");
    assert_eq!(hits[0].severity, Severity::Medium);
}

#[test]
fn sat027_fires_for_literal_builtin_address_comparison() {
    // The account name carries no builtin hint; the handler pins it to the
    // clock sysvar by comparing its key against the literal address.
    let src = one_ix_source(
        "let sysvar = next_account_info(accounts_iter)?;\n        if sysvar.key.to_string() != \"SysvarC1ock11111111111111111111111111111111\" { return Err(ProgramError::InvalidAccountData); }\n        let mut data = sysvar.data.borrow_mut();\n        data[0] = 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    let hits = by_rule_account(&findings, SAT027, "sysvar");
    assert_eq!(hits.len(), 1, "literal sysvar address: {findings:?}");
}

#[test]
fn sat027_is_silent_for_read_only_sysvar() {
    let src = one_ix_source(
        "let clock = next_account_info(accounts_iter)?;\n        let data = &clock.data.borrow();\n        let _slot = u64::from_le_bytes(data[0..8].try_into().unwrap());",
    );
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT027).is_empty(), "read-only clock must not fire: {findings:?}");
}

#[test]
fn sat027_is_silent_for_writable_state_account() {
    let src = one_ix_source(
        "let state = next_account_info(accounts_iter)?;\n        let mut data = state.data.borrow_mut();\n        data[0] = 1;",
    );
    let (_, findings) = run_lifecycle(&src);
    assert!(by_rule(&findings, SAT027).is_empty(), "writable state account must not fire: {findings:?}");
}
