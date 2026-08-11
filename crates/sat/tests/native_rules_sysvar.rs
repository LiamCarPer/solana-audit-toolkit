//! R7 slice tests: SAT032 — Sysvar-Introspection Misuse (the Wormhole bridge
//! class), exercised via `sysvar_introspection::check` directly on the parsed
//! files from `sat::native::analyze_source_and_files_for_test`.
//!
//! The rule is a pure AST scan (no `NativeProgram` model dependency), so the
//! shim only bridges `crate::types`. `crates/sat/src/native/rules/mod.rs`
//! wires the rule into `rules::run` (see the integration slice); this test
//! crate includes the rule file itself with `#[path]`, mirroring
//! `tests/native_rules_cpi.rs`.

mod types {
    pub use sat::types::{Finding, Severity};
}

#[path = "../src/native/rules/sysvar_introspection.rs"]
mod sysvar_introspection;

use sat::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT032: &str = "Sysvar-Introspection Misuse:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/sysvar/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Parse a source string and run only the SAT032 rule (file-level scan).
fn run(source: &str) -> Vec<Finding> {
    let (_, files) = sat::native::analyze_source_and_files_for_test(source);
    sysvar_introspection::check(&files)
}

fn run_fixture(name: &str) -> Vec<Finding> {
    run(&fixture_source(name))
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
        .unwrap_or_else(|| panic!("line containing `{needle}` not found"))
}

// ── Model sanity: guards against vacuous rule tests ─────────────────────────

#[test]
fn vuln_fixture_parses_and_yields_files() {
    let source = fixture_source("vuln.rs");
    let (_, files) = sat::native::analyze_source_and_files_for_test(&source);
    assert_eq!(files.len(), 1, "fixture must parse with syn (a parse regression is a test failure)");
    assert!(source.contains("load_current_index"), "fixture carries the unchecked load_current_index");
    assert!(source.contains("load_instruction_at"), "fixture carries the unchecked load_instruction_at");
}

// ── Rule firing on the vulnerable fixture ───────────────────────────────────

#[test]
fn vuln_fires_high_findings_for_both_unchecked_calls() {
    // The wormhole-era shape carries TWO unchecked call sites
    // (`load_current_index` and `load_instruction_at`, exactly like
    // `verify_signature.rs` at wormhole commit 79ab522), so the fixture fires
    // one HIGH finding per call site — both with the Sysvar-Introspection
    // title prefix.
    let source = fixture_source("vuln.rs");
    let findings = run(&source);

    let sat032 = by_rule(&findings, SAT032);
    assert_eq!(sat032.len(), 2, "{findings:?}");

    for f in &sat032 {
        assert_eq!(f.severity, Severity::High, "spec section 7: SAT032 is High");
        assert!(f.title.contains("parses caller-supplied account data"), "{}", f.title);
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(!f.description.is_empty(), "description: what, why, exploit sketch");
        assert!(f.suggestion.is_some(), "suggestion: the _checked variant / sysvar address validation");
    }

    let load_current =
        sat032.iter().find(|f| f.title.contains("load_current_index")).expect("finding for load_current_index");
    let expected_cur_loc = format!(
        "test.rs:{} (verify_signatures)",
        line_of(&source, "solana_program::sysvar::instructions::load_current_index(")
    );
    assert_eq!(
        load_current.location.as_deref(),
        Some(expected_cur_loc.as_str()),
        "location `file:line (function)` at the unchecked call site"
    );

    let load_at =
        sat032.iter().find(|f| f.title.contains("load_instruction_at")).expect("finding for load_instruction_at");
    let expected_at_loc = format!(
        "test.rs:{} (verify_signatures)",
        line_of(&source, "solana_program::sysvar::instructions::load_instruction_at(")
    );
    assert_eq!(
        load_at.location.as_deref(),
        Some(expected_at_loc.as_str()),
        "location `file:line (function)` at the unchecked call site"
    );
}

// ── Clean fixture ───────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_sat032_findings() {
    let findings = run_fixture("clean.rs");
    assert!(findings.is_empty(), "clean.rs must produce zero findings: {findings:?}");
}

// ── Inline FP guards ────────────────────────────────────────────────────────

/// `Clock::get()`-style sysvar accessors never trigger SAT032.
#[test]
fn clock_get_never_triggers() {
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
            let _clock_account = next_account_info(accounts_iter)?;
            let clock = solana_program::clock::Clock::get()?;
            let _slot = clock.slot;
            let rent = solana_program::sysvar::rent::Rent::get()?;
            let _lamports = rent.lamports_per_byte_year;
            Ok(())
        }
    "#;
    let findings = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

/// The checked variant with a plain `&AccountInfo` argument never triggers.
#[test]
fn checked_variant_with_accountinfo_argument_is_not_reported() {
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
            let instruction_acc = next_account_info(accounts_iter)?;
            let secp_ix = solana_program::sysvar::instructions::load_instruction_at_checked(
                0usize,
                instruction_acc,
            )?;
            let _pid = secp_ix.program_id;
            Ok(())
        }
    "#;
    let findings = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

/// A data argument rooted at a call (`sysvar::instructions::id()`) or a
/// literal is not a borrow over a local identifier and never triggers.
#[test]
fn data_arg_not_borrowed_from_local_is_not_reported() {
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
            let instruction_acc = next_account_info(accounts_iter)?;
            let empty: &[u8] = &[];
            let a = solana_program::sysvar::instructions::load_current_index(empty);
            let b = solana_program::sysvar::instructions::load_instruction_at(0usize, &[]);
            let _ = (a, b);
            Ok(())
        }
    "#;
    let findings = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}
