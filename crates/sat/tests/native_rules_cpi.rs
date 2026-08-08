//! R4 slice tests: SAT028 / SAT029 / SAT030 — CPI rules for native programs,
//! exercised via `cpi::check` directly on the pinned model plus the parsed
//! files from `sat::native::analyze_source_and_files_for_test`.
//!
//! `crates/sat/src/native/rules/mod.rs` is owned by the integration slice and
//! does not wire `cpi` in yet, so this test crate includes the rule file
//! itself with `#[path]` and bridges the `crate::native` / `crate::types`
//! paths it uses. Once the integration slice lands `pub mod cpi;` in
//! `rules/mod.rs`, this shim can be dropped in favor of
//! `sat::native::rules::cpi::check`.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
    }
}

#[path = "../src/native/rules/cpi.rs"]
mod cpi;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT028: &str = "Token CPI Unverified Authority:";
const SAT029: &str = "Self-Invocation:";
const SAT030: &str = "Cross-Instruction State Reuse:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/cpi/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the CPI rules.
fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = cpi::check(&program, &files);
    (program, findings)
}

fn run_fixture(name: &str) -> (NativeProgram, Vec<Finding>) {
    run(&fixture_source(name))
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

fn account<'a>(ix: &'a sat::native::model::NativeInstruction, name: &str) -> &'a sat::native::model::ResolvedAccount {
    ix.accounts
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("account `{name}` not resolved (have: {:?})", ix.accounts))
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
fn vuln_fixture_resolves_both_instructions() {
    let source = fixture_source("vuln.rs");
    let (program, _) = run(&source);
    assert_eq!(
        program.program_id.as_deref(),
        Some("CPICzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe"),
        "declare_id literal captured"
    );
    assert_eq!(program.instructions.len(), 2);

    let transfer = &program.instructions[0];
    assert_eq!(transfer.name, "process_transfer");
    let authority = account(transfer, "authority");
    assert!(!authority.is_signer_checked, "vuln: authority has no signer guard");
    assert!(!authority.key_checked, "vuln: authority key is not pinned");
    assert!(!authority.is_pda);
    assert!(account(transfer, "state").written, "vuln: state written by process_transfer");
    assert_eq!(account(transfer, "token_program").kind, sat::native::model::AccountKind::Program);

    let withdraw = &program.instructions[1];
    assert_eq!(withdraw.name, "process_withdraw");
    assert!(account(withdraw, "state").written, "vuln: state written by process_withdraw");
}

#[test]
fn clean_fixture_resolves_guarded_transfer() {
    let source = fixture_source("clean.rs");
    let (program, _) = run(&source);
    assert_eq!(program.instructions.len(), 2);
    let transfer = &program.instructions[0];
    assert!(account(transfer, "authority").is_signer_checked, "clean: authority signer guard reachable in the handler");
    assert!(account(transfer, "state").written);
    assert!(account(&program.instructions[1], "state").written);
}

// ── Rule firing on the vulnerable fixture ───────────────────────────────────

#[test]
fn vuln_yields_sat028_for_the_unverified_transfer_authority() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    let sat028 = by_rule(&findings, SAT028);
    assert_eq!(sat028.len(), 1, "{findings:?}");
    let f = sat028[0];
    assert_eq!(f.severity, Severity::High, "spec section 7: SAT028 is High");
    assert!(f.title.contains("authority"), "title names the authority account: {}", f.title);
    let expected_loc = format!("test.rs:{} (process_transfer)", line_of(&source, "invoke(&transfer_ix"));
    assert_eq!(
        f.location.as_deref(),
        Some(expected_loc.as_str()),
        "location `file:line (instruction)` at the invoke call site"
    );
    assert!(f.id.is_empty(), "id is filled by run() later");
    assert!(!f.description.is_empty(), "description: what, why, exploit sketch");
    assert!(f.suggestion.is_some(), "suggestion: the guard to add");
}

#[test]
fn vuln_yields_sat029_for_the_self_invocation() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    let sat029 = by_rule(&findings, SAT029);
    assert_eq!(sat029.len(), 1, "{findings:?}");
    let f = sat029[0];
    assert_eq!(f.severity, Severity::Medium, "spec section 7: SAT029 is Medium");
    let expected_loc = format!("test.rs:{} (process_transfer)", line_of(&source, "invoke(&self_ix"));
    assert_eq!(
        f.location.as_deref(),
        Some(expected_loc.as_str()),
        "location `file:line (instruction)` at the invoke call site"
    );
    assert!(!f.description.is_empty());
    assert!(f.suggestion.is_some());
}

#[test]
fn vuln_yields_sat030_listing_both_writers() {
    let source = fixture_source("vuln.rs");
    let (program, findings) = run(&source);

    let sat030 = by_rule(&findings, SAT030);
    assert_eq!(sat030.len(), 1, "{findings:?}");
    let f = sat030[0];
    assert_eq!(f.severity, Severity::Medium, "spec section 7: SAT030 is Medium");
    assert!(f.title.contains("`state`"), "title names the state account: {}", f.title);
    assert!(
        f.description.contains("process_transfer") && f.description.contains("process_withdraw"),
        "description lists the writer instructions: {}",
        f.description
    );
    // Location points at the first unguarded writer's dispatch arm.
    let arm_line = line_of(&source, "=> process_transfer(");
    assert_eq!(f.location.as_deref(), Some(format!("test.rs:{arm_line} (process_transfer)").as_str()));
    assert_eq!(program.instructions[0].line, arm_line, "instruction line == dispatch arm line");
    assert!(f.suggestion.is_some());
}

#[test]
fn vuln_findings_use_only_the_three_rule_prefixes() {
    let (_, findings) = run_fixture("vuln.rs");
    assert_eq!(findings.len(), 3, "{findings:?}");
    for f in &findings {
        assert!(
            f.title.starts_with(SAT028) || f.title.starts_with(SAT029) || f.title.starts_with(SAT030),
            "unexpected title prefix: {}",
            f.title
        );
    }
}

// ── Clean fixture ───────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_cpi_findings() {
    let (_, findings) = run_fixture("clean.rs");
    assert!(findings.is_empty(), "clean.rs must produce zero findings: {findings:?}");
}

// ── SAT028 FP filters (inline sources) ──────────────────────────────────────

/// A single-instruction token transfer CPI with `authority` unverified.
const TRANSFER_SKELETON: &str = r#"
    use solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint,
        entrypoint::ProgramResult,
        instruction::{AccountMeta, Instruction},
        program::invoke,
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
        let source = next_account_info(accounts_iter)?;
        let destination = next_account_info(accounts_iter)?;
        let authority = next_account_info(accounts_iter)?;
        let token_program = next_account_info(accounts_iter)?;
        {guard}
        let ix = Instruction {
            program_id: *token_program.key,
            accounts: vec![
                AccountMeta::new(source.key(), false),
                AccountMeta::new(destination.key(), false),
                AccountMeta::new_readonly(authority.key(), {meta_signer}),
            ],
            data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
        };
        invoke(&ix, &[source.clone(), destination.clone(), authority.clone()])?;
        Ok(())
    }
"#;

#[test]
fn signer_checked_authority_is_not_reported() {
    let src = TRANSFER_SKELETON
        .replace(
            "{guard}",
            "if !authority.is_signer {\n            return Err(ProgramError::MissingRequiredSignature);\n        }",
        )
        .replace("{meta_signer}", "false");
    let (_, findings) = run(&src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn accountmeta_signer_flag_is_not_reported() {
    // Even without a handler guard, an AccountMeta that requires the
    // authority's signature is a real signer constraint.
    let src = TRANSFER_SKELETON.replace("{guard}", "").replace("{meta_signer}", "true");
    let (_, findings) = run(&src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn unverified_authority_is_reported_without_any_filter() {
    let src = TRANSFER_SKELETON.replace("{guard}", "").replace("{meta_signer}", "false");
    let (_, findings) = run(&src);
    assert_eq!(by_rule(&findings, SAT028).len(), 1, "{findings:?}");
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn program_self_authority_is_not_reported() {
    // Builder-style token CPI passing the program itself as the authority:
    // it signs via `invoke_signed` seeds, so the rule must skip it.
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            program::invoke,
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
            let source = next_account_info(accounts_iter)?;
            let destination = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;
            invoke(
                &spl_token::instruction::transfer(
                    token_program.key,
                    source.key,
                    destination.key,
                    program_id,
                    &[program_id],
                    100,
                )?,
                &[source.clone(), destination.clone()],
            )?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn pda_authority_with_plain_invoke_is_reported() {
    // Key-compared PDA authority is fine *except* that plain `invoke` cannot
    // produce the PDA signature: SAT028 fires on the missing invoke_signed.
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke,
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
            let source = next_account_info(accounts_iter)?;
            let destination = next_account_info(accounts_iter)?;
            let authority = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;
            let (vault, _bump) = Pubkey::find_program_address(&[b"vault"], program_id);
            if authority.key != &vault {
                return Err(ProgramError::InvalidAccountData);
            }
            let ix = Instruction {
                program_id: *token_program.key,
                accounts: vec![
                    AccountMeta::new(source.key(), false),
                    AccountMeta::new(destination.key(), false),
                    AccountMeta::new_readonly(authority.key(), false),
                ],
                data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
            };
            invoke(&ix, &[source.clone(), destination.clone(), authority.clone()])?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    let sat028 = by_rule(&findings, SAT028);
    assert_eq!(sat028.len(), 1, "{findings:?}");
    assert!(sat028[0].description.contains("invoke_signed"), "PDA description suggests invoke_signed");
}

#[test]
fn pda_authority_with_invoke_signed_is_not_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke_signed,
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
            let source = next_account_info(accounts_iter)?;
            let destination = next_account_info(accounts_iter)?;
            let authority = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;
            let (vault, _bump) = Pubkey::find_program_address(&[b"vault"], program_id);
            if authority.key != &vault {
                return Err(ProgramError::InvalidAccountData);
            }
            let ix = Instruction {
                program_id: *token_program.key,
                accounts: vec![
                    AccountMeta::new(source.key(), false),
                    AccountMeta::new(destination.key(), false),
                    AccountMeta::new_readonly(authority.key(), false),
                ],
                data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
            };
            invoke_signed(&ix, &[source.clone(), destination.clone(), authority.clone()], &[&[b"vault"]])?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

// ── SAT028 builder-call shape ───────────────────────────────────────────────

#[test]
fn builder_style_unverified_authority_is_reported() {
    // `spl_token::instruction::transfer(...)`-style builder: the authority is
    // the last account argument of the standard transfer layout.
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            program::invoke,
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
            let source = next_account_info(accounts_iter)?;
            let destination = next_account_info(accounts_iter)?;
            let authority = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;
            invoke(
                &spl_token::instruction::transfer(
                    token_program.key,
                    source.key,
                    destination.key,
                    authority.key,
                    &[authority.key],
                    100,
                )?,
                &[source.clone(), destination.clone(), authority.clone()],
            )?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    let sat028 = by_rule(&findings, SAT028);
    assert_eq!(sat028.len(), 1, "{findings:?}");
    assert!(sat028[0].title.contains("authority"));
    assert_eq!(sat028[0].severity, Severity::High);
}

// ── SAT029 detection shapes ─────────────────────────────────────────────────

#[test]
fn self_invocation_literal_matching_declared_id_is_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke,
            program_error::ProgramError,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        declare_id!("SelfInvokeSelfInvokeSelfInvokeSelfInvokeSelfInv");
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let ix = Instruction {
                program_id: "SelfInvokeSelfInvokeSelfInvokeSelfInvokeSelfInv",
                accounts: vec![AccountMeta::new(state.key(), false)],
                data: vec![1u8, 0, 0, 0, 0, 0, 0, 0],
            };
            invoke(&ix, &[state.clone()])?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    let sat029 = by_rule(&findings, SAT029);
    assert_eq!(sat029.len(), 1, "{findings:?}");
    assert_eq!(sat029[0].severity, Severity::Medium);
}

#[test]
fn self_invocation_via_crate_id_is_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke,
            program_error::ProgramError,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        declare_id!("SelfInvokeSelfInvokeSelfInvokeSelfInvokeSelfInv");
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let ix = Instruction {
                program_id: crate::id(),
                accounts: vec![AccountMeta::new(state.key(), false)],
                data: vec![1u8, 0, 0, 0, 0, 0, 0, 0],
            };
            invoke(&ix, &[state.clone()])?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert_eq!(by_rule(&findings, SAT029).len(), 1, "{findings:?}");
}

#[test]
fn self_invocation_via_program_id_param_is_reported_without_declare_id() {
    // The entrypoint's `program_id` parameter always carries the current
    // program's id, so targeting it is a self-invocation even when the
    // program has no `declare_id!`.
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke,
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
            let state = next_account_info(accounts_iter)?;
            let ix = Instruction {
                program_id: *program_id,
                accounts: vec![AccountMeta::new(state.key(), true)],
                data: vec![1u8, 0, 0, 0, 0, 0, 0, 0],
            };
            invoke(&ix, &[state.clone()])?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert_eq!(by_rule(&findings, SAT029).len(), 1, "{findings:?}");
}

#[test]
fn self_invocation_literal_mismatch_is_not_reported() {
    let src = r#"
        use solana_program::{
            account_info::{next_account_info, AccountInfo},
            entrypoint,
            entrypoint::ProgramResult,
            instruction::{AccountMeta, Instruction},
            program::invoke,
            program_error::ProgramError,
            pubkey::Pubkey,
        };
        entrypoint!(process_instruction);
        declare_id!("SelfInvokeSelfInvokeSelfInvokeSelfInvokeSelfInv");
        pub fn process_instruction(
            _program_id: &Pubkey,
            accounts: &[AccountInfo],
            _instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let ix = Instruction {
                program_id: "OtherProgram11111111111111111111111111111111",
                accounts: vec![AccountMeta::new(state.key(), false)],
                data: vec![1u8, 0, 0, 0, 0, 0, 0, 0],
            };
            invoke(&ix, &[state.clone()])?;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

// ── SAT030 grouping ─────────────────────────────────────────────────────────

#[test]
fn sat030_single_writer_is_not_reported() {
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
            let mut data = state.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn sat030_all_writers_guarded_is_not_reported() {
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
            instruction_data: &[u8],
        ) -> ProgramResult {
            match &instruction_data[0..8] {
                [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_a(accounts),
                [9, 10, 11, 12, 13, 14, 15, 16, ..] => process_b(accounts),
                _ => Err(ProgramError::InvalidInstructionData),
            }
        }
        fn process_a(accounts: &[AccountInfo]) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            if state.data_is_empty() {
                return Err(ProgramError::InvalidAccountData);
            }
            let mut data = state.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
        fn process_b(accounts: &[AccountInfo]) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let data = state.data.borrow();
            if data[0..8] != [9u8, 9, 9, 9, 9, 9, 9, 9] {
                return Err(ProgramError::InvalidAccountData);
            }
            drop(data);
            let mut data = state.data.borrow_mut();
            data[0] = 2;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn sat030_unguarded_pair_is_reported() {
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
            instruction_data: &[u8],
        ) -> ProgramResult {
            match &instruction_data[0..8] {
                [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_a(accounts),
                [9, 10, 11, 12, 13, 14, 15, 16, ..] => process_b(accounts),
                _ => Err(ProgramError::InvalidInstructionData),
            }
        }
        fn process_a(accounts: &[AccountInfo]) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            let mut data = state.data.borrow_mut();
            data[0] = 1;
            Ok(())
        }
        fn process_b(accounts: &[AccountInfo]) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let state = next_account_info(accounts_iter)?;
            if state.data_is_empty() {
                return Err(ProgramError::InvalidAccountData);
            }
            let mut data = state.data.borrow_mut();
            data[0] = 2;
            Ok(())
        }
    "#;
    let (_, findings) = run(src);
    let sat030 = by_rule(&findings, SAT030);
    assert_eq!(sat030.len(), 1, "{findings:?}");
    assert!(sat030[0].description.contains("process_a") && sat030[0].description.contains("process_b"));
}
