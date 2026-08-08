use sat::types::Severity;

fn run_check(source: &str) -> Vec<sat::types::Finding> {
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);
    let parsed = syn::parse_file(source).unwrap();
    sat::deserialization::check_manual_deserialization(&accounts, &[(parsed, "test.rs".to_string())])
}

#[test]
fn test_unowned_account_info_deserialized_flagged_high() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn process(ctx: Context<Process>) -> Result<()> {
        let data = ctx.accounts.user.try_borrow_data()?;
        let parsed = UserState::try_from_slice(&data)?;
        msg!("{:?}", parsed);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    #[account(mut)]
    pub user: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub struct UserState {
    pub balance: u64,
}
"#;

    let findings = run_check(source);
    let deser: Vec<_> = findings.iter().filter(|f| f.title.contains("Manual Deserialization")).collect();
    assert_eq!(deser.len(), 1, "deserializing an unowned AccountInfo should be flagged");
    assert_eq!(deser[0].severity, Severity::High);
    assert!(deser[0].title.contains("Process::user"));
    assert!(deser[0].title.contains("without an owner constraint"));
}

#[test]
fn test_typed_account_manually_deserialized_flagged_medium() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn process(ctx: Context<Process>) -> Result<()> {
        let parsed = State::try_from_slice(&ctx.accounts.state.data.borrow())?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub value: u64,
}
"#;

    let findings = run_check(source);
    let deser: Vec<_> = findings.iter().filter(|f| f.title.contains("Manual Deserialization")).collect();
    assert_eq!(deser.len(), 1, "raw deserialization of a typed account should be flagged");
    assert_eq!(deser[0].severity, Severity::Medium);
    assert!(deser[0].title.contains("Process::state"));
}

#[test]
fn test_typed_account_normal_access_clean() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn process(ctx: Context<Process>) -> Result<()> {
        ctx.accounts.state.value = 42;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub value: u64,
}
"#;

    let findings = run_check(source);
    let deser: Vec<_> = findings.iter().filter(|f| f.title.contains("Manual Deserialization")).collect();
    assert!(deser.is_empty(), "typed access via the accounts wrapper is fine");
}

#[test]
fn test_instruction_arg_deserialization_clean() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn process(ctx: Context<Process>, data: Vec<u8>) -> Result<()> {
        let args = MyArgs::try_from_slice(&data)?;
        msg!("{:?}", args);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    pub authority: Signer<'info>,
}

pub struct MyArgs {
    pub amount: u64,
}
"#;

    let findings = run_check(source);
    let deser: Vec<_> = findings.iter().filter(|f| f.title.contains("Manual Deserialization")).collect();
    assert!(deser.is_empty(), "deserializing instruction args is normal");
}

#[test]
fn test_owned_account_info_manual_deserialize_clean() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn process(ctx: Context<Process>) -> Result<()> {
        let data = ctx.accounts.user.try_borrow_data()?;
        let parsed = UserState::try_from_slice(&data)?;
        msg!("{:?}", parsed);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    #[account(mut, owner = my_program::ID)]
    pub user: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub struct UserState {
    pub balance: u64,
}
"#;

    let findings = run_check(source);
    let deser: Vec<_> = findings.iter().filter(|f| f.title.contains("Manual Deserialization")).collect();
    assert!(deser.is_empty(), "owner constraint on the raw account mitigates spoofing");
}

#[test]
fn test_fixture_manual_deserialize_flagged() {
    use std::fs;

    let path = "tests/fixtures_ast/vulnerable/manual_deserialize.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(&source);
    let parsed = syn::parse_file(&source).unwrap();
    // `analyze_string_for_test` stamps accounts with file "test.rs", so the
    // parsed_files path must match for the same-file scoping to line up.
    let findings = sat::deserialization::check_manual_deserialization(&accounts, &[(parsed, "test.rs".to_string())]);

    let deser: Vec<_> = findings.iter().filter(|f| f.title.contains("Manual Deserialization")).collect();
    assert!(!deser.is_empty(), "fixture should produce a Manual Deserialization finding");
    assert!(deser.iter().any(|f| f.severity == Severity::High));
}
