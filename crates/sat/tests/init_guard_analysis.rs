use sat::types::Severity;

fn run_check(source: &str) -> Vec<sat::types::Finding> {
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);
    let parsed = syn::parse_file(source).unwrap();
    sat::init_guard::check_init_if_needed(&accounts, &[(parsed, "test.rs".to_string())])
}

#[test]
fn test_init_if_needed_without_guard_flagged_high() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.value = 0;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + 40)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;

    let findings = run_check(source);
    let reinit: Vec<_> = findings.iter().filter(|f| f.title.contains("init_if_needed")).collect();
    assert_eq!(reinit.len(), 1, "init_if_needed on authority-bearing account should be flagged");
    assert_eq!(reinit[0].severity, Severity::High);
    assert!(reinit[0].title.contains("without an initialization guard"));
    assert!(reinit[0].description.contains("front-run"));
}

#[test]
fn test_init_if_needed_with_guard_downgraded_to_medium() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        if !state.is_initialized {
            state.authority = ctx.accounts.authority.key();
            state.value = 0;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + 41)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub is_initialized: bool,
    pub value: u64,
}
"#;

    let findings = run_check(source);
    let reinit: Vec<_> = findings.iter().filter(|f| f.title.contains("init_if_needed")).collect();
    assert_eq!(reinit.len(), 1);
    assert_eq!(reinit[0].severity, Severity::Medium, "guard present → downgrade to MEDIUM");
    assert!(reinit[0].title.contains("with an initialization guard"));
}

#[test]
fn test_init_if_needed_on_token_account_not_flagged() {
    let source = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct OpenAccount<'info> {
    #[account(init_if_needed, payer = authority, token::mint = mint, token::authority = authority)]
    pub token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
}
"#;

    let findings = run_check(source);
    let reinit: Vec<_> = findings.iter().filter(|f| f.title.contains("init_if_needed")).collect();
    assert!(reinit.is_empty(), "token accounts are a legitimate init_if_needed use");
}

#[test]
fn test_plain_init_not_flagged() {
    let source = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 40)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;

    let findings = run_check(source);
    let reinit: Vec<_> = findings.iter().filter(|f| f.title.contains("init_if_needed")).collect();
    assert!(reinit.is_empty(), "plain #[account(init)] is not init_if_needed");
}

#[test]
fn test_no_init_if_needed_no_findings() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;

    pub fn update(ctx: Context<Update>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;

    let findings = run_check(source);
    let reinit: Vec<_> = findings.iter().filter(|f| f.title.contains("init_if_needed")).collect();
    assert!(reinit.is_empty());
}

#[test]
fn test_fixture_init_if_needed_flagged() {
    use std::fs;

    let path = "tests/fixtures_ast/vulnerable/init_if_needed.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(&source);
    let parsed = syn::parse_file(&source).unwrap();
    // `analyze_string_for_test` stamps accounts with file "test.rs", so the
    // parsed_files path must match for the same-file scoping to line up.
    let findings = sat::init_guard::check_init_if_needed(&accounts, &[(parsed, "test.rs".to_string())]);

    let reinit: Vec<_> = findings.iter().filter(|f| f.title.contains("init_if_needed")).collect();
    assert!(!reinit.is_empty(), "fixture should produce an init_if_needed finding");
    assert!(reinit.iter().any(|f| f.severity == Severity::High));
}
