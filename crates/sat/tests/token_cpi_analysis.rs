use sat::types::Severity;

fn run_check(source: &str) -> Vec<sat::types::Finding> {
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);
    let parsed = syn::parse_file(source).unwrap();
    sat::token_cpi::check_token_cpi(&accounts, &[(parsed, "test.rs".to_string())])
}

#[test]
fn test_transfer_checked_with_unconstrained_authority_flagged_high() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{self, TransferChecked};

#[program]
pub mod my_program {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer_checked(cpi_ctx, amount, 9)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: AccountInfo<'info>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"#;

    let findings = run_check(source);
    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert_eq!(cpi.len(), 1, "transfer CPI with unconstrained authority should be flagged");
    assert_eq!(cpi[0].severity, Severity::High);
    assert!(cpi[0].title.contains("TransferTokens::authority"));
    assert!(cpi[0].title.contains("transfer_checked"));
}

#[test]
fn test_transfer_checked_with_signer_authority_clean() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{self, TransferChecked};

#[program]
pub mod my_program {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer_checked(cpi_ctx, amount, 9)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"#;

    let findings = run_check(source);
    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert!(cpi.is_empty(), "Signer authority satisfies the check");
}

#[test]
fn test_seeded_pda_authority_clean() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{self, TransferChecked};

#[program]
pub mod my_program {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer_checked(cpi_ctx, amount, 9)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    #[account(seeds = [b"auth"])]
    pub authority: AccountInfo<'info>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"#;

    let findings = run_check(source);
    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert!(cpi.is_empty(), "seeded PDA authority satisfies the check");
}

#[test]
fn test_system_program_transfer_not_flagged() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer};

#[program]
pub mod my_program {
    use super::*;

    pub fn transfer_sol(ctx: Context<TransferSol>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi_accounts);
        system_program::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferSol<'info> {
    #[account(mut)]
    pub from: AccountInfo<'info>,
    #[account(mut)]
    pub to: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
"#;

    let findings = run_check(source);
    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert!(cpi.is_empty(), "system_program::transfer is not a token CPI");
}

#[test]
fn test_authority_not_from_ctx_accounts_skipped() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{self, TransferChecked};

#[program]
pub mod my_program {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
        let spoofer = Pubkey::new_unique();
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: spoofer.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer_checked(cpi_ctx, amount, 9)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: AccountInfo<'info>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"#;

    let findings = run_check(source);
    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert!(cpi.is_empty(), "authority not resolvable to an accounts field → skip");
}

#[test]
fn test_set_authority_with_unconstrained_authority_flagged() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{self, SetAuthority};

#[program]
pub mod my_program {
    use super::*;

    pub fn set_new_authority(ctx: Context<SetAuthority>, new_authority: Pubkey) -> Result<()> {
        let cpi_accounts = SetAuthority {
            account: ctx.accounts.token_account.to_account_info(),
            current_authority: ctx.accounts.current_authority.to_account_info(),
            new_authority: ctx.accounts.new_authority.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::set_authority(cpi_ctx, spl_token::instruction::AuthorityType::AccountOwner, new_authority)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetAuthority<'info> {
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    pub current_authority: AccountInfo<'info>,
    pub new_authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}
"#;

    let findings = run_check(source);
    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert_eq!(cpi.len(), 1, "set_authority with unconstrained current_authority should be flagged");
    assert!(cpi[0].title.contains("set_authority"));
    assert!(cpi[0].title.contains("SetAuthority::current_authority"));
}

#[test]
fn test_canary_token2022_fixture_stays_clean() {
    use std::fs;

    let path = "tests/fixtures_ast/vulnerable/token2022_transfer.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(&source);
    let parsed = syn::parse_file(&source).unwrap();
    let findings = sat::token_cpi::check_token_cpi(&accounts, &[(parsed, path.to_string())]);

    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert!(cpi.is_empty(), "the canary fixture declares authority as Signer — must stay clean");
}

#[test]
fn test_fixture_token_cpi_authority_flagged() {
    use std::fs;

    let path = "tests/fixtures_ast/vulnerable/token_cpi_authority.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(&source);
    let parsed = syn::parse_file(&source).unwrap();
    // `analyze_string_for_test` stamps accounts with file "test.rs", so the
    // parsed_files path must match for the same-file scoping to line up.
    let findings = sat::token_cpi::check_token_cpi(&accounts, &[(parsed, "test.rs".to_string())]);

    let cpi: Vec<_> = findings.iter().filter(|f| f.title.contains("Token Transfer CPI")).collect();
    assert!(!cpi.is_empty(), "fixture should produce a Token Transfer CPI finding");
    assert!(cpi.iter().any(|f| f.severity == Severity::High));
}
