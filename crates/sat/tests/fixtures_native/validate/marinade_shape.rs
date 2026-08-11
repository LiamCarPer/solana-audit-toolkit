//! Marinade-shape Anchor program regression fixture (SAT033 precision).
//!
//! Mirrors the `liquid-staking-program` benchmark shapes that produced 72
//! spurious "Unanchored Token Mint" findings before the precision fix:
//! - every handler delegates to `ctx.accounts.process(...)` and MULTIPLE
//!   Accounts structs define a `process` impl (the bare-name method-call
//!   leak class),
//! - the mint anchoring happens via Anchor typed accounts and framework
//!   constraints (`has_one` / `token::mint` / `seeds`), not via literal
//!   handler comparisons,
//! - `State` is a plain `#[account]` data struct whose fields (`lp_mint`,
//!   `msol_mint`, ...) must NOT be expanded as account slots.
//!
//! Expected: zero SAT031/SAT033 findings.
use anchor_lang::prelude::*;
use anchor_spl::token::{Burn, Mint, MintTo, Token, TokenAccount, Transfer, mint_to, transfer};

declare_id!("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD");

#[program]
pub mod liquid_staking {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, lamports: u64) -> Result<()> {
        ctx.accounts.process(lamports)
    }

    pub fn change_authority(ctx: Context<ChangeAuthority>) -> Result<()> {
        ctx.accounts.process()
    }

    pub fn remove_liquidity(ctx: Context<RemoveLiquidity>, tokens: u64) -> Result<()> {
        ctx.accounts.process(tokens)
    }
}

/// Plain data struct — NOT an Accounts bundle. Its fields are serialized
/// state columns and must never be expanded as instruction accounts.
#[account]
pub struct State {
    pub msol_mint: Pubkey,
    pub lp_mint: Pubkey,
    pub operational_sol_account: Pubkey,
    pub pause_authority: Pubkey,
    pub msol_supply: u64,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        has_one = msol_mint
    )]
    pub state: Box<Account<'info, State>>,

    #[account(mut)]
    pub msol_mint: Box<Account<'info, Mint>>,

    /// CHECK: PDA
    #[account(
        seeds = [b"msol", state.key().as_ref()],
        bump = state.msol_mint_authority_bump_seed
    )]
    pub msol_mint_authority: UncheckedAccount<'info>,

    /// user mSOL token account
    #[account(
        mut,
        token::mint = state.msol_mint
    )]
    pub mint_to: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> Deposit<'info> {
    pub fn process(&mut self, lamports: u64) -> Result<()> {
        // The mint anchoring is entirely framework-side: the Anchor runtime
        // checks `state.msol_mint == msol_mint.key()` (has_one) and
        // `mint_to.mint == state.msol_mint` (token::mint) before this runs,
        // and the mint authority is a program PDA (seeds).
        mint_to(
            CpiContext::new_with_signer(
                self.token_program.to_account_info(),
                MintTo {
                    mint: self.msol_mint.to_account_info(),
                    to: self.mint_to.to_account_info(),
                    authority: self.msol_mint_authority.to_account_info(),
                },
                &[&[b"msol", &self.state.key().to_bytes(), &[self.state.msol_mint_authority_bump_seed]]],
            ),
            lamports,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ChangeAuthority<'info> {
    #[account(
        mut,
        has_one = admin_authority
    )]
    pub state: Box<Account<'info, State>>,
    pub admin_authority: Signer<'info>,
}

impl<'info> ChangeAuthority<'info> {
    pub fn process(&mut self) -> Result<()> {
        // No token CPI here. Before the fix, this instruction still reported
        // `lp_mint`/`msol_mint` — leaked from other structs' process impls
        // through the State data-struct expansion.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RemoveLiquidity<'info> {
    #[account(mut)]
    pub state: Box<Account<'info, State>>,

    /// CHECK: PDA
    #[account(
        mut,
        seeds = [b"sol_leg", state.key().as_ref()],
        bump = state.sol_leg_bump_seed
    )]
    pub liq_pool_sol_leg_pda: SystemAccount<'info>,

    #[account(
        mut,
        token::mint = state.lp_mint
    )]
    pub burn_from: Box<Account<'info, TokenAccount>>,
    pub burn_from_authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> RemoveLiquidity<'info> {
    pub fn process(&mut self, tokens: u64) -> Result<()> {
        // System lamport transfer: `Transfer` without an `authority` field —
        // a lamport source, not a token account (the system-vs-token Transfer
        // name collision class).
        transfer(
            CpiContext::new_with_signer(
                self.system_program.to_account_info(),
                Transfer {
                    from: self.liq_pool_sol_leg_pda.to_account_info(),
                    to: self.state.operational_sol_account.to_account_info(),
                },
                &[&[b"sol_leg", &self.state.key().to_bytes(), &[self.state.sol_leg_bump_seed]]],
            ),
            tokens,
        )?;

        // Token burn whose source mint is pinned by `token::mint`.
        anchor_spl::token::burn(
            CpiContext::new(
                self.token_program.to_account_info(),
                Burn {
                    mint: self.state.lp_mint.to_account_info(),
                    from: self.burn_from.to_account_info(),
                    authority: self.burn_from_authority.to_account_info(),
                },
            ),
            tokens,
        )?;
        Ok(())
    }
}
