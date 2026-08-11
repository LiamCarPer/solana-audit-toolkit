//! Marinade-shape Anchor program regression fixture (SAT032 precision).
//!
//! Mirrors the `liquid-staking-program` benchmark shapes that produced 5
//! spurious "Permissionless State Creation" findings before the precision
//! fix:
//! - `stake_reserve` / `deactivate_stake` create a stake account
//!   (`#[account(init, ...)]`) while recording `stake_deposit_authority` /
//!   `stake_withdraw_authority` — but those slots are `#[account(seeds = ...,
//!   bump = ...)]` program-derived addresses, NOT caller-chosen keys,
//! - the standard `init` + `payer = <Signer>` + `system_program` wiring is
//!   present throughout (the payer only pays rent and is signer-pinned).
//!
//! Expected: zero SAT032 findings. (The Cashio `new_bank` shape — plain
//! `UncheckedAccount` authority slots without `seeds` — is covered by
//! `vuln.rs` and must KEEP firing.)
use anchor_lang::prelude::*;
use anchor_lang::solana_program::stake;

declare_id!("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD");

#[program]
pub mod liquid_staking {
    use super::*;

    pub fn stake_reserve(ctx: Context<StakeReserve>, validator_index: u32) -> Result<()> {
        ctx.accounts.process(validator_index)
    }

    pub fn deactivate_stake(ctx: Context<DeactivateStake>, stake_index: u32) -> Result<()> {
        ctx.accounts.process(stake_index)
    }
}

#[account]
pub struct State {
    pub reserve_bump_seed: u8,
    pub stake_deposit_bump_seed: u8,
    pub stake_withdraw_bump_seed: u8,
}

#[derive(Accounts)]
pub struct StakeReserve<'info> {
    #[account(mut)]
    pub state: Box<Account<'info, State>>,

    #[account(
        mut,
        seeds = [b"reserve", state.key().as_ref()],
        bump = state.reserve_bump_seed
    )]
    pub reserve_pda: SystemAccount<'info>,

    #[account(
        init,
        payer = rent_payer,
        space = 200,
        owner = stake::program::ID
    )]
    pub stake_account: Account<'info, StakeAccount>,

    /// CHECK: PDA
    #[account(
        seeds = [b"deposit", state.key().as_ref()],
        bump = state.stake_deposit_bump_seed
    )]
    pub stake_deposit_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub rent_payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub stake_program: Program<'info, Stake>,
}

impl<'info> StakeReserve<'info> {
    pub fn process(&mut self, validator_index: u32) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DeactivateStake<'info> {
    #[account(mut)]
    pub state: Box<Account<'info, State>>,

    #[account(
        init,
        payer = split_stake_rent_payer,
        space = 200,
        owner = stake::program::ID
    )]
    pub split_stake_account: Account<'info, StakeAccount>,

    /// CHECK: PDA
    #[account(
        seeds = [b"deposit", state.key().as_ref()],
        bump = state.stake_deposit_bump_seed
    )]
    pub stake_deposit_authority: UncheckedAccount<'info>,

    /// CHECK: PDA
    #[account(
        seeds = [b"withdraw", state.key().as_ref()],
        bump = state.stake_withdraw_bump_seed
    )]
    pub stake_withdraw_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        owner = system_program::ID
    )]
    pub split_stake_rent_payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub stake_program: Program<'info, Stake>,
}

impl<'info> DeactivateStake<'info> {
    pub fn process(&mut self, stake_index: u32) -> Result<()> {
        Ok(())
    }
}
