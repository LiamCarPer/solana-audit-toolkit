//! Vulnerable Anchor program: SAT032 — Permissionless State Creation (the
//! `new_bank` half of Cashio).
//!
//! `new_bank` creates a bank account (`#[account(init)]`) and records
//! caller-chosen keys (`admin`, `brrr_issue_authority`,
//! `burn_withdraw_authority`) as authorities — all `UncheckedAccount` with
//! `CHECK:` doc comments. Any caller can mint a fully self-consistent bank.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real anchor crates.
use anchor_lang::prelude::*;

#[program]
pub mod bankman {
    use super::*;

    pub fn new_bank(ctx: Context<NewBank>, bump: u8) -> Result<()> {
        ctx.accounts.bank.bump = bump;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct NewBank<'info> {
    #[account(init, payer = payer, seeds = [b"bank", payer.key().as_ref()], bump)]
    pub bank: Account<'info, Bank>,
    /// CHECK: the bank records this caller-chosen key as its authority.
    pub admin: UncheckedAccount<'info>,
    /// CHECK: issue authority for the crate program.
    pub brrr_issue_authority: UncheckedAccount<'info>,
    /// CHECK: burn authority for the crate program.
    pub burn_withdraw_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Bank {
    pub bump: u8,
}
