//! Clean Anchor program: SAT032 must stay silent — the creation instruction
//! records signer-pinned authorities only.
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

    pub fn set_admin(ctx: Context<SetAdmin>, bump: u8) -> Result<()> {
        ctx.accounts.bank.bump = bump;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct NewBank<'info> {
    #[account(init, payer = payer, seeds = [b"bank", payer.key().as_ref()], bump)]
    pub bank: Account<'info, Bank>,
    pub admin: Signer<'info>,
    pub brrr_issue_authority: Signer<'info>,
    pub burn_withdraw_authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// A non-creating instruction with an unchecked authority slot must NOT fire
/// (SAT032 is scoped to state-creation instructions).
#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut)]
    pub bank: Account<'info, Bank>,
    /// CHECK: only used after creation; the creation path pinned the key.
    pub admin: UncheckedAccount<'info>,
}

#[account]
pub struct Bank {
    pub bump: u8,
}
