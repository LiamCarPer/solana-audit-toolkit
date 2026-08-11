//! Accessor-only sysvar usage: `Clock::get()` reads the sysvar at its
//! well-known fixed address and works WITHOUT a declared `clock` field.
//!
//! This mirrors Jito's live mainnet tip-distribution program: the `claim`
//! handler calls `Clock::get()?` with no `clock` field declared in its
//! Accounts structs, and Anchor's own generated seeds constraint calls
//! `Clock::get().unwrap()` the same way.
//!
//! `sat` must NOT emit a "Missing Sysvar Account" finding for this file.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{clock::Clock, sysvar::Sysvar};

#[program]
pub mod sysvar_accessor_only {
    use super::*;

    /// Mirrors Jito tip-distribution `claim`: accessor call, no clock field.
    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let clock = Clock::get()?;
        if clock.epoch > 0 {
            msg!("claiming in epoch {}", clock.epoch);
        }
        Ok(())
    }

    /// Accessor call chained inline, still no declared clock field.
    pub fn direct(ctx: Context<Direct>) -> Result<()> {
        let ts = Clock::get()?.unix_timestamp;
        msg!("ts {}", ts);
        Ok(())
    }

    /// Fully-qualified accessor path (`sysvar::clock::Clock::get()`).
    pub fn qualified(ctx: Context<Qualified>) -> Result<()> {
        let slot = sysvar::clock::Clock::get()?.slot;
        msg!("slot {}", slot);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub recipient: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct Direct<'info> {
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Qualified<'info> {
    pub authority: Signer<'info>,
}
