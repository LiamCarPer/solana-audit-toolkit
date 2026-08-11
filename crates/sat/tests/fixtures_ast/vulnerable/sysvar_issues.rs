use anchor_lang::prelude::*;
use anchor_lang::solana_program::{sysvar::Sysvar, sysvar::clock::Clock};

#[program]
pub mod test_sysvar {
    use super::*;

    pub fn get_time(ctx: Context<GetTime>) -> Result<()> {
        let clock = Clock::get()?;
        msg!("Current timestamp: {}", clock.unix_timestamp);
        Ok(())
    }

    pub fn use_rent(ctx: Context<UseRent>) -> Result<()> {
        let rent = Rent::get()?;
        msg!("Rent: {:?}", rent);
        Ok(())
    }

    pub fn pass_clock(ctx: Context<PassClock>) -> Result<()> {
        // Non-accessor reference: `ctx.accounts.clock` requires a declared
        // `clock` field in the Accounts struct. Unlike the `Clock::get()`
        // accessor above (which reads the sysvar at its fixed address and
        // needs no declared account), this is a genuine Anchor constraint
        // failure.
        let clock_info = ctx.accounts.clock.to_account_info();
        msg!("clock key: {}", clock_info.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct GetTime<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UseRent<'info> {
    pub authority: Signer<'info>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct PassClock<'info> {
    pub authority: Signer<'info>,
}
