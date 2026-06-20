use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::{Sysvar, clock::Clock};

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
