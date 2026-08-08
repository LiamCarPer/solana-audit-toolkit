use anchor_lang::prelude::*;

#[program]
pub mod check_documented {
    use super::*;

    pub fn init_pool(ctx: Context<InitPool>) -> Result<()> {
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(init, payer = payer, space = 8 + 32)]
    pub pool: Account<'info, Pool>,
    /// The issue authority.
    /// CHECK: this is handled by the program's Validate implementation.
    pub issue_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    /// CHECK: Arbitrary.
    pub mint_authority: UncheckedAccount<'info>,
    /// This authority is NOT documented and NOT validated.
    pub withdraw_authority: UncheckedAccount<'info>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
}
