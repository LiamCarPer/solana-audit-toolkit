use anchor_lang::prelude::*;
use anchor_spl::token::{self, TransferChecked};

#[program]
pub mod token_cpi_fixture {
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
