//! Approve-only Token-2022 usage: delegates authority via `approve`, moves
//! no balances, triggers no transfer fee. Must NOT produce a transfer-fee
//! bypass finding (delegation is not a transfer).

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022};

#[program]
pub mod token2022_approve_only {
    use super::*;

    pub fn delegate_tokens(ctx: Context<DelegateTokens>, amount: u64) -> Result<()> {
        let cpi_accounts = anchor_spl::token_2022::Approve {
            to: ctx.accounts.token_account.to_account_info(),
            delegate: ctx.accounts.delegate.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token_2022::approve(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DelegateTokens<'info> {
    #[account(mut)]
    pub token_account: InterfaceAccount<'info, TokenAccount>,
    pub delegate: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}
