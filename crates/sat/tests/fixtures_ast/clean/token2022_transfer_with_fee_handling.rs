//! Token-2022 transfer WITH explicit transfer-fee handling: reads the
//! `TransferFeeConfig` extension, computes the fee with `calculate_fee`, and
//! transfers the post-fee amount. Must NOT produce a transfer-fee bypass
//! finding.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, TransferChecked};
use spl_token_2022::extension::transfer_fee::TransferFeeConfig;

#[program]
pub mod token2022_transfer_with_fee_handling {
    use super::*;

    pub fn transfer_tokens_with_fee(ctx: Context<TransferTokensWithFee>, amount: u64) -> Result<()> {
        let fee_config = ctx.accounts.mint.get_extension::<TransferFeeConfig>()?;
        let transfer_fee = fee_config.get_transfer_fee(Clock::get()?.epoch)?;
        let fee = transfer_fee.calculate_fee(amount);
        let amount_after_fee = amount.checked_sub(fee).ok_or(ProgramError::InvalidArgument)?;

        let cpi_accounts = TransferChecked {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token_2022::transfer_checked(cpi_ctx, amount_after_fee, 9)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokensWithFee<'info> {
    #[account(mut)]
    pub from: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub to: InterfaceAccount<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Program<'info, Token2022>,
}
