use anchor_lang::prelude::*;

#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[program]
pub mod close_vuln {
    use super::*;

    pub fn close_vault(ctx: Context<CloseVaultInsecure>) -> Result<()> {
        let vault_info = ctx.accounts.vault.to_account_info();
        let authority_info = ctx.accounts.authority.to_account_info();

        let vault_lamports = vault_info.lamports();
        **vault_info.try_borrow_mut_lamports()? = 0;
        **authority_info.try_borrow_mut_lamports()? = authority_info
            .lamports()
            .checked_add(vault_lamports)
            .ok_or(ErrorCode::Overflow)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct CloseVaultInsecure<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Overflow")]
    Overflow,
}
