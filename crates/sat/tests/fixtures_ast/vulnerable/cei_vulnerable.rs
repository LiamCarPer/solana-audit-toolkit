use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[program]
pub mod cei_vuln {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let vault_info = ctx.accounts.vault.to_account_info();

        let vault = &mut ctx.accounts.vault;

        invoke(&anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![],
            data: vec![],
        }, &[vault_info])?;

        vault.balance = vault.balance.saturating_sub(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawVuln<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}
