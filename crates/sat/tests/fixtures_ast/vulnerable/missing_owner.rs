use anchor_lang::prelude::*;

#[program]
pub mod test_unchecked {
    use super::*;

    pub fn process(ctx: Context<ProcessUnchecked>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProcessUnchecked<'info> {
    #[account(mut)]
    pub raw_account: AccountInfo<'info>,
    #[account(signer)]
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProcessUnsafe<'info> {
    #[account(mut)]
    pub raw_account: UncheckedAccount<'info>,
}
