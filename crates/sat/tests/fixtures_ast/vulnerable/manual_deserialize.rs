use anchor_lang::prelude::*;

#[program]
pub mod manual_deserialize_fixture {
    use super::*;

    pub fn process(ctx: Context<Process>) -> Result<()> {
        let data = ctx.accounts.user.try_borrow_data()?;
        let parsed = UserState::try_from_slice(&data)?;
        msg!("{:?}", parsed);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Process<'info> {
    #[account(mut)]
    pub user: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub struct UserState {
    pub balance: u64,
}
