use anchor_lang::prelude::*;

#[program]
pub mod test_auth {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, value: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.value = value;
        state.authority = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn update_value(ctx: Context<UpdateValue>, new_value: u64) -> Result<()> {
        ctx.accounts.state.value = new_value;
        Ok(())
    }

    pub fn close_state(_ctx: Context<CloseState>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 40)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateValue<'info> {
    pub state: Account<'info, State>,
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseState<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub closer: AccountInfo<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
