use anchor_lang::prelude::*;

#[program]
pub mod reinit_control {
    use super::*;

    pub fn create_config(ctx: Context<CreateConfig>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.authority.key();
        Ok(())
    }
}

// Control fixture for the reinit-risk rule: the struct DOES perform Anchor
// initialization (`config` carries `#[account(init)]`), so the rule's core
// value must be preserved — a second sensitive field (`state`) that is
// `mut`-without-`init` must still be flagged as a reinitialization risk.
#[derive(Accounts)]
pub struct CreateConfig<'info> {
    #[account(init, payer = authority, space = 8 + 40)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
}

#[account]
pub struct State {
    pub value: u64,
}
