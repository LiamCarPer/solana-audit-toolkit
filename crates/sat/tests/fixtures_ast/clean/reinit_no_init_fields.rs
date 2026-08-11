use anchor_lang::prelude::*;

#[program]
pub mod reinit_clean {
    use super::*;

    pub fn create_canonical_stake(ctx: Context<CreateCanonicalStake>, source_stake_index: u32, validator_index: u32) -> Result<()> {
        // Account creation happens entirely via stake-program CPI from the
        // stake account split below; no Anchor `init` happens in this struct.
        let _ = (source_stake_index, validator_index);
        Ok(())
    }
}

// Mirrors Marinade's `CreateCanonicalStake`: the name matches the
// init/create heuristic and every mutable field is `mut`-without-`init`,
// but the struct performs NO Anchor initialization at all (no field carries
// `#[account(init)]`). There is nothing an attacker could re-initialize, so
// the reinit-risk rule must not fire.
#[derive(Accounts)]
pub struct CreateCanonicalStake<'info> {
    #[account(
        mut,
        has_one = operational_sol_account
    )]
    pub state: Box<Account<'info, State>>,
    /// CHECK: PDA, created via split from source account
    #[account(mut)]
    pub canonical_stake: UncheckedAccount<'info>,
    /// CHECK: not important
    #[account(mut)]
    pub operational_sol_account: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct State {
    pub operational_sol_account: Pubkey,
}
