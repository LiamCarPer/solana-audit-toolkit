//! Clean native program: every validation anchors to canonical state, so
//! SAT031 must stay silent.
//!
//! The deposit path:
//! - `config` is owner-checked against the program id, making it canonical;
//! - every other account is owner-checked against the canonical config (or the
//!   program id), making their data program-controlled;
//! - the remaining mint/owner comparisons in the validation helper are then
//!   anchored, so no unanchored chain exists.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let config = next_account_info(accounts_iter)?;
    let collateral_mint = next_account_info(accounts_iter)?;
    let collateral_tokens = next_account_info(accounts_iter)?;
    let fee_tokens = next_account_info(accounts_iter)?;

    // Canonical anchors: the config and mint identities are pinned to the
    // program; the token accounts' owners are pinned to the config.
    if config.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if collateral_mint.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if collateral_tokens.owner != config.key {
        return Err(ProgramError::IllegalOwner);
    }
    if fee_tokens.owner != config.key {
        return Err(ProgramError::IllegalOwner);
    }

    validate(config, collateral_tokens, collateral_mint, fee_tokens)?;

    msg!("deposit validated");
    Ok(())
}

/// Every comparison here anchors to an owner-checked account.
fn validate(
    config: &AccountInfo,
    collateral_tokens: &AccountInfo,
    collateral_mint: &AccountInfo,
    fee_tokens: &AccountInfo,
) -> ProgramResult {
    assert_keys_eq!(collateral_tokens.mint, collateral_mint.key);
    assert_keys_eq!(fee_tokens.mint, collateral_tokens.mint);
    assert_keys_eq!(fee_tokens.owner, config.key);
    Ok(())
}
