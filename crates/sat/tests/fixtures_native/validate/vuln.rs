//! Vulnerable native program: SAT031 — Self-Referential Validation (Cashio
//! class).
//!
//! The deposit path validates mint/owner identity by comparing caller-supplied
//! accounts to each other only:
//! - `collateral_tokens.mint == collateral_mint.key`
//! - `fee_tokens.mint == fee_mint.key`
//! - `collateral_tokens.owner != fee_tokens.owner`
//! - `collateral_mint.key == fee_mint.key` (inline)
//!
//! No comparison anchors to the program id, a constant, an owner check, or a
//! literal-seed PDA — so a fully self-consistent chain of fabricated accounts
//! passes validation (the Cashio shape: `depositor_source.mint ==
//! collateral.mint` etc.).
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

    let collateral_mint = next_account_info(accounts_iter)?;
    let collateral_tokens = next_account_info(accounts_iter)?;
    let fee_mint = next_account_info(accounts_iter)?;
    let fee_tokens = next_account_info(accounts_iter)?;

    // SAT031: the whole validation is a self-referential chain.
    validate(collateral_tokens, collateral_mint, fee_tokens, fee_mint)?;

    if collateral_mint.key == fee_mint.key {
        return Err(ProgramError::InvalidAccountData);
    }

    msg!("deposit validated");
    Ok(())
}

/// Validates the deposit by comparing caller-supplied accounts to each other.
fn validate(
    collateral_tokens: &AccountInfo,
    collateral_mint: &AccountInfo,
    fee_tokens: &AccountInfo,
    fee_mint: &AccountInfo,
) -> ProgramResult {
    assert_keys_eq!(collateral_tokens.mint, collateral_mint.key);
    assert_keys_eq!(fee_tokens.mint, fee_mint.key);
    if collateral_tokens.owner != fee_tokens.owner {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
