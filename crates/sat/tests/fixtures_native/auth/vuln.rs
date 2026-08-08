//! Vulnerable native program: SAT019 (unverified signer), SAT020 (unverified
//! owner), SAT021 (unchecked authority key).
//!
//! Positional `next_account_info` accounts:
//! - `authority` — used on a privileged path with NO `is_signer` check (SAT019).
//! - `state` — data written with NO owner check (SAT020).
//! - `owner` — never compared to a stored/derived key and not signer-checked
//!   (SAT021).
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let owner = next_account_info(accounts_iter)?;

    // SAT020: `state` data is written without any owner check — an account
    // owned by any program can be passed here.
    let mut data = state.data.borrow_mut();
    data[0] = 1;

    // SAT019: `authority` gates a privileged path but its signature is never
    // verified.
    msg!("transferring authority: {}", authority.key);

    // SAT021: `owner` is never compared against a stored/derived key and is
    // not signer-checked either.
    msg!("owner: {}", owner.key);

    Ok(())
}
