//! Clean native program: the same three accounts with all authentication
//! guards present — a signer check, an owner check, and a key comparison.
//!
//! Positional `next_account_info` accounts:
//! - `authority` — `if !authority.is_signer { ... }` guard (kills SAT019).
//! - `state` — `state.owner == program_id` guard (kills SAT020); still written.
//! - `owner` — `owner.key == expected_owner.key` compare (kills SAT021).
//! - `expected_owner` — the key `owner` is compared against (also pinned).
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let owner = next_account_info(accounts_iter)?;
    let expected_owner = next_account_info(accounts_iter)?;

    // SAT019 guard: the authority must sign.
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SAT020 guard: the state account must be owned by this program.
    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // SAT021 guard: the owner account must be the expected key.
    if owner.key != expected_owner.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut data = state.data.borrow_mut();
    data[0] = 1;

    Ok(())
}
