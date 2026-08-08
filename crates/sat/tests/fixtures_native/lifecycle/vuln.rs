//! Vulnerable native program for the R3 lifecycle rules:
//! - SAT024: `process_close` closes `state` with a zero-length realloc while
//!   `process_deposit` writes the same account with no re-init guard.
//! - SAT025: `process_deposit` deserializes `state` with `try_from_slice` on
//!   an owner-unchecked account and never validates the discriminator.
//! - SAT026: `process_deposit` updates the balance with a raw `+=`.
//! - SAT027: `process_tick` borrows the `clock` sysvar mutably (a writable
//!   runtime builtin).
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
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data[0..8] {
        [1, 0, 0, 0, 0, 0, 0, 0] => process_close(_program_id, accounts, instruction_data),
        [2, 0, 0, 0, 0, 0, 0, 0] => process_deposit(_program_id, accounts, instruction_data),
        [3, 0, 0, 0, 0, 0, 0, 0] => process_tick(_program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// SAT024: closes `state` with `realloc(0)` — no `data_is_empty` /
/// discriminator guard anywhere, even though `process_deposit` writes the
/// same account.
pub fn process_close(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let state = next_account_info(accounts_iter)?;

    state.realloc(0, false)?;
    Ok(())
}

/// SAT024 (the other writer) + SAT025 + SAT026: writes `state` after
/// deserializing it from an owner-unchecked account, and bumps the balance
/// with a raw `+=`.
pub fn process_deposit(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let state = next_account_info(accounts_iter)?;

    let amount = u64::from_le_bytes(instruction_data[8..16].try_into().unwrap());

    let mut data = state.data.borrow_mut();
    let mut s: State = State::try_from_slice(&data)?;

    s.total += amount;

    data.copy_from_slice(&s.to_bytes());
    Ok(())
}

/// SAT027: the `clock` sysvar is borrowed mutably and written.
pub fn process_tick(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let clock = next_account_info(accounts_iter)?;

    let mut data = clock.data.borrow_mut();
    data[0] = 1;
    Ok(())
}

/// Minimal state type; the fixture only needs to parse.
struct State {
    total: u64,
}

impl State {
    fn to_bytes(&self) -> Vec<u8> {
        self.total.to_le_bytes().to_vec()
    }
}
