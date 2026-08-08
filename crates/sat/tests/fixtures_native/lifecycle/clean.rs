//! Clean native program: every R3 lifecycle hazard is guarded.
//! - SAT024: `process_close` closes `state` only after a `data_is_empty` and
//!   a discriminator re-init guard.
//! - SAT025: `process_deposit` verifies the owner of `state` before
//!   deserializing, then re-validates the discriminator.
//! - SAT026: balance updates use `checked_add`.
//! - SAT027: the `clock` sysvar is only read, never borrowed mutably.
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

const STATE_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

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

/// SAT024 (clean): closing is gated by a `data_is_empty` check and a
/// discriminator comparison before the zero-length realloc.
pub fn process_close(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let state = next_account_info(accounts_iter)?;

    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if state.data_is_empty() {
        return Err(ProgramError::UninitializedAccount);
    }
    let data = &state.data.borrow();
    if data[0..8] != STATE_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    drop(data);

    state.realloc(0, false)?;
    Ok(())
}

/// SAT024 (other writer) + SAT025 + SAT026 (clean): owner-checked,
/// discriminator-validated deserialization and a `checked_add` balance
/// update.
pub fn process_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let state = next_account_info(accounts_iter)?;

    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let amount = u64::from_le_bytes(instruction_data[8..16].try_into().unwrap());

    let data = &mut state.data.borrow_mut();
    if data[0..8] != STATE_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut s: State = State::try_from_slice(&data)?;
    s.total = s.total.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    data.copy_from_slice(&s.to_bytes());
    Ok(())
}

/// SAT027 (clean): the `clock` sysvar is only read.
pub fn process_tick(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let clock = next_account_info(accounts_iter)?;

    let data = &clock.data.borrow();
    let _slot = u64::from_le_bytes(data[8..16].try_into().unwrap());
    Ok(())
}

/// Minimal state type; the fixture only needs to parse.
struct State {
    discriminator: [u8; 8],
    total: u64,
}

impl State {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.discriminator);
        out.extend_from_slice(&self.total.to_le_bytes());
        out
    }
}
