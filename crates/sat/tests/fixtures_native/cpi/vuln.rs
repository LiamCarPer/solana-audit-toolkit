//! Vulnerable native program: SAT028 (token CPI unverified authority),
//! SAT029 (self-invocation) and SAT030 (cross-instruction state reuse).
//!
//! Dispatch (byte-slice discriminators):
//! - `process_transfer` — writes `state` with NO init guard, performs a token
//!   transfer CPI (Instruction-array style) whose authority AccountMeta is
//!   neither signer-checked nor key-compared, and self-invokes its own
//!   declared program id.
//! - `process_withdraw` — writes the same `state` account guarded by a
//!   `data_is_empty()` check (so SAT030 fires because the *other* writer is
//!   unguarded).
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

declare_id!("CPICzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match &instruction_data[0..8] {
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_transfer(program_id, accounts),
        [9, 10, 11, 12, 13, 14, 15, 16, ..] => process_withdraw(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_transfer(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let source = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    // SAT030: `state` is written without any init/discriminator guard — a
    // leftover or re-created account is accepted as if it were fresh.
    let mut data = state.data.borrow_mut();
    data[0] = 1;

    // SAT028: token transfer CPI whose authority AccountMeta is neither a
    // signer nor compared against a known key anywhere in the handler.
    let transfer_ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(source.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), false),
        ],
        data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
    };
    invoke(&transfer_ix, &[source.clone(), destination.clone(), authority.clone()])?;

    // SAT029: the program invokes an instruction targeting its own declared id.
    let self_ix = Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new(state.key(), true)],
        data: vec![9u8, 9, 9, 9, 9, 9, 9, 9],
    };
    invoke(&self_ix, &[state.clone()])?;

    msg!("transferred");
    Ok(())
}

fn process_withdraw(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;

    // Guarded writer: the account must be fresh before the write. SAT030
    // still fires because `process_transfer` writes the same account without
    // any guard.
    if state.data_is_empty() {
        msg!("initializing state");
    }

    let mut data = state.data.borrow_mut();
    data[0] = 2;

    Ok(())
}
