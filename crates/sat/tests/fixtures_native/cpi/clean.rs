//! Clean native program: the same CPI/state patterns with every guard
//! present — SAT028 (authority signer-checked in the handler AND marked as a
//! signer in its AccountMeta), no self-invocation, SAT030 (both state writers
//! guarded: `data_is_empty()` and a `data[0..8] == DISCRIMINATOR`-style
//! compare).
//!
//! Dispatch (byte-slice discriminators):
//! - `process_transfer` — signer-guarded token transfer CPI, guarded state
//!   write.
//! - `process_withdraw` — discriminator-guarded state write.
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

declare_id!("CleanCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

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

    // SAT028 guard: the transfer authority must sign.
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SAT020 guard: `state` must be owned by this program.
    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // SAT030 guard: only initialize a fresh account.
    if state.data_is_empty() {
        msg!("initializing state");
    }

    // SAT023 guard: effects before interactions — write state first.
    {
        let mut data = state.data.borrow_mut();
        data[0] = 1;
    }

    let transfer_ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(source.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), true),
        ],
        data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
    };
    invoke(&transfer_ix, &[source.clone(), destination.clone(), authority.clone()])?;

    Ok(())
}

fn process_withdraw(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;

    // SAT020 guard: `state` must be owned by this program.
    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // SAT030 guard: the discriminator must already be present.
    let data = state.data.borrow();
    if data[0..8] != [9u8, 9, 9, 9, 9, 9, 9, 9] {
        return Err(ProgramError::InvalidAccountData);
    }
    drop(data);

    let mut data = state.data.borrow_mut();
    data[0] = 2;

    Ok(())
}
