//! Control for the SAT028 suppression: a token transfer CPI over plain
//! `invoke` (no seeds) whose non-PDA authority is neither signer-checked,
//! never compared against a stored/derived key, and not marked as a signer in
//! its AccountMeta. SAT028 must STILL fire.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

declare_id!("UnaCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    match &instruction_data[0..8] {
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_transfer(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_transfer(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let source = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    // SAT028: no signer check, no key comparison, AccountMeta signer = false,
    // and the CPI uses plain `invoke` — the caller can name any account as
    // the authority.
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(source.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), false),
        ],
        data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
    };
    invoke(&ix, &[source.clone(), destination.clone(), authority.clone()])?;
    Ok(())
}
