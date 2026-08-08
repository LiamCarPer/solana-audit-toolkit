//! Byte-slice dispatch: `match &instruction_data[0..8]` with
//! `[a, b, c, d, e, f, g, h, ..]`-style arms calling per-instruction
//! handlers, plus a literal-discriminator arm and a fallback arm.
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
    instruction_data: &[u8],
) -> ProgramResult {
    match &instruction_data[0..8] {
        [a, b, c, d, e, f, g, h, ..] => process_deposit(program_id, accounts, instruction_data),
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_withdraw(program_id, accounts),
        [9, 9, 9, 9, 9, 9, 9, 9, ..] => Err(ProgramError::InvalidInstructionData),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_deposit(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    Ok(())
}

fn process_withdraw(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let vault = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;

    Ok(())
}
