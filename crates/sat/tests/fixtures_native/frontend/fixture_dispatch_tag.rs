//! u8 tag dispatch: `match instruction_data[0]` with integer arms; the
//! frontend falls back to `instruction_0x<tag>` names.
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
    match instruction_data[0] {
        0 => process_close(accounts),
        1 => process_update(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_close(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;

    Ok(())
}

fn process_update(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;

    if vault.key != state.key {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}
