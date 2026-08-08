//! Helper call graph: validation helpers taking `&AccountInfo` that perform
//! the signer/owner checks on behalf of the handler.
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

fn check_signer(account: &AccountInfo) -> Result<(), ProgramError> {
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

fn check_owner(account: &AccountInfo, expected: &Pubkey) -> Result<(), ProgramError> {
    if account.owner != expected {
        return Err(ProgramError::IllegalOwner);
    }
    Ok(())
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let admin = next_account_info(accounts_iter)?;

    check_signer(&authority)?;
    check_owner(&state, program_id)?;

    Ok(())
}
