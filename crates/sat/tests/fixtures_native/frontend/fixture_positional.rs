//! Positional iterator pattern: `next_account_info` over a tracked
//! `&mut accounts.iter()` iterator, with a signer guard, an owner guard, a
//! key-equality guard against a derived PDA, and a `system_program` check.
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
    let payer = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let (pda, _bump) = Pubkey::find_program_address(&[b"vault", authority.key.as_ref()], program_id)?;
    if vault.key != pda {
        return Err(ProgramError::InvalidSeeds);
    }

    if system_program.key != solana_program::system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}
