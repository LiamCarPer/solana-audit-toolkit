//! Subscript access pattern: `accounts[i]` with literal indices, a range
//! slice, a `&mut` binding, and a `borrow_mut` data write.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let state = &accounts[0];
    let authority = &accounts[1];
    let payer = &mut accounts[2];
    let token_account = &accounts[3];
    let _rest = &accounts[4..];

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut data = state.data.borrow_mut();
    data[0] = 1;

    Ok(())
}
