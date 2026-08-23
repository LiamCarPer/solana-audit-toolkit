//! Vulnerable native program: SAT038 — Unvalidated Flow.
//!
//! `state` is program-controlled (owner-checked against this program), but
//! its accounting is overwritten with a value read from `amount_source` —
//! an UNANCHORED account with no owner/key/signer validation on any path.
//! An attacker forges `amount_source`'s data and pollutes trusted state
//! (the Cashio-class pollution shape).
//!
//! Note: this fixture only needs to parse with `syn`.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let amount_source = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let state = next_account_info(accounts_iter)?;

    // `state` is trusted program-controlled storage.
    if state.owner != &_program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // SAT038: attacker-influenced value from the UNANCHORED account
    // `amount_source` flows into trusted state.
    let amount = u64::from_le_bytes(amount_source.data.borrow()[0..8].try_into().unwrap());
    msg!("crediting {}", amount);

    let mut data = state.data.borrow_mut();
    data[0..8].copy_from_slice(&amount.to_le_bytes());

    Ok(())
}
