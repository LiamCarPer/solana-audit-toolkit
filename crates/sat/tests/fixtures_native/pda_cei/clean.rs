//! Clean native program: SAT022 (PDA seed derivation mismatch) and SAT023
//! (state write after CPI) must NOT fire.
//!
//! - The `invoke_signed` signs with exactly the seeds used for the
//!   `find_program_address` derivation (`[b"escrow", owner.key()]` plus the
//!   returned bump) — no seed mismatch (SAT022).
//! - The state write (`borrow_mut` + field assign + `serialize`) happens
//!   BEFORE the external calls — Checks-Effects-Interactions order is
//!   respected (SAT023).
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

    let escrow = next_account_info(accounts_iter)?;
    let state = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let owner = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    // PDA guard: `escrow` must be the canonical derivation.
    let (pda, bump) = Pubkey::find_program_address(&[b"escrow", owner.key()], program_id);
    if escrow.key != &pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Ownership guard: `state` must be owned by this program.
    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Authority guard: `owner` must sign.
    if !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Effects before interactions: the state is written FIRST...
    let mut data = state.data.borrow_mut();
    let mut escrow_data = EscrowState::try_from_slice(&data)?;
    escrow_data.amount = 1_000;
    escrow_data.serialize(&mut data)?;

    // ...and only then the token transfer is built and executed, with the
    // same seeds as the derivation (plus the returned bump).
    let transfer_ix = spl_token::instruction::transfer(
        token_program.key,
        vault.key,
        escrow.key,
        escrow.key,
        &[],
        1_000,
    )?;
    invoke_signed(
        &transfer_ix,
        &[vault.clone(), escrow.clone(), token_program.clone()],
        &[&[b"escrow", owner.key().as_ref(), &[bump]]],
    )?;

    Ok(())
}
