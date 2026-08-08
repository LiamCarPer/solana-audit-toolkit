//! Vulnerable native program: SAT022 (PDA seed derivation mismatch) and
//! SAT023 (state write after CPI).
//!
//! Accounts (positional, `next_account_info` order):
//! - `escrow` — PDA validated against `find_program_address(&[b"escrow",
//!   owner.key()], program_id)`, but the `invoke_signed` signs with
//!   `[b"escrow", other.key()]` — a DIFFERENT PDA (SAT022).
//! - `state` — deserialized and written (`borrow_mut` + field assign +
//!   `serialize`) AFTER a token `invoke` in the same handler (SAT023).
//! - `vault`, `owner`, `other`, `token_program` — CPI participants.
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
    let other = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    // PDA guard: `escrow` must be the canonical derivation.
    let (pda, bump) = Pubkey::find_program_address(&[b"escrow", owner.key()], program_id);
    if escrow.key != &pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // SAT023: the external call comes FIRST...
    invoke(
        &spl_token::instruction::transfer(token_program.key, vault.key, escrow.key, escrow.key, &[], 1_000)?,
        &[vault.clone(), escrow.clone(), token_program.clone()],
    )?;

    // ...and the state write comes after it (Checks-Effects-Interactions
    // violation).
    let mut data = state.data.borrow_mut();
    let mut escrow_data = EscrowState::try_from_slice(&data)?;
    escrow_data.amount = 1_000;
    escrow_data.serialize(&mut data)?;

    // SAT022: the withdrawal signs with `other.key()` — a different PDA than
    // the `escrow` account this instruction validated.
    let transfer_ix = spl_token::instruction::transfer(
        token_program.key,
        vault.key,
        escrow.key,
        escrow.key,
        &[],
        500,
    )?;
    invoke_signed(
        &transfer_ix,
        &[vault.clone(), escrow.clone(), token_program.clone()],
        &[&[b"escrow", other.key().as_ref(), &[bump]]],
    )?;

    Ok(())
}
