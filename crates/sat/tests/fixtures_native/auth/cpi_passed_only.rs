//! CPI-passed-only token account (SAT020 suppression control).
//!
//! `token_account` is never read by this program: it only appears as an
//! argument of an SPL Token transfer CPI (through a helper, like Mango v3's
//! `invoke_transfer`), and the transfer instruction is built with the token
//! program id (`spl_token::ID`). The token program validates ownership of the
//! source/destination accounts at runtime, so SAT020 must NOT fire.
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

/// SPL Token transfer CPI helper: builds the instruction with the token
/// program id and passes the accounts through to `invoke_signed`.
fn invoke_transfer(
    token_program: &AccountInfo,
    vault: &AccountInfo,
    token_account: &AccountInfo,
    amount: u64,
) -> Result<(), ProgramError> {
    let transfer_instruction = spl_token::instruction::transfer(
        &spl_token::ID,
        vault.key,
        token_account.key,
        vault.key,
        &[],
        amount,
    )?;
    let accs = [token_program.clone(), vault.clone(), token_account.clone()];
    solana_program::program::invoke_signed(&transfer_instruction, &accs, &[])
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let token_program = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let token_account = next_account_info(accounts_iter)?;

    // The token account is only ever passed to the token CPI.
    invoke_transfer(token_program, vault, token_account, 100)?;

    Ok(())
}
