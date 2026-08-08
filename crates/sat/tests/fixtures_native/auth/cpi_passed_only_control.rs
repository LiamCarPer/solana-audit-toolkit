//! CPI-passed-only control: the same token CPI as `cpi_passed_only.rs`, but
//! the program ALSO deserializes the token account's data itself via
//! `try_from_slice` on `token_account.data.borrow()`. That data read is a
//! program use of the account, so SAT020 must fire here (the delist-path
//! shape — e.g. Mango v3's `TokenAccount::load_checked` reads).
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    borsh::try_from_slice,
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

    // The token account is passed to the token CPI...
    invoke_transfer(token_program, vault, token_account, 100)?;

    // ...but the program ALSO reads its data itself — a program use.
    let _balance: u64 = try_from_slice(&token_account.data.borrow())?;

    Ok(())
}
