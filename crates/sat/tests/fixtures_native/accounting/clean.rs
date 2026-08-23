//! Clean native program: SAT039 stays silent — the vault balance is
//! re-read AFTER the token CPI, and the ledger update uses the actual
//! post-CPI balance rather than mirroring the requested amount.
//!
//! Note: this fixture only needs to parse with `syn`.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let user_token_account = next_account_info(accounts_iter)?;
    let vault_token_account = next_account_info(accounts_iter)?;
    let state = next_account_info(accounts_iter)?;

    let deposit_amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    // Token CPI moves the funds first.
    token_transfer(user_token_account, vault_token_account, deposit_amount)?;

    // The post-CPI balance is RE-READ — no stale carry.
    let vault_balance_after = u64::from_le_bytes(vault_token_account.data.borrow()[64..72].try_into().unwrap());

    // The ledger records the ACTUAL delta, not the requested amount.
    let mut data = state.data.borrow_mut();
    data[0..8].copy_from_slice(&vault_balance_after.to_le_bytes());
    msg!("vault now {}", vault_balance_after);

    Ok(())
}

fn token_transfer(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    msg!("transfer {} -> {}", from.key, to.key);
    Ok(())
}
