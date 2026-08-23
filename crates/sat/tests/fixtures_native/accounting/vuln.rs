//! Vulnerable native program: SAT039 — Accounting Drift.
//!
//! `deposit` reads the vault balance BEFORE a token transfer, then updates
//! the internal ledger with the transferred amount — never re-reading the
//! actual post-CPI delta. Fee-on-transfer / transfer-hook tokens diverge
//! internal accounting from real balances by design.
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

    // Stale read: the vault balance is captured BEFORE the CPI...
    let vault_balance_before = u64::from_le_bytes(vault_token_account.data.borrow()[64..72].try_into().unwrap());

    let deposit_amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    // ...the token CPI moves funds (fees/hooks may reduce the actual delta)...
    token_transfer(user_token_account, vault_token_account, deposit_amount)?;

    // ...and the ledger mirrors the requested amount, not the real delta
    // (SAT039 High: ledger mirror), while also using the stale pre-read.
    msg!("vault had {} before", vault_balance_before);

    let mut data = state.data.borrow_mut();
    data[0..8].copy_from_slice(&deposit_amount.to_le_bytes());
    let _ = vault_balance_before;

    Ok(())
}

fn token_transfer(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    msg!("transfer {} -> {}", from.key, to.key);
    Ok(())
}
