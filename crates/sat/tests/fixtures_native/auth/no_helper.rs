//! Control fixture for the helper-guard FP filter: the same accounts as
//! `helper_guarded.rs` (`config`, `state`, `admin`), the same writes — but
//! WITHOUT the whitelisted helper calls. SAT019 / SAT020 / SAT021 must all
//! still fire here.
//!
//! This fixture only needs to parse with `syn`.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let config = next_account_info(accounts_iter)?;
    let state = next_account_info(accounts_iter)?;
    let admin = next_account_info(accounts_iter)?;

    // SAT020: `config` data is written without any owner check.
    let mut config_data = config.data.borrow_mut();
    config_data[0] = 1;

    // SAT020: `state` data is written without any owner check.
    let mut state_data = state.data.borrow_mut();
    state_data[0] = 1;

    // SAT019: `admin` gates a privileged path but its signature is never
    // verified; SAT021: its key is never compared to a stored/derived key.
    msg!("transferring admin: {}", admin.key);

    Ok(())
}
