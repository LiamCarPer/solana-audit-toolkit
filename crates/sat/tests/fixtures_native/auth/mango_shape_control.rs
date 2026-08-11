//! Mango-shape regression control: `TokenAccount::load_checked(..)` checks
//! NOTHING (it is a plain bytemuck-style load), so SAT020 must still fire for
//! the token account — exactly like Mango's RecoveryWithdraw* handlers.
//!
//! This is the load-bearing case for the curated-whitelist constraint: bare
//! `load`/`load_checked` are NEVER treated as owner checks. `load_checked` is
//! excluded by the exact-name rule, and the receiver type is not a local
//! state type.
//!
//! This fixture only needs to parse with `syn`.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let token_account = next_account_info(accounts_iter)?;

    // Mango's `TokenAccount::load_checked` — no owner check, no key pinning.
    let _ta = TokenAccount::load_checked(token_account)?;

    // Written: SAT020's stateful trigger is satisfied even without the
    // name-based kind inference.
    let mut data = token_account.data.borrow_mut();
    data[0] = 1;

    Ok(())
}
