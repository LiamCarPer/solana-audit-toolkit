//! Helper-guarded native program: the same vulnerable-looking accounts that
//! `no_helper.rs` and `vuln.rs` expose, but every privileged account is
//! guarded through a whitelisted helper call *in the handler body*:
//!
//! - `admin` — `load_signer(admin, true)` (Jito `jito_jsm_core::loader::load_signer`
//!   shape: errors on `!info.is_signer`) → kills SAT019 / SAT021.
//! - `state` — `load_system_account(state, true)` (owner == system program
//!   check) → kills SAT020.
//! - `config` — `Config::load(program_id, config, false)` (owner +
//!   discriminator + canonical-PDA check) → kills SAT020.
//!
//! The helpers are referenced by name only; they do not need to be defined
//! for the rule slice — the whitelist matches on callee name + account
//! argument. This fixture only needs to parse with `syn`.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let config = next_account_info(accounts_iter)?;
    let state = next_account_info(accounts_iter)?;
    let admin = next_account_info(accounts_iter)?;

    // Whitelisted helper guards, in the same handler body.
    load_signer(admin, true)?;
    load_system_account(state, true)?;
    Config::load(program_id, config, false)?;

    // Both state accounts are written — without the helper guards above,
    // SAT020 would fire on them.
    let mut state_data = state.data.borrow_mut();
    state_data[0] = 1;
    let mut config_data = config.data.borrow_mut();
    config_data[0] = 1;

    Ok(())
}
