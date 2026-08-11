//! Multi-writer global `config` with `load`-style guards and NO close path:
//! SAT030 must NOT fire — the "closed-and-recreated / attacker-funded reinit"
//! premise is impossible when no instruction closes, reassigns, or reinit-
//! marks the account class anywhere in the program.
//!
//! Both writers guard `config` with `Config::load` (owner + discriminator +
//! canonical-PDA checks implemented behind the method, exactly like Jito's
//! `vault_core::Config::load` / `restaking_core::Config::load`). The analyzer
//! cannot see through the method call, so its init-guard detector reports
//! both writers unguarded; the program-level close/reinit suppression is what
//! keeps SAT030 quiet.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

declare_id!("MwcCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

/// On-chain global config, guarded by [`Config::load`] in every writer
/// (Jito multi-writer design: 6+ instructions mutate the same config).
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u16,
}

impl Config {
    /// Owner + discriminator + canonical-PDA guard. The checks live behind
    /// the call (a separate `*_core` crate in real programs), so the
    /// analyzer's init-guard detector never sees them.
    pub fn load(_program_id: &Pubkey, _config: &AccountInfo, _expect_writable: bool) -> Result<(), ProgramError> {
        // Discriminator + owner + find_program_address checks happen here.
        msg!("load guard");
        Ok(())
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    match &instruction_data[0..8] {
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_set_fee(program_id, accounts),
        [9, 10, 11, 12, 13, 14, 15, 16, ..] => process_set_admin(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_set_fee(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config = next_account_info(accounts_iter)?;

    // Guarded like every Jito config writer: Config::load rejects any account
    // that is not the program-owned, discriminator-tagged canonical PDA.
    Config::load(program_id, config, true)?;

    let mut data = config.data.borrow_mut();
    data[1] = 1;
    Ok(())
}

fn process_set_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config = next_account_info(accounts_iter)?;

    Config::load(program_id, config, true)?;

    let mut data = config.data.borrow_mut();
    data[2] = 2;
    Ok(())
}
