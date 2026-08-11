//! Control for the SAT030 close/reinit suppression: the same multi-writer
//! `config` shape as `multi_writer_config.rs`, PLUS a close instruction that
//! reassigns `config` to the system program (the close+recreate premise).
//! SAT030 must STILL fire for `config`.
//!
//! The close path mirrors Jito's `close_program_account(program_id, account,
//! payer)` helper call shape (the closed account is the second argument).
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

declare_id!("ClsCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

/// On-chain global config, guarded by [`Config::load`] in every writer.
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u16,
}

impl Config {
    /// Owner + discriminator + canonical-PDA guard (see `multi_writer_config.rs`).
    pub fn load(_program_id: &Pubkey, _config: &AccountInfo, _expect_writable: bool) -> Result<(), ProgramError> {
        msg!("load guard");
        Ok(())
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    match &instruction_data[0..8] {
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_set_fee(program_id, accounts),
        [9, 10, 11, 12, 13, 14, 15, 16, ..] => process_set_admin(program_id, accounts),
        [17, 18, 19, 20, 21, 22, 23, 24, ..] => process_close_config(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_set_fee(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config = next_account_info(accounts_iter)?;

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

/// The close path: reassigns `config` to the system program, which makes the
/// close+recreate cycle possible (an attacker can then re-fund and re-init
/// the account and have the unguarded writers accept it as fresh).
fn process_close_config(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config = next_account_info(accounts_iter)?;
    let payer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    close_program_account(program_id, config, payer, system_program)
}

/// Mirrors `jito_jsm_core::close_program_account`'s call shape: the closed
/// account sits at argument index 1.
fn close_program_account(
    program_id: &Pubkey,
    config: &AccountInfo,
    payer: &AccountInfo,
    system_program: &AccountInfo,
) -> ProgramResult {
    // Zero the data, transfer the lamports to the payer, and assign the owner
    // to the system program (SystemInstruction::Assign).
    let ix = Instruction {
        program_id: *system_program.key,
        accounts: vec![AccountMeta::new(config.key(), true)],
        data: vec![2u8, 0, 0, 0, 0, 0, 0, 0],
    };
    invoke(&ix, &[config.clone(), payer.clone(), program_id.clone()])
}
