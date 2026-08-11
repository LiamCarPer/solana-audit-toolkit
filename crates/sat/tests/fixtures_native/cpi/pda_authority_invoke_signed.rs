//! Token CPI whose authority is the canonical vault PDA signed with the
//! checked `invoke_signed`: the runtime derives the authority's signature
//! from the seeds, so the caller cannot name an arbitrary account. SAT028
//! must NOT fire.
//!
//! Mirrors the Jito vault program's `UpdateVaultBalance` mint_to CPI exactly:
//! the authority (`vault_info`) is verified by `Vault::load` — owner +
//! discriminator + `create_program_address` checks implemented behind a
//! method in a separate `*_core` crate, which the analyzer cannot see into —
//! and the CPI is signed with `invoke_signed` using the vault's signing
//! seeds. Neither signer-check nor key-compare appears in the handler, so
//! without the checked-`invoke_signed` suppression SAT028 would fire.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

declare_id!("PdaCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

/// The vault state, loaded through a `load`-style guard like
/// `jito_vault_core::Vault`.
pub struct Vault {
    pub bump: u8,
}

impl Vault {
    /// Owner + discriminator + canonical-PDA check. The checks live behind
    /// the call (a separate `*_core` crate in real programs), so the
    /// analyzer's guard detectors never see them.
    pub fn load(_program_id: &Pubkey, _vault: &AccountInfo, _expect_writable: bool) -> Result<(), ProgramError> {
        msg!("load guard");
        Ok(())
    }

    /// Seeds used to sign for the vault PDA (`signing_seeds` in Jito).
    pub fn signing_seeds(&self) -> Vec<Vec<u8>> {
        vec![b"vault".to_vec(), vec![self.bump]]
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    match &instruction_data[0..8] {
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_update_balance(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_update_balance(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let source = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    // The authority must be the canonical vault PDA (mirrors
    // `Vault::load(program_id, vault_info, true)` — the owner, discriminator
    // and create_program_address checks live inside the method).
    Vault::load(program_id, authority, false)?;
    let vault = Vault { bump: 0 };
    let vault_seeds = vault.signing_seeds();
    let seed_slices: Vec<&[u8]> = vault_seeds.iter().map(|seed| seed.as_slice()).collect();

    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(source.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), false),
        ],
        data: vec![12u8, 0, 0, 0, 0, 0, 0, 0],
    };
    invoke_signed(&ix, &[source.clone(), destination.clone(), authority.clone()], &[&seed_slices])?;
    Ok(())
}
