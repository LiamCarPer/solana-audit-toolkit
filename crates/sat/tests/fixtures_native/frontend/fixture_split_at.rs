//! Positional account destructuring via `accounts.split_at(N)` (Jito vault
//! shape): both halves are tracked as positional slices, the fixed head is
//! destructured with a slice pattern, and the optional tail is peeked via
//! `.first()` — account indexes continue across the split.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let (required_accounts, optional_accounts) = accounts.split_at(3);

    let [state, authority, vault] = required_accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    check_mint_burn_admin(optional_accounts.first())?;
    Ok(())
}

fn check_mint_burn_admin(_admin: Option<&AccountInfo>) -> Result<(), ProgramError> {
    Ok(())
}
