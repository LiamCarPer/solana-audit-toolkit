//! Struct `try_from` pattern: accounts resolved through a
//! `MyAccounts::try_from(&accounts[..])` call, with the struct and its
//! `TryFrom` impl in the same file, followed by field accesses.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub struct MyAccounts<'info> {
    pub state: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    pub token_account: AccountInfo<'info>,
    pub vault: UncheckedAccount<'info>,
}

impl<'info> TryFrom<&'info [AccountInfo<'info>]> for MyAccounts<'info> {
    type Error = ProgramError;

    fn try_from(accounts: &'info [AccountInfo<'info>]) -> Result<Self, Self::Error> {
        let accounts_iter = &mut accounts.iter();
        let state = next_account_info(accounts_iter)?;
        let authority = next_account_info(accounts_iter)?;
        let token_account = next_account_info(accounts_iter)?;
        let vault = next_account_info(accounts_iter)?;
        Ok(MyAccounts { state, authority, token_account, vault })
    }
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accs = MyAccounts::try_from(&accounts[..])?;

    if !accs.authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if accs.state.owner != _program_id {
        return Err(ProgramError::IllegalOwner);
    }

    Ok(())
}
