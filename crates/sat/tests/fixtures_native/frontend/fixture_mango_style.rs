//! Mini Mango-v3-style program: a `State` struct with `load`/`load_mut`, a
//! `check_accounts`-style struct built via `TryFrom`, signer checks in a
//! validate helper, and a token-transfer CPI.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

declare_id!("MangoCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe");

pub struct State {
    pub version: u8,
    pub authority: Pubkey,
    pub token_account: Pubkey,
}

impl State {
    pub const LEN: usize = 65;

    pub fn load(account: &AccountInfo) -> Result<State, ProgramError> {
        let data = account.data.borrow();
        if data.len() < State::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(State {
            version: data[0],
            authority: Pubkey::new(&data[1..33]),
            token_account: Pubkey::new(&data[33..65]),
        })
    }

    pub fn load_mut(account: &AccountInfo) -> Result<State, ProgramError> {
        let mut data = account.data.borrow_mut();
        if data.len() < State::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(State {
            version: data[0],
            authority: Pubkey::new(&data[1..33]),
            token_account: Pubkey::new(&data[33..65]),
        })
    }
}

pub struct Accounts<'info> {
    pub state: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    pub token_account: AccountInfo<'info>,
}

impl<'info> TryFrom<&'info [AccountInfo<'info>]> for Accounts<'info> {
    type Error = ProgramError;

    fn try_from(accounts: &'info [AccountInfo<'info>]) -> Result<Self, Self::Error> {
        let accounts_iter = &mut accounts.iter();
        let state = next_account_info(accounts_iter)?;
        let authority = next_account_info(accounts_iter)?;
        let token_account = next_account_info(accounts_iter)?;
        Ok(Accounts { state, authority, token_account })
    }
}

fn validate(authority: &AccountInfo) -> Result<(), ProgramError> {
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accs = Accounts::try_from(accounts)?;
    validate(&accs.authority)?;

    if accs.state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let state = State::load(&accs.state)?;
    msg!("state version: {}", state.version);

    let state_mut = State::load_mut(&accs.state)?;
    state_mut.authority = accs.authority.key;

    let transfer_ix = Instruction::new_with_borsh(
        solana_program::token::ID,
        &[0u8; 8],
        vec![
            AccountMeta::new(*accs.token_account.key, false),
            AccountMeta::new_readonly(*accs.authority.key, true),
        ],
    );
    invoke(&transfer_ix, &[accs.token_account.clone(), accs.authority.clone()])?;

    Ok(())
}
