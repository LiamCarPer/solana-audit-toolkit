//! Clean native program: SAT038 must stay silent — every value that reaches
//! a privileged sink is either anchored (owner-checked source, constant
//! amount) or the flow is absent entirely.
//!
//! Note: this fixture only needs to parse with `syn`.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let price_feed = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let state = next_account_info(accounts_iter)?;

    // Anchored source: the feed is owner-checked against the oracle program.
    if price_feed.owner != &ORACLE_PROGRAM_ID {
        return Err(ProgramError::IllegalOwner);
    }

    let price = u64::from_le_bytes(price_feed.data.borrow()[0..8].try_into().unwrap());

    // Constant amount from validated instruction data — not attacker-derived.
    let amount = instruction_data
        .get(0..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);

    msg!("transferring {} at price {}", amount, price);
    let _ = destination;

    let mut data = state.data.borrow_mut();
    data[0..8].copy_from_slice(&price.to_le_bytes());

    Ok(())
}

mod oracle_program {
    use solana_program::pubkey::Pubkey;
    pub const ID: Pubkey = Pubkey::new_from_array([7u8; 32]);
}
