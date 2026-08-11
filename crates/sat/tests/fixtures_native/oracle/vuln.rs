//! Vulnerable native program: SAT034 (stale price), SAT035 (confidence),
//! SAT036 (exponent) — the feed is read but none of its safety fields are
//! consumed.
//!
//! Positional `next_account_info` accounts:
//! - `price_feed` — deserialized via `try_from_slice`, only `.price` used.
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

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let price_feed = next_account_info(accounts_iter)?;

    // SAT034/035/036: the price is used, but the feed's time field, confidence
    // field and exponent are never consumed — nothing bounds age or quality,
    // and the raw integer is used without its scale.
    let price = PythPrice::try_from_slice(&price_feed.data.borrow())?;
    let collateral_value = price.price as u128 * 10_000_000;
    msg!("collateral value: {}", collateral_value);

    Ok(())
}

/// Minimal Pyth-v2-shaped price struct.
struct PythPrice {
    price: i64,
    conf: u64,
    expo: i32,
    publish_time: i64,
}

impl PythPrice {
    fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 32 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(PythPrice {
            price: i64::from_le_bytes(data[0..8].try_into().unwrap()),
            conf: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            expo: i32::from_le_bytes(data[16..20].try_into().unwrap()),
            publish_time: i64::from_le_bytes(data[24..32].try_into().unwrap()),
        })
    }
}
