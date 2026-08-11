//! Clean native program: the feed's safety fields are all consumed —
//! SAT034/035/036 must stay silent.
//!
//! Positional `next_account_info` accounts:
//! - `price_feed` — deserialized, with staleness + confidence bounds and the
//!   exponent applied.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let price_feed = next_account_info(accounts_iter)?;

    // SAT025 guard: the feed must be owned by the oracle program.
    if price_feed.owner != &pyth_program::ID {
        return Err(ProgramError::IllegalOwner);
    }

    let price = PythPrice::try_from_slice(&price_feed.data.borrow())?;

    // SAT034: staleness bound (checked arithmetic keeps SAT026 silent).
    let now = Clock::get()?.unix_timestamp;
    if now.checked_sub(price.publish_time).ok_or(ProgramError::InvalidAccountData)? > MAX_AGE {
        return Err(ProgramError::InvalidAccountData);
    }

    // SAT035: confidence bound.
    if price.conf > price.price.unsigned_abs().checked_div(100).ok_or(ProgramError::InvalidAccountData)? {
        return Err(ProgramError::InvalidAccountData);
    }

    // SAT036: exponent applied before arithmetic.
    let scaled = (price.price as u128)
        .checked_mul(10u128.pow(price.expo as u32))
        .ok_or(ProgramError::InvalidAccountData)?;
    let collateral_value = scaled.checked_mul(10_000_000).ok_or(ProgramError::InvalidAccountData)?;
    msg!("collateral value: {}", collateral_value);

    Ok(())
}

const MAX_AGE: i64 = 60;

mod pyth_program {
    use solana_program::pubkey::Pubkey;
    pub const ID: Pubkey = Pubkey::new_from_array([7u8; 32]);
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
