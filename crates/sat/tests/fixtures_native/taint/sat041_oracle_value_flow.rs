//! SAT041 "Oracle Value Flow" honesty-gate fixture.
//!
//! Mango-class precipitating shape (per-instruction): a price derived from a
//! Mango-internal order book (`mark_price`) is written into a program-state
//! price cache, then a borrow/withdraw amount is computed from that cache and
//! used as a token-CPI amount — with NO external-oracle confidence/age/scale
//! bound anywhere on the path. The attacker can drive `mark_price` via
//! self-trades, so the value inflates the borrow amount.
//!
//! Only needs to parse with syn.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub struct MarketState {
    pub version: u8,
    pub mark_price: u64,
}

impl MarketState {
    pub fn load(account: &AccountInfo) -> Result<MarketState, solana_program::program_error::ProgramError> {
        let data = account.data.borrow();
        Ok(MarketState { version: data[0], mark_price: u64::from_le_bytes(data[1..9].try_into().unwrap()) })
    }
    pub fn load_mut(account: &AccountInfo) -> Result<MarketState, solana_program::program_error::ProgramError> {
        let data = account.data.borrow_mut();
        Ok(MarketState { version: data[0], mark_price: u64::from_le_bytes(data[1..9].try_into().unwrap()) })
    }
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let market = next_account_info(accounts_iter)?;
    let price_cache = next_account_info(accounts_iter)?;
    let borrower = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let token_prog = next_account_info(accounts_iter)?;

    let market_state = MarketState::load(market)?;
    msg!("mark price: {}", market_state.mark_price);

    // Cache the attacker-drivable mark price into program state.
    let mut cache = MarketState::load_mut(price_cache)?;
    cache.mark_price = market_state.mark_price;

    // Borrow amount derived from the cached price, sent via token CPI.
    let borrow_amount = cache.mark_price;
    let transfer = Instruction::new_with_borsh(
        *token_prog.key,
        &[1u8; 8],
        vec![
            AccountMeta::new(*vault.key, false),
            AccountMeta::new_readonly(*borrower.key, true),
        ],
    );
    invoke(&transfer, &[vault.clone(), borrower.clone()])?;

    Ok(())
}
