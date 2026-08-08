//! Mango-style fixed-point fixture (SAT026 FP regression): arithmetic on a
//! custom `FixedPoint` type whose operators are internally checked must NOT
//! be flagged. Mirrors Mango v3's `I80F48` usage patterns: constructor
//! initializers (`FixedPoint::from_num`/`from_bits`/`zero`), fixed-point
//! function parameters, and fixed-point struct fields (`market.fees_accrued`).
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

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data[0..8] {
        [1, 0, 0, 0, 0, 0, 0, 0] => process_apply_fees(_program_id, accounts, instruction_data),
        [2, 0, 0, 0, 0, 0, 0, 0] => process_cancel_orders(_program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn process_apply_fees(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let _market = next_account_info(accounts_iter)?;
    let mut market = Market::default();
    let base_fee = FixedPoint::from_num(0.0001);
    market.fees_accrued = apply_fees(&mut market, base_fee);
    Ok(())
}

pub fn process_cancel_orders(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let _market = next_account_info(accounts_iter)?;
    let mut market = Market::default();
    let qty = FixedPoint::from_num(1.5);
    cancel_all_advanced_orders(&mut market, qty);
    Ok(())
}

/// Mango-style fee accrual (mirrors `apply_fees`): every arithmetic operand
/// is a fixed-point field, parameter, or constructor.
fn apply_fees(market: &mut Market, base_fee: FixedPoint) -> FixedPoint {
    let one = FixedPoint::from_num(1.0);
    let rate = market.fee_rate;
    let net_rate = one - rate;
    let fee = base_fee * net_rate;
    market.fees_accrued += fee;
    market.total_fees = market.total_fees + fee;
    fee
}

/// Mirrors the `checked_add_net`-style helpers: fixed-point parameters only.
fn checked_add_net(a: FixedPoint, b: FixedPoint) -> FixedPoint {
    a + b
}

fn checked_sub_net(a: FixedPoint, b: FixedPoint) -> FixedPoint {
    a - b
}

/// Mirrors `verify_bookside_iteration`: a fixed-point accumulator derived
/// from `zero()` and compared against a fixed-point field.
fn verify_bookside_iteration(market: &mut Market, expected: FixedPoint) -> bool {
    let mut acc = FixedPoint::zero();
    acc += expected;
    market.fees_accrued >= acc
}

/// Mirrors `cancel_all_advanced_orders`: fees computed with constructors and
/// applied to fixed-point fields.
fn cancel_all_advanced_orders(market: &mut Market, qty: FixedPoint) {
    let cancel_fee = FixedPoint::from_num(1.0) * qty;
    let net = FixedPoint::from_bits(42);
    market.fees_accrued += cancel_fee + net;
    market.fees_accrued *= FixedPoint::from_num(2.0);
}

/// A Mango-style state struct with fixed-point fields.
struct Market {
    fee_rate: FixedPoint,
    fees_accrued: FixedPoint,
    total_fees: FixedPoint,
}

impl Market {
    fn default() -> Self {
        Market {
            fee_rate: FixedPoint::from_num(0.0001),
            fees_accrued: FixedPoint::zero(),
            total_fees: FixedPoint::zero(),
        }
    }
}

/// Fixed-point type with internally checked operators (Mango's `I80F48`).
#[derive(Clone, Copy, Debug)]
pub struct FixedPoint(i128);

impl FixedPoint {
    pub fn from_num(n: f64) -> Self {
        Self((n * 65536.0) as i128)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn from_bits(bits: u128) -> Self {
        Self(bits as i128)
    }
}

impl std::ops::Add for FixedPoint {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}
