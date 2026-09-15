//! Declarative scenario model: the language the differential engine speaks.
//!
//! A scenario is a normalized, program-agnostic description of a sequence of
//! protocol operations plus the invariants that must hold. It is authored by
//! the AI (or emitted as a stub by `parity init`) and executed against one or
//! more [`crate::model::ProgramModel`] implementations.

use serde::{Deserialize, Serialize};

/// Logical account roles. Concrete adapters map these to real pubkeys/layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A user / depositor / borrower.
    User,
    /// The pool's reserve/liquidity state account.
    Reserve,
    /// The token vault holding deposits.
    Vault,
    /// An obligation / loan account.
    Obligation,
    /// A price feed or oracle account.
    Oracle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSpec {
    pub role: Role,
    /// Logical name used to reference this account in ops.
    pub name: String,
    /// Initial integer quantity (lamports/token base units/shares).
    #[serde(default)]
    pub initial: u128,
}

/// A protocol operation in abstract, implementation-independent terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Supply `amount` of the base asset from `user`.
    Deposit { user: String, amount: u128 },
    /// Redeem `amount` of the base asset to `user`.
    Withdraw { user: String, amount: u128 },
    /// Borrow `amount` of the base asset to `user`.
    Borrow { user: String, amount: u128 },
    /// Repay `amount` of the base asset from `user`.
    Repay { user: String, amount: u128 },
    /// Accrue interest for `seconds` at the model's configured rate.
    Accrue { seconds: u64 },
    /// Set the oracle price (scaled integer).
    SetPrice { price: u128 },
}

/// Protocol invariants checked after every operation. These encode economics,
/// not syntax — the classes that survive audits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Invariant {
    /// Total assets ≥ total liabilities (the pool never becomes insolvent).
    Solvency,
    /// Sum of user shares equals the reserve's recorded share total.
    ShareConservation,
    /// The vault holds at least the accounted deposits.
    VaultBacking,
    /// No user can withdraw more value than they deposited (no free money),
    /// measured as monotonic non-increase of (user_balance - user_deposited).
    NoFreeMoney,
    /// Accounting quantities never decrease on a deposit.
    DepositMonotonic,
}

impl Invariant {
    pub fn name(&self) -> &'static str {
        match self {
            Invariant::Solvency => "solvency",
            Invariant::ShareConservation => "share_conservation",
            Invariant::VaultBacking => "vault_backing",
            Invariant::NoFreeMoney => "no_free_money",
            Invariant::DepositMonotonic => "deposit_monotonic",
        }
    }
}

/// A complete scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Initial supply/rate config for the model (price scale, rate per second).
    #[serde(default)]
    pub config: Config,
    #[serde(default)]
    pub accounts: Vec<AccountSpec>,
    pub ops: Vec<Op>,
    #[serde(default)]
    pub invariants: Vec<Invariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Oracle price scale (assets per unit).
    #[serde(default = "default_price")]
    pub price: u128,
    /// Interest rate per second in basis points (of 10_000).
    #[serde(default)]
    pub rate_bps_per_second: u64,
}

fn default_price() -> u128 {
    1
}

impl Default for Config {
    fn default() -> Self {
        Config { price: default_price(), rate_bps_per_second: 0 }
    }
}

impl Scenario {
    /// Parse from JSON.
    pub fn from_json(s: &str) -> anyhow::Result<Scenario> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Canonical, program-agnostic observable state. Adapters must map their
/// program's state onto exactly these fields so diffs are meaningful.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Observables {
    /// Total accounted deposits (base units).
    pub total_deposits: u128,
    /// Total accounted borrows (base units).
    pub total_borrows: u128,
    /// Total outstanding shares (accounting units).
    pub total_shares: u128,
    /// Recorded vault token balance (base units).
    pub vault_balance: u128,
    /// The user's share balance.
    pub user_shares: u128,
    /// The user's wallet/collateral balance.
    pub user_balance: u128,
    /// Oracle price in effect.
    pub price: u128,
}

impl Observables {
    /// Field-by-field comparison used by the differential engine.
    pub fn differences(&self, other: &Observables) -> Vec<(&'static str, String, String)> {
        let mut out = Vec::new();
        macro_rules! cmp {
            ($field:ident) => {
                if self.$field != other.$field {
                    out.push((stringify!($field), self.$field.to_string(), other.$field.to_string()));
                }
            };
        }
        cmp!(total_deposits);
        cmp!(total_borrows);
        cmp!(total_shares);
        cmp!(vault_balance);
        cmp!(user_shares);
        cmp!(user_balance);
        cmp!(price);
        out
    }
}
