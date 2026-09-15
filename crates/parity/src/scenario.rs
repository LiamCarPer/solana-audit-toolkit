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
    pub initial: u64,
}

/// A protocol operation in abstract, implementation-independent terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Supply `amount` of the base asset from `user`.
    Deposit { user: String, amount: u64 },
    /// Redeem `amount` of the base asset to `user`.
    Withdraw { user: String, amount: u64 },
    /// Borrow `amount` of the base asset to `user`.
    Borrow { user: String, amount: u64 },
    /// Repay `amount` of the base asset from `user`.
    Repay { user: String, amount: u64 },
    /// Accrue interest for `seconds` at the model's configured rate.
    Accrue { seconds: u64 },
    /// Set the oracle price (scaled integer).
    SetPrice { price: u64 },
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
    pub price: u64,
    /// Interest rate per second in basis points (of 10_000).
    #[serde(default)]
    pub rate_bps_per_second: u64,
}

fn default_price() -> u64 {
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
    pub total_deposits: u64,
    /// Total accounted borrows (base units).
    pub total_borrows: u64,
    /// Total outstanding shares (accounting units).
    pub total_shares: u64,
    /// Recorded vault token balance (base units).
    pub vault_balance: u64,
    /// The user's share balance.
    pub user_shares: u64,
    /// The user's wallet/collateral balance.
    pub user_balance: u64,
    /// Oracle price in effect.
    pub price: u64,
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

/// One step of a recorded execution: the canonical observables after an op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    /// Index into the scenario's `ops`.
    pub op_index: usize,
    pub observables: Observables,
    /// Error string when the program rejected the op (parity on revert).
    #[serde(default)]
    pub error: Option<String>,
}

/// A recorded execution of a scenario against a **real program** (emitted by a
/// generated `solana-program-test` harness). This is the bridge that lets the
/// differential engine compare a live program against the reference model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    /// Scenario name this trace belongs to.
    pub scenario: String,
    /// Human label for the program that produced it (`lending-ok`, `kamino`, …).
    pub model: String,
    pub steps: Vec<TraceStep>,
}

impl Trace {
    pub fn from_json(s: &str) -> anyhow::Result<Trace> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
