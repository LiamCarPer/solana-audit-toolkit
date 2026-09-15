//! `ProgramModel` — the behavioral interface the differential engine runs.
//!
//! Implementations:
//! - [`LendingModel`] — a source-derived reference model of a lending pool
//!   (shares, index interest, correct rounding). This is what the AI authors
//!   from protocol source, and it doubles as the "expected" side of a diff.
//! - A `program-test` adapter (P2) implements the same trait by executing real
//!   instructions, so the SAME scenarios run against the real program.

use crate::scenario::{Config, Observables, Op, Role, Scenario};

/// A runnable protocol model. `apply` mutates state; `observe` exposes the
/// canonical observables for diffing.
pub trait ProgramModel {
    fn name(&self) -> &str;
    fn apply(&mut self, op: &Op) -> Result<(), String>;
    fn observe(&self) -> Observables;
}

/// How a share-accounting division rounds. Audited code must round in the
/// protocol's favour; a divergence here is the classic "free money" bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rounding {
    /// Round toward zero (correct for shares burned on withdraw).
    Down,
    /// Round away from zero (correct for shares minted on deposit in some
    /// conventions; a bug when used on withdraw).
    Up,
}

fn div_round(numerator: u128, denominator: u128, rounding: Rounding) -> u128 {
    if denominator == 0 {
        return 0;
    }
    let q = numerator / denominator;
    let r = numerator % denominator;
    match rounding {
        Rounding::Down => q,
        Rounding::Up => q + u128::from(r != 0),
    }
}

/// A source-derived lending-pool reference model.
///
/// Accounting: depositors hold `shares` of `total_deposits`; interest accrues
/// to `total_deposits` (borrowers owe `total_borrows`). Rounding is explicit so
/// a variant can model a candidate implementation's rounding choice.
#[derive(Debug, Clone)]
pub struct LendingModel {
    name: String,
    config: Config,
    total_deposits: u128,
    total_borrows: u128,
    total_shares: u128,
    vault_balance: u128,
    user_shares: u128,
    user_balance: u128,
    /// Shares burned on withdraw round this way.
    withdraw_rounding: Rounding,
    /// Shares minted on deposit round this way.
    deposit_rounding: Rounding,
}

impl LendingModel {
    /// The reference ("expected") model: protocol-favourable rounding.
    pub fn reference(scenario: &Scenario) -> Self {
        Self::with_rounding(scenario, Rounding::Up, Rounding::Down)
    }

    /// A candidate model with explicit rounding (used to model a target, or to
    /// inject a bug in tests).
    pub fn with_rounding(scenario: &Scenario, withdraw_rounding: Rounding, deposit_rounding: Rounding) -> Self {
        let mut model = LendingModel {
            name: "lending-model".to_string(),
            config: scenario.config.clone(),
            total_deposits: 0,
            total_borrows: 0,
            total_shares: 0,
            vault_balance: 0,
            user_shares: 0,
            user_balance: 0,
            withdraw_rounding,
            deposit_rounding,
        };
        for acc in &scenario.accounts {
            if acc.role == Role::User {
                model.user_balance = acc.initial;
            }
        }
        model
    }

    pub fn named(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    fn shares_for_deposit(&self, amount: u128) -> u128 {
        if self.total_shares == 0 || self.total_deposits == 0 {
            return amount;
        }
        div_round(amount * self.total_shares, self.total_deposits, self.deposit_rounding)
    }

    fn shares_for_withdraw(&self, amount: u128) -> u128 {
        if self.total_shares == 0 || self.total_deposits == 0 {
            return amount;
        }
        // `ceil` here protects the pool: the withdrawn value never exceeds the
        // shares burned. `floor` lets a user burn fewer shares than the value
        // taken — the divergence the engine must catch.
        div_round(amount * self.total_shares, self.total_deposits, self.withdraw_rounding)
    }
}

impl ProgramModel for LendingModel {
    fn name(&self) -> &str {
        &self.name
    }

    fn apply(&mut self, op: &Op) -> Result<(), String> {
        match op {
            Op::Deposit { amount, .. } => {
                if *amount > self.user_balance {
                    return Err("insufficient balance".to_string());
                }
                let shares = self.shares_for_deposit(*amount);
                self.user_balance -= amount;
                self.user_shares += shares;
                self.total_shares += shares;
                self.total_deposits += amount;
                self.vault_balance += amount;
                Ok(())
            }
            Op::Withdraw { amount, .. } => {
                let shares = self.shares_for_withdraw(*amount);
                if shares > self.user_shares {
                    return Err("insufficient shares".to_string());
                }
                self.user_shares -= shares;
                self.total_shares -= shares;
                self.total_deposits = self.total_deposits.saturating_sub(*amount);
                self.vault_balance = self.vault_balance.saturating_sub(*amount);
                self.user_balance += amount;
                Ok(())
            }
            Op::Borrow { amount, .. } => {
                if *amount > self.vault_balance {
                    return Err("insufficient liquidity".to_string());
                }
                self.total_borrows += amount;
                self.vault_balance -= amount;
                self.user_balance += amount;
                Ok(())
            }
            Op::Repay { amount, .. } => {
                let amount = (*amount).min(self.total_borrows);
                self.total_borrows -= amount;
                self.vault_balance += amount;
                self.user_balance = self.user_balance.saturating_sub(amount);
                Ok(())
            }
            Op::Accrue { seconds } => {
                let interest = self
                    .total_borrows
                    .saturating_mul(self.config.rate_bps_per_second as u128)
                    .saturating_mul(*seconds as u128)
                    / 10_000;
                self.total_deposits = self.total_deposits.saturating_add(interest);
                self.total_borrows = self.total_borrows.saturating_add(interest);
                Ok(())
            }
            Op::SetPrice { price } => {
                self.config.price = *price;
                Ok(())
            }
        }
    }

    fn observe(&self) -> Observables {
        Observables {
            total_deposits: self.total_deposits,
            total_borrows: self.total_borrows,
            total_shares: self.total_shares,
            vault_balance: self.vault_balance,
            user_shares: self.user_shares,
            user_balance: self.user_balance,
            price: self.config.price,
        }
    }
}
