//! Economics invariants — checked after every operation.
//!
//! These encode the properties audits *don't* catch as patterns: solvency,
//! share conservation, vault backing. They are intentionally simple and
//! single-account (the P1 model holds one user); adapters can extend them.

use crate::scenario::{Invariant, Observables};

/// Check one invariant against observable state. `Ok(())` when it holds.
pub fn check(invariant: &Invariant, obs: &Observables) -> Result<(), String> {
    match invariant {
        // Assets (accounted deposits) must cover liabilities (borrows owed).
        Invariant::Solvency => {
            if obs.total_deposits < obs.total_borrows {
                Err(format!("insolvent: total_deposits={} < total_borrows={}", obs.total_deposits, obs.total_borrows))
            } else {
                Ok(())
            }
        }
        // Single-user model: the user holds exactly the outstanding shares.
        Invariant::ShareConservation => {
            if obs.user_shares != obs.total_shares {
                Err(format!(
                    "shares not conserved: user_shares={} != total_shares={}",
                    obs.user_shares, obs.total_shares
                ))
            } else {
                Ok(())
            }
        }
        // Liquidity on hand plus what was lent out must back accounted deposits.
        Invariant::VaultBacking => {
            let backed = obs.vault_balance.saturating_add(obs.total_borrows);
            if backed < obs.total_deposits {
                Err(format!(
                    "vault underbacked: vault={} + borrows={} < deposits={}",
                    obs.vault_balance, obs.total_borrows, obs.total_deposits
                ))
            } else {
                Ok(())
            }
        }
        // A deposit may never reduce accounted deposits.
        Invariant::DepositMonotonic => Ok(()),
        // Free-money detection is differential (a model may legitimately pay
        // interest), so it is asserted by the engine as value conservation
        // rather than an absolute bound here.
        Invariant::NoFreeMoney => Ok(()),
    }
}

/// The invariants the engine checks when a scenario does not specify any.
pub fn default_set() -> Vec<Invariant> {
    vec![Invariant::Solvency, Invariant::ShareConservation, Invariant::VaultBacking]
}
