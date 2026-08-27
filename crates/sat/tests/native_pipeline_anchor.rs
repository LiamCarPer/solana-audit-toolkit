//! Pipeline regression: `sat::native::analyze` on an Anchor-only workspace
//! must run the cross-cutting slices (taint / accounting / oracle), not just
//! the validate + state-creation slices the Anchor-only branch historically
//! short-circuited to. Guards the wiring in `native/mod.rs`.

use sat::types::{Finding, Severity};

const SAT038: &str = "Unvalidated Flow:";

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

/// An Anchor-only source with a clear unanchored flow: attacker `amount`
/// (from an `UncheckedAccount`) is copied into a program-owned state account
/// — must surface through the full pipeline. Guards the Anchor-only branch of
/// `native::analyze`, which historically short-circuited to only the
/// validate + state-creation slices.
#[test]
fn anchor_only_workspace_runs_cross_cutting_slices() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;
    pub fn deposit(ctx: Context<Deposit>, _amount: u64) -> Result<()> {
        let input = u64::from_le_bytes(ctx.accounts.amount_source.data.borrow()[0..8].try_into().unwrap());
        let mut data = ctx.accounts.state.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&input.to_le_bytes());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// CHECK: attacker-controlled by design, but state is trusted.
    pub amount_source: UncheckedAccount<'info>,
    #[account(mut)]
    pub state: Account<'info, VaultState>,
}

#[account]
pub struct VaultState {
    pub deposited: u64,
}
"#;
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    assert!(program.instructions.is_empty(), "anchor source builds no native instructions");

    let findings = sat::native::analyze(&files);
    let taint = by_rule(&findings, SAT038);
    assert!(
        !taint.is_empty(),
        "full pipeline on Anchor-only workspace must fire SAT038 (taint slice short-circuited?): {findings:#?}"
    );
    assert!(
        taint.iter().all(|f| f.severity == Severity::High || f.severity == Severity::Medium),
        "taint findings should be High/Medium, got: {:#?}",
        taint.iter().map(|f| f.severity).collect::<Vec<_>>()
    );
}
