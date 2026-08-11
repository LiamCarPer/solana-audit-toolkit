//! Integration tests for the markdown audit report generator.
//!
//! Renders hand-built findings through `sat::audit::render_markdown` and
//! runs the full pipeline through `sat::audit::run` against minimal
//! Anchor-shaped sources in `tempfile` directories (no hardcoded `/tmp`
//! paths, no program compilation, no network).

use std::fs;

use sat::audit;
use sat::types::{Finding, Severity};
use tempfile::tempdir;

/// A minimal Anchor-ish program: a `#[program]` module, one instruction,
/// a `#[derive(Accounts)]` struct, and a state account. Triggers the
/// Unsafe Arithmetic rule (SAT012) via an un-checked `+=` on a balance
/// (plain `= ... + ...` assignment is not visited by the walker).
const COUNTER_SOURCE: &str = r#"
use anchor_lang::prelude::*;

#[program]
pub mod counter {
    use super::*;

    pub fn increment(ctx: Context<Increment>, amount: u64) -> Result<()> {
        ctx.accounts.counter.balance += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Counter {
    pub balance: u64,
}
"#;

/// The same program with a MISSING-SIGNER pattern: an authority-named
/// `UncheckedAccount` with no signer constraint, so the Missing Signer
/// (SAT001) and Missing Owner (SAT002) rules fire.
const MISSING_SIGNER_SOURCE: &str = r#"
use anchor_lang::prelude::*;

#[program]
pub mod counter {
    use super::*;

    pub fn increment(ctx: Context<Increment>, amount: u64) -> Result<()> {
        ctx.accounts.counter.balance = ctx.accounts.counter.balance + amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
    #[account(mut)]
    pub authority: UncheckedAccount<'info>,
}

#[account]
pub struct Counter {
    pub balance: u64,
}
"#;

fn finding(id: &str, title: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        severity,
        description: "The field `authority` in `Vault` is not constrained as a signer.".to_string(),
        location: Some("programs/vault/src/lib.rs:42 (Vault::authority)".to_string()),
        suggestion: Some("Add `#[account(signer)]` to the field.".to_string()),
    }
}

#[test]
fn render_markdown_includes_sections() {
    let findings = vec![
        finding(
            "SAT-001",
            "Missing Signer: `Vault::authority` authority field is mutable but not marked as signer",
            Severity::High,
        ),
        finding("SAT-002", "CEI Violation: `withdraw` writes state after external call", Severity::Critical),
    ];

    let md = audit::render_markdown(&findings, "vault", Some("Vault2Au2xYJ9v8VQYqk7TqR1m2kq8fQwXq5tAbCdEfGhIjK"), None);

    assert!(md.contains("# Audit Report"), "header missing");
    assert!(md.contains("## Executive Summary"), "executive summary missing");
    assert!(md.contains("## Findings"), "findings section missing");
    assert!(md.contains("### "), "per-finding heading missing");
    assert!(md.contains("**Severity:**"), "severity label missing");
    assert!(md.contains("**Rule:**"), "rule label missing");
    assert!(md.contains("**Confidence:**"), "confidence label missing");
    assert!(md.contains("**Manual verification:**"), "manual verification label missing");
    assert!(md.contains("1. "), "numbered verification steps missing");
    assert!(md.contains("| CRITICAL | 1 |"), "critical count line missing");
    assert!(md.contains("| HIGH | 1 |"), "high count line missing");
    assert!(md.contains("| High | 1 |"), "high confidence line missing");
    assert!(md.contains("**Rule:** SAT014"), "CEI finding not classified as SAT014");

    // The honest-limitations text must always be present.
    assert!(md.contains("## Scope & Honest Limitations"), "limitations section missing");
    assert!(md.contains("field-level invariants"), "field-level invariant limitation missing");

    // The tx-report correlation section appears only when a report path is given.
    let with_tx = audit::render_markdown(&findings, "vault", None, Some("tx-report.json"));
    assert!(with_tx.contains("## Transaction Report Correlation"), "tx-report section missing");
    assert!(with_tx.contains("SAT011"), "SAT011 note missing");
    assert!(with_tx.contains("`tx-report.json`"), "tx-report path missing");

    assert!(!md.contains("## Transaction Report Correlation"), "tx-report section must be absent without a path");
}

#[test]
fn audit_run_generates_report_for_source() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("counter");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("lib.rs"), COUNTER_SOURCE).unwrap();
    let src = src_dir.to_str().unwrap().to_string();

    let report = dir.path().join("audit-report.md");
    let report_str = report.to_str().unwrap().to_string();

    audit::run(Some(&src), Some(&report_str), None).expect("audit run should succeed");

    let content = fs::read_to_string(&report).expect("report file should exist");
    assert!(content.contains("# Audit Report"), "report header missing");
    assert!(content.contains("## Findings"), "findings section missing");
    assert!(content.contains("| HIGH |"), "severity count line missing");
    assert!(content.contains("**Rule:** SAT012"), "unsafe arithmetic finding missing");
}

#[test]
fn audit_run_errors_on_missing_source() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let report = dir.path().join("audit-report.md");

    let err = audit::run(Some(missing.to_str().unwrap()), Some(report.to_str().unwrap()), None)
        .expect_err("running against a missing source should fail");
    assert!(err.to_string().contains("No Rust source files"), "unexpected error: {err}");
}

#[test]
fn audit_run_classifies_rule_ids() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("vault");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("lib.rs"), MISSING_SIGNER_SOURCE).unwrap();
    let src = src_dir.to_str().unwrap().to_string();

    let report = dir.path().join("audit-report.md");
    let report_str = report.to_str().unwrap().to_string();

    audit::run(Some(&src), Some(&report_str), None).expect("audit run should succeed");

    let content = fs::read_to_string(&report).expect("report file should exist");
    assert!(content.contains("**Rule:** SAT001"), "missing-signer finding not classified as SAT001");
    assert!(content.contains("Missing Signer"), "missing-signer finding title missing");
}
