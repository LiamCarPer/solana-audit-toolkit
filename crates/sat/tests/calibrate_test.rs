//! Integration tests for the FP-calibration harness (`sat::calibrate`).
//!
//! Uses `tempfile` directories only (no hardcoded `/tmp`, no network — local
//! corpus repos only), mirroring the `watch_diff` test conventions.

use std::fs;

use sat::calibrate;
use sat::types::{Finding, Severity};
use sat::watch::{FindingSignature, signature_from_finding};
use tempfile::tempdir;

/// A tiny Anchor program whose `authority` is either signer-constrained or an
/// unconstrained `UncheckedAccount` (the latter triggers SAT001).
const PROGRAM_SOURCE: &str = r#"
use anchor_lang::prelude::*;

#[program]
pub mod counter {
    use super::*;

    pub fn set(ctx: Context<Set>, v: u64) -> Result<()> {
        ctx.accounts.state.count = v;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Set<'info> {
    #[account(mut)]
    pub state: Account<'info, Counter>,
    #[account(mut)]
    pub authority: {AUTHORITY_TYPE},
}

#[account]
pub struct Counter {
    pub count: u64,
}
"#;

fn write_program(dir: &std::path::Path, signer: bool) {
    let authority = if signer { "Signer<'info>" } else { "UncheckedAccount<'info>" };
    let source = PROGRAM_SOURCE.replace("{AUTHORITY_TYPE}", authority);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(dir.join("src").join("lib.rs"), source).unwrap();
}

fn finding(title: &str, location: &str) -> Finding {
    Finding {
        id: String::new(),
        title: title.to_string(),
        severity: Severity::High,
        description: "test".to_string(),
        location: Some(location.to_string()),
        suggestion: None,
    }
}

#[test]
fn calibrate_scans_corpus_and_writes_state_and_report() {
    let dir = tempdir().unwrap();
    let vulnerable = dir.path().join("vulnerable");
    write_program(&vulnerable, false); // SAT001 fires
    let clean = dir.path().join("clean");
    write_program(&clean, true);

    let config = serde_json::json!({
        "repos": [
            { "name": "vulnerable", "local_path": vulnerable.to_str(), "src_path": "src" },
            { "name": "clean", "local_path": clean.to_str(), "src_path": "src" }
        ]
    });
    let config_path = dir.path().join("corpus.json");
    fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

    let report_path = dir.path().join("precision.md");
    calibrate::run(config_path.to_str().unwrap(), Some(report_path.to_str().unwrap()))
        .expect("calibration run should succeed");

    // State files exist for both repos.
    let vulnerable_state = fs::read_to_string(dir.path().join(".sat-calib").join("vulnerable.json"))
        .expect("vulnerable state must be written");
    let state: serde_json::Value = serde_json::from_str(&vulnerable_state).unwrap();
    let findings = state["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["title"].as_str().unwrap().contains("Missing Signer")),
        "vulnerable repo must carry the missing-signer finding"
    );
    // The informational token-2022 marker gets the HARDENING prior.
    assert!(findings.iter().any(|f| f["label"] == "HARDENING"), "informational priors must be labeled HARDENING");

    // The report renders with a per-rule table.
    let report = fs::read_to_string(&report_path).unwrap();
    assert!(report.contains("# Calibration Report"), "report header missing");
    assert!(report.contains("## Per-rule precision"), "per-rule table missing");
    assert!(report.contains("| SAT001"), "SAT001 row missing");
}

#[test]
fn fp_label_recomputes_precision_and_exports_suppressions() {
    let dir = tempdir().unwrap();
    let vulnerable = dir.path().join("vulnerable");
    write_program(&vulnerable, false);

    let config = serde_json::json!({
        "repos": [
            { "name": "vulnerable", "local_path": vulnerable.to_str(), "src_path": "src" }
        ]
    });
    let config_path = dir.path().join("corpus.json");
    fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

    let report_path = dir.path().join("precision.md");
    calibrate::run(config_path.to_str().unwrap(), Some(report_path.to_str().unwrap())).unwrap();

    // First pass: everything security-relevant is UNLABELED → no suppressions.
    let supp_path = dir.path().join(".sat-calib").join("suppressions.json");
    let supps: serde_json::Value = serde_json::from_str(&fs::read_to_string(&supp_path).unwrap()).unwrap();
    assert!(supps["suppressions"].as_array().unwrap().is_empty(), "no FPs labeled yet");

    // Flip the missing-signer finding to FP by hand and recompute.
    let state_path = dir.path().join(".sat-calib").join("vulnerable.json");
    let mut state: serde_json::Value = serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    for finding in state["findings"].as_array_mut().unwrap() {
        if finding["title"].as_str().unwrap().contains("Missing Signer") {
            finding["label"] = serde_json::json!("FP");
        }
    }
    fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    calibrate::run(config_path.to_str().unwrap(), Some(report_path.to_str().unwrap())).unwrap();

    // Precision for SAT001 is now 0/1 with a downgrade suggestion.
    let report = fs::read_to_string(&report_path).unwrap();
    let row = report.lines().find(|l| l.starts_with("| SAT001 |")).expect("SAT001 row must exist after recompute");
    assert!(row.contains("| 0 | 1 |"), "SAT001 must be TP=0 FP=1: {row}");
    assert!(row.contains("0%"), "precision must be 0%: {row}");
    assert!(row.contains("DOWNGrade"), "downgrade suggestion must appear: {row}");

    // The confirmed FP is exported as a suppression.
    let supps: serde_json::Value = serde_json::from_str(&fs::read_to_string(&supp_path).unwrap()).unwrap();
    let suppressions = supps["suppressions"].as_array().unwrap();
    assert_eq!(suppressions.len(), 1, "one confirmed FP must be exported");
    assert_eq!(suppressions[0]["rule_id"], "SAT001");
    assert!(suppressions[0]["title"].as_str().unwrap().contains("Missing Signer"));
}

#[test]
fn apply_suppressions_via_signature_roundtrip() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("program").join("src");
    fs::create_dir_all(&src).unwrap();

    let f = finding("Missing Signer: `Set::authority`", &format!("{}:10 (Set::authority)", src.display()));
    let sig: FindingSignature = signature_from_finding(&f, src.to_str().unwrap());

    let file = calibrate::SuppressionFile { suppressions: vec![sig] };
    let supp_path = dir.path().join("suppressions.json");
    fs::write(&supp_path, serde_json::to_string(&file).unwrap()).unwrap();

    let mut findings = vec![f.clone()];
    calibrate::apply_suppressions(&mut findings, supp_path.to_str().unwrap(), src.to_str().unwrap())
        .expect("suppression application should succeed");
    assert!(findings.is_empty(), "the exact finding must be suppressed");

    let other = finding("Missing Owner: `Set::authority`", &format!("{}:10 (Set::authority)", src.display()));
    let mut findings = vec![other.clone()];
    calibrate::apply_suppressions(&mut findings, supp_path.to_str().unwrap(), src.to_str().unwrap()).unwrap();
    assert_eq!(findings.len(), 1, "a different title must survive");
}
