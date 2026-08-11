//! Integration tests for SARIF rule classification.
//!
//! Verifies that finding titles map to the intended SARIF rules (SAT014 for
//! CEI violations, SAT015 for PDA seed mismatches, SAT016 for init-if-needed
//! risk, SAT017 for token-CPI authorities, SAT018 for manual deserialization)
//! and that existing rules still classify correctly. Output paths use
//! `tempfile::tempdir()` so the tests pass on Windows (no hardcoded `/tmp`
//! paths).

use std::fs;

use sat::sarif::export_sarif;
use sat::types::{Finding, Severity};
use tempfile::tempdir;

fn export_and_parse(findings: &[Finding]) -> serde_json::Value {
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("sat_rules_test.sarif");
    export_sarif(findings, "test_program", output_path.to_str().unwrap()).unwrap();
    let content = fs::read_to_string(&output_path).unwrap();
    serde_json::from_str(&content).unwrap()
}

fn finding(title: &str, severity: Severity) -> Finding {
    Finding {
        id: "SAT-TEST".to_string(),
        title: title.to_string(),
        severity,
        description: "Test finding".to_string(),
        location: Some("tests/fixtures/src/lib.rs:10".to_string()),
        suggestion: Some("Fix it".to_string()),
    }
}

#[test]
fn cei_violation_maps_to_sat014_error() {
    let parsed = export_and_parse(&[finding(
        "CEI Violation: `withdraw` writes state after external call — reentrancy risk",
        Severity::Critical,
    )]);

    let result = &parsed["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "SAT014");
    assert_eq!(result["level"], "error");
}

#[test]
fn pda_seed_mismatch_maps_to_sat015_error() {
    let parsed = export_and_parse(&[finding(
        "PDA Seed Mismatch: `deposit` derives `vault` from seeds per IDL but `Deposit::vault` has no `seeds` constraint",
        Severity::High,
    )]);

    let result = &parsed["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "SAT015");
    assert_eq!(result["level"], "error");
}

#[test]
fn missing_signer_still_maps_to_sat001() {
    let parsed = export_and_parse(&[finding(
        "Missing Signer: `Foo::authority` authority field is missing signer constraint",
        Severity::High,
    )]);

    let result = &parsed["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "SAT001");
    assert_eq!(result["level"], "error");
}

#[test]
fn severity_levels_map_to_sarif_levels() {
    let parsed = export_and_parse(&[
        finding("Unsafe Arithmetic: test", Severity::Medium),
        finding("Low severity finding", Severity::Low),
        finding("Informational finding", Severity::Informational),
    ]);

    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["level"], "warning");
    assert_eq!(results[1]["level"], "note");
    assert_eq!(results[2]["level"], "note");
}

#[test]
fn init_if_needed_maps_to_sat016_error() {
    let parsed = export_and_parse(&[finding(
        "Reinitialization Risk: `Initialize::state` uses init_if_needed on authority-bearing account `State` without an initialization guard",
        Severity::High,
    )]);

    let result = &parsed["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "SAT016");
    assert_eq!(result["level"], "error");
}

#[test]
fn token_transfer_cpi_maps_to_sat017_error() {
    let parsed = export_and_parse(&[finding(
        "Token Transfer CPI: `transfer` calls `spl_token::transfer` with authority `Transfer::authority` not constrained as signer",
        Severity::High,
    )]);

    let result = &parsed["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "SAT017");
    assert_eq!(result["level"], "error");
}

#[test]
fn manual_deserialization_maps_to_sat018_error() {
    let parsed = export_and_parse(&[finding(
        "Manual Deserialization: `Parse::data` data is deserialized from raw bytes without owner or discriminator validation",
        Severity::High,
    )]);

    let result = &parsed["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "SAT018");
    assert_eq!(result["level"], "error");
}

#[test]
fn rules_table_declares_sat001_through_sat036() {
    let parsed = export_and_parse(&[]);
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 36, "SAT001..SAT036 should all be declared");
    for id in [
        "SAT014", "SAT015", "SAT016", "SAT017", "SAT018", "SAT019", "SAT020", "SAT021", "SAT022", "SAT023", "SAT024",
        "SAT025", "SAT026", "SAT027", "SAT028", "SAT029", "SAT030", "SAT031", "SAT032", "SAT033", "SAT034", "SAT035",
        "SAT036",
    ] {
        assert!(rules.iter().any(|r| r["id"] == id), "rules table missing {id}");
    }
}
