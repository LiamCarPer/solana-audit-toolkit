//! Integration tests for the release delta scanner (`sat::watch`).
//!
//! Uses `tempfile` directories only (no hardcoded `/tmp`), never hits the
//! network (local repos only), and relies on `analyzer::collect` over tiny
//! Anchor-shaped programs.

use std::fs;

use sat::types::{Finding, Severity};
use sat::watch::{FindingSignature, WatchRepo, diff_signatures, scan_repo, signature_from_finding};
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
        description: "test finding".to_string(),
        location: Some(location.to_string()),
        suggestion: None,
    }
}

#[test]
fn signature_normalizes_locations() {
    let sig = signature_from_finding(
        &finding("Missing Signer: `Set::authority`", r"C:\repo\program\src\lib.rs:10 (Set::authority)"),
        r"C:\repo\program\src",
    );
    assert_eq!(sig.location, "lib.rs:10 (Set::authority)", "source prefix must be stripped and separators normalized");
}

#[test]
fn first_scan_marks_all_findings_added() {
    let dir = tempdir().unwrap();
    let repo = WatchRepo {
        name: "counter".to_string(),
        src_path: "src".to_string(),
        url: None,
        local_path: None,
        branch: "master".to_string(),
        rev: None,
    };
    let repo_dir = dir.path().join(&repo.name);
    write_program(&repo_dir, false); // vulnerable variant

    let diff = scan_repo(&repo, dir.path(), &dir.path().join("out")).expect("first scan should succeed");
    assert!(
        diff.added.iter().any(|s| s.title.contains("Missing Signer")),
        "first scan must report the missing-signer finding as added, got: {:?}",
        diff.added
    );
}

#[test]
fn second_scan_reports_removed_when_fixed() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out");

    let repo = WatchRepo {
        name: "counter".to_string(),
        src_path: "src".to_string(),
        url: None,
        local_path: None,
        branch: "master".to_string(),
        rev: None,
    };
    let repo_dir = dir.path().join(&repo.name);

    write_program(&repo_dir, false); // vulnerable
    let first = scan_repo(&repo, dir.path(), &out).expect("first scan should succeed");
    assert!(first.added.iter().any(|s| s.title.contains("Missing Signer")));

    // Fix the program and re-scan: the missing-signer finding must disappear.
    fs::remove_dir_all(repo_dir.join("src")).unwrap();
    write_program(&repo_dir, true); // fixed variant
    let second = scan_repo(&repo, dir.path(), &out).expect("second scan should succeed");
    assert!(second.added.is_empty(), "fixing the program must not add findings: {:?}", second.added);
    assert!(
        second.removed.iter().any(|s| s.title.contains("Missing Signer")),
        "fixing the program must remove the missing-signer finding, got: {:?}",
        second.removed
    );
}

#[test]
fn diff_signatures_reports_symmetric_changes() {
    let a = FindingSignature {
        rule_id: "SAT001".to_string(),
        title: "Missing Signer: `x`".to_string(),
        location: "lib.rs:1 (x)".to_string(),
        severity: "HIGH".to_string(),
    };
    let b = FindingSignature {
        rule_id: "SAT002".to_string(),
        title: "Missing Owner: `y`".to_string(),
        location: "lib.rs:2 (y)".to_string(),
        severity: "HIGH".to_string(),
    };

    let diff = diff_signatures(std::slice::from_ref(&a), &[a.clone(), b.clone()]);
    assert_eq!(diff.added, vec![b.clone()]);
    assert!(diff.removed.is_empty());

    let diff = diff_signatures(&[a.clone(), b.clone()], std::slice::from_ref(&a));
    assert_eq!(diff.removed, vec![b]);
    assert!(diff.added.is_empty());
}

#[test]
fn run_tolerates_missing_local_repo() {
    let dir = tempdir().unwrap();
    let valid = dir.path().join("valid");
    write_program(&valid, false);
    let config = serde_json::json!({
        "repos": [
            { "name": "bogus", "src_path": "src" },
            { "name": "valid", "local_path": valid.to_str(), "src_path": "src" }
        ]
    });
    let config_path = dir.path().join("watch.json");
    fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

    let out = dir.path().join("out");
    sat::watch::run(config_path.to_str().unwrap(), out.to_str().unwrap()).expect("run must tolerate a bad repo");

    assert!(out.join("valid.json").exists(), "valid repo state must be written despite the bogus repo");
    // A missing local repo scans as an empty program: no findings beyond the
    // always-emitted "No Token-2022 Usage Detected" informational.
    let bogus_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("bogus.json")).unwrap()).unwrap();
    let signatures = bogus_state["signatures"].as_array().unwrap();
    assert!(signatures.len() <= 1, "bogus repo must have no real findings, got: {signatures:?}");
    if !signatures.is_empty() {
        assert!(
            signatures[0]["title"].as_str().unwrap().contains("Token-2022"),
            "only the informational token-2022 marker is expected: {signatures:?}"
        );
    }
}
