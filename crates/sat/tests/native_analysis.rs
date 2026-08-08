//! End-to-end tests for the native backend: full `native::analyze` pipeline
//! (frontend + all rule slices wired through `rules::run`) and SARIF rule
//! classification for the SAT019–SAT030 rules.

use std::fs;

use sat::native;
use sat::sarif;
use sat::types::{Finding, Severity};

fn analyze_fixture(rel: &str) -> (native::model::NativeProgram, Vec<Finding>) {
    let path = format!("tests/fixtures_native/{rel}");
    let source = fs::read_to_string(&path).unwrap();
    let (program, files) = native::analyze_source_and_files_for_test(&source);
    let findings = native::analyze(&files);
    (program, findings)
}

#[test]
fn test_e2e_auth_vuln_fixture() {
    let (_program, findings) = analyze_fixture("auth/vuln.rs");
    let prefixes = ["Unverified Signer Account:", "Unverified Owner Account:", "Unchecked Authority Key:"];
    for prefix in prefixes {
        assert!(
            findings.iter().any(|f| f.title.starts_with(prefix)),
            "expected a finding starting with '{prefix}' in auth/vuln.rs, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_e2e_pda_cei_vuln_fixture() {
    let (_program, findings) = analyze_fixture("pda_cei/vuln.rs");
    for prefix in ["Seed Derivation Mismatch:", "State Write After CPI:"] {
        assert!(
            findings.iter().any(|f| f.title.starts_with(prefix)),
            "expected a finding starting with '{prefix}' in pda_cei/vuln.rs, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_e2e_lifecycle_vuln_fixture() {
    let (_program, findings) = analyze_fixture("lifecycle/vuln.rs");
    for prefix in
        ["Account Reinit After Close:", "Unchecked Deserialization:", "Unsafe Arithmetic:", "Writable Builtin Account:"]
    {
        assert!(
            findings.iter().any(|f| f.title.starts_with(prefix)),
            "expected a finding starting with '{prefix}' in lifecycle/vuln.rs, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_e2e_cpi_vuln_fixture() {
    let (_program, findings) = analyze_fixture("cpi/vuln.rs");
    for prefix in ["Token CPI Unverified Authority:", "Self-Invocation:", "Cross-Instruction State Reuse:"] {
        assert!(
            findings.iter().any(|f| f.title.starts_with(prefix)),
            "expected a finding starting with '{prefix}' in cpi/vuln.rs, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_e2e_clean_fixtures_produce_no_native_findings() {
    for rel in ["auth/clean.rs", "pda_cei/clean.rs", "lifecycle/clean.rs", "cpi/clean.rs"] {
        let (_program, findings) = analyze_fixture(rel);
        assert!(
            findings.is_empty(),
            "clean fixture {rel} should produce zero native findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_e2e_anchor_code_produces_no_native_findings() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod counter {
    use super::*;
    pub fn increment(ctx: Context<Increment>) -> Result<()> {
        ctx.accounts.counter.count += 1;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
}

#[account]
pub struct Counter {
    pub count: u64,
}
"#;
    let (_program, files) = native::analyze_source_and_files_for_test(source);
    let findings = native::analyze(&files);
    assert!(findings.is_empty(), "Anchor-only code must produce no native findings");
}

#[test]
fn test_sarif_classification_of_native_rules() {
    let cases: &[(&str, &str)] = &[
        ("Unverified Signer Account: `x`", "SAT019"),
        ("Unverified Owner Account: `x`", "SAT020"),
        ("Unchecked Authority Key: `x`", "SAT021"),
        ("Seed Derivation Mismatch: `x`", "SAT022"),
        ("State Write After CPI: `x`", "SAT023"),
        ("Account Reinit After Close: `x`", "SAT024"),
        ("Unchecked Deserialization: `x`", "SAT025"),
        ("Writable Builtin Account: `x`", "SAT027"),
        ("Token CPI Unverified Authority: `x`", "SAT028"),
        ("Self-Invocation: `x`", "SAT029"),
        ("Cross-Instruction State Reuse: `x`", "SAT030"),
        // SAT026 intentionally reuses the Anchor SAT012 title.
        ("Unsafe Arithmetic: `a + b`", "SAT012"),
    ];

    let findings: Vec<Finding> = cases
        .iter()
        .map(|(title, _)| Finding {
            id: String::new(),
            title: title.to_string(),
            severity: Severity::High,
            description: String::new(),
            location: Some("test.rs:1".to_string()),
            suggestion: None,
        })
        .collect();

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("native.sarif");
    sarif::export_sarif(&findings, "program", out.to_str().unwrap()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();

    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), cases.len());

    for (i, (title, expected_id)) in cases.iter().enumerate() {
        let rule_id = results[i]["ruleId"].as_str().unwrap_or_default();
        assert_eq!(rule_id, *expected_id, "title '{title}' should classify as {expected_id}");
    }

    // Every native rule id must exist in the SARIF rules table.
    let rules: Vec<&str> = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    for id in
        ["SAT019", "SAT020", "SAT021", "SAT022", "SAT023", "SAT024", "SAT025", "SAT027", "SAT028", "SAT029", "SAT030"]
    {
        assert!(rules.contains(&id), "SARIF rules table missing {id}");
    }
}
