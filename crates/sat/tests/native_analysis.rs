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
fn test_e2e_validate_vuln_fixture() {
    let (_program, findings) = analyze_fixture("validate/vuln.rs");
    assert!(
        findings.iter().any(|f| f.title.starts_with("Self-Referential Validation:")),
        "expected a Self-Referential Validation finding in validate/vuln.rs, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn test_e2e_state_creation_vuln_fixture() {
    let (_program, findings) = analyze_fixture("state_creation/vuln.rs");
    assert!(
        findings.iter().any(|f| f.title.starts_with("Permissionless State Creation:")),
        "expected a Permissionless State Creation finding in state_creation/vuln.rs, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn test_e2e_oracle_vuln_fixture() {
    let (_program, findings) = analyze_fixture("oracle/vuln.rs");
    for prefix in ["Stale Oracle Price:", "Oracle Confidence Unvalidated:", "Oracle Decimals/Exponent Mismatch:"] {
        assert!(
            findings.iter().any(|f| f.title.starts_with(prefix)),
            "expected a finding starting with '{prefix}' in oracle/vuln.rs, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_e2e_clean_fixtures_produce_no_native_findings() {
    for rel in [
        "auth/clean.rs",
        "pda_cei/clean.rs",
        "lifecycle/clean.rs",
        "cpi/clean.rs",
        "validate/clean.rs",
        "state_creation/clean.rs",
        "oracle/clean.rs",
    ] {
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
fn test_expectations_render_shape() {
    // pda_cei vuln fixture: byte-match dispatch + find_program_address with a
    // literal seed (b"escrow") and a dynamic seed (owner.key()).
    let source = fs::read_to_string("tests/fixtures_native/pda_cei/vuln.rs").unwrap();
    let (program, _) = native::analyze_source_and_files_for_test(&source);
    let doc: serde_json::Value = serde_json::from_str(&native::expectations::render(&program).unwrap()).unwrap();

    assert_eq!(doc["source"], "native");
    assert!(doc["program_name"].as_str().is_some_and(|n| !n.is_empty()));
    let instructions = doc["instructions"].as_array().unwrap();
    assert!(!instructions.is_empty(), "native fixture must resolve instructions");

    let mut saw_pda = false;
    for ix in instructions {
        assert!(ix["name"].as_str().is_some());
        assert!(ix["handler"].as_str().is_some());
        for account in ix["accounts"].as_array().unwrap() {
            assert!(account["is_signer_expected"].is_boolean());
            assert!(account["is_writable_expected"].is_boolean());
            if let Some(pda) = account["pda"].as_object() {
                saw_pda = true;
                let seeds = pda["seeds"].as_array().unwrap();
                assert!(
                    seeds.iter().any(|s| s == "escrow"),
                    "literal seed b\"escrow\" must be exported, got: {seeds:?}"
                );
                assert!(pda["dynamic_seed_count"].as_u64().unwrap() >= 1, "owner.key() seed must count as dynamic");
            }
        }
    }
    assert!(saw_pda, "fixture has find_program_address; expectations must carry pda info");
}

#[test]
fn test_expectations_export_writes_json_file() {
    let source = fs::read_to_string("tests/fixtures_native/auth/vuln.rs").unwrap();
    let (_program, files) = native::analyze_source_and_files_for_test(&source);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("expectations.json");
    native::expectations::export(&files, out.to_str().unwrap()).unwrap();

    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(json["source"], "native");
    assert!(!json["instructions"].as_array().unwrap().is_empty());
}

#[test]
fn test_expectations_anchor_only_workspace_is_empty() {
    let source = r#"
#[program]
pub mod counter {
    use super::*;
    pub fn increment(ctx: Context<Increment>) -> Result<()> {
        Ok(())
    }
}
#[derive(Accounts)]
pub struct Increment<'info> {}
"#;
    let (program, _files) = native::analyze_source_and_files_for_test(source);
    let doc = native::expectations::build(&program);
    assert!(doc.instructions.is_empty(), "Anchor-only workspace exports no expectations");
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
        ("Self-Referential Validation: `x`", "SAT031"),
        ("Permissionless State Creation: `x`", "SAT032"),
        ("Unanchored Token Mint: `x`", "SAT033"),
        ("Stale Oracle Price: `x`", "SAT034"),
        ("Oracle Confidence Unvalidated: `x`", "SAT035"),
        ("Oracle Decimals/Exponent Mismatch: `x`", "SAT036"),
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
    for id in [
        "SAT019", "SAT020", "SAT021", "SAT022", "SAT023", "SAT024", "SAT025", "SAT027", "SAT028", "SAT029", "SAT030",
        "SAT031", "SAT032", "SAT033", "SAT034", "SAT035", "SAT036",
    ] {
        assert!(rules.contains(&id), "SARIF rules table missing {id}");
    }
}
