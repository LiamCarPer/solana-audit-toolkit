use anyhow::Result;
use serde_json;
use std::fs;

use sat::idl::IdlJson;

const FIXTURES_DIR: &str = "tests/fixtures";

fn load_idl(name: &str) -> Result<IdlJson> {
    let path = format!("{FIXTURES_DIR}/{name}.json");
    let content = fs::read_to_string(&path)?;
    let idl: IdlJson = serde_json::from_str(&content)?;
    Ok(idl)
}

#[test]
fn test_parse_vault_idl() {
    let idl = load_idl("vault").expect("should parse vault IDL");
    assert_eq!(idl.name, "vault");
    assert_eq!(idl.instructions.len(), 4);
    assert_eq!(idl.accounts.len(), 2);
    assert_eq!(idl.accounts[0].name, "VaultState");
    assert!(idl.metadata.is_some());
    assert_eq!(idl.metadata.unwrap().address.unwrap(), "Vau1t11111111111111111111111111111111111111");
}

#[test]
fn test_parse_staking_idl() {
    let idl = load_idl("staking").expect("should parse staking IDL");
    assert_eq!(idl.name, "staking");
    assert_eq!(idl.instructions.len(), 5);
    assert_eq!(idl.types.len(), 1);
    assert_eq!(idl.types[0].name, "PoolStatus");
    assert_eq!(idl.types[0].ty.variants.len(), 3);
}

#[test]
fn test_parse_governance_idl() {
    let idl = load_idl("governance").expect("should parse governance IDL");
    assert_eq!(idl.name, "governance");
    assert_eq!(idl.accounts.len(), 3);
    let proposal = &idl.accounts[1];
    assert_eq!(proposal.name, "ProposalState");
    assert_eq!(idl.types[0].name, "ProposalStatus");
    assert_eq!(idl.types[0].ty.variants.len(), 4);
}

#[test]
fn test_state_identification() {
    let idl = load_idl("vault").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    assert_eq!(states.len(), 2);

    let vault = states.iter().find(|s| s.name == "VaultState").unwrap();
    assert!(vault.has_init_flag, "VaultState should have isInitialized flag");
    assert!(vault.has_bump, "VaultState should have bump");
    assert!(vault.has_authority, "VaultState should have authority");
    assert!(vault.field_names.contains(&"totalDeposits".to_string()), "VaultState should have totalDeposits field");
    assert!(vault.field_names.contains(&"isInitialized".to_string()), "VaultState should have isInitialized field");

    let deposit = states.iter().find(|s| s.name == "UserDeposit").unwrap();
    assert!(deposit.has_bump);
    assert!(!deposit.has_init_flag);
}

#[test]
fn test_state_identification_with_enum() {
    let idl = load_idl("staking").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let pool = states.iter().find(|s| s.name == "PoolState").unwrap();
    assert!(pool.has_status_enum);
    assert_eq!(pool.status_field.as_deref(), Some("status"));
    assert_eq!(pool.status_variants, vec!["Active", "Paused", "Closed"]);
}

#[test]
fn test_state_identification_governance() {
    let idl = load_idl("governance").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let proposal = states.iter().find(|s| s.name == "ProposalState").unwrap();
    assert!(proposal.has_status_enum);
    assert_eq!(proposal.status_variants, vec!["Active", "Passed", "Rejected", "Executed"]);
}

#[test]
fn test_instruction_categorization() {
    let idl = load_idl("vault").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);

    let init_vault = instructions.iter().find(|i| i.name == "initializeVault").unwrap();
    assert!(init_vault.is_initializer(), "initializeVault should be an initializer");
    assert!(init_vault.is_writable_for("VaultState"));

    let deposit = instructions.iter().find(|i| i.name == "deposit").unwrap();
    assert!(deposit.is_mutator(), "deposit should be a mutator");
    assert!(deposit.has_signer);

    let withdraw = instructions.iter().find(|i| i.name == "withdraw").unwrap();
    assert!(withdraw.is_mutator(), "withdraw should be a mutator");

    let close = instructions.iter().find(|i| i.name == "closeVault").unwrap();
    assert!(close.is_terminator(), "closeVault should be a terminator");
}

#[test]
fn test_reinitialization_detection() {
    let idl = load_idl("reinit_vuln").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);

    let findings = sat::idl::check_reinit_for_test(&states, &instructions);
    assert!(!findings.is_empty(), "should detect reinitialization risk");

    let reinit_finding =
        findings.iter().find(|f| f.title.contains("Reinitialization")).expect("should find reinitialization finding");
    assert_eq!(reinit_finding.severity, sat::types::Severity::Critical);
    assert!(reinit_finding.description.contains("is_initialized"));
}

#[test]
fn test_no_reinit_false_positive_on_clean() {
    let idl = load_idl("clean_program").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);

    let findings = sat::idl::check_reinit_for_test(&states, &instructions);
    let reinit_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Reinitialization")).collect();
    assert!(
        reinit_findings.is_empty(),
        "clean program should not have reinitialization findings (has isInitialized flag)"
    );
}

#[test]
fn test_access_control_detection() {
    let idl = load_idl("reinit_vuln").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);

    let findings = sat::idl::check_access_for_test(&instructions);

    let update_admin = findings
        .iter()
        .find(|f| f.title.contains("updateAdmin") || f.title.contains("Missing Access"))
        .expect("should flag updateAdmin for missing access control");
    assert!(update_admin.severity >= sat::types::Severity::High);
    assert!(update_admin.description.contains("signer"));
}

#[test]
fn test_access_control_clean() {
    let idl = load_idl("clean_program").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);

    let findings = sat::idl::check_access_for_test(&instructions);
    let access_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Access")).collect();
    assert!(
        access_findings.is_empty(),
        "clean program should not have missing access control (all mutators have signers)"
    );
}

#[test]
fn test_staking_transition_analysis() {
    let idl = load_idl("staking").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);
    let graphs = sat::idl::build_graph_for_test(&states, &instructions);

    let pool_graph = graphs.iter().find(|g| g.account_name == "PoolState").unwrap();
    assert!(pool_graph.states.iter().any(|s| s == "Active"));
    assert!(pool_graph.states.iter().any(|s| s == "Closed"));
    assert!(!pool_graph.edges.is_empty(), "PoolState should have transitions");
}

#[test]
fn test_no_state_lockout_in_staking() {
    let idl = load_idl("staking").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);
    let graphs = sat::idl::build_graph_for_test(&states, &instructions);

    let findings = sat::idl::check_lockout_for_test(&graphs, &instructions);

    let pool_lockout: Vec<_> =
        findings.iter().filter(|f| f.title.contains("PoolState") && f.title.contains("Lockout")).collect();
    assert!(pool_lockout.is_empty(), "PoolState should not have state lockout (has init and close)");
}

#[test]
fn test_discriminator_collision_detection() {
    let idl = load_idl("vault").unwrap();
    let findings = sat::idl::check_discriminators_for_test(&idl);
    assert!(findings.is_empty(), "vault instructions should not have discriminator collisions");
}

#[test]
fn test_governance_analysis_complete() {
    let idl = load_idl("governance").unwrap();
    let states = sat::idl::identify_states_for_test(&idl);
    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);
    let graphs = sat::idl::build_graph_for_test(&states, &instructions);

    let findings_reinit = sat::idl::check_reinit_for_test(&states, &instructions);
    let findings_access = sat::idl::check_access_for_test(&instructions);
    let findings_lockout = sat::idl::check_lockout_for_test(&graphs, &instructions);

    let all_findings: Vec<_> =
        findings_reinit.iter().chain(findings_access.iter()).chain(findings_lockout.iter()).collect();

    assert!(!all_findings.is_empty(), "governance should produce some findings");

    let reinit_proposal =
        all_findings.iter().any(|f| f.title.contains("ProposalState") && f.title.contains("Reinitialization"));
    assert!(reinit_proposal, "ProposalState has no isInitialized flag, should flag reinitialization");
}

#[test]
fn test_empty_idl() {
    let idl = IdlJson {
        version: "0.1.0".to_string(),
        name: "empty".to_string(),
        instructions: vec![],
        accounts: vec![],
        types: vec![],
        metadata: None,
    };
    let states = sat::idl::identify_states_for_test(&idl);
    assert!(states.is_empty());

    let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);
    assert!(instructions.is_empty());

    let graphs = sat::idl::build_graph_for_test(&states, &instructions);
    assert!(graphs.is_empty());
}

#[test]
fn test_full_analysis_does_not_panic() {
    let test_files = ["vault", "reinit_vuln", "staking", "clean_program", "governance"];
    for file in &test_files {
        let idl = load_idl(file).unwrap();
        let states = sat::idl::identify_states_for_test(&idl);
        let instructions = sat::idl::categorize_instructions_for_test(&idl, &states);
        let graphs = sat::idl::build_graph_for_test(&states, &instructions);

        let _f1 = sat::idl::check_discriminators_for_test(&idl);
        let _f2 = sat::idl::check_reinit_for_test(&states, &instructions);
        let _f3 = sat::idl::check_access_for_test(&instructions);
        let _f4 = sat::idl::check_lockout_for_test(&graphs, &instructions);
    }
}

#[test]
fn test_parse_idl_roundtrip() {
    let path = format!("{FIXTURES_DIR}/vault.json");
    let idl = sat::idl::parse_idl(&path).expect("should parse vault IDL");
    assert_eq!(idl.name, "vault");
}
