//! Integration tests for the PDA seed cross-check
//! (`sat::pda::check_pda_seed_mismatch`).

use sat::analyzer::{AccountsStruct, analyze_string_for_test};
use sat::idl::{IdlAccountItem, IdlInstruction, IdlJson, IdlPda, IdlSeed};
use sat::types::{Finding, Severity};

/// Parse the source with syn and extract the accounts structs with the
/// analyzer, mirroring how the check is exercised in production.
fn parse_source(source: &str) -> (Vec<AccountsStruct>, syn::File) {
    let (accounts, _, _) = analyze_string_for_test(source);
    let parsed = syn::parse_file(source).expect("test source should parse");
    (accounts, parsed)
}

fn pda_account(name: &str, seeds: Vec<IdlSeed>) -> IdlAccountItem {
    IdlAccountItem { name: name.to_string(), is_mut: true, is_signer: false, pda: Some(IdlPda { seeds }), desc: None }
}

fn const_seed(bytes: &[u8]) -> IdlSeed {
    IdlSeed { kind: "const".to_string(), value: Some(bytes.to_vec()), path: None, account: None }
}

fn account_seed(name: &str) -> IdlSeed {
    IdlSeed { kind: "account".to_string(), value: None, path: None, account: Some(name.to_string()) }
}

fn arg_seed(name: &str) -> IdlSeed {
    IdlSeed { kind: "arg".to_string(), value: None, path: Some(name.to_string()), account: None }
}

/// A single-instruction IDL named `deposit` with the given accounts.
fn deposit_idl(accounts: Vec<IdlAccountItem>) -> IdlJson {
    IdlJson {
        version: "0.1.0".to_string(),
        name: "vault".to_string(),
        instructions: vec![IdlInstruction { name: "deposit".to_string(), accounts, args: vec![], discriminator: None }],
        accounts: vec![],
        types: vec![],
        metadata: None,
    }
}

fn run_check(accounts: &[AccountsStruct], idl: Option<&IdlJson>, parsed: &syn::File) -> Vec<Finding> {
    sat::pda::check_pda_seed_mismatch(accounts, idl, &[(parsed.clone(), "test.rs".to_string())])
}

fn pda_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|f| f.title.contains("PDA Seed Mismatch")).collect()
}

#[test]
fn test_matching_seeds_are_not_flagged() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(seeds = [b"state", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, parsed) = parse_source(source);
    let idl = deposit_idl(vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all = run_check(&accounts, Some(&idl), &parsed);
    let findings = pda_findings(&all);

    assert!(findings.is_empty(), "matching seeds should not be flagged: {findings:?}");
}

#[test]
fn test_missing_seeds_constraint_flagged_high() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, parsed) = parse_source(source);
    let idl = deposit_idl(vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all = run_check(&accounts, Some(&idl), &parsed);
    let findings = pda_findings(&all);

    assert_eq!(findings.len(), 1, "expected exactly one missing-seeds finding");
    let f = findings[0];
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.title.contains("`deposit` derives `vault` from seeds per IDL but `Deposit::vault` has no `seeds` constraint"),
        "unexpected title: {}",
        f.title
    );
    let location = f.location.as_deref().expect("finding should have a location");
    assert!(location.starts_with("test.rs:"), "unexpected location: {location}");
    assert!(location.ends_with(" (deposit, vault)"), "unexpected location: {location}");
    assert!(
        f.description.contains("bypassing PDA checks"),
        "description should explain the account-substitution risk: {}",
        f.description
    );
    assert!(
        f.suggestion.as_deref().is_some_and(|s| s.contains("single source of truth")),
        "suggestion should mention aligning seeds with the IDL"
    );
}

#[test]
fn test_seed_count_mismatch_flagged_high() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(seeds = [b"state"], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, parsed) = parse_source(source);
    let idl = deposit_idl(vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all = run_check(&accounts, Some(&idl), &parsed);
    let findings = pda_findings(&all);

    assert_eq!(findings.len(), 1, "expected exactly one count-mismatch finding");
    let f = findings[0];
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.title.contains("`deposit` declares 2 seeds for `vault` but `Deposit::vault` declares 1 seed"),
        "unexpected title: {}",
        f.title
    );
}

#[test]
fn test_seed_value_mismatch_flagged_medium() {
    // `VaultDeposit` matches the `deposit` instruction via the suffix
    // heuristic (struct name ends with the instruction name).
    let source = r#"
#[derive(Accounts)]
pub struct VaultDeposit<'info> {
    #[account(seeds = [b"pool", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, parsed) = parse_source(source);
    let idl = deposit_idl(vec![pda_account("vault", vec![const_seed(b"vault"), account_seed("authority")])]);

    let all = run_check(&accounts, Some(&idl), &parsed);
    let findings = pda_findings(&all);

    assert_eq!(findings.len(), 1, "expected exactly one seed-diff finding");
    let f = findings[0];
    assert_eq!(f.severity, Severity::Medium);
    assert!(
        f.title.contains("seed 0 of `vault` in `deposit` differs between IDL (b\"vault\") and code (b\"pool\")"),
        "unexpected title: {}",
        f.title
    );
    assert!(f.description.contains("bypassing PDA checks"), "description should explain the derivation risk");
}

#[test]
fn test_arg_seed_is_never_flagged() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(seeds = [amount.as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, parsed) = parse_source(source);
    let idl = deposit_idl(vec![pda_account("vault", vec![arg_seed("amount")])]);

    let all = run_check(&accounts, Some(&idl), &parsed);
    let findings = pda_findings(&all);

    assert!(findings.is_empty(), "arg-kind IDL seeds must never be flagged: {findings:?}");
}

#[test]
fn test_no_idl_means_no_findings() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(seeds = [b"state", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, parsed) = parse_source(source);

    let findings = run_check(&accounts, None, &parsed);

    assert!(findings.is_empty(), "without an IDL there is nothing to cross-check: {findings:?}");
}
