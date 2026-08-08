//! Integration tests for the PDA seed cross-check
//! (`sat::pda::check_pda_seed_mismatch`).

use std::path::PathBuf;

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

/// Like [`parse_source`], but stamps the resulting structs with a custom
/// file path (`analyze_string_for_test` always stamps "test.rs"), so
/// multi-file scenarios can use distinct paths.
fn parse_source_at(source: &str, path: &str) -> (Vec<AccountsStruct>, syn::File) {
    let (accounts, _, _) = analyze_string_for_test(source);
    let accounts = accounts
        .into_iter()
        .map(|mut a| {
            a.file = PathBuf::from(path);
            a
        })
        .collect();
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

/// A single-instruction IDL named `ix_name` with the given accounts.
fn single_ix_idl(ix_name: &str, accounts: Vec<IdlAccountItem>) -> IdlJson {
    IdlJson {
        version: "0.1.0".to_string(),
        name: "vault".to_string(),
        instructions: vec![IdlInstruction { name: ix_name.to_string(), accounts, args: vec![], discriminator: None }],
        accounts: vec![],
        types: vec![],
        metadata: None,
    }
}

/// A single-instruction IDL named `deposit` with the given accounts.
fn deposit_idl(accounts: Vec<IdlAccountItem>) -> IdlJson {
    single_ix_idl("deposit", accounts)
}

fn run_check(accounts: &[AccountsStruct], idl: Option<&IdlJson>, parsed: &syn::File) -> Vec<Finding> {
    sat::pda::check_pda_seed_mismatch(accounts, idl, &[(parsed.clone(), "test.rs".to_string())])
}

/// Run the check over several parsed files with distinct paths, mirroring a
/// multi-file workspace.
fn run_check_multi(
    accounts: &[AccountsStruct],
    idl: Option<&IdlJson>,
    files: Vec<(syn::File, String)>,
) -> Vec<Finding> {
    sat::pda::check_pda_seed_mismatch(accounts, idl, &files)
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
fn test_full_init_attr_with_seeds_is_extracted() {
    // Regression: the standard Anchor init pattern (`init, payer, space, seeds,
    // bump`) must not be misread as "no seeds constraint". Non-seeds key-value
    // items used to abort parse_nested_meta's comma handling before `seeds`.
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(init, payer = authority, space = 8 + 40, seeds = [b"state", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
"#;
    let (accounts, parsed) = parse_source(source);
    let idl = deposit_idl(vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all = run_check(&accounts, Some(&idl), &parsed);
    let findings = pda_findings(&all);

    assert!(findings.is_empty(), "standard init attr with matching seeds must not be flagged: {findings:?}");
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

#[test]
fn test_multi_file_same_struct_name_reports_wrong_file_only() {
    // Two files both define `Initialize` for the `initialize` instruction.
    // File A's seeds match the IDL; file B's differ. Only file B has the
    // `#[program]` handler, which pins the instruction to B's struct: the
    // check must compare against B (finding at B's path) and must not
    // compare IDL seeds against file A's same-named struct.
    let source_a = r#"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(seeds = [b"state", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let source_b = r#"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(seeds = [b"pool", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[program]
mod initialize_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}
"#;
    let (accounts_a, parsed_a) = parse_source_at(source_a, "a.rs");
    let (accounts_b, parsed_b) = parse_source_at(source_b, "b.rs");
    let mut accounts = accounts_a;
    accounts.extend(accounts_b);

    let idl =
        single_ix_idl("initialize", vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all =
        run_check_multi(&accounts, Some(&idl), vec![(parsed_a, "a.rs".to_string()), (parsed_b, "b.rs".to_string())]);
    let findings = pda_findings(&all);

    assert_eq!(findings.len(), 1, "only file B's struct mismatches: {findings:?}");
    let f = findings[0];
    assert_eq!(f.severity, Severity::Medium);
    let location = f.location.as_deref().expect("finding should have a location");
    assert!(location.starts_with("b.rs:"), "finding must be located at file B, got: {location}");
}

#[test]
fn test_multi_file_handler_evidence_disambiguates_suffix_match() {
    // Both files define `VaultInitialize` (suffix match to `initialize`), so
    // there is no exact name match. Only file B has the handler, which
    // disambiguates the suffix-only candidates toward B's struct.
    let source_a = r#"
#[derive(Accounts)]
pub struct VaultInitialize<'info> {
    #[account(seeds = [b"state", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let source_b = r#"
#[derive(Accounts)]
pub struct VaultInitialize<'info> {
    #[account(seeds = [b"state"], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[program]
mod vault_program {
    use super::*;

    pub fn initialize(ctx: Context<VaultInitialize>) -> Result<()> {
        Ok(())
    }
}
"#;
    let (accounts_a, parsed_a) = parse_source_at(source_a, "a.rs");
    let (accounts_b, parsed_b) = parse_source_at(source_b, "b.rs");
    let mut accounts = accounts_a;
    accounts.extend(accounts_b);

    let idl =
        single_ix_idl("initialize", vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all =
        run_check_multi(&accounts, Some(&idl), vec![(parsed_a, "a.rs".to_string()), (parsed_b, "b.rs".to_string())]);
    let findings = pda_findings(&all);

    assert_eq!(findings.len(), 1, "the handler in B disambiguates the suffix match: {findings:?}");
    let f = findings[0];
    assert_eq!(f.severity, Severity::High);
    let location = f.location.as_deref().expect("finding should have a location");
    assert!(location.starts_with("b.rs:"), "finding must be located at file B, got: {location}");
}

#[test]
fn test_multi_file_ambiguous_without_handler_is_skipped() {
    // Two files define `Initialize` but neither file has a `#[program]`
    // handler, so there is no evidence to pick between them. The check must
    // skip the instruction entirely — even though file B's seeds mismatch
    // the IDL — rather than guess and risk a false positive against the
    // wrong file's struct.
    let source_a = r#"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(seeds = [b"state", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let source_b = r#"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(seeds = [b"pool", authority.key()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts_a, parsed_a) = parse_source_at(source_a, "a.rs");
    let (accounts_b, parsed_b) = parse_source_at(source_b, "b.rs");
    let mut accounts = accounts_a;
    accounts.extend(accounts_b);

    let idl =
        single_ix_idl("initialize", vec![pda_account("vault", vec![const_seed(b"state"), account_seed("authority")])]);

    let all =
        run_check_multi(&accounts, Some(&idl), vec![(parsed_a, "a.rs".to_string()), (parsed_b, "b.rs".to_string())]);
    let findings = pda_findings(&all);

    assert!(findings.is_empty(), "ambiguous structs without handler evidence must be skipped: {findings:?}");
}
