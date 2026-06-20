use sat::analyzer;
use sat::types::Severity;

#[test]
fn test_missing_signer_detection() {
    let source = r#"
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    pub authority: AccountInfo<'info>,
    pub token_account: Account<'info, TokenAccount>,
}
"#;
    let (accounts, _instructions, findings) = analyzer::analyze_string_for_test(source);
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].name, "TransferTokens");
    assert_eq!(accounts[0].fields.len(), 2);

    let authority_field = accounts[0].fields.iter().find(|f| f.name == "authority").unwrap();
    assert!(!authority_field.has_signer);

    let signer_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Signer")).collect();
    assert!(!signer_findings.is_empty(), "should detect missing signer on authority field");
    assert!(signer_findings[0].severity >= Severity::Medium);
    assert!(signer_findings[0].description.contains("authority"));
}

#[test]
fn test_signer_constraint_detected() {
    let source = r#"
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}
"#;
    let (accounts, _, findings) = analyzer::analyze_string_for_test(source);
    let authority = accounts[0].fields.iter().find(|f| f.name == "authority").unwrap();
    assert!(authority.has_signer, "should detect #[account(signer)]");

    let signer_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Signer")).collect();
    assert!(signer_findings.is_empty(), "should not flag when signer is present");
}

#[test]
fn test_signer_type_respected() {
    let source = r#"
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    pub authority: Signer<'info>,
}
"#;
    let (accounts, _, findings) = analyzer::analyze_string_for_test(source);
    let authority = accounts[0].fields.iter().find(|f| f.name == "authority").unwrap();
    assert!(authority.is_signer_type);

    let signer_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Signer")).collect();
    assert!(signer_findings.is_empty(), "Signer<'info> should satisfy signer requirement");
}

#[test]
fn test_missing_owner_on_account_info() {
    let source = r#"
#[derive(Accounts)]
pub struct ReadState<'info> {
    pub some_account: AccountInfo<'info>,
}
"#;
    let (accounts, _, findings) = analyzer::analyze_string_for_test(source);
    let field = &accounts[0].fields[0];
    assert!(field.is_account_info);
    assert!(!field.has_owner);

    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();
    assert!(!owner_findings.is_empty(), "should flag AccountInfo without owner");
    assert!(owner_findings[0].severity >= Severity::High);
}

#[test]
fn test_missing_owner_on_unchecked_account() {
    let source = r#"
#[derive(Accounts)]
pub struct ProcessUnsafe<'info> {
    pub raw: UncheckedAccount<'info>,
}
"#;
    let (accounts, _, findings) = analyzer::analyze_string_for_test(source);
    let field = &accounts[0].fields[0];
    assert!(field.is_unchecked_account);

    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();
    assert!(!owner_findings.is_empty(), "should flag UncheckedAccount without owner");
}

#[test]
fn test_no_owner_flag_when_signer_present() {
    let source = r#"
#[derive(Accounts)]
pub struct SafeRead<'info> {
    #[account(signer)]
    pub raw: AccountInfo<'info>,
}
"#;
    let (_accounts, _, findings) = analyzer::analyze_string_for_test(source);
    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();
    assert!(owner_findings.is_empty(), "should not flag AccountInfo with signer (user account)");
}

#[test]
fn test_detects_mut_constraint() {
    let source = r#"
#[derive(Accounts)]
pub struct ModifyState<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub value: u64,
}
"#;
    let (accounts, _, _findings) = analyzer::analyze_string_for_test(source);
    let state = accounts[0].fields.iter().find(|f| f.name == "state").unwrap();
    assert!(state.has_mut, "should detect #[account(mut)]");
}

#[test]
fn test_detects_init_constraint() {
    let source = r#"
#[derive(Accounts)]
pub struct CreateState<'info> {
    #[account(init, payer = authority, space = 40)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct State {
    pub value: u64,
}
"#;
    let (accounts, _, _findings) = analyzer::analyze_string_for_test(source);
    let state = accounts[0].fields.iter().find(|f| f.name == "state").unwrap();
    assert!(state.has_init);
}

#[test]
fn test_detects_owner_constraint() {
    let source = r#"
#[derive(Accounts)]
pub struct SafeRead<'info> {
    #[account(owner = my_program::ID)]
    pub raw: AccountInfo<'info>,
}
"#;
    let (accounts, _, _findings) = analyzer::analyze_string_for_test(source);
    let field = &accounts[0].fields[0];
    assert!(field.has_owner);
    assert_eq!(field.owner_value.as_deref(), Some("my_program::ID"));
}

#[test]
fn test_extracts_instruction_names() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
}
"#;
    let (_accounts, instructions, _findings) = analyzer::analyze_string_for_test(source);
    assert_eq!(instructions.len(), 2);
    assert!(instructions.iter().any(|i| i.name == "initialize"));
    assert!(instructions.iter().any(|i| i.name == "deposit"));
}

#[test]
fn test_discriminator_collision_detection() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn swap_tokens(ctx: Context<SwapTokens>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
}
"#;
    let (_accounts, instructions, findings) = analyzer::analyze_string_for_test(source);
    assert_eq!(instructions.len(), 1);

    let disc_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Discriminator Collision")).collect();
    assert!(disc_findings.is_empty(), "single instruction should not have collisions");
}

#[test]
fn test_clean_program_no_false_positives() {
    let source = r#"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 40)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateValue<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;
    let (_accounts, _instructions, findings) = analyzer::analyze_string_for_test(source);
    let signer_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Signer")).collect();
    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();
    assert!(signer_findings.is_empty(), "clean program should have no missing signer findings");
    assert!(owner_findings.is_empty(), "clean program should have no missing owner findings");
}

#[test]
fn test_multiple_accounts_structs_in_file() {
    let source = r#"
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub recipient: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Close<'info> {
    pub admin: AccountInfo<'info>,
}
"#;
    let (accounts, _, findings) = analyzer::analyze_string_for_test(source);
    assert_eq!(accounts.len(), 2);
    assert!(findings.len() >= 2, "should flag both missing signer (admin) and missing owner (recipient)");
}

#[test]
fn test_field_with_no_account_attr() {
    let source = r#"
#[derive(Accounts)]
pub struct Simple<'info> {
    pub data: AccountInfo<'info>,
    #[account(mut)]
    pub user: Signer<'info>,
}
"#;
    let (accounts, _, _) = analyzer::analyze_string_for_test(source);
    let data = accounts[0].fields.iter().find(|f| f.name == "data").unwrap();
    assert!(!data.has_signer);
    assert!(!data.has_mut);
    assert!(!data.has_init);
    assert!(!data.has_owner);
}

#[test]
fn test_sarif_export_produces_valid_json() {
    use sat::sarif;
    use sat::types::{Finding, Severity};
    use std::fs;

    let findings = vec![Finding {
        id: "SAT-001".to_string(),
        title: "Missing Signer".to_string(),
        severity: Severity::High,
        description: "Test finding".to_string(),
        location: Some("test.rs:1".to_string()),
        suggestion: Some("Fix it".to_string()),
    }];

    let output_path = "/tmp/sat_test_sarif.json";
    sarif::export_sarif(&findings, "test_program", output_path).unwrap();

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "sat");

    fs::remove_file(output_path).unwrap();
}

#[test]
fn test_sarif_empty_findings() {
    use sat::sarif;
    use std::fs;

    let findings: Vec<sat::types::Finding> = vec![];
    let output_path = "/tmp/sat_test_empty.sarif";
    sarif::export_sarif(&findings, "test", output_path).unwrap();

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 0);

    fs::remove_file(output_path).unwrap();
}

#[test]
fn test_fixture_missing_auth_finds_issues() {
    use std::fs;
    let path = "tests/fixtures_ast/vulnerable/missing_auth.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, instructions, findings) = sat::analyzer::analyze_string_for_test(&source);

    assert!(!accounts.is_empty(), "should find Accounts structs");
    assert_eq!(instructions.len(), 3, "should find 3 instruction handlers");

    let signer_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Signer")).collect();
    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();

    assert!(!signer_findings.is_empty(), "missing_auth fixture should have signer issues");
    assert!(!owner_findings.is_empty(), "missing_auth fixture should have owner issues");
}

#[test]
fn test_fixture_missing_owner_finds_issues() {
    use std::fs;
    let path = "tests/fixtures_ast/vulnerable/missing_owner.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, instructions, findings) = sat::analyzer::analyze_string_for_test(&source);

    assert_eq!(accounts.len(), 2, "should find 2 Accounts structs");
    assert_eq!(instructions.len(), 1);

    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();
    assert!(!owner_findings.is_empty(), "missing_owner fixture should have AccountInfo without owner");
    assert!(owner_findings.len() >= 2, "should flag both AccountInfo and UncheckedAccount");
}

#[test]
fn test_fixture_clean_produces_no_false_positives() {
    use std::fs;
    let path = "tests/fixtures_ast/clean/clean_program.rs";
    let source = fs::read_to_string(path).unwrap();
    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(&source);

    let signer_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Signer")).collect();
    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();

    assert!(signer_findings.is_empty(), "clean fixture should have no missing signer findings");
    assert!(owner_findings.is_empty(), "clean fixture should have no missing owner findings");
}

#[test]
fn test_fixture_sysvar_issues_parses() {
    use std::fs;
    let path = "tests/fixtures_ast/vulnerable/sysvar_issues.rs";
    let source = fs::read_to_string(path).unwrap();
    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(&source);

    assert!(!accounts.is_empty(), "sysvar fixture should parse and find Accounts structs");
    let get_time = accounts.iter().find(|a| a.name == "GetTime").unwrap();
    assert!(get_time.fields.iter().any(|f| f.name == "authority"));
}

#[test]
fn test_all_fixture_files_parse() {
    use std::fs;
    let dirs = ["tests/fixtures_ast/vulnerable", "tests/fixtures_ast/clean"];
    for dir in &dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "rs") {
                    let source = fs::read_to_string(&path).unwrap();
                    let result = std::panic::catch_unwind(|| sat::analyzer::analyze_string_for_test(&source));
                    assert!(result.is_ok(), "should parse {} without panicking", path.display());
                }
            }
        }
    }
}
