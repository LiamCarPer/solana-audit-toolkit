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
    #[account(mut)]
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
    #[account(mut)]
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
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut)]
    pub admin: AccountInfo<'info>,
}
"#;
    let (accounts, _, findings) = analyzer::analyze_string_for_test(source);
    assert_eq!(accounts.len(), 2);
    let owner_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Owner")).collect();
    assert!(owner_findings.len() >= 2, "should flag missing owner on recipient and admin");
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

    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("sat_test_sarif.json");
    sarif::export_sarif(&findings, "test_program", output_path.to_str().unwrap()).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "sat");
}

#[test]
fn test_sarif_empty_findings() {
    use sat::sarif;
    use std::fs;

    let findings: Vec<sat::types::Finding> = vec![];
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("sat_test_empty.sarif");
    sarif::export_sarif(&findings, "test", output_path.to_str().unwrap()).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 0);
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
    let (accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(&source);

    assert!(!accounts.is_empty(), "sysvar fixture should parse and find Accounts structs");
    let get_time = accounts.iter().find(|a| a.name == "GetTime").unwrap();
    assert!(get_time.fields.iter().any(|f| f.name == "authority"));

    let missing_sysvar: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing Sysvar")).collect();
    assert!(
        missing_sysvar.iter().any(|f| f.title.contains("Clock")),
        "Clock::get() without a declared clock sysvar should be flagged"
    );
    assert!(
        !missing_sysvar.iter().any(|f| f.title.contains("Rent")),
        "Rent::get() must not be flagged because UseRent declares `rent: Sysvar<'info, Rent>`"
    );
}

#[test]
fn test_missing_has_one_requires_storage_authority_field() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn update(ctx: Context<Update>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let has_one_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing `has_one`")).collect();

    assert_eq!(has_one_findings.len(), 1, "should flag missing has_one when storage has authority");
}

#[test]
fn test_arithmetic_detector_skips_plain_loop_counters() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn count(ctx: Context<Count>) -> Result<()> {
        let mut i = 0u64;
        i += 1;
        let j = i + 2;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Count<'info> {
    pub authority: Signer<'info>,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let arithmetic_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Unsafe Arithmetic")).collect();

    assert!(arithmetic_findings.is_empty(), "plain counters should not be reported as bounty-relevant arithmetic");
}

#[test]
fn test_arithmetic_detector_flags_account_balance_updates() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        ctx.accounts.state.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let arithmetic_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Unsafe Arithmetic")).collect();

    assert!(!arithmetic_findings.is_empty(), "account balance arithmetic should be reported");
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

#[test]
fn test_cei_ordering_detects_write_after_cpi() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;

        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let cei_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("CEI Violation")).collect();
    assert!(!cei_findings.is_empty(), "should detect CEI violation — write after invoke()");
    assert!(
        cei_findings[0].severity == sat::types::Severity::Critical
            || cei_findings[0].severity == sat::types::Severity::High,
        "CEI should be Critical or High"
    );
    assert!(cei_findings[0].description.contains("reentrancy"));
}

#[test]
fn test_cei_ordering_skips_safe_write_before_cpi() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_sub(amount).unwrap();

        invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let cei_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("CEI Violation")).collect();
    assert!(cei_findings.is_empty(), "should NOT flag when write happens BEFORE CPI (safe)");
}

#[test]
fn test_cei_ordering_no_cpi_no_flags() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn update(ctx: Context<Update>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let cei_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("CEI Violation")).collect();
    assert!(cei_findings.is_empty(), "no CPI calls — should have no CEI findings");
}

#[test]
fn test_account_closing_detects_manual_lamports() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn close_vault(ctx: Context<Close>) -> Result<()> {
        let vault_info = ctx.accounts.vault.to_account_info();
        let vault_lamports = vault_info.lamports();
        **vault_info.try_borrow_mut_lamports()? = 0;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let close_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Unsafe Account Closing")).collect();
    assert!(!close_findings.is_empty(), "should detect manual lamports manipulation without close constraint");
}

#[test]
fn test_account_closing_skips_when_close_present() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn close_vault(ctx: Context<Close>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, close = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let close_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Unsafe Account Closing")).collect();
    assert!(close_findings.is_empty(), "should NOT flag when close constraint is present");
}

// ── SARIF location parsing (A2) ───────────────────────────────────────────────

#[test]
fn test_sarif_extracts_uri_and_line_from_location() {
    use sat::sarif;
    use sat::types::Finding;
    use std::fs;

    let findings = vec![Finding {
        id: "SAT-001".to_string(),
        title: "Missing Signer".to_string(),
        severity: Severity::High,
        description: "Test finding".to_string(),
        location: Some("src/lib.rs:42 (Foo::bar)".to_string()),
        suggestion: Some("Fix it".to_string()),
    }];

    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("sat_test_location.json");
    sarif::export_sarif(&findings, "test_program", output_path.to_str().unwrap()).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let physical = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(physical["artifactLocation"]["uri"], "src/lib.rs");
    assert_eq!(physical["region"]["startLine"], 42);
}

#[test]
fn test_sarif_windows_path_location_parses_drive_letter() {
    use sat::sarif;
    use sat::types::Finding;
    use std::fs;

    let findings = vec![Finding {
        id: "SAT-001".to_string(),
        title: "Missing Signer".to_string(),
        severity: Severity::High,
        description: "Test finding".to_string(),
        location: Some("C:\\repo\\src\\lib.rs:42 (Foo::bar)".to_string()),
        suggestion: None,
    }];

    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("sat_test_win.json");
    sarif::export_sarif(&findings, "test_program", output_path.to_str().unwrap()).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let physical = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(physical["artifactLocation"]["uri"], "C:\\repo\\src\\lib.rs");
    assert_eq!(physical["region"]["startLine"], 42);
}

#[test]
fn test_sarif_location_without_line_omits_region_line() {
    use sat::sarif;
    use sat::types::Finding;
    use std::fs;

    let findings = vec![Finding {
        id: "SAT-001".to_string(),
        title: "Sysvar Misuse".to_string(),
        severity: Severity::High,
        description: "Test finding".to_string(),
        location: Some("Sysvar: rent (SysvarRent111111111111111111111111111111111)".to_string()),
        suggestion: None,
    }];

    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("sat_test_noline.json");
    sarif::export_sarif(&findings, "test_program", output_path.to_str().unwrap()).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let physical = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(
        physical["artifactLocation"]["uri"], "Sysvar: rent (SysvarRent111111111111111111111111111111111)",
        "locations without a line fall back to the whole string as the URI"
    );
    assert!(physical["region"].get("startLine").is_none(), "no startLine should be emitted without a line number");
}

// ── Coverage gaps (A5) ────────────────────────────────────────────────────────

#[test]
fn test_serialization_mismatch_detected() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn update(ctx: Context<Update>, input: UpdateArgs) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub total: u64,
}

pub struct UpdateArgs {
    pub total: u32,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let mismatch: Vec<_> = findings.iter().filter(|f| f.title.contains("Serialization Mismatch")).collect();
    assert_eq!(mismatch.len(), 1, "u32 arg vs u64 storage should be flagged");
    assert_eq!(mismatch[0].severity, Severity::High);
    assert!(mismatch[0].description.contains("truncation"));
}

#[test]
fn test_serialization_matching_widths_no_finding() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn update(ctx: Context<Update>, input: UpdateArgs) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub total: u64,
}

pub struct UpdateArgs {
    pub total: u64,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let mismatch: Vec<_> = findings.iter().filter(|f| f.title.contains("Serialization Mismatch")).collect();
    assert!(mismatch.is_empty(), "matching widths should not be flagged");
}

fn vault_deposit_idl() -> sat::idl::IdlJson {
    use sat::idl::{IdlAccountItem, IdlInstruction, IdlJson};

    IdlJson {
        version: "0.1.0".to_string(),
        name: "vault".to_string(),
        instructions: vec![IdlInstruction {
            name: "deposit".to_string(),
            accounts: vec![IdlAccountItem {
                name: "vault".to_string(),
                is_mut: true,
                is_signer: false,
                pda: None,
                desc: None,
            }],
            args: vec![],
            discriminator: None,
        }],
        accounts: vec![],
        types: vec![],
        metadata: None,
    }
}

#[test]
fn test_missing_mut_detected_via_idl() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);
    let findings = sat::analyzer::check_missing_mut(&accounts, Some(&vault_deposit_idl()));
    let mut_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing `mut`")).collect();
    assert_eq!(mut_findings.len(), 1, "IDL marks vault writable but there is no #[account(mut)]");
    assert_eq!(mut_findings[0].severity, Severity::High);
}

#[test]
fn test_missing_mut_skipped_when_mut_present() {
    let source = r#"
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);
    let findings = sat::analyzer::check_missing_mut(&accounts, Some(&vault_deposit_idl()));
    let mut_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("Missing `mut`")).collect();
    assert!(mut_findings.is_empty(), "declared #[account(mut)] should satisfy the check");
}

#[test]
fn test_tx_report_correlation_detects_signer_mismatch() {
    let source = r#"
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}
"#;

    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);

    let dir = tempfile::tempdir().unwrap();
    let report_path = dir.path().join("tx_report.json");
    std::fs::write(
        &report_path,
        r#"{
            "schema_version": "1.0",
            "program_name": "test",
            "instructions": [
                {
                    "name": "TransferTokens",
                    "accounts": [
                        {"name": "from", "is_signer": false, "is_writable": true},
                        {"name": "authority", "is_signer": false, "is_writable": false}
                    ]
                }
            ]
        }"#,
    )
    .unwrap();

    let findings = sat::tx_report::check_tx_report_correlation(&accounts, report_path.to_str().unwrap());
    let signer_mismatch: Vec<_> = findings.iter().filter(|f| f.title.contains("Tx-Report Mismatch")).collect();
    assert_eq!(signer_mismatch.len(), 1, "authority is declared signer but was not a signer at runtime");
    assert_eq!(signer_mismatch[0].severity, Severity::Critical);
}

#[test]
fn test_tx_report_invalid_json_returns_info_finding() {
    let source = r#"
#[derive(Accounts)]
pub struct Foo<'info> {
    pub authority: Signer<'info>,
}
"#;

    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(source);

    let dir = tempfile::tempdir().unwrap();
    let report_path = dir.path().join("bad.json");
    std::fs::write(&report_path, "not json").unwrap();

    let findings = sat::tx_report::check_tx_report_correlation(&accounts, report_path.to_str().unwrap());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("Failed to parse"), "{}", findings[0].title);
    assert_eq!(findings[0].severity, Severity::Informational);
}

#[test]
fn test_token2022_fixture_detects_fee_bypass_and_interfaces() {
    use std::fs;

    let path = "tests/fixtures_ast/vulnerable/token2022_transfer.rs";
    let source = fs::read_to_string(path).unwrap();
    let parsed = syn::parse_file(&source).unwrap();

    let (accounts, _instructions, _findings) = sat::analyzer::analyze_string_for_test(&source);
    let parsed_files = vec![(parsed, path.to_string())];

    let findings =
        sat::token2022::analyze(std::path::Path::new("tests/fixtures_ast/vulnerable"), &parsed_files, &accounts);

    let fee_bypass: Vec<_> = findings.iter().filter(|f| f.title.contains("Transfer Fee Bypass")).collect();
    assert_eq!(fee_bypass.len(), 1, "transfer_checked with no fee handling should be flagged");
    assert_eq!(fee_bypass[0].severity, Severity::High);

    let interface: Vec<_> = findings.iter().filter(|f| f.title.contains("Token-2022 InterfaceAccount")).collect();
    assert_eq!(interface.len(), 3, "from/to/mint are InterfaceAccount fields");
}

#[test]
fn test_interface_account_detection_positive_and_negative() {
    let positive = r#"
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: InterfaceAccount<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, _, _) = sat::analyzer::analyze_string_for_test(positive);
    let findings = sat::token2022::detect_interface_account(&accounts);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("from"));

    let negative = r#"
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
"#;
    let (accounts, _, _) = sat::analyzer::analyze_string_for_test(negative);
    let findings = sat::token2022::detect_interface_account(&accounts);
    assert!(findings.is_empty(), "plain Account<TokenAccount> is not an interface account");
}

#[test]
fn test_cpi_depth_flags_overflow_chain() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn a(ctx: Context<Empty>) -> Result<()> {
        invoke(&b_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn b(ctx: Context<Empty>) -> Result<()> {
        invoke(&c_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn c(ctx: Context<Empty>) -> Result<()> {
        invoke(&d_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn d(ctx: Context<Empty>) -> Result<()> {
        invoke(&e_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn e(ctx: Context<Empty>) -> Result<()> {
        invoke(&f_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn f(ctx: Context<Empty>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Empty<'info> {
    pub x: AccountInfo<'info>,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let overflow: Vec<_> = findings.iter().filter(|f| f.title.contains("CPI Depth Overflow")).collect();
    assert!(!overflow.is_empty(), "a→f chain exceeds the Solana CPI depth limit of 4");
    assert_eq!(overflow[0].severity, Severity::Critical);
    assert!(overflow[0].title.contains("`a`"), "the entry-point instruction should be flagged");
}

#[test]
fn test_cpi_depth_ok_below_limit() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn a(ctx: Context<Empty>) -> Result<()> {
        invoke(&b_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn b(ctx: Context<Empty>) -> Result<()> {
        invoke(&c_instruction(ctx.accounts.x.key()), &[ctx.accounts.x.to_account_info()])?;
        Ok(())
    }

    pub fn c(ctx: Context<Empty>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Empty<'info> {
    pub x: AccountInfo<'info>,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let overflow: Vec<_> = findings.iter().filter(|f| f.title.contains("CPI Depth Overflow")).collect();
    assert!(overflow.is_empty(), "depth-3 chain is within the limit");
}

#[test]
fn test_cpi_depth_unresolved_warning() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let cpi_instruction = Instruction { program_id: ctx.accounts.token_program.key(), accounts: vec![], data: vec![] };
        invoke(&cpi_instruction, &[ctx.accounts.token_program.to_account_info()])?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub token_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
"#;

    let (_accounts, _instructions, findings) = sat::analyzer::analyze_string_for_test(source);
    let unresolved: Vec<_> = findings.iter().filter(|f| f.title.contains("CPI Depth Unresolved")).collect();
    assert_eq!(unresolved.len(), 1, "untraceable invoke target should produce an informational warning");
    assert_eq!(unresolved[0].severity, Severity::Informational);
}
