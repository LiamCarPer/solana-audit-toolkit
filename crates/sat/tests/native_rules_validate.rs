//! R5 slice tests: SAT031 — Self-Referential Validation (the Cashio class),
//! exercised via `validate::check` directly on the pinned model plus the
//! parsed files from `sat::native::analyze_source_and_files_for_test`.
//!
//! `crates/sat/src/native/rules/mod.rs` is owned by the integration slice; the
//! test crate includes the rule file itself with `#[path]` and bridges the
//! `crate::native` / `crate::types` paths it uses (same pattern as the other
//! rule-slice tests).

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
    }
}

#[path = "../src/native/rules/validate.rs"]
mod validate;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT031: &str = "Self-Referential Validation:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/validate/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the validation rule.
fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = validate::check(&program, &files);
    (program, findings)
}

fn run_fixture(name: &str) -> (NativeProgram, Vec<Finding>) {
    run(&fixture_source(name))
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

fn account<'a>(ix: &'a sat::native::model::NativeInstruction, name: &str) -> &'a sat::native::model::ResolvedAccount {
    ix.accounts
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("account `{name}` not resolved (have: {:?})", ix.accounts))
}

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
        .unwrap_or_else(|| panic!("line containing `{needle}` not found"))
}

// ── Model sanity: guards against vacuous rule tests ─────────────────────────

#[test]
fn vuln_fixture_resolves_accounts_for_validation() {
    let (program, _) = run_fixture("vuln.rs");
    assert_eq!(program.instructions.len(), 1, "no-dispatch fallback instruction");
    let ix = &program.instructions[0];
    assert_eq!(ix.handler, "process_instruction");
    for name in ["collateral_mint", "collateral_tokens", "fee_mint", "fee_tokens"] {
        account(ix, name);
    }
    assert!(ix.accounts.iter().all(|a| a.name != "config"), "vuln fixture has no canonical anchor");
}

// ── Finding shape ────────────────────────────────────────────────────────────

#[test]
fn vuln_fixture_fires_self_referential_findings() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    // Two unanchored components: the mint-identity chain (all four accounts)
    // and the owner-equality chain (collateral_tokens ↔ fee_tokens).
    let flagged = by_rule(&findings, SAT031);
    assert_eq!(flagged.len(), 2, "two unanchored components expected: {findings:#?}");

    for f in &flagged {
        assert_eq!(f.severity, Severity::High);
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(!f.description.is_empty());
        assert!(f.suggestion.is_some());
        let expected_loc = format!("test.rs:{} (process_instruction)", line_of(&source, "pub fn process_instruction"));
        assert_eq!(f.location.as_deref(), Some(expected_loc.as_str()));
    }

    // The mint chain mentions every fabricated account; the owner chain
    // mentions the two token accounts.
    let mint_chain =
        flagged.iter().find(|f| f.description.contains("`fee_mint`")).expect("mint chain mentions fee_mint");
    for account in ["collateral_mint", "collateral_tokens", "fee_mint", "fee_tokens"] {
        assert!(
            mint_chain.description.contains(&format!("`{account}`")),
            "chain must mention `{account}`: {}",
            mint_chain.description
        );
    }
    let owner_chain = flagged.iter().find(|f| f.description.contains(".owner")).expect("owner chain mentions .owner");
    for account in ["collateral_tokens", "fee_tokens"] {
        assert!(
            owner_chain.description.contains(&format!("`{account}`")),
            "owner chain must mention `{account}`: {}",
            owner_chain.description
        );
    }
}

// ── Clean gate ───────────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_validation_findings() {
    let (_, findings) = run_fixture("clean.rs");
    assert!(findings.is_empty(), "anchored validation should produce no SAT031 findings: {findings:#?}");
}

// ── FP filters (inline sources) ──────────────────────────────────────────────

/// A comparison against the program id is a canonical anchor.
#[test]
fn owner_compared_to_program_id_is_anchored() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;

    if state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if authority.key != state.key {
        return Err(ProgramError::InvalidAccountData);
    }
    msg!("ok");
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "owner check against program id anchors the chain: {findings:#?}");
}

/// A comparison against a named constant is a canonical anchor.
#[test]
fn comparison_to_const_mint_is_anchored() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

const USDC_MINT: Pubkey = Pubkey::new_from_array([0u8; 32]);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let tokens = next_account_info(accounts_iter)?;
    let mint = next_account_info(accounts_iter)?;

    assert_keys_eq!(tokens.mint, USDC_MINT);
    msg!("mint pinned: {}", mint.key);
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "comparison to a constant pins the mint: {findings:#?}");
}

/// An owner check against a canonical account propagates through the chain.
#[test]
fn owner_checked_config_anchors_dependent_comparisons() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config = next_account_info(accounts_iter)?;
    let tokens = next_account_info(accounts_iter)?;
    let mint = next_account_info(accounts_iter)?;

    if config.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if tokens.owner != config.key {
        return Err(ProgramError::IllegalOwner);
    }
    assert_keys_eq!(tokens.mint, mint.key);
    msg!("ok");
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "owner-checked accounts anchor later comparisons: {findings:#?}");
}

/// A self-referential chain through a local alias still fires.
#[test]
fn alias_local_chain_fires() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let a = next_account_info(accounts_iter)?;
    let b = next_account_info(accounts_iter)?;

    let mint = a.mint;
    if mint == b.mint {
        msg!("same mint");
    }
    Ok(())
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT031);
    assert_eq!(flagged.len(), 1, "alias-local chain is still self-referential: {findings:#?}");
}

/// A Vipers-style method-call validate with `self`-based field access fires.
#[test]
fn method_call_validate_self_fields_fires() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let crate_mint = next_account_info(accounts_iter)?;
    let crate_tokens = next_account_info(accounts_iter)?;

    let chain = Validation {
        crate_mint,
        crate_tokens,
    };
    chain.validate()?;
    msg!("ok");
    Ok(())
}

struct Validation<'info> {
    crate_mint: &'info AccountInfo<'info>,
    crate_tokens: &'info AccountInfo<'info>,
}

impl<'info> Validation<'info> {
    fn validate(&self) -> ProgramResult {
        assert_keys_eq!(self.crate_tokens.mint, self.crate_mint.key);
        Ok(())
    }
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT031);
    assert_eq!(flagged.len(), 1, "method-call validate with self-fields must fire: {findings:#?}");
}

// ── Anchor fallback path (the Cashio shape) ──────────────────────────────────

/// The Cashio shape: `#[program]` + `#[access_control(ctx.accounts.validate())]`
/// + Vipers `impl Validate` with `assert_keys_eq!` chains, including a nested
///   Accounts bundle slot (`self.common.crate_mint`).
#[test]
fn anchor_access_control_validate_chain_fires() {
    let source = r#"
use anchor_lang::prelude::*;
use vipers::{assert_keys_eq, validate::Validate};

declare_id!("BRRRot6ig147TBU6EGp7TMesmQrwu729CbG6qu2ZUHWm");

#[program]
pub mod printer {
    use super::*;

    #[access_control(ctx.accounts.validate())]
    pub fn print_cash(ctx: Context<PrintCash>, amount: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct PrintCash<'info> {
    pub common: Box<Account<'info, Common>>,
    pub depositor: Signer<'info>,
    pub depositor_source: Box<Account<'info, TokenAccount>>,
}

#[derive(Accounts)]
pub struct Common<'info> {
    pub bank: Box<Account<'info, Bank>>,
    pub collateral: Box<Account<'info, Collateral>>,
    pub crate_mint: Box<Account<'info, Mint>>,
    pub crate_token: Box<Account<'info, TokenAccount>>,
}

pub struct Bank {
    pub crate_mint: Pubkey,
}

pub struct Collateral {
    pub bank: Pubkey,
    pub mint: Pubkey,
}

impl<'info> Validate<'info> for PrintCash<'info> {
    fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.common.bank, self.common.collateral.bank);
        assert_keys_eq!(self.common.bank.crate_mint, self.common.crate_mint);
        assert_keys_eq!(self.common.crate_token.mint, self.depositor_source.mint);
        Ok(())
    }
}
"#;
    let (program, findings) = run(source);
    assert!(program.instructions.is_empty(), "anchor-only source builds no native instructions");
    let flagged = by_rule(&findings, SAT031);
    // Three unanchored components: {bank.key, collateral.bank},
    // {bank.crate_mint, crate_mint.key} and {crate_token.mint,
    // depositor_source.mint}.
    assert_eq!(flagged.len(), 3, "three unanchored components expected: {findings:#?}");
    let bank_key =
        flagged.iter().find(|f| f.description.contains("`collateral`.bank")).expect("bank-identity component fires");
    for account in ["`bank`.key", "`collateral`.bank"] {
        assert!(bank_key.description.contains(account), "chain must mention {account}: {}", bank_key.description);
    }
    let bank_field =
        flagged.iter().find(|f| f.description.contains("`bank`.crate_mint")).expect("bank-field component fires");
    assert!(bank_field.description.contains("`crate_mint`.key"), "{}", bank_field.description);
    let crate_token_chain =
        flagged.iter().find(|f| f.title.contains("`crate_token`")).expect("crate_token component fires");
    assert!(crate_token_chain.description.contains("`depositor_source`.mint"), "{}", crate_token_chain.description);
    for f in &flagged {
        assert_eq!(f.severity, Severity::High);
        assert!(f.id.is_empty());
        assert!(f.location.as_deref().unwrap_or_default().contains("(print_cash)"));
    }
}

/// The Cashio shape with every chain anchored to a constant stays silent.
#[test]
fn anchor_const_pinned_validation_is_silent() {
    let source = r#"
use anchor_lang::prelude::*;
use vipers::{assert_keys_eq, validate::Validate};

const ISSUE_AUTHORITY_ADDRESS: Pubkey = Pubkey::new_from_array([0u8; 32]);
const USDC_MINT: Pubkey = Pubkey::new_from_array([1u8; 32]);

#[program]
pub mod printer {
    use super::*;

    #[access_control(ctx.accounts.validate())]
    pub fn print_cash(ctx: Context<PrintCash>, amount: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct PrintCash<'info> {
    pub mint: Box<Account<'info, Mint>>,
    pub tokens: Box<Account<'info, TokenAccount>>,
    pub issue_authority: Signer<'info>,
}

impl<'info> Validate<'info> for PrintCash<'info> {
    fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.tokens.mint, USDC_MINT);
        assert_keys_eq!(self.issue_authority, ISSUE_AUTHORITY_ADDRESS);
        Ok(())
    }
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT031);
    assert!(flagged.is_empty(), "anchored anchor validation must not fire: {findings:#?}");
}
