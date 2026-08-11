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

// ── SAT033 precision: Marinade-shape Anchor fallback (regression) ────────────

/// Marinade-shape program: token CPIs inside `process` impls, mint anchoring
/// via typed accounts + framework constraints, and plain data structs
/// (`State`) whose fields must not be expanded as accounts. No SAT033 and no
/// SAT031 findings may fire.
#[test]
fn marinade_shape_fixture_produces_no_token_mint_findings() {
    let (_, findings) = run_fixture("marinade_shape.rs");
    let sat033 = by_rule(&findings, "Unanchored Token Mint:");
    let sat031 = by_rule(&findings, SAT031);
    assert!(sat033.is_empty(), "marinade-shape token CPIs are constraint-anchored; no SAT033 expected: {sat033:#?}");
    assert!(sat031.is_empty(), "marinade-shape has no unanchored chains: {sat031:#?}");
}

/// A token-CPI source pinned by `#[account(has_one = ...)]` / `token::mint`
/// on the Accounts struct needs no visible handler comparison (the Anchor
/// runtime verifies the constraint before the handler runs).
#[test]
fn typed_mint_constraint_anchors_token_cpi_source() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{mint_to, Mint, MintTo, Token, TokenAccount};

#[program]
pub mod pool {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.msol_mint.to_account_info(),
                    to: ctx.accounts.mint_to.to_account_info(),
                    authority: ctx.accounts.msol_mint_authority.to_account_info(),
                },
                &[&[b"msol", &ctx.accounts.state.key().to_bytes(), &[1]]],
            ),
            amount,
        )?;
        Ok(())
    }
}

#[account]
pub struct State {
    pub msol_mint: Pubkey,
    pub msol_mint_authority_bump_seed: u8,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = msol_mint)]
    pub state: Box<Account<'info, State>>,
    #[account(mut)]
    pub msol_mint: Box<Account<'info, Mint>>,
    /// CHECK: PDA
    #[account(seeds = [b"msol", state.key().as_ref()], bump = state.msol_mint_authority_bump_seed)]
    pub msol_mint_authority: UncheckedAccount<'info>,
    #[account(mut, token::mint = state.msol_mint)]
    pub mint_to: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, "Unanchored Token Mint:");
    assert!(flagged.is_empty(), "has_one/token::mint/seeds pin the mint; no SAT033 expected: {findings:#?}");
}

/// Guard against over-suppression: a token CPI whose source mint is NOT
/// constraint-pinned still fires.
#[test]
fn unconstrained_token_cpi_source_still_fires() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{mint_to, Mint, MintTo, Token, TokenAccount};

#[program]
pub mod pool {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        mint_to(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.msol_mint.to_account_info(),
                    to: ctx.accounts.mint_to.to_account_info(),
                    authority: ctx.accounts.any_authority.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// CHECK: no constraint pins this mint.
    pub msol_mint: Account<'info, Mint>,
    #[account(mut)]
    pub mint_to: Box<Account<'info, TokenAccount>>,
    /// CHECK: arbitrary.
    pub any_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, "Unanchored Token Mint:");
    assert_eq!(flagged.len(), 1, "unpinned mint source must fire: {findings:#?}");
    assert!(flagged[0].title.contains("`msol_mint`"), "{}", flagged[0].title);
}

/// `anchor_lang::system_program::Transfer` (lamport transfer, no `authority`
/// field) is not a token source; the token `Transfer` (with `authority`) on
/// an unconstrained account still fires. The two structs share the name
/// `Transfer`; the presence of the `authority` field is the discriminator.
#[test]
fn system_lamport_transfer_is_not_a_token_source() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};
use anchor_spl::token::{transfer as transfer_tokens, Token, TokenAccount, Transfer as TokenTransfer};

#[program]
pub mod vault {
    use super::*;

    pub fn move_lamports(ctx: Context<MoveLamports>, amount: u64) -> Result<()> {
        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.lamport_source.to_account_info(),
                    to: ctx.accounts.lamport_dest.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }

    pub fn move_tokens(ctx: Context<MoveTokens>, amount: u64) -> Result<()> {
        transfer_tokens(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.token_source.to_account_info(),
                    to: ctx.accounts.token_dest.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct MoveLamports<'info> {
    #[account(mut)]
    pub lamport_source: SystemAccount<'info>,
    #[account(mut)]
    pub lamport_dest: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MoveTokens<'info> {
    /// CHECK: no constraint pins this token account.
    #[account(mut)]
    pub token_source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_dest: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, "Unanchored Token Mint:");
    assert_eq!(flagged.len(), 1, "only the token transfer source fires (lamport source has no mint): {findings:#?}");
    let loc = flagged[0].location.as_deref().unwrap_or_default();
    assert!(flagged[0].title.contains("`token_source`"), "{}", flagged[0].title);
    assert!(loc.contains("move_tokens"), "finding must point at move_tokens, got: {loc}");
}

/// Two instructions sharing the helper method name `process` must not leak
/// each other's token CPIs: only the instruction whose own `process` contains
/// the CPI fires.
#[test]
fn sibling_process_impl_does_not_leak() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{mint_to, Mint, MintTo, Token, TokenAccount};

#[program]
pub mod pool {
    use super::*;

    pub fn clean_ix(ctx: Context<CleanIx>) -> Result<()> {
        ctx.accounts.process()
    }

    pub fn dirty_ix(ctx: Context<DirtyIx>, amount: u64) -> Result<()> {
        ctx.accounts.process(amount)
    }
}

#[derive(Accounts)]
pub struct CleanIx<'info> {
    #[account(mut)]
    pub state: Account<'info, CleanState>,
    pub admin: Signer<'info>,
}

#[account]
pub struct CleanState {
    pub value: u64,
}

impl<'info> CleanIx<'info> {
    pub fn process(&mut self) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DirtyIx<'info> {
    /// CHECK: no constraint pins this mint.
    pub msol_mint: Account<'info, Mint>,
    #[account(mut)]
    pub mint_to: Box<Account<'info, TokenAccount>>,
    /// CHECK: arbitrary.
    pub any_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

impl<'info> DirtyIx<'info> {
    pub fn process(&mut self, amount: u64) -> Result<()> {
        mint_to(
            CpiContext::new(
                self.token_program.to_account_info(),
                MintTo {
                    mint: self.msol_mint.to_account_info(),
                    to: self.mint_to.to_account_info(),
                    authority: self.any_authority.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, "Unanchored Token Mint:");
    assert_eq!(flagged.len(), 1, "only dirty_ix has a token CPI: {findings:#?}");
    let loc = flagged[0].location.as_deref().unwrap_or_default();
    assert!(loc.contains("dirty_ix"), "finding must point at dirty_ix, got: {loc}");
}

/// An account pinned by a CONSTANT-seed PDA (`#[account(seeds = [SOME_CONST],
/// bump)])` is a canonical anchor: the Anchor runtime derives its address
/// before the handler runs, so a comparison against one of its fields pins
/// the other side (tip-distribution `migrate_tda_merkle_root_upload_authority`
/// shape — the "PDA IS the anchor" class).
#[test]
fn const_seed_pda_field_anchors_comparison() {
    let source = r#"
use anchor_lang::prelude::*;

const CONFIG_SEED: &[u8] = b"config";

#[program]
pub mod tip_distribution {
    use super::*;

    pub fn migrate_tda(ctx: Context<MigrateTda>) -> Result<()> {
        let distribution_account = &mut ctx.accounts.tip_distribution_account;
        if distribution_account.merkle_root_upload_authority
            != ctx.accounts.merkle_root_upload_config.original_upload_authority
        {
            return Err(ErrorCode::InvalidTdaForMigration.into());
        }
        Ok(())
    }
}

#[account]
pub struct TipDistributionAccount {
    pub merkle_root_upload_authority: Pubkey,
    pub merkle_root: Option<[u8; 32]>,
}

#[account]
pub struct MerkleRootUploadConfig {
    pub original_upload_authority: Pubkey,
    pub override_authority: Pubkey,
}

#[derive(Accounts)]
pub struct MigrateTda<'info> {
    #[account(mut)]
    pub tip_distribution_account: Account<'info, TipDistributionAccount>,

    #[account(
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub merkle_root_upload_config: Account<'info, MerkleRootUploadConfig>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid TDA for migration")]
    InvalidTdaForMigration,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT031);
    assert!(flagged.is_empty(), "constant-seed PDA field pins the comparison; no SAT031 expected: {findings:#?}");
}

/// The Cashio guard: a PDA whose seeds reference a caller-supplied account
/// (`bank` seeded with `crate_token.key()`) is NOT a canonical anchor — the
/// attacker chooses the seed, so the comparison stays unanchored.
#[test]
fn caller_seeded_pda_does_not_anchor_comparison() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod bankman {
    use super::*;

    #[access_control(ctx.accounts.validate())]
    pub fn set_hard_cap(ctx: Context<SetHardCap>) -> Result<()> {
        Ok(())
    }
}

#[account]
pub struct Bank {
    pub curator: Pubkey,
}

#[account]
pub struct Collateral {
    pub bank: Pubkey,
    pub mint: Pubkey,
}

#[derive(Accounts)]
pub struct SetHardCap<'info> {
    #[account(mut)]
    pub bank: Account<'info, Bank>,
    #[account(mut)]
    pub collateral: Account<'info, Collateral>,
    pub curator: Signer<'info>,
}

impl<'info> SetHardCap<'info> {
    pub fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.collateral.bank, self.bank);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct NewBank<'info> {
    #[account(init, payer = payer, seeds = [b"Bank", crate_token.key().as_ref()], bump, space = 64)]
    pub bank: Account<'info, Bank>,
    /// CHECK: arbitrary.
    pub crate_token: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT031);
    assert_eq!(
        flagged.len(),
        1,
        "caller-seeded PDA does not anchor; the collateral.bank == bank.key chain fires: {findings:#?}"
    );
    assert!(flagged[0].description.contains("`collateral`.bank"), "{}", flagged[0].description);
}
