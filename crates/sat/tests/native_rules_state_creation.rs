//! R6 slice tests: SAT032 — Permissionless State Creation (Anchor path),
//! exercised via `state_creation::check` directly on the parsed files from
//! `sat::native::analyze_source_and_files_for_test`.
//!
//! The rule only runs on Anchor-only workspaces (no native marker), which the
//! test sources satisfy. `#[path]` shim bridges the imports the rule file
//! uses, including the shared helpers it pulls from the validate slice.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::NativeProgram;
    }
    pub mod rules {
        pub mod validate {
            pub use sat::native::rules::validate::{StructIndex, anchor_instructions, has_anchor_program};
        }
    }
}

#[path = "../src/native/rules/state_creation.rs"]
mod state_creation;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT032: &str = "Permissionless State Creation:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/state_creation/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the state-creation rule.
fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = state_creation::check(&program, &files);
    (program, findings)
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
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
fn vuln_fixture_is_an_anchor_only_workspace() {
    let (program, _) = run(&fixture_source("vuln.rs"));
    assert!(program.instructions.is_empty(), "anchor-only source builds no native instructions");
}

// ── Finding shape ────────────────────────────────────────────────────────────

#[test]
fn vuln_fixture_fires_per_unverified_authority_slot() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    let flagged = by_rule(&findings, SAT032);
    assert_eq!(flagged.len(), 3, "admin + two crate authorities expected: {findings:#?}");

    for f in &flagged {
        assert_eq!(f.severity, Severity::High);
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(!f.description.is_empty());
        assert!(f.suggestion.is_some());
        let expected_loc = format!("test.rs:{} (new_bank)", line_of(&source, "pub fn new_bank"));
        assert_eq!(f.location.as_deref(), Some(expected_loc.as_str()));
        assert!(f.description.contains("new_bank"), "description must name the instruction: {}", f.description);
    }

    for slot in ["`admin`", "`brrr_issue_authority`", "`burn_withdraw_authority`"] {
        assert!(flagged.iter().any(|f| f.title.contains(slot)), "missing finding for {slot}: {findings:#?}");
    }
}

// ── Clean gate ───────────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_state_creation_findings() {
    let (_, findings) = run(&fixture_source("clean.rs"));
    assert!(findings.is_empty(), "signer-pinned authorities must not fire: {findings:#?}");
}

// ── FP filters (inline sources) ──────────────────────────────────────────────

/// A `Signer<'info>`-typed authority on a creation instruction is pinned.
#[test]
fn signer_typed_authority_is_pinned() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod registry {
    use super::*;

    pub fn create_registry(ctx: Context<CreateRegistry>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateRegistry<'info> {
    #[account(init, payer = payer)]
    pub registry: Account<'info, Registry>,
    pub admin: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Registry {
    pub owner: Pubkey,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT032);
    assert!(flagged.is_empty(), "signer-typed authority must be pinned: {findings:#?}");
}

/// An `#[account(signer)]`-constrained unchecked account is pinned.
#[test]
fn signer_constraint_is_pinned() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod registry {
    use super::*;

    pub fn create_registry(ctx: Context<CreateRegistry>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateRegistry<'info> {
    #[account(init, payer = payer)]
    pub registry: Account<'info, Registry>,
    #[account(signer)]
    /// CHECK: pinned by the signer constraint.
    pub admin: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Registry {
    pub owner: Pubkey,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT032);
    assert!(flagged.is_empty(), "signer-constrained authority must be pinned: {findings:#?}");
}

/// A non-creating instruction with an unchecked authority slot does not fire.
#[test]
fn non_creating_instruction_is_not_flagged() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod registry {
    use super::*;

    pub fn update_registry(ctx: Context<UpdateRegistry>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateRegistry<'info> {
    #[account(mut)]
    pub registry: Account<'info, Registry>,
    /// CHECK: post-creation update path; SAT032 targets creation only.
    pub admin: UncheckedAccount<'info>,
}

#[account]
pub struct Registry {
    pub owner: Pubkey,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT032);
    assert!(flagged.is_empty(), "non-creating instruction must not fire: {findings:#?}");
}

/// `init_if_needed`-based creation with an unchecked authority fires too.
#[test]
fn init_if_needed_creation_fires() {
    let source = r#"
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn open_vault(ctx: Context<OpenVault>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct OpenVault<'info> {
    #[account(init_if_needed, payer = payer, seeds = [b"vault", payer.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: the vault records this caller-chosen key as owner.
    pub owner: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT032);
    assert_eq!(flagged.len(), 1, "init_if_needed creation with unchecked owner must fire: {findings:#?}");
}
