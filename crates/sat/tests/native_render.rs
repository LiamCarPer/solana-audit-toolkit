//! Tests for native instruction summary rendering (`sat::render`).
//!
//! The native backend resolves instructions (name / handler / discriminator /
//! resolved account list) that the Anchor-oriented `AnalysisContext` cannot
//! see, so the CLI renders a dedicated "Native Instruction Handlers" block for
//! native workspaces (docs/BENCHMARK.md: "add instruction-count rendering for
//! native programs so engagement is visible"). These tests pin that text.

use std::fs;
use std::io::Write;

use sat::render;

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/frontend/{name}");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

fn native_summary(source: &str) -> String {
    let program = sat::native::analyze_source_for_test(source);
    render::native_instructions_summary(&program)
}

/// Inline native program for the `analyzer::collect` pipeline test: two
/// dispatched instructions, one with a resolved signer account and one whose
/// handler body resolves no accounts.
const INLINE_NATIVE_SOURCE: &str = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match &instruction_data[0..8] {
        [1, 2, 3, 4, 5, 6, 7, 8, ..] => process_deposit(_program_id, accounts),
        [9, 9, 9, 9, 9, 9, 9, 9, ..] => process_withdraw(_program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_deposit(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

fn process_withdraw(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    Ok(())
}
"#;

#[test]
fn test_native_summary_lists_dispatch_instructions_with_metadata() {
    let text = native_summary(&fixture_source("fixture_dispatch_match8.rs"));

    // Intro line with resolved count and entrypoint location.
    assert!(
        text.contains("Resolved 3 native instruction(s) from entrypoint test.rs:15"),
        "intro line missing, got:\n{text}"
    );

    // Wildcard-pattern arm: handler resolved, no literal discriminator bytes.
    assert!(text.contains("process_deposit"), "instruction name missing, got:\n{text}");
    assert!(text.contains("handler: process_deposit"), "handler missing, got:\n{text}");
    assert!(text.contains("(no discriminator)"), "no-discriminator placeholder missing, got:\n{text}");

    // Literal byte-prefix arm: discriminator rendered as hex.
    assert!(text.contains("process_withdraw"), "instruction name missing, got:\n{text}");
    assert!(text.contains("[0x0102030405060708]"), "discriminator hex missing, got:\n{text}");

    // Literal-prefix arm with an inline (non-call) body: synthetic name and
    // zero resolved accounts carry the unresolved marker.
    assert!(text.contains("instruction_0x0909090909090909"), "synthetic name missing, got:\n{text}");
    assert!(text.contains("accounts: 0 (!)"), "unresolved 0-account marker missing, got:\n{text}");

    // Footer: total resolved vs. resolved-with-accounts counts.
    assert!(text.contains("3 instructions resolved (2 with resolved accounts)"), "footer missing, got:\n{text}");
    // Dispatch was recovered (multiple arms): no recovery warning.
    assert!(
        !text.contains("frontend dispatch recovery is limited"),
        "recovery warning must not fire when dispatch resolves, got:\n{text}"
    );
}

#[test]
fn test_collect_anchor_workspace_has_no_native_summary() {
    // Anchor-only source: `collect` must not produce a native program, so the
    // CLI keeps rendering the Anchor `Instruction Handlers` block instead.
    let anchor_source = r#"
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
    let dir = tempfile::tempdir().unwrap();
    let src_path = dir.path().join("lib.rs");
    let mut file = fs::File::create(&src_path).unwrap();
    file.write_all(anchor_source.as_bytes()).unwrap();

    let output = sat::analyzer::collect(Some(dir.path().to_str().unwrap()), None, None).unwrap();
    assert!(output.native_program.is_none(), "Anchor-only workspace must not resolve a native program");
}

#[test]
fn test_native_summary_fallback_warns_about_dispatch_recovery() {
    // fixture_positional has no dispatch match: the frontend falls back to the
    // single entrypoint instruction (no discriminator) — the honest notice
    // about limited dispatch recovery must be shown.
    let text = native_summary(&fixture_source("fixture_positional.rs"));

    assert!(
        text.contains("Resolved 1 native instruction(s) from entrypoint test.rs:15"),
        "intro line missing, got:\n{text}"
    );
    assert!(text.contains("process_instruction"), "fallback instruction name missing, got:\n{text}");
    assert!(text.contains("(no discriminator)"), "fallback has no discriminator, got:\n{text}");
    assert!(text.contains("1 instructions resolved (1 with resolved accounts)"), "footer missing, got:\n{text}");
    assert!(
        text.contains("frontend dispatch recovery is limited for this program style"),
        "honest recovery notice missing, got:\n{text}"
    );
}

#[test]
fn test_collect_pipeline_renders_native_summary_from_tempdir() {
    let dir = tempfile::tempdir().unwrap();
    let src_path = dir.path().join("program.rs");
    let mut file = fs::File::create(&src_path).unwrap();
    file.write_all(INLINE_NATIVE_SOURCE.as_bytes()).unwrap();

    let output = sat::analyzer::collect(Some(dir.path().to_str().unwrap()), None, None).unwrap();
    let program = output.native_program.expect("inline native source must resolve a native program");
    assert_eq!(program.instructions.len(), 2, "both dispatch arms must be resolved");

    let text = render::native_instructions_summary(&program);
    assert!(text.contains("Resolved 2 native instruction(s)"), "intro line missing, got:\n{text}");
    assert!(text.contains("process_deposit"), "instruction name missing, got:\n{text}");
    assert!(text.contains("process_withdraw"), "instruction name missing, got:\n{text}");
    assert!(text.contains("[0x0102030405060708]"), "discriminator hex missing, got:\n{text}");
    assert!(text.contains("accounts: 1"), "signer account count missing, got:\n{text}");
    assert!(text.contains("accounts: 0 (!)"), "unresolved 0-account marker missing, got:\n{text}");
    assert!(text.contains("2 instructions resolved (1 with resolved accounts)"), "footer missing, got:\n{text}");
}
