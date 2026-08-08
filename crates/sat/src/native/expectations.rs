//! Native program expectations export (`sat analyze src --expectations`).
//!
//! Serializes the source-derived account model — per instruction: expected
//! signers, writable accounts, and PDA seeds — as JSON. This is the native
//! analog of an Anchor IDL: the Rust Security Toolkit (`rts`) consumes it to
//! run runtime tier-1/tier-2 style checks (signer presence, writable roles,
//! PDA seed cross-reference) against real transactions of programs that ship
//! no IDL.
//!
//! Contract notes for `rts`:
//! - `source` is always `"native"`; `instructions[].accounts[]` maps 1:1 to the
//!   instruction's account order (positional `AccountMeta` order).
//! - `pda.seeds` contains only seeds that are *statically* verifiable (string
//!   or integer literals); `pda.dynamic_seed_count` counts seed expressions
//!   that depend on runtime values and can only be verified on-chain.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::native::model::{NativeInstruction, NativeProgram, ResolvedAccount};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ExpectationsDoc {
    pub program_name: String,
    pub program_id: Option<String>,
    pub source: &'static str,
    pub instructions: Vec<ExpectationInstruction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpectationInstruction {
    pub name: String,
    pub discriminator_hex: Option<String>,
    pub handler: String,
    pub accounts: Vec<ExpectationAccount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpectationAccount {
    pub name: String,
    pub index: usize,
    pub is_signer_expected: bool,
    pub is_writable_expected: bool,
    pub pda: Option<ExpectationPda>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpectationPda {
    /// Statically verifiable seeds (string/integer literals).
    pub seeds: Vec<String>,
    /// Seed expressions that depend on runtime values.
    pub dynamic_seed_count: usize,
}

/// Build the expectations document from the resolved program model.
pub fn build(program: &NativeProgram) -> ExpectationsDoc {
    ExpectationsDoc {
        program_name: program_name(program),
        program_id: program.program_id.clone(),
        source: "native",
        instructions: program.instructions.iter().map(render_instruction).collect(),
    }
}

/// Render the expectations document as pretty JSON.
pub fn render(program: &NativeProgram) -> Result<String> {
    Ok(serde_json::to_string_pretty(&build(program))?)
}

/// Export expectations for a parsed workspace to a JSON file.
pub fn export(parsed_files: &[(syn::File, String)], out_path: &str) -> Result<()> {
    let program = crate::native::frontend::build_program(parsed_files);
    let json = render(&program)?;
    std::fs::write(out_path, json)?;
    Ok(())
}

fn program_name(program: &NativeProgram) -> String {
    // Prefer the program crate directory: the entrypoint usually lives at
    // <crate>/src/entrypoint.rs, so walk up past a "src" directory.
    let path = std::path::Path::new(&program.entrypoint_file);
    let dir = path
        .parent()
        .filter(|p| p.file_name().is_some_and(|n| n == "src"))
        .and_then(Path::parent)
        .unwrap_or_else(|| path.parent().unwrap_or(path));
    dir.file_name().and_then(|n| n.to_str()).filter(|n| !n.is_empty()).map(str::to_owned).unwrap_or_else(|| {
        path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "program".to_string())
    })
}

fn render_instruction(ix: &NativeInstruction) -> ExpectationInstruction {
    ExpectationInstruction {
        name: ix.name.clone(),
        discriminator_hex: ix.discriminator.as_ref().map(|d| d.iter().map(|b| format!("{b:02x}")).collect()),
        handler: ix.handler.clone(),
        accounts: ix.accounts.iter().map(render_account).collect(),
    }
}

fn render_account(account: &ResolvedAccount) -> ExpectationAccount {
    let (seeds, dynamic) = match &account.seeds[..] {
        [] => (Vec::new(), 0),
        seeds => {
            let mut static_seeds = Vec::new();
            let mut dynamic_count = 0;
            for seed in seeds {
                match literal_seed_value(seed) {
                    Some(v) => static_seeds.push(v),
                    None => dynamic_count += 1,
                }
            }
            (static_seeds, dynamic_count)
        }
    };

    ExpectationAccount {
        name: account.name.clone(),
        index: account.index,
        // The program requires a signature when the frontend saw a signer
        // guard or the account is signer-by-construction.
        is_signer_expected: account.is_signer_checked || account.kind == crate::native::model::AccountKind::Signer,
        is_writable_expected: account.written,
        pda: if account.is_pda || !account.seeds.is_empty() {
            Some(ExpectationPda { seeds, dynamic_seed_count: dynamic })
        } else {
            None
        },
    }
}

/// Extract a statically-verifiable seed value from a seed expression's source
/// text: `b"escrow"` / `"escrow"` / integer literals. Everything else
/// (identifiers, calls, fields) is dynamic.
fn literal_seed_value(seed: &str) -> Option<String> {
    let text = seed.trim();
    if let Some(inner) = text.strip_prefix("b\"") {
        return inner.strip_suffix('"').map(str::to_owned);
    }
    if let Some(inner) = text.strip_prefix('"') {
        return inner.strip_suffix('"').map(str::to_owned);
    }
    if text.chars().all(|c| c.is_ascii_digit()) && !text.is_empty() {
        return Some(text.to_string());
    }
    None
}
