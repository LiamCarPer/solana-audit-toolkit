//! PoC generator (`sat poc <finding-id>`).
//!
//! Resolves a finding from a prior `sat analyze src` run, classifies it to a
//! rule (SAT001..SAT031), and generates a runnable ProgramTest PoC crate in
//! `out_dir` (default `pocs/`):
//!
//! - `pocs/Cargo.toml` — plain crate (edition 2024) with harness deps mirrored
//!   from the target program's Cargo.toml when it can be located, plus an
//!   optional `{ path = "../programs/<lib>", features = ["no-entrypoint"] }`
//!   dependency when the analyzed path lives under `<root>/programs/<lib>/src`.
//! - `pocs/tests/poc_sat<rule>.rs` — one ProgramTest integration test per rule,
//!   each with a per-rule exploit scenario exercising the vulnerability.
//! - `pocs/src/lib.rs` — shared `accounts` module + PDA/address-book helpers
//!   (only emitted for Anchor programs with an IDL, so tests stay lean).
//! - `pocs/README.md` — next steps and harness-edit notes.
//!
//! Generated tests are auto-resolved where the analyzed model carries the
//! data: program id (declare_id!/IDL metadata), the instruction payload
//! (Anchor `sha256("global:<ix>")[..8]` discriminator + borsh args, or the
//! native dispatch tag), the `AccountMeta` list (signer/writable flags), PDA
//! derivations from the model's seeds, and Anchor account discriminators for
//! state accounts. The remaining `// EDIT ME` markers are limited to raw
//! account-data bytes for unresolvable types and program-crate specifics
//! (processor path when the crate is not under `<root>/programs/`).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use crate::analyzer::{AnalysisOutput, collect};
use crate::fuzzer_layout;
use crate::fuzzer_seeds;
use crate::idl::IdlJson;
use crate::native::model::NativeProgram;
use crate::sarif::classify_finding_rule;
use crate::types::Finding;
use crate::ui;

/// Fallback program id when neither the IDL metadata address nor a native
/// `declare_id!` is available.
const DEFAULT_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Every rule id `classify_finding_rule` can return. Rules outside this list
/// fall back to the generic template with a warning.
const RULE_IDS: &[&str] = &[
    "SAT001", "SAT002", "SAT003", "SAT004", "SAT005", "SAT006", "SAT007", "SAT008", "SAT009", "SAT010", "SAT011",
    "SAT012", "SAT013", "SAT014", "SAT015", "SAT016", "SAT017", "SAT018", "SAT019", "SAT020", "SAT021", "SAT022",
    "SAT023", "SAT024", "SAT025", "SAT026", "SAT027", "SAT028", "SAT029", "SAT030", "SAT031",
];

/// Dependency keys whose versions are mirrored from the target program's
/// Cargo.toml (same list as the fuzzer's `MIRRORED_DEPENDENCIES`).
const MIRRORED_DEPENDENCIES: &[&str] =
    &["anchor-lang", "solana-program", "solana-sdk", "solana-program-test", "spl-token", "spl-token-2022"];

/// Names that heuristically denote an authority role (mirrors
/// `analyzer::check_missing_signer`).
const AUTHORITY_NAMES: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "signer",
    "governor",
    "governance_authority",
    "vault_authority",
    "pool_admin",
    "creator",
    "manager",
    "operator",
    "upgrade_authority",
    "mint_authority",
    "freeze_authority",
];

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run(finding_id: &str, path: Option<&str>, out_dir: &str) -> Result<()> {
    ui::print_banner();
    ui::print_section_header("PoC Generation");

    let output = collect(path, None, None)?;

    if output.parsed_files.is_empty() {
        bail!(
            "no Rust source files found at `{}` — pass the same path you used for `sat analyze src`",
            path.unwrap_or("<default source path>")
        );
    }

    let finding = output.findings.iter().find(|f| f.id == finding_id).ok_or_else(|| {
        anyhow::anyhow!("finding {finding_id} not found — re-run `sat analyze src` against the same source path first")
    })?;

    let rule = classify_finding_rule(finding);
    ui::print_success(&format!("Resolved {finding_id} ({rule}): {}", finding.title));
    println!("severity : {}", finding.severity);
    println!("location : {}", finding.location.as_deref().unwrap_or("(none)"));
    println!("output   : {out_dir}/");

    let rule_known = RULE_IDS.contains(&rule.as_str());
    if !rule_known {
        ui::print_warning(&format!("rule {rule} is not a known SAT rule — generating the generic fallback template"));
    }

    let files = generate_crate(Path::new(out_dir), &output, finding, &rule, rule_known)?;

    ui::print_success(&format!("PoC crate generated at {out_dir}/"));
    for file in &files {
        ui::print_notice(&format!("wrote {file}"));
    }
    ui::print_notice("Next steps:");
    println!("  1. cd {out_dir}");
    println!("  2. Resolve the remaining `// EDIT ME` markers (account-data bytes only for the top rules)");
    println!("  3. Run: cargo test");
    println!();
    Ok(())
}

// ── Crate generation ──────────────────────────────────────────────────────────

fn generate_crate(
    out_dir: &Path,
    output: &AnalysisOutput,
    finding: &Finding,
    rule: &str,
    rule_known: bool,
) -> Result<Vec<String>> {
    fs::create_dir_all(out_dir.join("tests"))?;
    fs::create_dir_all(out_dir.join("src"))?;

    let mut ctx = resolve_template_context(output, finding, rule);

    // Locate the target program crate for the path dependency and version
    // mirroring. Only paths under a `programs/` directory yield a path dep.
    let program_crate = detect_program_crate(ctx.source_path.as_deref());
    let lib_name = program_crate.as_ref().and_then(|dir| dir.file_name()).and_then(|n| n.to_str());
    let program_toml = program_crate
        .as_ref()
        .map(|dir| dir.join("Cargo.toml"))
        .filter(|p| p.exists())
        .or_else(|| adjacent_cargo_toml(ctx.source_path.as_deref()));

    // The located crate name feeds the test's `ProgramTest::new` name and the
    // `processor!(lib::entry)` path — no EDIT ME when it was found.
    ctx.lib_name = lib_name.map(str::to_string);

    let mut files = Vec::new();

    let cargo_toml = render_cargo_toml(&ctx, lib_name, program_toml.as_deref());
    fs::write(out_dir.join("Cargo.toml"), cargo_toml)?;
    files.push("Cargo.toml".to_string());

    if let Some(idl) = &output.ctx.idl {
        let accounts_module = fuzzer_layout::render_account_factories(idl);
        let pda_setup = fuzzer_seeds::render_pda_setup(idl);
        let signer_info = fuzzer_seeds::render_signer_info(idl);
        fs::write(
            out_dir.join("src").join("lib.rs"),
            render_lib_rs(idl, &ctx, &accounts_module, &pda_setup, &signer_info),
        )?;
        files.push("src/lib.rs".to_string());
    }

    let test_name = format!("poc_{}.rs", rule.to_lowercase());
    fs::write(out_dir.join("tests").join(&test_name), render_test_file(&ctx, rule_known))?;
    files.push(format!("tests/{test_name}"));

    fs::write(out_dir.join("README.md"), render_readme(&ctx, lib_name))?;
    files.push("README.md".to_string());

    Ok(files)
}

// ── Context resolution ────────────────────────────────────────────────────────

/// Everything a rule template needs to render its exploit scenario.
struct TemplateContext {
    rule: String,
    finding: Finding,
    source_path: Option<String>,
    ix_name: String,
    /// `#[program]` module name (Anchor) — best-effort processor-path hint.
    module_hint: Option<String>,
    /// Crate lib name when the program crate was located under `programs/`.
    lib_name: Option<String>,
    program_id: String,
    program_id_placeholder: bool,
    is_native: bool,
    has_idl: bool,
    metas: Vec<MetaAccount>,
    args: Vec<TemplateArg>,
    /// Account flagged by the finding's location context (`Struct::field`).
    flagged_account: Option<String>,
    /// Best-guess state account (first non-signer, non-well-known, non-program).
    state_meta: Option<String>,
    /// Account type name of the state account (IDL name or Rust type arg).
    state_type: Option<String>,
    /// Anchor instruction discriminator from the IDL, when present.
    ix_discriminator: Option<Vec<u8>>,
    /// Native dispatch discriminator bytes, when the entrypoint matched arms.
    native_discriminator: Option<Vec<u8>>,
    /// Native handler function name (entrypoint or match-arm handler) — used
    /// for the `processor!(lib::handler)` path on native programs.
    native_handler: Option<String>,
    /// Native seed source text (ResolvedAccount.seeds) for PDA comments.
    seed_literals: Vec<String>,
    /// IDL account type names, for `accounts::build_*` seeding.
    idl_accounts: Vec<String>,
}

impl TemplateContext {
    /// The 8-byte instruction discriminator: the IDL-declared bytes when the
    /// IDL carries them, else `sha256("global:<ix>")[..8]`.
    fn discriminator(&self) -> [u8; 8] {
        if let Some(bytes) = &self.ix_discriminator
            && bytes.len() >= 8
        {
            let mut disc = [0u8; 8];
            disc.copy_from_slice(&bytes[..8]);
            return disc;
        }
        instruction_discriminator(&self.ix_name)
    }
}

#[derive(Debug, Clone)]
struct MetaAccount {
    name: String,
    is_signer: bool,
    is_mut: bool,
    is_pda: bool,
    /// `find_program_address` seed expressions (source text) when the model
    /// carries them (native `ResolvedAccount.seeds`).
    seeds: Vec<String>,
}

#[derive(Debug, Clone)]
struct TemplateArg {
    name: String,
    /// Rust type text for borsh serialization (`u64`, `Pubkey`, ...).
    rust: String,
}

#[derive(Debug, Default)]
struct LocationContext {
    file: String,
    line: Option<u32>,
    /// Parenthetical context: `AccountsStruct::field`, a function/instruction
    /// name, or an `Instruction: <name>` label.
    context: Option<String>,
}

fn resolve_template_context(output: &AnalysisOutput, finding: &Finding, rule: &str) -> TemplateContext {
    let loc = parse_location(finding.location.as_deref().unwrap_or(""));
    let native = output.native_program.as_ref();

    let mut ctx = TemplateContext {
        rule: rule.to_string(),
        finding: finding.clone(),
        source_path: first_parsed_file_dir(output),
        ix_name: String::new(),
        module_hint: None,
        lib_name: None,
        program_id: DEFAULT_PROGRAM_ID.to_string(),
        program_id_placeholder: true,
        is_native: native.is_some(),
        has_idl: false,
        metas: Vec::new(),
        args: Vec::new(),
        flagged_account: None,
        state_meta: None,
        state_type: None,
        native_discriminator: None,
        native_handler: None,
        seed_literals: Vec::new(),
        idl_accounts: Vec::new(),
        ix_discriminator: None,
    };

    if let Some(program) = native {
        resolve_native(&mut ctx, program, &loc);
    } else if let Some(idl) = &output.ctx.idl {
        resolve_idl(&mut ctx, output, idl, &loc);
    } else {
        resolve_anchor_ast(&mut ctx, output, &loc);
    }

    // The flagged account comes from the `(Struct::field)` location context.
    ctx.flagged_account = loc
        .context
        .as_deref()
        .and_then(|c| c.split("::").nth(1))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // Best-guess state account: the first non-signer, non-well-known account
    // whose type resolves to an Anchor `Account<'info, T>` (so its data can be
    // auto-seeded with the real discriminator), falling back to the first
    // non-signer account that is neither a well-known program/sysvar nor
    // program/token/mint-named.
    let state_candidates: Vec<String> = ctx
        .metas
        .iter()
        .filter(|m| {
            !m.is_signer
                && well_known_expr(&m.name).is_none()
                && !m.name.to_lowercase().contains("program")
                && !m.name.to_lowercase().contains("token")
                && !m.name.to_lowercase().contains("mint")
        })
        .map(|m| m.name.clone())
        .collect();
    ctx.state_meta = state_candidates
        .iter()
        .find(|name| state_type_for(output, &ctx, name).is_some())
        .or_else(|| state_candidates.first())
        .cloned();

    ctx.state_type = ctx.state_meta.as_ref().and_then(|name| state_type_for(output, &ctx, name));

    ctx
}

/// The directory of the first parsed file, used to locate the program crate.
fn first_parsed_file_dir(output: &AnalysisOutput) -> Option<String> {
    output.parsed_files.first().map(|(_, path)| {
        let p = Path::new(path);
        p.parent().map(|d| d.to_string_lossy().to_string()).unwrap_or_else(|| path.clone())
    })
}

fn resolve_native(ctx: &mut TemplateContext, program: &NativeProgram, loc: &LocationContext) {
    ctx.is_native = true;
    ctx.program_id = program.program_id.clone().unwrap_or_else(|| DEFAULT_PROGRAM_ID.to_string());
    ctx.program_id_placeholder = program.program_id.is_none();

    let want = loc.context.as_deref().unwrap_or("");
    let ix = program
        .instructions
        .iter()
        .find(|ix| ix.name == want || ix.handler == want)
        .or_else(|| program.instructions.iter().find(|ix| ix.name == "process_instruction"))
        .or_else(|| program.instructions.first());

    if let Some(ix) = ix {
        ctx.ix_name = ix.name.clone();
        ctx.native_discriminator = ix.discriminator.clone();
        ctx.native_handler = Some(ix.handler.clone());
        ctx.metas = ix
            .accounts
            .iter()
            .map(|a| MetaAccount {
                name: a.name.clone(),
                is_signer: a.is_signer_expected(),
                is_mut: a.written,
                is_pda: a.is_pda,
                seeds: a.seeds.clone(),
            })
            .collect();
        for account in &ix.accounts {
            ctx.seed_literals.extend(account.seeds.iter().cloned());
        }
    }
}

fn resolve_idl(ctx: &mut TemplateContext, output: &AnalysisOutput, idl: &IdlJson, loc: &LocationContext) {
    ctx.has_idl = true;
    ctx.idl_accounts = idl.accounts.iter().map(|a| a.name.clone()).collect();
    ctx.program_id =
        idl.metadata.as_ref().and_then(|m| m.address.clone()).unwrap_or_else(|| DEFAULT_PROGRAM_ID.to_string());
    ctx.program_id_placeholder = ctx.program_id == DEFAULT_PROGRAM_ID;

    // Instruction name: the location context may name it directly; otherwise
    // it comes from the flagged accounts struct (`Struct::field`) via a
    // handler-signature scan, falling back to the first IDL instruction.
    let want = loc.context.as_deref().unwrap_or("");
    let from_struct_ix = loc
        .context
        .as_deref()
        .and_then(|c| c.split("::").next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| find_ix_for_accounts_struct(&output.parsed_files, s));

    let ix = idl
        .instructions
        .iter()
        .find(|ix| ix.name == want)
        .or_else(|| from_struct_ix.as_ref().and_then(|name| idl.instructions.iter().find(|ix| ix.name == *name)))
        .or_else(|| idl.instructions.first());

    if let Some(ix) = ix {
        ctx.ix_name = ix.name.clone();
        ctx.ix_discriminator = ix.discriminator.clone();
        ctx.metas = ix
            .accounts
            .iter()
            .map(|a| MetaAccount {
                name: a.name.clone(),
                is_signer: a.is_signer,
                is_mut: a.is_mut,
                is_pda: a.pda.as_ref().is_some_and(|p| !p.seeds.is_empty()),
                seeds: Vec::new(),
            })
            .collect();
        ctx.args = ix
            .args
            .iter()
            .filter_map(|arg| {
                let rust = arg_rust_type(&arg.ty);
                if rust == "unknown" { None } else { Some(TemplateArg { name: arg.name.clone(), rust }) }
            })
            .collect();
    }

    ctx.module_hint = output.ctx.instructions.iter().find(|i| i.name == ctx.ix_name).map(|i| i.program_name.clone());
}

fn resolve_anchor_ast(ctx: &mut TemplateContext, output: &AnalysisOutput, loc: &LocationContext) {
    // Anchor program without an IDL: reconstruct instruction + account metas
    // from the parsed AST (accounts struct fields in declaration order).
    let want = loc.context.as_deref().unwrap_or("");

    // Program id from `declare_id!("...")` when present.
    if let Some(id) = extract_declared_id(&output.parsed_files) {
        ctx.program_id = id;
        ctx.program_id_placeholder = false;
    }

    let (struct_name, ix_name, module_hint) = if want.contains("::") {
        let struct_name = want.split("::").next().unwrap_or("").trim().to_string();
        let ix = find_ix_for_accounts_struct(&output.parsed_files, &struct_name);
        let hint = ix
            .as_ref()
            .and_then(|n| output.ctx.instructions.iter().find(|i| i.name == *n))
            .map(|i| i.program_name.clone());
        (Some(struct_name), ix, hint)
    } else if !want.is_empty() {
        let ix = output.ctx.instructions.iter().find(|i| i.name == want);
        let hint = ix.map(|i| i.program_name.clone());
        let struct_name = ix.as_ref().and_then(|i| struct_used_by_ix(&output.parsed_files, &i.name));
        (struct_name, ix.map(|i| i.name.clone()), hint)
    } else {
        let ix = output.ctx.instructions.first();
        let hint = ix.map(|i| i.program_name.clone());
        let struct_name = ix.as_ref().and_then(|i| struct_used_by_ix(&output.parsed_files, &i.name));
        (struct_name, ix.map(|i| i.name.clone()), hint)
    };

    ctx.module_hint = module_hint;
    ctx.ix_name = ix_name.unwrap_or_else(|| {
        output.ctx.instructions.first().map(|i| i.name.clone()).unwrap_or_else(|| "process".to_string())
    });
    ctx.args = handler_args(&output.parsed_files, &ctx.ix_name);

    let structs = if let Some(name) = &struct_name {
        output.ctx.accounts_structs.iter().find(|s| s.name == *name).into_iter().collect::<Vec<_>>()
    } else {
        vec![]
    };
    let accts = structs.first().copied().or_else(|| output.ctx.accounts_structs.first());

    if let Some(accts) = accts {
        ctx.metas = accts
            .fields
            .iter()
            .map(|f| MetaAccount {
                name: f.name.clone(),
                is_signer: f.is_signer_type || f.has_signer,
                is_mut: f.has_mut,
                is_pda: f.has_seeds,
                seeds: Vec::new(),
            })
            .collect();
    }
}

/// Best-effort account type name for `name`:
/// - IDL: matching `IdlAccountDef` (exact name, then case-insensitive);
/// - AST: the generic argument of the `Account<'info, T>` field type.
fn state_type_for(output: &AnalysisOutput, ctx: &TemplateContext, name: &str) -> Option<String> {
    if ctx.has_idl {
        if let Some(idl) = &output.ctx.idl {
            let lower = name.to_lowercase();
            for def in &idl.accounts {
                if def.name == name || def.name.to_lowercase() == lower {
                    return Some(def.name.clone());
                }
            }
            // Account names usually mirror their type (`vault` → `Vault`).
            let pascal = to_pascal_case(name);
            if let Some(def) = idl.accounts.iter().find(|d| d.name == pascal) {
                return Some(def.name.clone());
            }
        }
        return None;
    }
    // AST path: find the field's type argument (Account<'info, State> → State).
    // Requires the Anchor `Account<` wrapper — a plain `AccountInfo<'info>`
    // field has no resolvable state type.
    let accts = output.ctx.accounts_structs.iter().find(|s| s.fields.iter().any(|f| f.name == name))?;
    let field = accts.fields.iter().find(|f| f.name == name)?;
    if field.ty_name.starts_with("Account<") { generic_type_arg(&field.ty_name) } else { None }
}

/// Extracts the last generic argument of a rendered type string:
/// `Account<info, State>` → `State`, `Account<'info, State>` → `State`.
fn generic_type_arg(ty_name: &str) -> Option<String> {
    let start = ty_name.find('<')?;
    let end = ty_name.rfind('>')?;
    if end <= start {
        return None;
    }
    let inner = &ty_name[start + 1..end];
    let mut last = inner.split(',').next_back().unwrap_or("").trim().to_string();
    last = last.trim_end_matches('>').trim().to_string();
    if last.is_empty() { None } else { Some(last) }
}

fn to_pascal_case(name: &str) -> String {
    name.split(['_', '-'])
        .filter(|part| !part.is_empty())
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        })
        .collect()
}

// ── Location parsing ──────────────────────────────────────────────────────────

/// Parses `{file}:{line} ({context})` defensively. The line may be absent; the
/// context may be `AccountsStruct::field`, a function name, or absent. Uses
/// the *last* `:<digits>` sequence so Windows drive letters are never mistaken
/// for a line separator.
fn parse_location(location: &str) -> LocationContext {
    let mut loc = LocationContext::default();

    if let Some(open) = location.rfind(" (") {
        let tail = &location[open + 2..];
        if let Some(stripped) = tail.strip_suffix(')') {
            loc.context = Some(stripped.trim().to_string());
        }
    } else if let Some(rest) = location.strip_prefix("Instruction: ") {
        loc.context = Some(rest.trim().to_string());
    }

    let bytes = location.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] != b':' {
            continue;
        }
        let digits_start = i + 1;
        let mut digits_end = digits_start;
        while digits_end < bytes.len() && bytes[digits_end].is_ascii_digit() {
            digits_end += 1;
        }
        let has_digits = digits_end > digits_start;
        let followed_by_boundary = digits_end == bytes.len() || bytes[digits_end] == b' ' || bytes[digits_end] == b'(';
        if has_digits && followed_by_boundary {
            loc.line = location[digits_start..digits_end].parse().ok();
            loc.file = location[..i].trim().to_string();
            break;
        }
    }

    if loc.file.is_empty() {
        loc.file = location.to_string();
    }
    loc
}

// ── AST helpers ───────────────────────────────────────────────────────────────

/// Finds the instruction (handler fn name) whose signature references
/// `Context<{struct_name}>` inside a `#[program]` module.
fn find_ix_for_accounts_struct(parsed_files: &[(syn::File, String)], struct_name: &str) -> Option<String> {
    let needle = format!("Context<{struct_name}>");
    for (file, _) in parsed_files {
        for item in &file.items {
            if let syn::Item::Mod(item_mod) = item {
                if !item_mod.attrs.iter().any(|a| a.path().is_ident("program")) {
                    continue;
                }
                if let Some((_, items)) = &item_mod.content {
                    for mod_item in items {
                        if let syn::Item::Fn(func) = mod_item {
                            let sig = &func.sig;
                            let hits = sig.inputs.iter().any(|arg| {
                                if let syn::FnArg::Typed(pat_type) = arg {
                                    crate::analyzer::type_to_string(&pat_type.ty).contains(&needle)
                                } else {
                                    false
                                }
                            });
                            if hits {
                                return Some(sig.ident.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Finds the accounts struct a handler references (`Context<X>` in the
/// signature of the fn named `ix_name`).
fn struct_used_by_ix(parsed_files: &[(syn::File, String)], ix_name: &str) -> Option<String> {
    for (file, _) in parsed_files {
        for item in &file.items {
            if let syn::Item::Mod(item_mod) = item {
                if !item_mod.attrs.iter().any(|a| a.path().is_ident("program")) {
                    continue;
                }
                if let Some((_, items)) = &item_mod.content {
                    for mod_item in items {
                        if let syn::Item::Fn(func) = mod_item {
                            if func.sig.ident != ix_name {
                                continue;
                            }
                            for arg in &func.sig.inputs {
                                if let syn::FnArg::Typed(pat_type) = arg {
                                    let ty = crate::analyzer::type_to_string(&pat_type.ty);
                                    if let Some(open) = ty.find("Context<") {
                                        let rest = &ty[open + "Context<".len()..];
                                        if let Some(close) = rest.find('>') {
                                            return Some(rest[..close].trim().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// The `declare_id!("<base58>")` literal from the parsed files, when present
/// (Anchor AST path — the IDL path takes the metadata address instead).
fn extract_declared_id(parsed_files: &[(syn::File, String)]) -> Option<String> {
    for (file, _) in parsed_files {
        for item in &file.items {
            if let syn::Item::Macro(m) = item
                && m.mac.path.is_ident("declare_id")
                && let Ok(lit) = syn::parse2::<syn::LitStr>(m.mac.tokens.clone())
            {
                return Some(lit.value());
            }
        }
    }
    None
}

/// Instruction args (name + Rust type) from the `#[program]` handler
/// signature: every typed fn arg after the `Context<Accounts>` one. Types map
/// through the same vocabulary the IDL path uses (`u64`, `String`, `Pubkey`,
/// `Vec<u8>`, ...) so the generated payload can borsh-serialize defaults.
fn handler_args(parsed_files: &[(syn::File, String)], ix_name: &str) -> Vec<TemplateArg> {
    let mut args = Vec::new();
    for (file, _) in parsed_files {
        for item in &file.items {
            if let syn::Item::Mod(item_mod) = item {
                if !item_mod.attrs.iter().any(|a| a.path().is_ident("program")) {
                    continue;
                }
                if let Some((_, items)) = &item_mod.content {
                    for mod_item in items {
                        if let syn::Item::Fn(func) = mod_item {
                            if func.sig.ident != ix_name {
                                continue;
                            }
                            for input in &func.sig.inputs {
                                if let syn::FnArg::Typed(pat_type) = input {
                                    let ty = crate::analyzer::type_to_string(&pat_type.ty);
                                    if ty.contains("Context") {
                                        continue;
                                    }
                                    let name = match &*pat_type.pat {
                                        syn::Pat::Ident(pat_ident) => pat_ident.ident.to_string(),
                                        _ => continue,
                                    };
                                    let rust = syn_type_rust(&pat_type.ty);
                                    if rust != "unknown" {
                                        args.push(TemplateArg { name, rust });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    args
}

/// Rust type text for a syn type, mirroring `arg_rust_type` for IDL values.
fn syn_type_rust(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(type_path) => {
            let Some(segment) = type_path.path.segments.last() else { return "unknown".to_string() };
            match segment.ident.to_string().as_str() {
                "u8" | "u16" | "u32" | "u64" | "u128" | "i8" | "i16" | "i32" | "i64" | "i128" | "bool" => {
                    segment.ident.to_string()
                }
                "String" => "String".to_string(),
                "Pubkey" => "Pubkey".to_string(),
                "Vec" => match &segment.arguments {
                    syn::PathArguments::AngleBracketed(args) => {
                        let inner = args.args.iter().find_map(|a| match a {
                            syn::GenericArgument::Type(inner_ty) => {
                                let inner = syn_type_rust(inner_ty);
                                if inner == "unknown" { None } else { Some(inner) }
                            }
                            _ => None,
                        });
                        inner.map(|inner| format!("Vec<{inner}>")).unwrap_or_else(|| "unknown".to_string())
                    }
                    _ => "unknown".to_string(),
                },
                _ => "unknown".to_string(),
            }
        }
        _ => "unknown".to_string(),
    }
}

// ── Program crate / version detection ─────────────────────────────────────────

/// Returns the target program's crate directory when the analyzed path lives
/// under a `programs/` directory (e.g. `<root>/programs/<lib>/src/lib.rs`).
fn detect_program_crate(path: Option<&str>) -> Option<PathBuf> {
    let mut current = Path::new(path?);
    loop {
        if current.file_name().and_then(|n| n.to_str()) == Some("programs") {
            let children: Vec<PathBuf> =
                fs::read_dir(current).ok()?.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect();
            return children.iter().find(|d| d.join("Cargo.toml").exists()).or_else(|| children.first()).cloned();
        }
        current = current.parent()?;
    }
}

/// A `Cargo.toml` adjacent to the analyzed path (its own directory for a
/// directory path, its parent for a file path) — used for version mirroring
/// when the crate is not under `programs/`.
fn adjacent_cargo_toml(path: Option<&str>) -> Option<PathBuf> {
    let p = Path::new(path?);
    let base = if p.is_dir() { p.to_path_buf() } else { p.parent()?.to_path_buf() };
    let candidate = base.join("Cargo.toml");
    if candidate.exists() { Some(candidate) } else { None }
}

/// Mirrors dependency versions from the target program's Cargo.toml, checking
/// both `[dependencies]` and `[workspace.dependencies]` (same pattern as the
/// fuzzer's `program_dependency_versions`).
fn program_dependency_versions(program_toml: Option<&Path>) -> HashMap<String, String> {
    let Some(toml_path) = program_toml else { return HashMap::new() };
    let Ok(content) = fs::read_to_string(toml_path) else { return HashMap::new() };
    let Ok(table) = content.parse::<toml::Value>() else { return HashMap::new() };

    let mut versions = HashMap::new();
    let sections = [
        table.get("dependencies").and_then(toml::Value::as_table),
        table.get("workspace").and_then(|ws| ws.get("dependencies")).and_then(toml::Value::as_table),
    ];
    for deps in sections.into_iter().flatten() {
        for key in MIRRORED_DEPENDENCIES {
            if versions.contains_key(*key) {
                continue;
            }
            let version = deps.get(*key).and_then(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| value.get("version").and_then(toml::Value::as_str).map(str::to_string))
            });
            if let Some(version) = version {
                versions.insert((*key).to_string(), version);
            }
        }
    }
    versions
}

// ── Cargo.toml rendering ──────────────────────────────────────────────────────

fn render_cargo_toml(ctx: &TemplateContext, lib_name: Option<&str>, program_toml: Option<&Path>) -> String {
    let versions = program_dependency_versions(program_toml);
    let warn = match program_toml {
        Some(_) if MIRRORED_DEPENDENCIES.iter().any(|key| versions.contains_key(*key)) => String::new(),
        Some(toml_path) => format!(
            "# WARN: could not mirror versions from {} — using defaults; align them with the target program if the build fails\n",
            toml_path.display()
        ),
        None => "# No target program Cargo.toml located — using default dependency versions.\n".to_string(),
    };

    let lib_line = match lib_name {
        Some(lib) => format!("{lib} = {{ path = \"../programs/{lib}\", features = [\"no-entrypoint\"] }}\n"),
        None => format!(
            "# Program crate not located under <root>/programs/ — no path dependency.\n# The generated tests reference `processor!({}::entry)`; add a path dep or\n# edit the processor path once the crate is at its final location.\n",
            ctx.module_hint.as_deref().unwrap_or("my_program")
        ),
    };

    let anchor_lang = versions.get("anchor-lang").map(String::as_str).unwrap_or("0.29");
    let solana_program = versions.get("solana-program").map(String::as_str).unwrap_or("4");
    let solana_program_test = versions.get("solana-program-test").map(String::as_str).unwrap_or("4");
    let solana_sdk = versions.get("solana-sdk").map(String::as_str).unwrap_or("4");
    let spl_token = versions.get("spl-token").map(String::as_str).unwrap_or("7");
    let spl_token_2022 = versions.get("spl-token-2022").map(String::as_str).unwrap_or("7");

    format!(
        r#"[package]
name = "pocs"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
{lib_line}{warn}anchor-lang = "{anchor_lang}"
solana-program = "{solana_program}"
solana-program-test = "{solana_program_test}"
solana-sdk = "{solana_sdk}"
spl-token = "{spl_token}"
spl-token-2022 = "{spl_token_2022}"
borsh = "1"
rand = "0.8"
tokio = {{ version = "1", features = ["full"] }}
"#
    )
}

// ── src/lib.rs rendering (IDL programs only) ──────────────────────────────────

fn render_lib_rs(
    idl: &IdlJson,
    ctx: &TemplateContext,
    accounts_module: &str,
    pda_setup: &str,
    signer_info: &str,
) -> String {
    let ix_list = idl.instructions.iter().map(|ix| ix.name.clone()).collect::<Vec<_>>().join(", ");
    format!(
        r#"// Auto-generated by `sat poc` — shared PoC harness helpers.
// Program : {program}
// Instructions: {ix_list}

use std::str::FromStr;

use solana_program::pubkey::Pubkey;

{accounts_module}
{pda_setup}
{signer_info}
pub fn program_id() -> Pubkey {{
    Pubkey::from_str("{program_id}").expect("generated program id must be a valid pubkey")
}}

pub fn fuzz_account_pubkey(name: &str) -> Pubkey {{
    well_known_account(name).unwrap_or_else(|| {{
        Pubkey::find_program_address(&[b"sat-poc", name.as_bytes()], &program_id()).0
    }})
}}

pub fn well_known_account(name: &str) -> Option<Pubkey> {{
    match name {{
        "system_program" => Some(solana_program::system_program::ID),
        "token_program" => Some(spl_token::ID),
        "token_2022_program" | "token2022_program" => Some(spl_token_2022::ID),
        "rent" => Some(solana_program::sysvar::rent::ID),
        "clock" => Some(solana_program::sysvar::clock::ID),
        "instructions" => Some(solana_program::sysvar::instructions::ID),
        _ => None,
    }}
}}
"#,
        program = idl.name,
        ix_list = ix_list,
        accounts_module = accounts_module,
        pda_setup = pda_setup,
        signer_info = signer_info,
        program_id = ctx.program_id,
    )
}

// ── Test-file rendering ───────────────────────────────────────────────────────

fn render_test_file(ctx: &TemplateContext, rule_known: bool) -> String {
    let header = render_finding_header(ctx, rule_known);
    let imports = render_imports(ctx);
    let stub = if ctx.rule == "SAT014" { render_stub_program() } else { String::new() };
    let program_id_fn = render_program_id_fn(ctx);
    let harness = render_set_up_program_test(ctx);
    let scenario = render_scenario(ctx);
    format!("{header}\n{imports}\n\n{stub}{program_id_fn}{harness}\n{scenario}")
}

fn render_finding_header(ctx: &TemplateContext, rule_known: bool) -> String {
    let guidance = if rule_known {
        "Program id, instruction payload, AccountMetas and PDA derivations are auto-resolved\n//! from the analyzed model. Resolve the remaining `// EDIT ME` markers (raw account-data\n//! bytes, processor path when the program crate is not under `programs/`), then run `cargo test`."
    } else {
        "The finding classified to an unknown rule — this is the generic fallback template. Resolve every `// EDIT ME` marker, then run `cargo test`."
    };
    let mut description = ctx.finding.description.replace('\n', " ");
    if description.len() > 400 {
        description.truncate(400);
        description.push('…');
    }
    format!(
        r#"//! PoC for {id} — {title}
//!
//! Rule       : {rule} (classify_finding_rule)
//! Severity   : {severity}
//! Location   : {location}
//! Description: {description}
//!
//! Generated by `sat poc`. {guidance}
"#,
        id = ctx.finding.id,
        title = ctx.finding.title,
        rule = ctx.rule,
        severity = ctx.finding.severity,
        location = ctx.finding.location.as_deref().unwrap_or("(none)"),
        description = description,
        guidance = guidance,
    )
}

fn render_imports(ctx: &TemplateContext) -> String {
    let mut out = String::from(
        "use std::str::FromStr;\n\nuse solana_program_test::{processor, BanksClient, ProgramTest};\nuse solana_sdk::{\n    account::Account,\n    instruction::{AccountMeta, Instruction},\n    pubkey::Pubkey,\n    signature::Signer,\n    signer::keypair::Keypair,\n    transaction::Transaction,\n};\n",
    );
    if matches!(ctx.rule.as_str(), "SAT017" | "SAT028") {
        out.push_str("use solana_program::program_option::COption;\nuse spl_token::state::{Account as TokenAccount, AccountState, Mint as TokenMint};\n");
    }
    out
}

fn render_program_id_fn(ctx: &TemplateContext) -> String {
    let note = if ctx.program_id_placeholder {
        "    // EDIT ME: program id not resolvable from declare_id!/IDL metadata — set the real id\n"
    } else {
        ""
    };
    format!(
        "fn program_id() -> Pubkey {{\n{note}    Pubkey::from_str(\"{program_id}\").expect(\"valid program id\")\n}}\n",
        note = note,
        program_id = ctx.program_id,
    )
}

fn render_set_up_program_test(ctx: &TemplateContext) -> String {
    let processor_path = processor_path(ctx);
    let edit_mark = if ctx.lib_name.is_none() {
        "    // EDIT ME: processor path — program crate not located; expected `processor!(<lib>::<entry|handler>)`\n"
    } else {
        ""
    };
    format!(
        r#"fn set_up_program_test() -> (ProgramTest, Keypair) {{
    let mut program_test = ProgramTest::new("{name}", program_id(), processor!({processor}));
{edit_mark}    let payer = Keypair::new();
    program_test.add_account(
        payer.pubkey(),
        Account {{
            lamports: 1_000_000_000_000,
            data: vec![],
            owner: solana_program::system_program::ID,
            executable: false,
            rent_epoch: 0,
        }},
    );
    (program_test, payer)
}}
"#,
        name = ctx.lib_name.as_deref().unwrap_or(ctx.module_hint.as_deref().unwrap_or("my_program")),
        processor = processor_path,
        edit_mark = edit_mark,
    )
}

/// The `lib::entry` path used by `processor!`. Prefers the located crate lib
/// name, then the Anchor `#[program]` module name, then a placeholder.
/// Native programs expose their handler function (`process_instruction` or
/// the match-arm handler) instead of Anchor's generated `entry`.
fn processor_path(ctx: &TemplateContext) -> String {
    let lib = ctx.lib_name.clone().or_else(|| ctx.module_hint.clone()).unwrap_or_else(|| "my_program".to_string());
    if ctx.is_native {
        let handler = ctx.native_handler.as_deref().unwrap_or("process_instruction");
        format!("{lib}::{handler}")
    } else {
        format!("{lib}::entry")
    }
}

fn render_stub_program() -> String {
    r#"// Inline stub so the handler's external CPI resolves under ProgramTest.
pub mod stub_program {
    use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey};

    entrypoint!(process_instruction);

    pub fn process_instruction(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        _instruction_data: &[u8],
    ) -> ProgramResult {
        Ok(())
    }
}

"#
    .to_string()
}

// ── Scenario dispatch ─────────────────────────────────────────────────────────

fn render_scenario(ctx: &TemplateContext) -> String {
    match ctx.rule.as_str() {
        "SAT001" | "SAT019" | "SAT021" => render_missing_signer_scenario(ctx),
        "SAT002" | "SAT020" | "SAT018" | "SAT025" => render_unverified_account_scenario(ctx),
        "SAT005" | "SAT016" | "SAT024" => render_reinit_scenario(ctx),
        "SAT012" | "SAT026" => render_unsafe_arithmetic_scenario(ctx),
        "SAT014" => render_cei_scenario(ctx),
        "SAT015" | "SAT022" => render_pda_seed_mismatch_scenario(ctx),
        "SAT017" | "SAT028" => render_token_cpi_scenario(ctx),
        "SAT030" => render_cross_instruction_scenario(ctx),
        _ => render_generic_scenario(ctx),
    }
}

// ── Shared scenario building blocks ───────────────────────────────────────────

fn ident(name: &str) -> String {
    name.chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' }).collect::<String>()
}

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Canonical pubkey expression for well-known program/sysvar account names.
fn well_known_expr(name: &str) -> Option<String> {
    let norm: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    match norm.as_str() {
        "systemprogram" => Some("solana_program::system_program::ID".to_string()),
        "tokenprogram" => Some("spl_token::ID".to_string()),
        "token2022program" => Some("spl_token_2022::ID".to_string()),
        "rent" => Some("solana_program::sysvar::rent::ID".to_string()),
        "clock" => Some("solana_program::sysvar::clock::ID".to_string()),
        "instructions" => Some("solana_program::sysvar::instructions::ID".to_string()),
        _ => None,
    }
}

fn is_well_known(name: &str) -> bool {
    well_known_expr(name).is_some()
}

/// First authority-named meta account (the natural target for
/// SAT001/SAT019/SAT021-style findings).
fn first_authority_named(ctx: &TemplateContext) -> Option<String> {
    ctx.metas
        .iter()
        .find(|m| {
            let lower = m.name.to_lowercase();
            AUTHORITY_NAMES.contains(&lower.as_str())
                || lower.ends_with("_authority")
                || lower.ends_with("_admin")
                || lower.ends_with("_owner")
        })
        .map(|m| m.name.clone())
}

/// Default pubkey expression per meta account.
fn default_pubkey_exprs(ctx: &TemplateContext) -> HashMap<String, String> {
    let mut exprs = HashMap::new();
    for meta in &ctx.metas {
        let expr = if let Some(well_known) = well_known_expr(&meta.name) {
            well_known
        } else if meta.is_signer {
            format!("{}_kp.pubkey()", ident(&meta.name))
        } else if ctx.has_idl && meta.is_pda {
            format!(
                "pocs::pda_{ix}_{acct}(&payer.pubkey(), &program_id(), &signer_pubkeys).0",
                ix = ident(&ctx.ix_name),
                acct = ident(&meta.name)
            )
        } else if ctx.has_idl {
            format!("pocs::account_address(\"{}\", &payer.pubkey(), &signer_pubkeys)", escape_str(&meta.name))
        } else {
            format!("{}_pubkey", ident(&meta.name))
        };
        exprs.insert(meta.name.clone(), expr);
    }
    exprs
}

/// Declares + funds a keypair for every signer meta account.
fn keypair_lines(ctx: &TemplateContext) -> String {
    let mut out = String::new();
    for meta in &ctx.metas {
        if !meta.is_signer {
            continue;
        }
        out.push_str(&format!(
            "    let {}_kp = Keypair::new();\n    program_test.add_account(\n        {}_kp.pubkey(),\n        Account {{ lamports: 1_000_000_000_000, data: vec![], owner: solana_program::system_program::ID, executable: false, rent_epoch: 0 }},\n    );\n",
            ident(&meta.name),
            ident(&meta.name)
        ));
    }
    out
}

/// Emits the pubkey definitions for every non-signer, non-well-known account
/// whose expression is the plain `{name}_pubkey` form (non-IDL paths), so the
/// generated test compiles without hand-written key definitions:
///
/// - Accounts whose seeds the model resolved to safe expressions get a real
///   `Pubkey::find_program_address` derivation, so the PDA account is real.
/// - Everything else gets a deterministic `Pubkey::new_from_array([i; 32])`
///   placeholder keyed off the account's index (index+1, so the bytes are
///   nonzero and unique per account; stable across regenerations).
fn address_setup_lines(ctx: &TemplateContext, exprs: &HashMap<String, String>) -> String {
    let mut out = String::new();
    for (i, meta) in ctx.metas.iter().enumerate() {
        if meta.is_signer || is_well_known(&meta.name) {
            continue;
        }
        let plain = format!("{}_pubkey", ident(&meta.name));
        if exprs.get(&meta.name).map(String::as_str) != Some(plain.as_str()) {
            continue; // overridden by the scenario (attacker key, wrong PDA, ...)
        }
        let binding = ident(&meta.name);
        if meta.is_pda && !meta.seeds.is_empty() && meta.seeds.iter().all(|s| is_safe_seed_expr(s)) {
            let seed_args = meta.seeds.iter().map(|s| render_seed_arg(ctx, s)).collect::<Vec<_>>().join(", ");
            out.push_str(&format!(
                "    // `{name}`: PDA with the program's real seeds (from the model) — derive it\n    // so the account is at the actual derived address.\n    let ({binding}_pubkey, _bump) = Pubkey::find_program_address(&[{seed_args}], &program_id());\n",
                name = escape_str(&meta.name),
                binding = binding,
                seed_args = seed_args,
            ));
        } else {
            out.push_str(&format!(
                "    // `{name}`: deterministic placeholder address (index {idx}). For PDAs,\n    // edit the seeds below if the model could not resolve them to literals.\n    let {binding}_pubkey = Pubkey::new_from_array([{idx}u8; 32]);\n",
                name = escape_str(&meta.name),
                binding = binding,
                idx = i + 1,
            ));
        }
    }
    out
}

/// A seed expression is safe to inline into the generated test when it is a
/// byte-string literal, an existing reference, or derives from the payer (the
/// only handler-local values guaranteed to exist in the test scope).
fn is_safe_seed_expr(seed: &str) -> bool {
    let trimmed = seed.trim();
    trimmed.starts_with("b\"") || trimmed.starts_with("&") || trimmed.starts_with("payer.")
}

/// Renders one safe seed source-text expression into a `&[u8]` argument for
/// `find_program_address`:
/// - `b"..."` byte literals stay byte slices (`.as_slice()`);
/// - `payer.pubkey()` / `payer.key` map to the test's payer pubkey bytes;
/// - `{signer}.key...` refs map to the signer keypair's pubkey bytes;
/// - other pre-existing `&` references pass through.
fn render_seed_arg(ctx: &TemplateContext, seed: &str) -> String {
    let trimmed = seed.trim();
    if trimmed.starts_with("b\"") {
        return format!("{trimmed}.as_slice()");
    }
    if let Some(rest) = trimmed.strip_prefix("payer.")
        && (rest.starts_with("pubkey") || rest.starts_with("key"))
    {
        return "payer.pubkey().as_ref()".to_string();
    }
    for meta in &ctx.metas {
        if meta.is_signer {
            let prefix = format!("{}.", ident(&meta.name));
            if trimmed.starts_with(&prefix) {
                return format!("{}_kp.pubkey().as_ref()", ident(&meta.name));
            }
        }
    }
    trimmed.to_string()
}

/// Anchor account discriminator: `sha256("account:<type>")[..8]`. This is the
/// same computation Anchor performs for `#[account]` types, so the generated
/// state data passes the program's discriminator check.
fn account_discriminator(type_name: &str) -> [u8; 8] {
    let preimage = format!("account:{type_name}");
    let hash = Sha256::digest(preimage.as_bytes());
    let mut discriminator = [0_u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}

/// `signer_pubkeys` in fuzzer convention: index 0 = payer, then IDL signers.
fn signer_pubkeys_line(ctx: &TemplateContext) -> String {
    let mut parts = vec!["payer.pubkey()".to_string()];
    for meta in &ctx.metas {
        if meta.is_signer {
            parts.push(format!("{}_kp.pubkey()", ident(&meta.name)));
        }
    }
    format!("    let signer_pubkeys = vec![{}];\n", parts.join(", "))
}

/// Seeds every non-signer, non-well-known account (except `skip`) via
/// `add_account` so the instruction has real accounts to read/write.
fn seed_lines(ctx: &TemplateContext, exprs: &HashMap<String, String>, skip: &HashSet<String>) -> String {
    let mut out = String::new();
    let mut used_rng = false;
    for meta in &ctx.metas {
        if meta.is_signer || skip.contains(&meta.name) || is_well_known(&meta.name) {
            continue;
        }
        let Some(expr) = exprs.get(&meta.name) else { continue };
        let name = escape_str(&meta.name);
        if ctx.has_idl {
            if let Some(ty) = idl_account_type_for(ctx, &meta.name) {
                if !used_rng {
                    out.push_str("    let mut rng = rand::thread_rng();\n");
                    used_rng = true;
                }
                out.push_str(&format!(
                    "    // {name}: valid {ty} account data (discriminator + borsh) via the generated factory\n    program_test.add_account(\n        {expr},\n        Account {{ lamports: 10_000_000, data: pocs::accounts::build_{snake}(&mut rng), owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n",
                    name = name,
                    ty = ty,
                    expr = expr,
                    snake = to_snake_case(&ty),
                ));
            } else {
                out.push_str(&format!(
                    "    // {name}: no matching IDL account type — placeholder data, EDIT ME\n    program_test.add_account(\n        {expr},\n        Account {{ lamports: 10_000_000, data: vec![0; 1024], owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n",
                    name = name,
                    expr = expr,
                ));
            }
        } else if ctx.state_meta.as_deref() == Some(&meta.name) {
            match &ctx.state_type {
                Some(ty) => {
                    let disc = account_discriminator(ty);
                    let bytes = disc.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
                    let binding = ident(&meta.name);
                    out.push_str(&format!(
                        "    // {name}: program-owned state account — real Anchor account discriminator\n    // sha256(\"account:{ty}\")[..8] plus a zero-filled payload, which is the borsh\n    // default of every field (edit only if the handler requires nonzero fields).\n    let mut {binding}_data = vec![{bytes}];\n    {binding}_data.extend(vec![0u8; 120]);\n    program_test.add_account(\n        {expr},\n        Account {{ lamports: 10_000_000, data: {binding}_data, owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n",
                        name = name,
                        ty = ty,
                        binding = binding,
                        bytes = bytes,
                        expr = expr,
                    ));
                }
                None => out.push_str(&format!(
                    "    // {name}: program-owned state account. EDIT ME: seed data the handler can\n    // deserialize (8-byte discriminator + borsh fields)\n    program_test.add_account(\n        {expr},\n        Account {{ lamports: 10_000_000, data: vec![0; 1024], owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n",
                    name = name,
                    expr = expr,
                )),
            }
        } else {
            out.push_str(&format!(
                "    // {name}: placeholder account data, EDIT ME as needed\n    program_test.add_account(\n        {expr},\n        Account {{ lamports: 10_000_000, data: vec![0; 1024], owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n",
                name = name,
                expr = expr,
            ));
        }
    }
    out
}

/// IDL account type name for `name`, when the IDL has a matching def.
fn idl_account_type_for(ctx: &TemplateContext, name: &str) -> Option<String> {
    if !ctx.has_idl {
        return None;
    }
    let lower = name.to_lowercase();
    // Name mirroring (vault → Vault, user_state → UserState) plus exact match.
    let pascal = to_pascal_case(name);
    ctx.idl_accounts
        .iter()
        .find(|def| def.as_str() == name || def.to_lowercase() == lower || def.as_str() == pascal)
        .cloned()
}

/// The instruction payload: 8-byte anchor discriminator + borsh args.
fn payload_lines(ctx: &TemplateContext, args: &[(String, String)]) -> String {
    if ctx.is_native {
        return native_payload_lines(ctx);
    }
    let disc = ctx.discriminator();
    let bytes = disc.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
    let mut out = format!("    // sha256(\"global:{}\")[..8]\n    let mut payload = vec![{bytes}];\n", ctx.ix_name);
    for (name, expr) in args {
        out.push_str(&format!("    // arg `{name}` (borsh)\n    payload.extend(borsh::to_vec(&{expr}).unwrap());\n"));
    }
    if ctx.args.is_empty() {
        out.push_str("    // FILL IN: append the instruction's args in borsh order if it takes any.\n");
    }
    out
}

fn native_payload_lines(ctx: &TemplateContext) -> String {
    if let Some(disc) = &ctx.native_discriminator {
        let bytes = disc.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
        format!(
            "    // dispatch discriminator from the handler's match arm\n    let payload = vec![{bytes}];\n    // FILL IN: append any instruction data the handler reads.\n"
        )
    } else {
        "    // FILL IN: the instruction data the program dispatches on.\n    let payload = vec![];\n".to_string()
    }
}

/// The `AccountMeta` list for the instruction, honoring per-account pubkey
/// expressions and signer-flag overrides.
fn metas_lines(ctx: &TemplateContext, exprs: &HashMap<String, String>, sigs: &HashMap<String, bool>) -> String {
    ctx.metas
        .iter()
        .map(|meta| {
            let pubkey = exprs.get(&meta.name).cloned().unwrap_or_else(|| format!("{}_pubkey", ident(&meta.name)));
            let is_signer = sigs.get(&meta.name).copied().unwrap_or(meta.is_signer);
            let ctor = if meta.is_mut { "AccountMeta::new" } else { "AccountMeta::new_readonly" };
            format!("            {ctor}({pubkey}, {is_signer}), // {}", escape_str(&meta.name))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Signing keypair list: payer first, then every signer meta keypair.
fn signing_list(ctx: &TemplateContext) -> String {
    let mut parts = vec!["&payer".to_string()];
    for meta in &ctx.metas {
        if meta.is_signer {
            parts.push(format!("&{}_kp", ident(&meta.name)));
        }
    }
    format!("&[{}]", parts.join(", "))
}

/// Captures the state account's data before the exploit transaction.
fn before_state_line(ctx: &TemplateContext, exprs: &HashMap<String, String>) -> String {
    match ctx.state_meta.as_ref().and_then(|name| exprs.get(name)) {
        Some(expr) => format!("    let before = banks_client.get_account({expr}).await.unwrap();\n\n"),
        None => String::new(),
    }
}

/// The exploit transaction + `process_transaction`, then the post-state
/// assertions. `extra_pre_tx` runs right before the transaction is built.
fn tx_block(
    ctx: &TemplateContext,
    exprs: &HashMap<String, String>,
    sigs: &HashMap<String, bool>,
    payload: &str,
    extra_pre_tx: &str,
    expect_msg: &str,
) -> String {
    let metas = metas_lines(ctx, exprs, sigs);
    format!(
        r#"{payload}{extra_pre_tx}    let ix = Instruction::new_with_bytes(
        program_id(),
        &payload,
        vec![
{metas}
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        {signers},
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.expect("{expect_msg}");
"#,
        payload = payload,
        extra_pre_tx = extra_pre_tx,
        metas = metas,
        signers = signing_list(ctx),
        expect_msg = expect_msg,
    )
}

/// Reads the state account back and asserts its data changed.
fn state_changed_assert(ctx: &TemplateContext, exprs: &HashMap<String, String>, why: &str) -> String {
    match ctx.state_meta.as_ref().and_then(|name| exprs.get(name)) {
        Some(expr) => format!(
            "    let after = banks_client.get_account({expr}).await.unwrap();\n    assert_ne!(\n        before.as_ref().map(|a| a.data.clone()),\n        after.as_ref().map(|a| a.data.clone()),\n        \"{why}\",\n    );\n"
        ),
        None => String::new(),
    }
}

// ── Discriminator / arg helpers ───────────────────────────────────────────────

fn instruction_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{name}");
    let hash = Sha256::digest(preimage.as_bytes());
    let mut discriminator = [0_u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}

/// The Rust type text for an IDL arg type, or "unknown".
fn arg_rust_type(ty: &serde_json::Value) -> String {
    match ty.as_str() {
        Some("u8") => "u8".to_string(),
        Some("u16") => "u16".to_string(),
        Some("u32") => "u32".to_string(),
        Some("u64") => "u64".to_string(),
        Some("u128") => "u128".to_string(),
        Some("i8") => "i8".to_string(),
        Some("i16") => "i16".to_string(),
        Some("i32") => "i32".to_string(),
        Some("i64") => "i64".to_string(),
        Some("i128") => "i128".to_string(),
        Some("bool") => "bool".to_string(),
        Some("publicKey") => "Pubkey".to_string(),
        Some("string") => "String".to_string(),
        Some("bytes") => "Vec<u8>".to_string(),
        _ => "unknown".to_string(),
    }
}

/// A benign default value for an arg of the given Rust type.
fn default_arg_expr(rust: &str) -> String {
    match rust {
        "u8" => "1u8".to_string(),
        "u16" => "1u16".to_string(),
        "u32" => "1u32".to_string(),
        "u64" => "1u64".to_string(),
        "u128" => "1u128".to_string(),
        "i8" => "1i8".to_string(),
        "i16" => "1i16".to_string(),
        "i32" => "1i32".to_string(),
        "i64" => "1i64".to_string(),
        "i128" => "1i128".to_string(),
        "bool" => "true".to_string(),
        "Pubkey" => "Keypair::new().pubkey()".to_string(),
        "String" => "\"poc\".to_string()".to_string(),
        "Vec<u8>" => "vec![0xAA; 8]".to_string(),
        _ => "/* FILL IN */ 0u64".to_string(),
    }
}

/// Overflow/underflow boundary values for the unsafe-arithmetic scenarios.
fn boundary_arg_expr(rust: &str) -> String {
    match rust {
        "u8" => "u8::MAX".to_string(),
        "u16" => "u16::MAX".to_string(),
        "u32" => "u32::MAX".to_string(),
        "u64" => "u64::MAX".to_string(),
        "u128" => "u128::MAX".to_string(),
        "i8" => "i8::MIN".to_string(),
        "i16" => "i16::MIN".to_string(),
        "i32" => "i32::MIN".to_string(),
        "i64" => "i64::MIN".to_string(),
        "i128" => "i128::MIN".to_string(),
        _ => default_arg_expr(rust),
    }
}

fn default_arg_exprs(ctx: &TemplateContext) -> Vec<(String, String)> {
    ctx.args.iter().map(|a| (a.name.clone(), default_arg_expr(&a.rust))).collect()
}

fn boundary_arg_exprs(ctx: &TemplateContext) -> Vec<(String, String)> {
    ctx.args.iter().map(|a| (a.name.clone(), boundary_arg_expr(&a.rust))).collect()
}

/// IDL `Name`-style names → snake_case Rust idents (same as fuzzer_layout).
fn to_snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() {
            let breaks = i > 0 && (chars[i - 1].is_ascii_lowercase() || chars[i - 1].is_ascii_digit());
            if breaks {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() { "field".to_string() } else { trimmed.to_string() }
}

// ── Per-rule exploit scenarios ─────────────────────────────────────────────────

/// SAT001 / SAT019 — the authority is present without the signer flag and the
/// transaction is never signed with it; the instruction must still execute and
/// mutate state.
fn render_missing_signer_scenario(ctx: &TemplateContext) -> String {
    let auth = ctx
        .flagged_account
        .clone()
        .filter(|n| ctx.metas.iter().any(|m| m.name == *n))
        .or_else(|| first_authority_named(ctx))
        .unwrap_or_default();

    let mut exprs = default_pubkey_exprs(ctx);
    let mut sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let mut skip: HashSet<String> = HashSet::new();
    let mut prelude = String::new();

    if !auth.is_empty() {
        prelude.push_str(&format!(
            "    // `{auth}` — supplied WITHOUT the signer flag (NOT a signer). The\n    // transaction is not signed with it, and no signature is ever required.\n"
        ));
        prelude.push_str(
            "    let attacker = Keypair::new();\n    program_test.add_account(\n        attacker.pubkey(),\n        Account { lamports: 1_000_000_000_000, data: vec![], owner: solana_program::system_program::ID, executable: false, rent_epoch: 0 },\n    );\n",
        );
        exprs.insert(auth.clone(), "attacker.pubkey()".to_string());
        sigs.insert(auth.clone(), false);
        skip.insert(auth.clone());
    }

    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &skip);
    let before = before_state_line(ctx, &exprs);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let expect = format!(
        "the instruction must execute WITHOUT the `{auth}` signature",
        auth = if auth.is_empty() { "authority" } else { &auth }
    );
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", &expect);
    let changed = state_changed_assert(ctx, &exprs, "state must change even though the authority never signed");

    format!(
        r#"#[tokio::test]
async fn missing_signer_executes_without_authority_signature() {{
    let (mut program_test, payer) = set_up_program_test();

{prelude}{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

{before}{tx}{changed}}}
"#,
        prelude = prelude,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        before = before,
        tx = tx,
        changed = changed,
    )
}

/// SAT002 / SAT020 / SAT018 / SAT025 — the flagged account is pre-created as
/// an account owned by an attacker-controlled program with attacker-crafted
/// data; the program must read/accept it anyway.
fn render_unverified_account_scenario(ctx: &TemplateContext) -> String {
    let target = ctx
        .flagged_account
        .clone()
        .filter(|n| ctx.metas.iter().any(|m| m.name == *n))
        .or_else(|| ctx.metas.iter().find(|m| !m.is_signer && !is_well_known(&m.name)).map(|m| m.name.clone()))
        .unwrap_or_default();

    let mut exprs = default_pubkey_exprs(ctx);
    let mut sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let mut skip: HashSet<String> = HashSet::new();
    let mut prelude = String::new();

    if !target.is_empty() {
        prelude.push_str(&format!(
            "    // `{target}` — pre-created as an account OWNED BY AN ATTACKER-CONTROLLED\n    // program, with attacker-crafted data. The target program must accept it\n    // without any owner/discriminator validation.\n"
        ));
        prelude.push_str(
            "    let attacker_program_id = Pubkey::new_unique(); // EDIT ME: a program the attacker controls\n    let attacker = Keypair::new();\n    program_test.add_account(\n        attacker.pubkey(),\n        Account {\n            lamports: 10_000_000,\n            data: vec![0x41; 128], // EDIT ME: attacker-crafted data the program reads\n            owner: attacker_program_id, // NOT program_id()\n            executable: false,\n            rent_epoch: 0,\n        },\n    );\n",
        );
        exprs.insert(target.clone(), "attacker.pubkey()".to_string());
        sigs.insert(target.clone(), false);
        skip.insert(target.clone());
    }

    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &skip);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let expect = "the program must process the account even though it is not owned by it";
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", expect);

    let post_assert = if !target.is_empty() {
        "    // The attacker-owned account was accepted by the handler (no owner check\n    // rejected it). Assert it is still present and attacker-owned.\n    let after = banks_client.get_account(attacker.pubkey()).await.unwrap();\n    assert!(after.is_some(), \"the attacker-owned account was consumed or rejected\");\n    assert_eq!(after.unwrap().owner, attacker_program_id);\n"
            .to_string()
    } else {
        String::new()
    };

    format!(
        r#"#[tokio::test]
async fn unverified_account_accepted_from_attacker_owner() {{
    let (mut program_test, payer) = set_up_program_test();

{prelude}{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

{tx}{post_assert}}}
"#,
        prelude = prelude,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        tx = tx,
        post_assert = post_assert,
    )
}

/// SAT005 / SAT016 / SAT024 — call the initializer twice; the second call must
/// succeed and overwrite. SAT016 additionally pre-creates the state account as
/// system-owned so `init_if_needed` re-initializes it.
fn render_reinit_scenario(ctx: &TemplateContext) -> String {
    let state = ctx
        .state_meta
        .clone()
        .unwrap_or_else(|| ctx.metas.first().map(|m| m.name.clone()).unwrap_or_else(|| "state".to_string()));
    let state_expr =
        default_pubkey_exprs(ctx).get(&state).cloned().unwrap_or_else(|| format!("{}_pubkey", ident(&state)));

    let exprs = default_pubkey_exprs(ctx);
    let sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let mut skip: HashSet<String> = HashSet::new();
    skip.insert(state.clone());

    let pre_created = if ctx.rule == "SAT016" {
        format!(
            "    // SAT016: pre-create `{state}` as a SYSTEM-OWNED (rent-funded, empty)\n    // account. `init_if_needed` re-initializes and overwrites it instead of\n    // skipping initialization.\n    program_test.add_account(\n        {state_expr},\n        Account {{ lamports: 10_000_000, data: vec![], owner: solana_program::system_program::ID, executable: false, rent_epoch: 0 }},\n    );\n"
        )
    } else {
        String::new()
    };

    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &skip);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", "the initializer must execute");
    let tx2 = tx_block(ctx, &exprs, &sigs, &payload, "", "the SECOND initialization must succeed and overwrite");

    let reinit_note = match ctx.rule.as_str() {
        "SAT016" => {
            "// NOTE (SAT016): with `init_if_needed`, the second call sees an already-\n    // initialized account and skips init — the risk window is the system-owned\n    // pre-created account above, whose init reuses attacker-influenced space.\n"
        }
        "SAT024" => {
            "// NOTE (SAT024): this mirrors a closed-then-recreated account. A closed\n    // account loses its data and lamports; the handler re-initializes without\n    // re-validation, so the second call must also succeed.\n"
        }
        _ => {
            "// NOTE (SAT005): the initializer must guard against overwriting existing\n    // state. If the second call errors with a discriminator/init conflict, the\n    // program DOES guard — the PoC then proves the first-call overwrite path\n    // instead.\n"
        }
    };

    let state_assert = if ctx.state_meta.is_some() {
        format!(
            "    // The state account was (re)written by both calls.\n    let after = banks_client.get_account({state_expr}).await.unwrap();\n    assert!(after.is_some(), \"state account must exist after both initializations\");\n    assert_ne!(after.unwrap().owner, solana_program::system_program::ID, \"state must be owned by the program after init\");\n"
        )
    } else {
        String::new()
    };

    format!(
        r#"#[tokio::test]
async fn reinitialization_overwrites_state() {{
    let (mut program_test, payer) = set_up_program_test();

{pre_created}{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

    // First initialization of `{state}`.
{tx}
    let mid = banks_client.get_account({state_expr}).await.unwrap();
    assert!(mid.is_some(), "state must exist after the first initialization");

    // SECOND initialization against the same account — must succeed and overwrite.
    // (For SAT016 the second call exercises the re-init path; for SAT024 it
    // exercises the re-init-after-close path.)
{reinit_note}{tx2}{state_assert}}}
"#,
        pre_created = pre_created,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        state = state,
        state_expr = state_expr,
        tx = tx,
        tx2 = tx2,
        reinit_note = reinit_note,
        state_assert = state_assert,
    )
}

/// SAT012 / SAT026 — boundary values (u64::MAX, 0, i64::MIN) in the
/// instruction args; observe the wrap/overflow behavior.
fn render_unsafe_arithmetic_scenario(ctx: &TemplateContext) -> String {
    let exprs = default_pubkey_exprs(ctx);
    let sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &HashSet::new());
    let before = before_state_line(ctx, &exprs);
    let payload = payload_lines(ctx, &boundary_arg_exprs(ctx));
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", "the program should accept the boundary operands");
    let changed = state_changed_assert(ctx, &exprs, "state must reflect the boundary-value write");

    format!(
        r#"#[tokio::test]
async fn boundary_values_wrap_or_overflow() {{
    let (mut program_test, payer) = set_up_program_test();

{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

    // NOTE (overflow-checks): `cargo test` (debug) compiles with overflow-checks
    // ENABLED, so a real overflow aborts the program (Err(Panic)) instead of
    // wrapping. The production binary (release, overflow-checks off) wraps:
    //   RUSTFLAGS="-C overflow-checks=no" cargo test
    // to observe the wrapping behavior the release binary exhibits.

{before}{tx}{changed}}}
"#,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        before = before,
        tx = tx,
        changed = changed,
    )
}

/// SAT014 — register an inline stub for the external program, invoke the
/// handler, and assert the post-CPI state write landed (write-after-CPI order
/// is accepted).
fn render_cei_scenario(ctx: &TemplateContext) -> String {
    let external = ctx
        .metas
        .iter()
        .find(|m| m.name.to_lowercase().contains("program") && !is_well_known(&m.name))
        .map(|m| m.name.clone());

    let mut exprs = default_pubkey_exprs(ctx);
    let mut sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let mut skip: HashSet<String> = HashSet::new();

    let mut prelude = String::new();
    match &external {
        Some(name) => {
            prelude.push_str(&format!(
                "    // The handler CPIs into `{name}`. Register an inline stub so the invoke\n    // resolves under ProgramTest.\n"
            ));
            prelude.push_str(
                "    let external_id = Pubkey::new_unique(); // EDIT ME: the real external program the handler invokes\n    program_test.add_program(\"stub_program\", external_id, processor!(stub_program::entry));\n",
            );
            exprs.insert(name.clone(), "external_id".to_string());
            sigs.insert(name.clone(), false);
            skip.insert(name.clone());
        }
        None => prelude.push_str("    // FILL IN: register the external program the handler CPIs into.\n"),
    }

    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &skip);
    let before = before_state_line(ctx, &exprs);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", "the handler must complete despite the external CPI");
    let changed =
        state_changed_assert(ctx, &exprs, "the post-CPI state write must land — write-after-CPI order is accepted");

    format!(
        r#"#[tokio::test]
async fn state_write_lands_after_external_cpi() {{
    let (mut program_test, payer) = set_up_program_test();

{prelude}{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

    // The handler performs an external CPI and THEN writes state. This PoC
    // shows the write-after-CPI order is accepted: the transaction succeeds
    // and the post-CPI state write lands — the CEI violation (a reentrant call
    // during the CPI observes stale state).

{before}{tx}{changed}}}
"#,
        prelude = prelude,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        before = before,
        tx = tx,
        changed = changed,
    )
}

/// SAT015 / SAT022 — derive the state account with WRONG seeds and pass it;
/// the program must accept the account at the wrong PDA.
fn render_pda_seed_mismatch_scenario(ctx: &TemplateContext) -> String {
    let state = ctx.state_meta.clone().unwrap_or_else(|| {
        ctx.metas.iter().find(|m| !m.is_signer && !is_well_known(&m.name)).map(|m| m.name.clone()).unwrap_or_default()
    });

    let mut exprs = default_pubkey_exprs(ctx);
    let mut sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let mut skip: HashSet<String> = HashSet::new();

    let mut prelude = String::new();
    let seeds_comment = if ctx.seed_literals.is_empty() {
        "    // EDIT ME: the program's real seeds — e.g.\n    //   Pubkey::find_program_address(&[b\"correct-seed\", payer.pubkey().as_ref()], &program_id())\n".to_string()
    } else {
        let quoted = ctx.seed_literals.iter().map(|s| format!("    //   {s}")).collect::<Vec<_>>().join("\n");
        format!(
            "    // The program's real seeds (from the handler):\n{quoted}\n    // EDIT ME: turn those into the correct find_program_address call.\n"
        )
    };

    if !state.is_empty() {
        prelude.push_str(&format!(
            "    // `{state}` is derived with WRONG seeds on purpose: they differ from the\n    // program's real derivation. A correct handler rejects an account that is\n    // not at the PDA derived from its declared seeds.\n{seeds_comment}    let (wrong_pda, _wrong_bump) = Pubkey::find_program_address(&[b\"wrong-seed\"], &program_id());\n"
        ));
        let idl_hint = if ctx.has_idl && ctx.state_meta.as_deref() == Some(state.as_str()) {
            format!(
                "    // Correct derivation helper (from the IDL): pocs::pda_{ix}_{acct}(&payer.pubkey(), &program_id(), &signer_pubkeys)\n",
                ix = ident(&ctx.ix_name),
                acct = ident(&state)
            )
        } else {
            String::new()
        };
        prelude.push_str(&idl_hint);
        prelude.push_str(&format!(
            "    program_test.add_account(\n        wrong_pda,\n        Account {{ lamports: 10_000_000, data: {data}, owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n",
            data = wrong_pda_data_expr(ctx, &state),
        ));
        exprs.insert(state.clone(), "wrong_pda".to_string());
        sigs.insert(state.clone(), false);
        skip.insert(state.clone());
    }

    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &skip);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", "the program must accept the account at the wrong PDA address");

    let post_assert = if state.is_empty() {
        String::new()
    } else {
        "    let wrong_pda_after = banks_client.get_account(wrong_pda).await.unwrap();\n    assert!(wrong_pda_after.is_some(), \"wrong-PDA account must still exist after the call\");\n".to_string()
    };

    format!(
        r#"#[tokio::test]
async fn wrong_pda_seeds_accepted() {{
    let (mut program_test, payer) = set_up_program_test();

{prelude}{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

{tx}{post_assert}}}
"#,
        prelude = prelude,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        tx = tx,
        post_assert = post_assert,
    )
}

/// Data expression for the wrong-PDA account: the IDL factory when available,
/// else the Anchor account discriminator + zero-filled borsh default when the
/// state type is resolvable, else a placeholder with an EDIT ME note.
fn wrong_pda_data_expr(ctx: &TemplateContext, name: &str) -> String {
    if let Some(ty) = idl_account_type_for(ctx, name) {
        return format!("pocs::accounts::build_{}(&mut rng)", to_snake_case(&ty));
    }
    if let Some(ty) = &ctx.state_type {
        let disc = account_discriminator(ty);
        let bytes = disc.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
        format!(
            "{{\n        let mut data = vec![{bytes}]; // sha256(\"account:{ty}\")[..8]\n        data.extend(vec![0u8; 120]); // borsh default fields\n        data\n    }}",
            bytes = bytes,
            ty = ty,
        )
    } else {
        "vec![0; 1024] // EDIT ME: valid account data".to_string()
    }
}

/// SAT017 / SAT028 — seed a mint + token accounts and present the authority
/// WITHOUT a signature; the transfer must execute.
fn render_token_cpi_scenario(ctx: &TemplateContext) -> String {
    let authority = ctx
        .flagged_account
        .clone()
        .filter(|n| ctx.metas.iter().any(|m| m.name == *n))
        .or_else(|| first_authority_named(ctx))
        .unwrap_or_default();

    let mut exprs = default_pubkey_exprs(ctx);
    let mut sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let mut skip: HashSet<String> = HashSet::new();

    let mut prelude = String::new();
    if !authority.is_empty() {
        prelude.push_str(&format!(
            "    // `{authority}` — present in the metas WITHOUT the signer flag; the\n    // transaction is not signed with it.\n"
        ));
    } else {
        prelude.push_str("    // FILL IN: the token authority account name from the finding.\n");
    }
    prelude.push_str(
        "    let attacker = Keypair::new();\n    let authority_pubkey = attacker.pubkey();\n    program_test.add_account(\n        authority_pubkey,\n        Account { lamports: 1_000_000_000_000, data: vec![], owner: solana_program::system_program::ID, executable: false, rent_epoch: 0 },\n    );\n",
    );

    prelude.push_str(
        r#"    // SPL token environment: a shared mint plus source/destination token
    // accounts owned by the (non-signing) authority.
    let mint_pubkey = Keypair::new().pubkey();
    let source_pubkey = Keypair::new().pubkey();
    let destination_pubkey = Keypair::new().pubkey();

    let mint_data = {
        let mint = TokenMint {
            mint_authority: COption::Some(payer.pubkey()),
            supply: 1_000_000_000_000,
            decimals: 9,
            is_initialized: true,
            freeze_authority: COption::None,
        };
        let mut data = vec![0u8; TokenMint::LEN];
        TokenMint::pack(&mint, &mut data).expect("mint pack");
        data
    };
    program_test.add_account(
        mint_pubkey,
        Account { lamports: 10_000_000, data: mint_data, owner: spl_token::ID, executable: false, rent_epoch: 0 },
    );

    let token_data = {
        let account = TokenAccount {
            mint: mint_pubkey,
            owner: authority_pubkey,
            amount: 1_000_000_000,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        };
        let mut data = vec![0u8; TokenAccount::LEN];
        TokenAccount::pack(&account, &mut data).expect("token account pack");
        data
    };
    program_test.add_account(
        source_pubkey,
        Account { lamports: 10_000_000, data: token_data, owner: spl_token::ID, executable: false, rent_epoch: 0 },
    );
    let dest_data = {
        let account = TokenAccount {
            mint: mint_pubkey,
            owner: destination_pubkey,
            amount: 0,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        };
        let mut data = vec![0u8; TokenAccount::LEN];
        TokenAccount::pack(&account, &mut data).expect("token account pack");
        data
    };
    program_test.add_account(
        destination_pubkey,
        Account { lamports: 10_000_000, data: dest_data, owner: spl_token::ID, executable: false, rent_epoch: 0 },
    );
"#,
    );

    if !authority.is_empty() {
        exprs.insert(authority.clone(), "authority_pubkey".to_string());
        sigs.insert(authority.clone(), false);
        skip.insert(authority.clone());
    }

    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &skip);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let tx = tx_block(
        ctx,
        &exprs,
        &sigs,
        &payload,
        "    // FILL IN: the target program's transfer instruction — its token accounts\n    // (source/destination/mint/token_program) and amount arg.\n",
        "the transfer must execute without the authority's signature",
    );

    let post_assert = if ctx.state_meta.is_some() {
        let state_expr = exprs.get(ctx.state_meta.as_deref().unwrap_or_default()).cloned().unwrap_or_default();
        format!(
            "    // Assert the post-transfer state (adjust to the target program's layout).\n    let after = banks_client.get_account({state_expr}).await.unwrap();\n    assert!(after.is_some());\n"
        )
    } else {
        "    // FILL IN: assert the token balance delta (decode via TokenAccount::unpack).\n".to_string()
    };

    format!(
        r#"#[tokio::test]
async fn token_transfer_with_unverified_authority() {{
    let (mut program_test, payer) = set_up_program_test();

{prelude}{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

    // NOTE: if the handler performs an spl_token::instruction::transfer CPI,
    // spl_token independently enforces the authority's signature at the CPI
    // level — this PoC demonstrates the PROGRAM itself does not require it.
    // A full exploit wires the target program's real transfer handler here.
{tx}{post_assert}}}
"#,
        prelude = prelude,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        tx = tx,
        post_assert = post_assert,
    )
}

/// SAT030 — two instructions in one transaction reuse the same state account
/// with no init guard between them; both must succeed.
fn render_cross_instruction_scenario(ctx: &TemplateContext) -> String {
    let exprs = default_pubkey_exprs(ctx);
    let sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &HashSet::new());
    let before = before_state_line(ctx, &exprs);
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));

    let state_expr = ctx.state_meta.as_ref().and_then(|name| exprs.get(name)).cloned();

    // One instruction is enough to demonstrate cross-instruction reuse; the
    // second slot is a scaffold for the finding's second instruction.
    let two_ix_tx = format!(
        r#"{payload}    let ix = Instruction::new_with_bytes(
        program_id(),
        &payload,
        vec![
{metas}
        ],
    );
    let ix2 = Instruction::new_with_bytes(
        program_id(),
        &payload,
        vec![
{metas}
        ],
    );
    // FILL IN: `ix2` may target a DIFFERENT instruction that reuses the same
    // state account (e.g. update/withdraw after initialize) — see the finding.
    let tx = Transaction::new_signed_with_payer(
        &[ix, ix2],
        Some(&payer.pubkey()),
        {signers},
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.expect("both instructions must execute against the reused state account");
"#,
        payload = payload,
        metas = metas_lines(ctx, &exprs, &sigs),
        signers = signing_list(ctx),
    );

    let post = match (&state_expr, &before.is_empty()) {
        (Some(expr), false) => format!(
            "    let after = banks_client.get_account({expr}).await.unwrap();\n    assert_ne!(before.as_ref().map(|a| a.data.clone()), after.as_ref().map(|a| a.data.clone()), \"state must change across the two instructions\");\n"
        ),
        _ => String::new(),
    };

    format!(
        r#"#[tokio::test]
async fn state_reused_across_instructions_in_one_transaction() {{
    let (mut program_test, payer) = set_up_program_test();

{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

    // Two instructions in ONE transaction both consume the same `{state}` state
    // account with no init guard in between.
{before}{two_ix_tx}{post}}}
"#,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        state = ctx.state_meta.clone().unwrap_or_else(|| "state".to_string()),
        before = before,
        two_ix_tx = two_ix_tx,
        post = post,
    )
}

/// Generic fallback — full harness, placeholder accounts seeded from the
/// IDL/ResolvedAccount data, and a comment block quoting the finding.
fn render_generic_scenario(ctx: &TemplateContext) -> String {
    let exprs = default_pubkey_exprs(ctx);
    let sigs: HashMap<String, bool> = ctx.metas.iter().map(|m| (m.name.clone(), m.is_signer)).collect();
    let keypairs = keypair_lines(ctx);
    let addresses = address_setup_lines(ctx, &exprs);
    let signer_pubkeys = if ctx.has_idl { signer_pubkeys_line(ctx) } else { String::new() };
    let seeds = seed_lines(ctx, &exprs, &HashSet::new());
    let payload = payload_lines(ctx, &default_arg_exprs(ctx));
    let tx = tx_block(ctx, &exprs, &sigs, &payload, "", "adjust the harness until the flagged path executes");

    let suggestion = ctx.finding.suggestion.clone().unwrap_or_else(|| "(none)".to_string());
    let accounts_note = if ctx.metas.is_empty() {
        "    // No accounts resolved for this finding — add the AccountMetas the handler expects.\n".to_string()
    } else {
        let names = ctx.metas.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ");
        format!("    // Accounts exercised: {names}.\n")
    };

    format!(
        r#"// FILL IN: sequence that proves exploitability
// ---------------------------------------------------------------------------
// Finding      : {id} — {title}
// Location     : {location}
// Suggestion   : {suggestion}
// Instruction  : {ix_name}
// ---------------------------------------------------------------------------
// The generic template seeds the resolved accounts and issues one call to the
// flagged handler. Turn it into a concrete exploit: boundary args, a second
// instruction, an attacker-controlled account, or a reentrancy callback.

#[tokio::test]
async fn generic_exploit_scenario() {{
    let (mut program_test, payer) = set_up_program_test();

{keypairs}{addresses}{signer_pubkeys}{seeds}    let (mut banks_client, payer_pubkey, recent_blockhash) = program_test.start().await;

{accounts_note}{tx}}}
"#,
        id = ctx.finding.id,
        title = ctx.finding.title,
        location = ctx.finding.location.as_deref().unwrap_or("(none)"),
        suggestion = suggestion,
        ix_name = ctx.ix_name,
        keypairs = keypairs,
        addresses = addresses,
        signer_pubkeys = signer_pubkeys,
        seeds = seeds,
        accounts_note = accounts_note,
        tx = tx,
    )
}

// ── README ────────────────────────────────────────────────────────────────────

fn render_readme(ctx: &TemplateContext, lib_name: Option<&str>) -> String {
    let program_note = match lib_name {
        Some(lib) => format!(
            "The target program crate was located under `programs/`: the generated\nCargo.toml depends on `{lib}` with `features = [\"no-entrypoint\"]`.\n"
        ),
        None => "The target program crate was NOT located under `<root>/programs/`.\nThe generated tests reference a placeholder processor path — resolve the\n`// EDIT ME` markers and add a path dependency once the crate is in place.\n"
            .to_string(),
    };
    format!(
        r#"# PoC crate (generated by `sat poc`)

Generated for finding `{id}` ({rule}): {title}

{program_note}
## Run

    cargo test

Each `tests/poc_sat*.rs` file is one ProgramTest integration test exercising
the flagged rule. Run a single test:

    cargo test --test poc_{rule_lower}

## Harness edits

The generator auto-resolves everything the analyzed model carries:

- Program id — from `declare_id!` (native) or IDL metadata address.
- Instruction payload — Anchor `sha256("global:<ix>")[..8]` discriminator plus
  borsh-serialized args from the IDL, or the native dispatch tag bytes.
- AccountMetas — ordered, with signer/writable flags from the Accounts
  struct / ResolvedAccount model.
- PDA derivations — `find_program_address` emitted inline when the model's
  seeds resolve to literals/payer/signer expressions.
- Anchor account discriminators (`sha256("account:<type>")[..8]`) for state
  accounts, with a zero-filled payload that is the borsh default of the fields.

The remaining `// EDIT ME` markers are limited to:

- Raw account-data bytes for accounts whose type/layout is not resolvable
  (e.g. untyped `AccountInfo` payloads the handler parses itself).
- Program-crate specifics: the processor path when the crate was not located
  under `<root>/programs/`, and the external-program id for CPI scenarios.

The tests deliberately attempt the vulnerable path (missing signature,
attacker-owned accounts, boundary values, wrong-PDA seeds, ...) and assert
the program accepts it.
- For unsafe-arithmetic rules run with overflow-checks off to observe wrapping:

    RUSTFLAGS="-C overflow-checks=no" cargo test

## Layout

- `src/lib.rs` — shared account factories / PDA helpers (only generated when an
  IDL is available; tests are self-contained otherwise).
- `tests/poc_satXXX.rs` — one integration test per rule.
- `Cargo.toml` — harness dependencies, versions mirrored from the target
  program's Cargo.toml when it was found.
"#,
        id = ctx.finding.id,
        rule = ctx.rule,
        rule_lower = ctx.rule.to_lowercase(),
        title = ctx.finding.title,
        program_note = program_note,
    )
}

// ── Tests (generator self-checks) ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    /// Minimal `TemplateContext` for rendering-unit tests (real `Finding` so no
    /// `Default` impl is required on the production struct).
    fn test_ctx() -> TemplateContext {
        TemplateContext {
            rule: "SAT001".to_string(),
            finding: Finding {
                id: "SAT-001".to_string(),
                title: "Missing Signer Constraint".to_string(),
                severity: Severity::High,
                description: String::new(),
                location: None,
                suggestion: None,
            },
            source_path: None,
            ix_name: "do_thing".to_string(),
            module_hint: None,
            lib_name: None,
            program_id: DEFAULT_PROGRAM_ID.to_string(),
            program_id_placeholder: false,
            is_native: false,
            has_idl: false,
            metas: Vec::new(),
            args: Vec::new(),
            flagged_account: None,
            state_meta: None,
            state_type: None,
            ix_discriminator: None,
            native_discriminator: None,
            native_handler: None,
            seed_literals: Vec::new(),
            idl_accounts: Vec::new(),
        }
    }

    #[test]
    fn parse_location_handles_anchor_native_and_idl_shapes() {
        let loc = parse_location("src/lib.rs:37 (UpdateValue::authority)");
        assert_eq!(loc.file, "src/lib.rs");
        assert_eq!(loc.line, Some(37));
        assert_eq!(loc.context.as_deref(), Some("UpdateValue::authority"));

        let loc = parse_location("programs/x/src/lib.rs:14 (withdraw)");
        assert_eq!(loc.context.as_deref(), Some("withdraw"));
        assert_eq!(loc.line, Some(14));

        let loc = parse_location("Instruction: initialize");
        assert_eq!(loc.context.as_deref(), Some("initialize"));

        // Windows drive letter must not be treated as a line separator.
        let loc = parse_location("C:\\Users\\me\\src\\lib.rs:9 (process)");
        assert_eq!(loc.line, Some(9));
        assert_eq!(loc.file, "C:\\Users\\me\\src\\lib.rs");
    }

    #[test]
    fn parse_location_without_line_still_yields_context() {
        let loc = parse_location("Sysvar: rent (sysvar_issues.rs)");
        assert_eq!(loc.line, None);
    }

    #[test]
    fn discriminator_matches_fuzzer_convention() {
        let expected = {
            let preimage = "global:initialize";
            let hash = Sha256::digest(preimage.as_bytes());
            let mut disc = [0u8; 8];
            disc.copy_from_slice(&hash[..8]);
            disc
        };
        assert_eq!(instruction_discriminator("initialize"), expected);
    }

    #[test]
    fn program_crate_detection_walks_programs_dir() {
        let dir = tempfile::tempdir().unwrap();
        let programs = dir.path().join("programs");
        let crate_dir = programs.join("my_vault");
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"my_vault\"\n").unwrap();

        let detected = detect_program_crate(Some(&crate_dir.join("src").join("lib.rs").to_string_lossy())).unwrap();
        assert_eq!(detected, crate_dir);
        assert_eq!(detect_program_crate(Some(dir.path().to_str().unwrap())), None);
    }

    #[test]
    fn account_discriminator_matches_anchor_sha256_prefix() {
        let expected = {
            let preimage = "account:State";
            let hash = Sha256::digest(preimage.as_bytes());
            let mut disc = [0u8; 8];
            disc.copy_from_slice(&hash[..8]);
            disc
        };
        assert_eq!(account_discriminator("State"), expected);
        assert_ne!(account_discriminator("State"), account_discriminator("Vault"));
    }

    #[test]
    fn safe_seed_classification_allows_literals_and_payer_derived() {
        assert!(is_safe_seed_expr("b\"vault\""));
        assert!(is_safe_seed_expr("&payer.key"));
        assert!(is_safe_seed_expr("payer.pubkey().as_ref()"));
        assert!(!is_safe_seed_expr("authority.key.as_ref()"));
        assert!(!is_safe_seed_expr("ctx.accounts.vault.key()"));
        assert!(!is_safe_seed_expr(""));
    }

    #[test]
    fn seed_args_map_to_test_scope_values() {
        let mut ctx = test_ctx();
        ctx.is_native = true;
        ctx.metas = vec![MetaAccount {
            name: "authority".into(),
            is_signer: true,
            is_mut: false,
            is_pda: false,
            seeds: vec![],
        }];
        // Byte-string literals become byte slices.
        assert_eq!(render_seed_arg(&ctx, "b\"vault\""), "b\"vault\".as_slice()");
        // Payer-derived seeds resolve to the test payer's pubkey bytes.
        assert_eq!(render_seed_arg(&ctx, "payer.key.as_ref()"), "payer.pubkey().as_ref()");
        // Signer-account seeds resolve to the signer keypair's pubkey bytes.
        assert_eq!(render_seed_arg(&ctx, "authority.key.as_ref()"), "authority_kp.pubkey().as_ref()");
    }

    #[test]
    fn address_setup_lines_define_deterministic_placeholder_keys() {
        let mut ctx = test_ctx();
        ctx.is_native = true;
        ctx.metas = vec![
            MetaAccount { name: "authority".into(), is_signer: true, is_mut: false, is_pda: false, seeds: vec![] },
            MetaAccount { name: "vault".into(), is_signer: false, is_mut: true, is_pda: false, seeds: vec![] },
            MetaAccount { name: "rent".into(), is_signer: false, is_mut: false, is_pda: false, seeds: vec![] },
        ];
        let exprs = default_pubkey_exprs(&ctx);
        let rendered = address_setup_lines(&ctx, &exprs);
        // Only `vault` gets a placeholder key (signers/well-known are skipped).
        assert!(rendered.contains("let vault_pubkey = Pubkey::new_from_array([2u8; 32]);"));
        assert!(!rendered.contains("authority_pubkey ="));
        assert!(!rendered.contains("rent_pubkey ="));
    }

    #[test]
    fn address_setup_lines_derive_pda_with_safe_seeds() {
        let mut ctx = test_ctx();
        ctx.is_native = true;
        ctx.metas = vec![MetaAccount {
            name: "vault".into(),
            is_signer: false,
            is_mut: true,
            is_pda: true,
            seeds: vec!["b\"vault\"".to_string(), "payer.key.as_ref()".to_string()],
        }];
        let exprs = default_pubkey_exprs(&ctx);
        let rendered = address_setup_lines(&ctx, &exprs);
        assert!(rendered.contains(
            "Pubkey::find_program_address(&[b\"vault\".as_slice(), payer.pubkey().as_ref()], &program_id())"
        ));
        assert!(!rendered.contains("new_from_array"));
    }

    #[test]
    fn address_setup_lines_skip_overridden_accounts() {
        let mut ctx = test_ctx();
        ctx.is_native = true;
        ctx.metas = vec![
            MetaAccount { name: "state".into(), is_signer: false, is_mut: true, is_pda: false, seeds: vec![] },
            MetaAccount { name: "victim".into(), is_signer: false, is_mut: false, is_pda: false, seeds: vec![] },
        ];
        let mut exprs = default_pubkey_exprs(&ctx);
        exprs.insert("state".to_string(), "wrong_pda".to_string());
        let rendered = address_setup_lines(&ctx, &exprs);
        assert!(!rendered.contains("state_pubkey"));
        assert!(rendered.contains("let victim_pubkey = Pubkey::new_from_array([2u8; 32]);"));
    }

    #[test]
    fn sat021_dispatches_to_missing_signer_scenario() {
        let mut ctx = test_ctx();
        ctx.rule = "SAT021".to_string();
        ctx.is_native = true;
        let rendered = render_scenario(&ctx);
        assert!(rendered.contains("missing_signer_executes_without_authority_signature"));
    }

    #[test]
    fn native_processor_path_uses_handler_not_entry() {
        let mut ctx = test_ctx();
        ctx.is_native = true;
        ctx.lib_name = Some("native_auth".to_string());
        ctx.native_handler = Some("handle_auth".to_string());
        assert_eq!(processor_path(&ctx), "native_auth::handle_auth");

        let mut anchor_ctx = test_ctx();
        anchor_ctx.lib_name = Some("simple_poc".to_string());
        assert_eq!(processor_path(&anchor_ctx), "simple_poc::entry");
    }

    #[test]
    fn state_seed_lines_emit_real_account_discriminator() {
        let mut ctx = test_ctx();
        ctx.ix_name = "do_thing".to_string();
        ctx.state_meta = Some("state".to_string());
        ctx.state_type = Some("State".to_string());
        ctx.metas = vec![
            MetaAccount { name: "authority".into(), is_signer: true, is_mut: false, is_pda: false, seeds: vec![] },
            MetaAccount { name: "state".into(), is_signer: false, is_mut: true, is_pda: false, seeds: vec![] },
        ];
        let exprs = default_pubkey_exprs(&ctx);
        let rendered = seed_lines(&ctx, &exprs, &HashSet::new());
        let disc = account_discriminator("State");
        let bytes = disc.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
        assert!(rendered.contains(&format!("let mut state_data = vec![{bytes}];")), "discriminator must be embedded");
        assert!(!rendered.contains("EDIT ME"), "state account data must be auto-resolved");
    }

    #[test]
    fn native_payload_embeds_dispatch_tag_bytes() {
        let mut ctx = test_ctx();
        ctx.is_native = true;
        ctx.ix_name = "handle_auth".to_string();
        ctx.native_discriminator = Some(vec![0xAA, 0xBB]);
        let rendered = native_payload_lines(&ctx);
        assert!(rendered.contains("let payload = vec![170, 187];"));
        // The tag itself is auto-resolved; only extra handler data stays a note.
        assert!(rendered.contains("FILL IN: append any instruction data the handler reads"));
    }

    #[test]
    fn declare_id_is_extracted_from_anchor_source() {
        let source = r#"
use anchor_lang::prelude::*;
declare_id!("poc11111111111111111111111111111111111111");
#[program]
pub mod simple { pub fn go(ctx: Context<Go>) -> Result<()> { Ok(()) } }
#[derive(Accounts)]
pub struct Go<'info> { pub state: Account<'info, State> }
#[account]
pub struct State { pub value: u64 }
"#;
        let file = syn::parse_file(source).expect("source should parse");
        assert_eq!(
            extract_declared_id(&[(file, "lib.rs".to_string())]).as_deref(),
            Some("poc11111111111111111111111111111111111111")
        );
        assert_eq!(extract_declared_id(&[]), None);
    }

    #[test]
    fn handler_args_are_extracted_after_context() {
        let source = r#"
use anchor_lang::prelude::*;
#[program]
pub mod simple {
    pub fn do_thing(ctx: Context<DoThing>, amount: u64, label: String) -> Result<()> {
        Ok(())
    }
}
#[derive(Accounts)]
pub struct DoThing<'info> { pub state: Account<'info, State> }
#[account]
pub struct State { pub value: u64 }
"#;
        let file = syn::parse_file(source).expect("source should parse");
        let args = handler_args(&[(file, "lib.rs".to_string())], "do_thing");
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name, "amount");
        assert_eq!(args[0].rust, "u64");
        assert_eq!(args[1].name, "label");
        assert_eq!(args[1].rust, "String");
        assert!(handler_args(&[], "do_thing").is_empty());
    }
}
