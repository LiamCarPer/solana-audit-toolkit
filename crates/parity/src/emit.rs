//! `parity emit-harness` — scaffold a `solana-program-test` adapter for a real
//! target program.
//!
//! The differential engine compares a reference model against a recorded trace
//! of a real program. Producing that trace needs a small harness crate that
//! (a) registers the target program in `ProgramTest`, (b) maps scenario ops to
//! the target's instructions, and (c) reads the target's state into the
//! canonical [`crate::scenario::Observables`].
//!
//! That mapping is protocol-specific — the AI authors it. This module generates
//! the crate skeleton, **mirroring the target's own dependency versions** so it
//! builds in the target's environment, and leaves four clearly marked TODOs:
//! program id, account seeding, `build_op`, and `observe`.

use std::path::Path;

use anyhow::{Context, Result};

/// Dependency versions read from the target (and its workspace), used to pin
/// the generated harness so it compiles against the same Solana stack.
#[derive(Debug, Clone, Default)]
pub struct TargetVersions {
    pub anchor_lang: Option<String>,
    pub solana_program: Option<String>,
    pub solana_program_test: Option<String>,
    pub solana_sdk: Option<String>,
    pub spl_token: Option<String>,
}

impl TargetVersions {
    fn get<'a>(&'a self, key: &str) -> Option<&'a str> {
        match key {
            "anchor-lang" => self.anchor_lang.as_deref(),
            "solana-program" => self.solana_program.as_deref(),
            "solana-program-test" => self.solana_program_test.as_deref(),
            "solana-sdk" => self.solana_sdk.as_deref(),
            "spl-token" => self.spl_token.as_deref(),
            _ => None,
        }
    }

    /// Version or `fallback`, reported as `(version, mirrored)`.
    fn resolved(&self, key: &str, fallback: &str) -> (String, bool) {
        match self.get(key) {
            Some(v) => (v.to_string(), true),
            None => (fallback.to_string(), false),
        }
    }
}

/// Read a dependency's version string from a `[dependencies]` or
/// `[workspace.dependencies]` table. Handles `x = "1.2"`, `x = { version = "1.2" }`
/// and `x.workspace = true` (returns `None`; the workspace table supplies it).
fn dep_version(table: &toml::Value, name: &str) -> Option<String> {
    let entry = table.get(name)?;
    match entry {
        toml::Value::String(v) => Some(v.clone()),
        toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(str::to_string),
        _ => None,
    }
}

/// Whether the target declares `name.workspace = true` (version inherited).
/// Kept for documentation of the layout; version lookup falls back to the
/// workspace table automatically when the local entry carries no `version`.
#[allow(dead_code)]
fn uses_workspace_inheritance(table: &toml::Value, name: &str) -> bool {
    table
        .get(name)
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("workspace"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Walk up from `start` looking for a `Cargo.toml` with `[workspace.dependencies]`.
fn find_workspace_deps(start: &Path) -> Option<toml::Value> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let manifest = d.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest)
            && let Ok(value) = text.parse::<toml::Value>()
            && let Some(deps) = value.get("workspace").and_then(|w| w.get("dependencies")).cloned()
        {
            return Some(deps);
        }
        dir = d.parent();
    }
    None
}

/// Read the versions the target program is built with.
pub fn read_target_versions(program_dir: &Path) -> Result<TargetVersions> {
    let manifest = program_dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("failed to read target manifest {}", manifest.display()))?;
    let value: toml::Value = text.parse().with_context(|| format!("invalid TOML in {}", manifest.display()))?;
    let deps = value.get("dependencies").cloned().unwrap_or(toml::Value::Table(Default::default()));
    let ws = find_workspace_deps(program_dir).unwrap_or(toml::Value::Table(Default::default()));

    let mut out = TargetVersions::default();
    for (key, slot) in [
        ("anchor-lang", &mut out.anchor_lang),
        ("solana-program", &mut out.solana_program),
        ("solana-program-test", &mut out.solana_program_test),
        ("solana-sdk", &mut out.solana_sdk),
        ("spl-token", &mut out.spl_token),
    ] {
        // A direct `version` wins; otherwise fall back to the workspace table
        // (covers `x.workspace = true` and undeclared-but-inherited deps).
        let v = dep_version(&deps, key).or_else(|| dep_version(&ws, key));
        *slot = v;
    }
    Ok(out)
}

/// The library crate name of a target (its manifest `[lib] name`, else the
/// package name with `-` → `_`).
fn target_lib_name(program_dir: &Path, fallback: &str) -> String {
    let manifest = program_dir.join("Cargo.toml");
    if let Ok(text) = std::fs::read_to_string(&manifest)
        && let Ok(value) = text.parse::<toml::Value>()
    {
        if let Some(name) = value.get("lib").and_then(|l| l.get("name")).and_then(|n| n.as_str()) {
            return name.to_string();
        }
        if let Some(name) = value.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str()) {
            return name.replace('-', "_");
        }
    }
    fallback.replace('-', "_")
}

fn render_cargo_toml(name: &str, program_dir: &Path, lib_name: &str, versions: &TargetVersions) -> String {
    let (anchor, a_mirrored) = versions.resolved("anchor-lang", "0.29");
    let (solana_program, sp_mirrored) = versions.resolved("solana-program", "1.17");
    let (solana_program_test, spt_mirrored) = versions.resolved("solana-program-test", &solana_program);
    let (solana_sdk, sdk_mirrored) = versions.resolved("solana-sdk", &solana_program);
    let (spl_token, tok_mirrored) = versions.resolved("spl-token", "4");

    let all_mirrored = a_mirrored && sp_mirrored && spt_mirrored && sdk_mirrored && tok_mirrored;
    let warn = if all_mirrored {
        String::new()
    } else {
        format!(
            "# WARN: some versions were not found in {} — defaults may not match the target; mirror them if the build fails\n",
            program_dir.display()
        )
    };

    let program_path =
        program_dir.canonicalize().unwrap_or_else(|_| program_dir.to_path_buf()).to_string_lossy().to_string();

    format!(
        r#"[package]
name = "{name}-harness"
version = "0.1.0"
edition = "2021"
publish = false

# Standalone crate (own workspace root) so it does not join the target or
# parity workspaces.
[workspace]

[dependencies]
{warn}{lib_name} = {{ path = "{program_path}", features = ["no-entrypoint"] }}
anchor-lang = "{anchor}"
solana-program = "{solana_program}"
solana-program-test = "{solana_program_test}"
solana-sdk = "{solana_sdk}"
spl-token = "{spl_token}"
anyhow = "1"
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
tokio = {{ version = "1", features = ["full"] }}

[[bin]]
name = "{name}-harness"
path = "src/main.rs"
"#
    )
}

fn render_main_rs(name: &str, lib_name: &str) -> String {
    format!(
        r#"//! `{name}` parity harness — records a canonical trace of the real program.
//!
//! Generated by `parity emit-harness`. Four protocol-specific pieces are left
//! for the author (marked TODO):
//!   1. `PROGRAM_ID`           — the target's on-chain id (or `declare_id!`).
//!   2. `seed_accounts`        — create/seed the accounts the ops touch.
//!   3. `build_op`             — map a scenario op to a target instruction.
//!   4. `observe`              — read target state into `Observables`.
//!
//! Run: `{name}-harness --scenario scenario.json --out trace.json`

use std::path::PathBuf;

use anyhow::{{Context, Result}};
use solana_program_test::{{processor, ProgramTest}};
use solana_sdk::{{
    account::Account,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
}};
use serde::{{Deserialize, Serialize}};

/// TODO(1): the target's program id.
const PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// ── Wire types (mirror parity::Scenario / Trace / Observables) ───────────────

#[derive(Debug, Clone, Deserialize)]
struct Scenario {{
    name: String,
    #[serde(default)]
    config: Config,
    #[serde(default)]
    accounts: Vec<AccountSpec>,
    ops: Vec<Op>,
}}

#[derive(Debug, Clone, Deserialize, Default)]
struct Config {{
    #[serde(default = "one")]
    price: u64,
    #[serde(default)]
    rate_bps_per_second: u64,
}}

fn one() -> u64 {{ 1 }}

#[derive(Debug, Clone, Deserialize)]
struct AccountSpec {{
    role: String,
    name: String,
    #[serde(default)]
    initial: u64,
}}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Op {{
    Deposit {{ user: String, amount: u64 }},
    Withdraw {{ user: String, amount: u64 }},
    Borrow {{ user: String, amount: u64 }},
    Repay {{ user: String, amount: u64 }},
    Accrue {{ seconds: u64 }},
    SetPrice {{ price: u64 }},
}}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Observables {{
    total_deposits: u64,
    total_borrows: u64,
    total_shares: u64,
    vault_balance: u64,
    user_shares: u64,
    user_balance: u64,
    price: u64,
}}

#[derive(Debug, Clone, Serialize)]
struct TraceStep {{
    op_index: usize,
    observables: Observables,
    error: Option<String>,
}}

#[derive(Debug, Clone, Serialize)]
struct Trace {{
    scenario: String,
    model: String,
    steps: Vec<TraceStep>,
}}

// ── Adapter (protocol-specific) ──────────────────────────────────────────────

/// TODO(2): seed the accounts the scenario touches (reserve/vault/user/oracle).
fn seed_accounts(_program_test: &mut ProgramTest, _scenario: &Scenario) {{
    // Example:
    // let reserve = Pubkey::new_from_array([1u8; 32]);
    // program_test.add_account(reserve, Account {{ lamports: 1_000_000_000, data: vec![0u8; 64], owner: PROGRAM_ID, executable: false, rent_epoch: 0 }});
}}

/// TODO(3): map a scenario op to a target instruction. Return `Err` for ops the
/// target does not support so the engine reports a result divergence.
fn build_op(_op: &Op, _scenario: &Scenario) -> Result<Instruction> {{
    anyhow::bail!("build_op not implemented — map scenario ops to {lib_name} instructions")
}}

/// TODO(4): read target state into canonical observables.
fn observe(_scenario: &Scenario) -> Observables {{
    Observables::default()
}}

// ── Runner ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {{
    let args: Vec<String> = std::env::args().collect();
    let mut scenario_path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {{
        match args[i].as_str() {{
            "--scenario" => {{ scenario_path = args.get(i + 1).map(PathBuf::from); i += 2; }}
            "--out" => {{ out = args.get(i + 1).map(PathBuf::from); i += 2; }}
            other => anyhow::bail!("unknown argument `{{other}}` (expected --scenario FILE [--out FILE])"),
        }}
    }}
    let scenario_path = scenario_path.context("--scenario is required")?;
    let scenario: Scenario = serde_json::from_str(
        &std::fs::read_to_string(&scenario_path)
            .with_context(|| format!("failed to read {{}}", scenario_path.display()))?,
    )
    .context("invalid scenario JSON")?;

    let mut program_test = ProgramTest::new("{lib_name}", PROGRAM_ID, processor!({lib_name}::entry));
    seed_accounts(&mut program_test, &scenario);

    let context = program_test.start_with_context().await;
    let mut banks_client = context.banks_client;
    let payer = context.payer;
    let recent_blockhash = context.last_blockhash;

    let mut steps = Vec::new();
    for (op_index, op) in scenario.ops.iter().enumerate() {{
        let error = match build_op(op, &scenario) {{
            Err(e) => Some(e.to_string()),
            Ok(ix) => {{
                let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], recent_blockhash);
                banks_client.process_transaction(tx).await.err().map(|e| e.to_string())
            }}
        }};
        steps.push(TraceStep {{ op_index, observables: observe(&scenario), error }});
    }}

    let trace = Trace {{ scenario: scenario.name.clone(), model: "{name}".to_string(), steps }};
    let json = serde_json::to_string_pretty(&trace)?;
    match out {{
        Some(path) => {{ std::fs::write(&path, json).with_context(|| format!("failed to write {{}}", path.display()))?; }}
        None => println!("{{json}}"),
    }}
    Ok(())
}}
"#
    )
}

/// Scaffold a harness crate for `program_dir` into `out_dir`.
pub fn emit(program_dir: &Path, name: &str, out_dir: &Path) -> Result<()> {
    let versions = read_target_versions(program_dir)?;
    let lib_name = target_lib_name(program_dir, name);

    std::fs::create_dir_all(out_dir.join("src")).with_context(|| format!("failed to create {}", out_dir.display()))?;
    std::fs::write(out_dir.join("Cargo.toml"), render_cargo_toml(name, program_dir, &lib_name, &versions))
        .context("failed to write harness Cargo.toml")?;
    std::fs::write(out_dir.join("src/main.rs"), render_main_rs(name, &lib_name))
        .context("failed to write harness src/main.rs")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_target(dir: &Path, deps: &str, pkg: &str) {
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{pkg}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{deps}"),
        )
        .unwrap();
    }

    #[test]
    fn reads_versions_from_target_and_workspace() {
        let root = tempfile::tempdir().unwrap();
        let prog = root.path().join("programs/vault");
        std::fs::create_dir_all(&prog).unwrap();
        // Workspace manifest with inherited deps.
        std::fs::write(
            root.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"programs/vault\"]\n\n[workspace.dependencies]\nsolana-program = \"~1.17.18\"\nanchor-lang = \"0.29.0\"\n",
        )
        .unwrap();
        write_target(
            &prog,
            "anchor-lang = { workspace = true }\nsolana-program.workspace = true\nspl-token = { version = \"4.0.0\" }\n",
            "vault",
        );

        let v = read_target_versions(&prog).unwrap();
        assert_eq!(v.solana_program.as_deref(), Some("~1.17.18"), "workspace-inherited version");
        assert_eq!(v.anchor_lang.as_deref(), Some("0.29.0"));
        assert_eq!(v.spl_token.as_deref(), Some("4.0.0"), "direct dependency version");
        assert_eq!(v.solana_program_test, None, "not declared -> falls back at render time");
    }

    #[test]
    fn generated_harness_mirrors_versions_and_has_adapter_todos() {
        let root = tempfile::tempdir().unwrap();
        let prog = root.path().join("vault");
        std::fs::create_dir_all(&prog).unwrap();
        write_target(
            &prog,
            "anchor-lang = \"0.29.0\"\nsolana-program = \"1.17.18\"\nsolana-program-test = \"1.17.18\"\nsolana-sdk = \"1.17.18\"\n",
            "my-vault",
        );

        let out = root.path().join("harness");
        emit(&prog, "vault", &out).unwrap();

        let cargo = std::fs::read_to_string(out.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("solana-program-test = \"1.17.18\""), "must mirror program-test: {cargo}");
        assert!(cargo.contains("solana-program = \"1.17.18\""));
        assert!(cargo.contains("my_vault = {"), "path dep uses the lib crate name");
        assert!(cargo.contains("[workspace]"), "standalone crate");

        let main = std::fs::read_to_string(out.join("src/main.rs")).unwrap();
        for needle in ["TODO(1)", "TODO(2)", "TODO(3)", "TODO(4)", "fn build_op", "fn observe"] {
            assert!(main.contains(needle), "generated skeleton missing {needle}");
        }
        // The wire struct must carry the canonical observable fields.
        for field in
            ["total_deposits", "total_borrows", "total_shares", "vault_balance", "user_shares", "user_balance", "price"]
        {
            assert!(main.contains(field), "observable field {field} missing from generated wire type");
        }
    }

    #[test]
    fn warns_when_versions_are_not_mirrored() {
        let root = tempfile::tempdir().unwrap();
        let prog = root.path().join("bare");
        std::fs::create_dir_all(&prog).unwrap();
        write_target(&prog, "", "bare");
        let out = root.path().join("harness");
        emit(&prog, "bare", &out).unwrap();
        let cargo = std::fs::read_to_string(out.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("WARN"), "unmirrored versions must warn: {cargo}");
    }
}
