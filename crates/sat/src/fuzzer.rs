use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::idl;
use crate::ui;

const FUZZER_DIR: &str = "fuzzer";
const DEFAULT_PROGRAM_ID: &str = "11111111111111111111111111111111";

#[derive(Debug, Clone)]
struct FuzzerConfig {
    program_name: String,
    program_lib_name: String,
    crate_name: String,
    program_id: String,
    instructions: Vec<FuzzerInstructionConfig>,
    has_vault: bool,
    has_token: bool,
    has_state_init_flag: bool,
}

#[derive(Debug, Clone)]
struct FuzzerInstructionConfig {
    name: String,
    accounts: Vec<FuzzerAccountConfig>,
}

#[derive(Debug, Clone)]
struct FuzzerAccountConfig {
    name: String,
    is_mut: bool,
    is_signer: bool,
}

pub fn init() -> Result<()> {
    ui::print_banner();
    ui::print_section_header("Fuzzer Initialization");

    let config = match idl::find_idl_in_workspace().ok().and_then(|p| idl::parse_idl(&p).ok()) {
        Some(idl) => config_from_idl(idl),
        None => {
            ui::print_warning("No Anchor IDL found. Generating fuzzer with default configuration...");
            default_config()
        }
    };

    generate_fuzzer(&config)?;
    update_workspace_cargo()?;

    ui::print_success("Fuzzer crate generated successfully.");
    ui::print_notice(&format!("Fuzzer created at: {FUZZER_DIR}/"));
    ui::print_notice("Next steps:");
    println!("  1. cd {FUZZER_DIR}");
    println!("  2. Review src/lib.rs account factories and invariant hooks");
    println!("  3. Run: sat fuzz run");
    println!();
    Ok(())
}

fn config_from_idl(idl: idl::IdlJson) -> FuzzerConfig {
    let program_name = idl.name.clone();
    let program_lib_name = program_name.replace('-', "_");
    let crate_name = format!("fuzzer_{}", sanitize_ident(&program_name));
    let program_id =
        idl.metadata.and_then(|metadata| metadata.address).unwrap_or_else(|| DEFAULT_PROGRAM_ID.to_string());

    let instructions = idl
        .instructions
        .iter()
        .map(|ix| FuzzerInstructionConfig {
            name: ix.name.clone(),
            accounts: ix
                .accounts
                .iter()
                .map(|account| FuzzerAccountConfig {
                    name: account.name.clone(),
                    is_mut: account.is_mut,
                    is_signer: account.is_signer,
                })
                .collect(),
        })
        .collect::<Vec<_>>();

    let has_vault =
        program_name.contains("vault") || idl.accounts.iter().any(|a| a.name.to_lowercase().contains("vault"));
    let has_token = instructions.iter().any(|ix| {
        ix.accounts.iter().any(|a| a.name.to_lowercase().contains("token") || a.name.to_lowercase().contains("mint"))
    });
    let has_state_init_flag = idl.accounts.iter().any(|a| {
        a.ty.fields.iter().any(|f| {
            let lower = f.name.to_lowercase();
            lower == "is_initialized" || lower == "initialized" || lower == "isinitialized"
        })
    });

    FuzzerConfig {
        program_name,
        program_lib_name,
        crate_name,
        program_id,
        instructions,
        has_vault,
        has_token,
        has_state_init_flag,
    }
}

fn default_config() -> FuzzerConfig {
    FuzzerConfig {
        program_name: "program".to_string(),
        program_lib_name: "program".to_string(),
        crate_name: "fuzzer_program".to_string(),
        program_id: DEFAULT_PROGRAM_ID.to_string(),
        instructions: vec![
            FuzzerInstructionConfig {
                name: "initialize".to_string(),
                accounts: vec![
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: true, is_signer: true },
                    FuzzerAccountConfig { name: "system_program".to_string(), is_mut: false, is_signer: false },
                ],
            },
            FuzzerInstructionConfig {
                name: "update".to_string(),
                accounts: vec![
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: false, is_signer: true },
                ],
            },
            FuzzerInstructionConfig {
                name: "close".to_string(),
                accounts: vec![
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: true, is_signer: true },
                ],
            },
        ],
        has_vault: false,
        has_token: false,
        has_state_init_flag: false,
    }
}

fn generate_fuzzer(config: &FuzzerConfig) -> Result<()> {
    let dir = PathBuf::from(FUZZER_DIR);
    fs::create_dir_all(dir.join("src"))?;
    fs::create_dir_all(dir.join("fuzz_targets"))?;

    fs::write(dir.join("Cargo.toml"), render_cargo_toml(config))?;
    fs::write(dir.join("src").join("lib.rs"), render_lib_rs(config))?;
    fs::write(dir.join("fuzz_targets").join("instruction_fuzz.rs"), render_fuzz_target(config))?;
    Ok(())
}

fn render_cargo_toml(config: &FuzzerConfig) -> String {
    format!(
        r#"[package]
name = "fuzzer-{}"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
{} = {{ path = "../programs/{}", features = ["no-entrypoint"] }}
anchor-lang = "0.29"
solana-program = "4"
solana-program-test = "4"
solana-sdk = "4"
spl-token = "7"
spl-token-2022 = "7"
arbitrary = {{ version = "1", features = ["derive"] }}
rand = "0.8"
libfuzzer-sys = "0.4"
tokio = {{ version = "1", features = ["full"] }}

[[bin]]
name = "instruction_fuzz"
path = "fuzz_targets/instruction_fuzz.rs"
test = false
doc = false
"#,
        sanitize_package_name(&config.program_name),
        config.program_lib_name,
        config.program_lib_name
    )
}

fn render_lib_rs(config: &FuzzerConfig) -> String {
    let invariants = render_invariants(config);
    let checks = render_invariant_checks(config);
    let date = chrono::Local::now().format("%Y-%m-%d");
    let ix_list = config.instruction_names().join(", ");

    format!(
        r#"// Auto-generated by `sat fuzz init` — {date}
// Program: {prog}
// Instructions: {ix_list}

use std::str::FromStr;

use arbitrary::Arbitrary;
use solana_program_test::{{processor, BanksClient, ProgramTest}};
use solana_sdk::{{
    account::Account,
    instruction::{{AccountMeta, Instruction}},
    pubkey::Pubkey,
    signature::Signer,
    signer::keypair::Keypair,
    transaction::Transaction,
}};

#[derive(Arbitrary, Debug, Clone)]
pub enum FuzzInstruction {{
{enum_variants}}}

impl FuzzInstruction {{
    pub fn as_ix_name(&self) -> &'static str {{
        match self {{
{ix_name_match}
        }}
    }}

    pub fn to_instruction(&self, payer: &Pubkey) -> Instruction {{
        match self {{
{to_ix_match}
        }}
    }}

    fn account_metas(&self, payer: &Pubkey) -> Vec<AccountMeta> {{
        match self {{
{account_meta_match}
        }}
    }}
}}

pub fn program_id() -> Pubkey {{
    Pubkey::from_str("{program_id}").expect("generated program id must be a valid pubkey")
}}

pub fn fuzz_account_pubkey(name: &str) -> Pubkey {{
    well_known_account(name).unwrap_or_else(|| {{
        Pubkey::find_program_address(&[b"sat-fuzz", name.as_bytes()], &program_id()).0
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

pub fn set_up_program_test() -> ProgramTest {{
    let mut program_test = ProgramTest::new("{lib_name}", program_id(), processor!({lib_name}::entry));
    seed_fuzz_accounts(&mut program_test);
    program_test
}}

pub fn seed_fuzz_accounts(program_test: &mut ProgramTest) {{
{seed_accounts}
}}

pub async fn snapshot_instruction_accounts(
    banks_client: &mut BanksClient,
    instruction: &Instruction,
) -> Vec<(Pubkey, Account)> {{
    let mut snapshot = Vec::new();
    for meta in &instruction.accounts {{
        if let Ok(Some(account)) = banks_client.get_account(meta.pubkey).await {{
            snapshot.push((meta.pubkey, account));
        }}
    }}
    snapshot
}}

{invariants}

pub fn check_invariants(
    _banks_client: &mut BanksClient,
    _payer: &Keypair,
    before_snapshot: &[(Pubkey, Account)],
    after_snapshot: &[(Pubkey, Account)],
    trace: &[FuzzInstruction],
) -> Result<(), Vec<String>> {{
    let mut violations = Vec::new();
    if trace.is_empty() {{
        return Ok(());
    }}
{checks}
    if violations.is_empty() {{ Ok(()) }} else {{ Err(violations) }}
}}
"#,
        date = date,
        prog = config.program_name,
        ix_list = ix_list,
        enum_variants = render_arbitrary_enum_variants(config),
        ix_name_match = render_ix_name_match(config),
        to_ix_match = render_to_instruction_match(config),
        account_meta_match = render_account_meta_match(config),
        program_id = config.program_id,
        lib_name = config.program_lib_name,
        seed_accounts = render_seed_accounts(config),
        invariants = invariants,
        checks = checks,
    )
}

fn render_arbitrary_enum_variants(config: &FuzzerConfig) -> String {
    config.instructions.iter().map(|ix| format!("    {}(Vec<u8>),\n", to_pascal_case(&ix.name))).collect()
}

fn render_ix_name_match(config: &FuzzerConfig) -> String {
    config
        .instructions
        .iter()
        .map(|ix| format!("            FuzzInstruction::{}(_) => \"{}\",\n", to_pascal_case(&ix.name), ix.name))
        .collect()
}

fn render_to_instruction_match(config: &FuzzerConfig) -> String {
    config
        .instructions
        .iter()
        .map(|ix| {
            let discriminator = instruction_discriminator(&ix.name);
            format!(
                "            FuzzInstruction::{}(data) => {{\n                let mut payload = vec![{}];\n                payload.extend(data.iter().copied());\n                Instruction::new_with_bytes(program_id(), &payload, self.account_metas(payer))\n            }},\n",
                to_pascal_case(&ix.name),
                discriminator.iter().map(|byte| byte.to_string()).collect::<Vec<_>>().join(", ")
            )
        })
        .collect()
}

fn render_account_meta_match(config: &FuzzerConfig) -> String {
    config
        .instructions
        .iter()
        .map(|ix| {
            let metas = ix
                .accounts
                .iter()
                .map(|account| {
                    let constructor = if account.is_mut { "AccountMeta::new" } else { "AccountMeta::new_readonly" };
                    let pubkey_expr = if account.is_signer {
                        "*payer".to_string()
                    } else {
                        format!("fuzz_account_pubkey(\"{}\")", account.name)
                    };
                    format!("                {constructor}({pubkey_expr}, {}),\n", account.is_signer)
                })
                .collect::<String>();

            format!("            FuzzInstruction::{}(_) => vec![\n{}            ],\n", to_pascal_case(&ix.name), metas)
        })
        .collect()
}

fn render_seed_accounts(config: &FuzzerConfig) -> String {
    let mut accounts = BTreeMap::new();
    for ix in &config.instructions {
        for account in &ix.accounts {
            if account.is_signer || is_well_known_account_name(&account.name) {
                continue;
            }
            accounts.insert(account.name.clone(), account.is_mut);
        }
    }

    if accounts.is_empty() {
        return "    // No non-signer IDL accounts found to seed.\n".to_string();
    }

    accounts
        .keys()
        .map(|name| {
            format!(
                "    program_test.add_account(\n        fuzz_account_pubkey(\"{name}\"),\n        Account {{ lamports: 10_000_000, data: vec![0; 1024], owner: program_id(), executable: false, rent_epoch: 0 }},\n    );\n"
            )
        })
        .collect()
}

fn render_invariants(config: &FuzzerConfig) -> String {
    let mut out = String::from("// Security Invariants\n\n");

    if config.has_token {
        out.push_str(
            "/// Token Supply Preservation\npub fn check_token_supply(before: u64, after: u64) -> Option<String> {\n    if before != after { Some(format!(\"Token supply changed: {before} -> {after}\")) } else { None }\n}\n",
        );
    }

    if config.has_vault {
        out.push_str(
            "/// Vault Balance Consistency\npub fn check_vault_consistency(vault: u64, total_deposits: u64) -> Option<String> {\n    if vault < total_deposits { Some(format!(\"Vault underfunded: vault={vault} < deposits={total_deposits}\")) } else { None }\n}\n",
        );
    }

    out.push_str(
        "/// Account Drain Detection\npub fn check_unexpected_account_drain(before: &[(Pubkey, Account)], after: &[(Pubkey, Account)]) -> Vec<String> {\n    let mut violations = Vec::new();\n    for ((pk_before, acct_before), (pk_after, acct_after)) in before.iter().zip(after.iter()) {\n        if pk_before != pk_after { continue; }\n        if acct_before.lamports > 0 && acct_after.lamports == 0 && !acct_before.data.is_empty() {\n            violations.push(format!(\"Account {pk_before} was drained to zero lamports\"));\n        }\n    }\n    violations\n}\n\n",
    );

    out.push_str(
        "/// Authority Immutability\npub fn check_authority_immutability(before: &[(Pubkey, Account)], after: &[(Pubkey, Account)]) -> Vec<String> {\n    let mut violations = Vec::new();\n    for ((pk_before, acct_before), (pk_after, acct_after)) in before.iter().zip(after.iter()) {\n        if pk_before != pk_after { continue; }\n        if acct_before.owner != acct_after.owner {\n            violations.push(format!(\"Account {pk_before} owner changed from {} to {}\", acct_before.owner, acct_after.owner));\n        }\n    }\n    violations\n}\n",
    );

    if config.has_state_init_flag {
        out.push_str(
            "/// State Integrity\npub fn check_state_integrity(before: &[(Pubkey, Account)], after: &[(Pubkey, Account)]) -> Vec<String> {\n    let mut violations = Vec::new();\n    for ((pk_before, acct_before), (pk_after, acct_after)) in before.iter().zip(after.iter()) {\n        if pk_before != pk_after || acct_before.data.len() < 9 || acct_after.data.len() < 9 { continue; }\n        if acct_before.data[..8] != acct_after.data[..8] { continue; }\n        let was_init = acct_before.data[8] != 0;\n        let is_init = acct_after.data[8] != 0;\n        if was_init && !is_init { violations.push(format!(\"Account {pk_before} was de-initialized (true -> false)\")); }\n    }\n    violations\n}\n",
        );
    }

    out
}

fn render_invariant_checks(config: &FuzzerConfig) -> String {
    let mut out = String::new();

    if config.has_token {
        out.push_str("    // Token supply preservation: wire token account decoding here once account factories are program-specific.\n");
    }
    if config.has_vault {
        out.push_str("    // Vault balance consistency: decode vault/user deposit accounts here once layouts are program-specific.\n");
    }
    out.push_str("    violations.extend(check_unexpected_account_drain(before_snapshot, after_snapshot));\n");
    out.push_str("    violations.extend(check_authority_immutability(before_snapshot, after_snapshot));\n");
    if config.has_state_init_flag {
        out.push_str("    violations.extend(check_state_integrity(before_snapshot, after_snapshot));\n");
    }

    out
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

fn sanitize_ident(name: &str) -> String {
    let ident = name.chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' }).collect::<String>();
    ident.trim_matches('_').to_string()
}

fn sanitize_package_name(name: &str) -> String {
    name.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '-' { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn instruction_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{name}");
    let hash = Sha256::digest(preimage.as_bytes());
    let mut discriminator = [0_u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}

fn is_well_known_account_name(name: &str) -> bool {
    matches!(
        name,
        "system_program"
            | "token_program"
            | "token_2022_program"
            | "token2022_program"
            | "rent"
            | "clock"
            | "instructions"
    )
}

trait FuzzerConfigExt {
    fn instruction_names(&self) -> Vec<String>;
}

impl FuzzerConfigExt for FuzzerConfig {
    fn instruction_names(&self) -> Vec<String> {
        self.instructions.iter().map(|ix| ix.name.clone()).collect()
    }
}

fn update_workspace_cargo() -> Result<()> {
    let workspace_toml = PathBuf::from("Cargo.toml");
    if !workspace_toml.exists() {
        return Ok(());
    }
    if fs::read_to_string(&workspace_toml)?.contains("\"fuzzer\"") {
        return Ok(());
    }
    let content = fs::read_to_string(&workspace_toml)?;
    let mut new_content = String::new();
    for line in content.lines() {
        new_content.push_str(line);
        new_content.push('\n');
        if line.trim() == "members = [" {
            new_content.push_str("    \"fuzzer\",\n");
        }
    }
    if new_content != content {
        fs::write(&workspace_toml, &new_content)?;
        ui::print_notice("Added fuzzer to workspace members in Cargo.toml");
    }
    Ok(())
}

fn render_fuzz_target(config: &FuzzerConfig) -> String {
    let date = chrono::Local::now().format("%Y-%m-%d");
    format!(
        r#"// Auto-generated fuzz target for {prog} — {date}

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use {crate_name}::{{check_invariants, set_up_program_test, snapshot_instruction_accounts, FuzzInstruction}};

use solana_sdk::{{signature::Signer, transaction::Transaction}};

#[derive(Arbitrary, Debug)]
struct FuzzInput {{
    instructions: Vec<FuzzInstruction>,
}}

fuzz_target!(|input: FuzzInput| {{
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {{
        let program_test = set_up_program_test();
        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        let mut trace = Vec::new();
        for ix in &input.instructions {{
            let instruction = ix.to_instruction(&payer.pubkey());
            let before = snapshot_instruction_accounts(&mut banks_client, &instruction).await;

            let mut transaction = Transaction::new_with_payer(&[instruction.clone()], Some(&payer.pubkey()));
            transaction.sign(&[&payer], recent_blockhash);

            if banks_client.process_transaction(transaction).await.is_err() {{
                break;
            }}

            let after = snapshot_instruction_accounts(&mut banks_client, &instruction).await;
            trace.push(ix.clone());

            if let Err(violations) = check_invariants(&mut banks_client, &payer, &before, &after, &trace) {{
                panic!("Invariant violation:\n{{}}", violations.join("\n"));
            }}
        }}
    }});
}});
"#,
        prog = config.program_name,
        date = date,
        crate_name = config.crate_name,
    )
}

// ── Run ───────────────────────────────────────────────────────────────────────

pub fn run() -> Result<()> {
    ui::print_banner();
    ui::print_section_header("Fuzz Execution");

    let fuzzer_dir = PathBuf::from(FUZZER_DIR);
    if !fuzzer_dir.join("Cargo.toml").exists() {
        ui::print_warning("No fuzzer crate found. Run `sat fuzz init` first.");
        return Ok(());
    }

    ui::print_notice("Building fuzzer...");
    let build_status = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(&fuzzer_dir)
        .status()
        .context("Failed to build fuzzer crate")?;

    if !build_status.success() {
        ui::print_warning("Fuzzer build failed. Review compilation errors above.");
        ui::print_notice(
            "The generated template now includes discriminators, IDL account metas, seeded accounts, and snapshots.",
        );
        ui::print_notice("You still need program-specific account factories for rich Anchor account layouts.");
        return Ok(());
    }

    ui::print_success("Fuzzer built successfully.");
    println!();
    ui::print_notice("Running fuzzer (Ctrl+C to stop)...");
    println!();

    let status = Command::new("cargo")
        .args(["fuzz", "run", "instruction_fuzz", "--", "-max_total_time=60"])
        .current_dir(&fuzzer_dir)
        .status()
        .context("Failed to run fuzzer")?;

    if status.success() {
        ui::print_success("Fuzz run completed without crashes.");
    } else {
        ui::print_warning("Fuzz run exited with errors. Check output for crash details.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_is_prepended_to_generated_instruction_data() {
        let config = default_config();
        let rendered = render_to_instruction_match(&config);
        let discriminator =
            instruction_discriminator("initialize").iter().map(|byte| byte.to_string()).collect::<Vec<_>>().join(", ");

        assert!(rendered.contains(&format!("let mut payload = vec![{discriminator}]")));
        assert!(rendered.contains("payload.extend(data.iter().copied())"));
    }

    #[test]
    fn generated_fuzzer_uses_snapshots_for_invariants() {
        let config = default_config();
        let target = render_fuzz_target(&config);

        assert!(target.contains("let before = snapshot_instruction_accounts"));
        assert!(target.contains("let after = snapshot_instruction_accounts"));
        assert!(target.contains("check_invariants(&mut banks_client, &payer, &before, &after, &trace)"));
    }
}
