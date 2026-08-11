use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::fuzzer_layout;
use crate::fuzzer_seeds;
use crate::fuzzer_token2022;
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
    /// Raw IDL account type names (e.g. `VaultState`); used to pick the
    /// generated `accounts::build_*` factory for each seeded account.
    account_types: Vec<String>,
    has_vault: bool,
    has_token: bool,
    has_token_2022: bool,
    has_state_init_flag: bool,
}

#[derive(Debug, Clone)]
struct FuzzerInstructionConfig {
    name: String,
    accounts: Vec<FuzzerAccountConfig>,
    args: Vec<FuzzerArgConfig>,
}

#[derive(Debug, Clone)]
struct FuzzerAccountConfig {
    name: String,
    is_mut: bool,
    is_signer: bool,
    /// True when the IDL declares a `pda` (seeds) block for this account on
    /// this instruction; drives `pda_<ix>_<acct>` address resolution.
    pda: bool,
}

/// A single instruction argument lifted from the IDL.
///
/// Design decision (typed args): the generated `FuzzInstruction` variant shape is driven
/// by these args:
/// - no args → `Name(Vec<u8>)` — payload stays raw/fuzzable (unchanged from before);
/// - every arg supported → `Name { field: ty, ... }` — fields in IDL order;
/// - at least one `Unsupported` arg → `Name { raw: Vec<u8> }` fallback, plus a generated
///   comment listing the skipped args. The fallback keeps the variant fuzzable (raw bytes)
///   instead of emitting a variant that cannot compile.
#[derive(Debug, Clone)]
struct FuzzerArgConfig {
    name: String,
    ty: FuzzerArgType,
}

/// The subset of Anchor IDL scalar types the generated fuzzer can borsh-serialize without
/// the program's own types.
///
/// IDL mapping: string values map directly (`"u64"` → `U64`, `"u32"` → `U32`, `"u16"`,
/// `"u8"`, `"i64"`, `"i32"`, `"bool"`); `"publicKey"` → `Pubkey`; `"string"` → `String`.
/// Everything else (objects like `{"defined": ...}`, `{"vec": ...}`, `{"option": ...}`, or
/// unknown scalars) → `Unsupported`.
///
/// Note: `Pubkey` args are rendered as `[u8; 32]` variant fields, not `Pubkey`, because
/// solana-sdk 4.x does not implement `arbitrary::Arbitrary` for `Pubkey` and the generated
/// enum derives `Arbitrary`. The serialized bytes are identical (`Pubkey::to_bytes()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FuzzerArgType {
    U64,
    U32,
    U16,
    U8,
    I64,
    I32,
    Bool,
    Pubkey,
    String,
    Unsupported,
}

impl FuzzerArgType {
    /// The Rust type used for this arg in a generated typed variant field.
    ///
    /// `Pubkey` maps to `[u8; 32]` because solana-sdk 4.x has no `arbitrary::Arbitrary` impl
    /// for `Pubkey` (the generated enum derives `Arbitrary`); `[u8; 32]` serializes to the
    /// same 32 bytes as `Pubkey::to_bytes()`.
    fn rust_type(self) -> &'static str {
        match self {
            FuzzerArgType::U64 => "u64",
            FuzzerArgType::U32 => "u32",
            FuzzerArgType::U16 => "u16",
            FuzzerArgType::U8 => "u8",
            FuzzerArgType::I64 => "i64",
            FuzzerArgType::I32 => "i32",
            FuzzerArgType::Bool => "bool",
            FuzzerArgType::Pubkey => "[u8; 32]",
            FuzzerArgType::String => "String",
            FuzzerArgType::Unsupported => unreachable!("Unsupported args render as the raw fallback shape"),
        }
    }
}

pub fn init() -> Result<()> {
    ui::print_banner();
    ui::print_section_header("Fuzzer Initialization");

    let (mut config, layout, pda_setup, signer_info) =
        match idl::find_idl_in_workspace().ok().and_then(|p| idl::parse_idl(&p).ok()) {
            Some(idl) => {
                let layout = fuzzer_layout::render_account_factories(&idl);
                let pda_setup = fuzzer_seeds::render_pda_setup(&idl);
                let signer_info = fuzzer_seeds::render_signer_info(&idl);
                (config_from_idl(idl), layout, pda_setup, signer_info)
            }
            None => {
                ui::print_warning("No Anchor IDL found. Generating fuzzer with default configuration...");
                let empty_idl = idl::IdlJson {
                    version: "0.1.0".to_string(),
                    name: "program".to_string(),
                    instructions: vec![],
                    accounts: vec![],
                    types: vec![],
                    metadata: None,
                };
                let layout = fuzzer_layout::render_account_factories(&empty_idl);
                let pda_setup = fuzzer_seeds::render_pda_setup(&empty_idl);
                let signer_info = fuzzer_seeds::render_signer_info(&empty_idl);
                (default_config(), layout, pda_setup, signer_info)
            }
        };

    // Token-2022 detection: OR in the target program's Cargo.toml (the same
    // file version mirroring reads); `config_from_idl` already applied the
    // IDL account-name fallback.
    let program_toml = PathBuf::from("programs").join(&config.program_lib_name).join("Cargo.toml");
    if program_has_token_2022(&program_toml) {
        config.has_token_2022 = true;
    }

    generate_fuzzer(&config, &layout, &pda_setup, &signer_info, &program_toml)?;
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
                    pda: account.pda.is_some(),
                })
                .collect(),
            args: ix
                .args
                .iter()
                .map(|arg| FuzzerArgConfig { name: sanitize_field_name(&arg.name), ty: fuzzer_arg_type(&arg.ty) })
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
    // IDL-name fallback for token-2022: any instruction account name containing
    // "2022" (covers `token_2022_program` / `token2022_program`). `init()` ORs
    // in the primary signal (the target program's Cargo.toml dependency).
    let has_token_2022 =
        instructions.iter().any(|ix| ix.accounts.iter().any(|account| account.name.to_lowercase().contains("2022")));

    FuzzerConfig {
        program_name,
        program_lib_name,
        crate_name,
        program_id,
        instructions,
        account_types: idl.accounts.iter().map(|account| account.name.clone()).collect(),
        has_vault,
        has_token,
        has_token_2022,
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
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false, pda: false },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: true, is_signer: true, pda: false },
                    FuzzerAccountConfig {
                        name: "system_program".to_string(),
                        is_mut: false,
                        is_signer: false,
                        pda: false,
                    },
                ],
                args: vec![],
            },
            FuzzerInstructionConfig {
                name: "update".to_string(),
                accounts: vec![
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false, pda: false },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: false, is_signer: true, pda: false },
                ],
                args: vec![],
            },
            FuzzerInstructionConfig {
                name: "close".to_string(),
                accounts: vec![
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false, pda: false },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: true, is_signer: true, pda: false },
                ],
                args: vec![],
            },
        ],
        account_types: vec![],
        has_vault: false,
        has_token: false,
        has_token_2022: false,
        has_state_init_flag: false,
    }
}

/// Maps an Anchor IDL arg type (`serde_json::Value`) to the fuzzable subset. String values
/// map directly; `"publicKey"` → `Pubkey`, `"string"` → `String`; objects and unknown
/// scalars → `Unsupported` (see `FuzzerArgType`).
fn fuzzer_arg_type(ty: &serde_json::Value) -> FuzzerArgType {
    match ty.as_str() {
        Some("u64") => FuzzerArgType::U64,
        Some("u32") => FuzzerArgType::U32,
        Some("u16") => FuzzerArgType::U16,
        Some("u8") => FuzzerArgType::U8,
        Some("i64") => FuzzerArgType::I64,
        Some("i32") => FuzzerArgType::I32,
        Some("bool") => FuzzerArgType::Bool,
        Some("publicKey") => FuzzerArgType::Pubkey,
        Some("string") => FuzzerArgType::String,
        _ => FuzzerArgType::Unsupported,
    }
}

/// The three variant shapes a generated `FuzzInstruction` variant can take
/// (see `FuzzerArgConfig` for the design decision).
enum VariantShape<'a> {
    /// `Name(Vec<u8>)` — the instruction has no IDL args.
    RawTuple,
    /// `Name { field: ty, ... }` — every IDL arg maps to a supported scalar.
    Typed(&'a [FuzzerArgConfig]),
    /// `Name { raw: Vec<u8> }` — at least one arg was `Unsupported`.
    RawFallback,
}

fn variant_shape(ix: &FuzzerInstructionConfig) -> VariantShape<'_> {
    if ix.args.is_empty() {
        VariantShape::RawTuple
    } else if ix.args.iter().all(|arg| arg.ty != FuzzerArgType::Unsupported) {
        VariantShape::Typed(&ix.args)
    } else {
        VariantShape::RawFallback
    }
}

/// Match pattern used by `as_ix_name`/`account_metas` for this instruction's variant shape.
/// The leading space in the struct pattern keeps the rendered form `Name { .. }`.
fn variant_match_pattern(ix: &FuzzerInstructionConfig) -> &'static str {
    match variant_shape(ix) {
        VariantShape::RawTuple => "(_)",
        VariantShape::Typed(_) | VariantShape::RawFallback => " { .. }",
    }
}

/// Comma-joined names of the args skipped by the raw fallback shape.
fn unsupported_arg_names(ix: &FuzzerInstructionConfig) -> String {
    ix.args
        .iter()
        .filter(|arg| arg.ty == FuzzerArgType::Unsupported)
        .map(|arg| arg.name.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

fn generate_fuzzer(
    config: &FuzzerConfig,
    layout: &str,
    pda_setup: &str,
    signer_info: &str,
    program_toml: &Path,
) -> Result<()> {
    let dir = PathBuf::from(FUZZER_DIR);
    fs::create_dir_all(dir.join("src"))?;
    fs::create_dir_all(dir.join("fuzz_targets"))?;

    fs::write(dir.join("Cargo.toml"), render_cargo_toml(config, program_toml))?;
    fs::create_dir_all(dir.join("tests"))?;
    fs::write(dir.join("src").join("lib.rs"), render_lib_rs(config, layout, pda_setup, signer_info))?;
    fs::write(dir.join("fuzz_targets").join("instruction_fuzz.rs"), render_fuzz_target(config))?;
    fs::write(dir.join("tests").join("adversarial.rs"), render_adversarial_test(config))?;
    fs::write(dir.join("README.md"), render_readme(config))?;
    Ok(())
}

/// Dependency keys whose versions are mirrored from the target program's
/// Cargo.toml into the generated fuzzer crate.
const MIRRORED_DEPENDENCIES: &[&str] =
    &["anchor-lang", "solana-program", "solana-sdk", "solana-program-test", "spl-token", "spl-token-2022"];

/// Reads the target program's Cargo.toml (`programs/<lib_name>/Cargo.toml`)
/// and extracts version strings for [`MIRRORED_DEPENDENCIES`], checking both
/// `[dependencies]` and `[workspace.dependencies]` sections. Plain string
/// versions (`"0.30.1"`) and `{ version = "..." }` tables are supported.
/// A missing/unparseable file yields an empty map; callers fall back to the
/// default versions.
fn program_dependency_versions(path: &Path) -> HashMap<String, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return HashMap::new(),
    };
    let table: toml::Value = match content.parse() {
        Ok(table) => table,
        Err(_) => return HashMap::new(),
    };

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

/// True when the target program's Cargo.toml — the same file version mirroring
/// reads — declares `spl-token-2022` or `token-2022` in `[dependencies]` or
/// `[workspace.dependencies]` (keys compared case-insensitively). A
/// missing/unparseable file yields `false`; callers fall back to IDL
/// account-name detection.
fn program_has_token_2022(path: &Path) -> bool {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return false,
    };
    let table: toml::Value = match content.parse() {
        Ok(table) => table,
        Err(_) => return false,
    };
    let sections = [
        table.get("dependencies").and_then(toml::Value::as_table),
        table.get("workspace").and_then(|ws| ws.get("dependencies")).and_then(toml::Value::as_table),
    ];
    sections
        .into_iter()
        .flatten()
        .any(|deps| deps.keys().any(|key| matches!(key.to_ascii_lowercase().as_str(), "spl-token-2022" | "token-2022")))
}

fn render_cargo_toml(config: &FuzzerConfig, program_toml: &Path) -> String {
    let versions = program_dependency_versions(program_toml);
    let warn = if MIRRORED_DEPENDENCIES.iter().all(|key| versions.contains_key(*key)) {
        String::new()
    } else {
        format!(
            "# WARN: could not read {} — using default versions; mirror the target program's Cargo.toml versions if the build fails\n",
            program_toml.display()
        )
    };
    let anchor_lang = versions.get("anchor-lang").map(String::as_str).unwrap_or("0.29");
    let solana_program = versions.get("solana-program").map(String::as_str).unwrap_or("4");
    let solana_program_test = versions.get("solana-program-test").map(String::as_str).unwrap_or("4");
    let solana_sdk = versions.get("solana-sdk").map(String::as_str).unwrap_or("4");
    let spl_token = versions.get("spl-token").map(String::as_str).unwrap_or("7");
    let spl_token_2022 = versions.get("spl-token-2022").map(String::as_str).unwrap_or("7");

    format!(
        r#"[package]
name = "fuzzer-{package_name}"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
{warn}{lib} = {{ path = "../programs/{lib}", features = ["no-entrypoint"] }}
anchor-lang = "{anchor_lang}"
solana-program = "{solana_program}"
solana-program-test = "{solana_program_test}"
solana-sdk = "{solana_sdk}"
spl-token = "{spl_token}"
spl-token-2022 = "{spl_token_2022}"
arbitrary = {{ version = "1", features = ["derive"] }}
borsh = "1"
rand = "0.8"
libfuzzer-sys = "0.4"
tokio = {{ version = "1", features = ["full"] }}

[[bin]]
name = "instruction_fuzz"
path = "fuzz_targets/instruction_fuzz.rs"
test = false
doc = false
"#,
        package_name = sanitize_package_name(&config.program_name),
        lib = config.program_lib_name,
        warn = warn,
        anchor_lang = anchor_lang,
        solana_program = solana_program,
        solana_program_test = solana_program_test,
        solana_sdk = solana_sdk,
        spl_token = spl_token,
        spl_token_2022 = spl_token_2022,
    )
}

fn render_lib_rs(config: &FuzzerConfig, layout: &str, pda_setup: &str, signer_info: &str) -> String {
    let invariants = render_invariants(config);
    let checks = render_invariant_checks(config);
    let date = chrono::Local::now().format("%Y-%m-%d");
    let ix_list = config.instruction_names().join(", ");
    let token_account_import = if has_seeded_token_accounts(config) && !config.has_token_2022 {
        // In token-2022 mode token accounts are seeded by the `token2022_accounts`
        // module, so the `spl_token` account types are not referenced here.
        "use spl_token::state::{Account as SplTokenAccount, AccountState};\n"
    } else {
        ""
    };
    // Token-2022 extension factories: a complete `pub mod` embedded as-is after
    // the layout module when the program is token-2022, nothing otherwise.
    let token_2022_factories =
        if config.has_token_2022 { fuzzer_token2022::render_token_2022_factories() } else { String::new() };

    format!(
        r#"// Auto-generated by `sat fuzz init` — {date}
// Program: {prog}
// Instructions: {ix_list}

use std::str::FromStr;

use arbitrary::Arbitrary;
use solana_program::program_option::COption;
use solana_program_test::{{processor, BanksClient, ProgramTest}};
use solana_sdk::{{
    account::Account,
    instruction::{{AccountMeta, Instruction}},
    pubkey::Pubkey,
    signature::Signer,
    signer::keypair::Keypair,
    transaction::Transaction,
}};
use spl_token::state::Mint as SplTokenMint;
{token_account_import}
{layout}
{token_2022_factories}
{pda_setup}

{signer_info}
#[derive(Arbitrary, Debug, Clone)]
pub enum FuzzInstruction {{
{enum_variants}}}

impl FuzzInstruction {{
    pub fn as_ix_name(&self) -> &'static str {{
        match self {{
{ix_name_match}
        }}
    }}

    /// Builds the instruction: 8-byte Anchor discriminator + borsh args, with
    /// account metas resolved by `account_metas` (signer ordinals: 0 = payer).
    pub fn to_instruction(&self, payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Result<Instruction, borsh::io::Error> {{
        match self {{
{to_ix_match}
        }}
    }}

    /// Resolves each IDL account to a pubkey: signers → `signer_pubkeys[<ordinal>]`
    /// (0 = payer), PDA accounts → their IDL-seeded `pda_<ix>_<acct>` address,
    /// everything else → `account_address` (well-known canonicals, else the
    /// deterministic sat-fuzz PDA).
    #[allow(unused_variables)] // `payer`/`signer_pubkeys` unused when every account is a signer or well-known
    fn account_metas(&self, payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Vec<AccountMeta> {{
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

pub fn set_up_program_test() -> (ProgramTest, Keypair, Vec<Keypair>) {{
    let mut program_test = ProgramTest::new("{lib_name}", program_id(), processor!({lib_name}::entry));
    let payer = Keypair::new();
    program_test.add_account(
        payer.pubkey(),
        Account {{ lamports: 1_000_000_000_000, data: vec![], owner: solana_program::system_program::ID, executable: false, rent_epoch: 0 }},
    );
    let keypairs: Vec<Keypair> = (0..MAX_SIGNERS.saturating_sub(1)).map(|_| Keypair::new()).collect();
    for keypair in &keypairs {{
        program_test.add_account(
            keypair.pubkey(),
            Account {{ lamports: 1_000_000_000_000, data: vec![], owner: solana_program::system_program::ID, executable: false, rent_epoch: 0 }},
        );
    }}
    let signer_pubkeys: Vec<Pubkey> =
        std::iter::once(payer.pubkey()).chain(keypairs.iter().map(|k| k.pubkey())).collect();
    seed_fuzz_accounts(&mut program_test, &payer.pubkey(), &signer_pubkeys);
    (program_test, payer, keypairs)
}}

pub fn seed_fuzz_accounts(program_test: &mut ProgramTest, payer: &Pubkey, signer_pubkeys: &[Pubkey]) {{
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
        token_account_import = token_account_import,
        layout = layout,
        token_2022_factories = token_2022_factories,
        pda_setup = pda_setup,
        signer_info = signer_info,
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
    config
        .instructions
        .iter()
        .map(|ix| {
            let name = to_pascal_case(&ix.name);
            match variant_shape(ix) {
                VariantShape::RawTuple => format!("    {name}(Vec<u8>),\n"),
                VariantShape::Typed(args) => {
                    let fields = args
                        .iter()
                        .map(|arg| format!("{}: {}", arg.name, arg.ty.rust_type()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("    {name} {{ {fields} }},\n")
                }
                VariantShape::RawFallback => format!(
                    "    // Skipped args (Unsupported IDL types, not borsh-serializable without program types): {}\n    {name} {{ raw: Vec<u8> }},\n",
                    unsupported_arg_names(ix)
                ),
            }
        })
        .collect()
}

fn render_ix_name_match(config: &FuzzerConfig) -> String {
    config
        .instructions
        .iter()
        .map(|ix| {
            format!(
                "            FuzzInstruction::{}{} => \"{}\",\n",
                to_pascal_case(&ix.name),
                variant_match_pattern(ix),
                ix.name
            )
        })
        .collect()
}

/// Renders the `to_instruction` match arms.
///
/// Serialization decision: payload = 8-byte discriminator + each arg borsh-serialized
/// independently (`borsh::to_vec` per field, in IDL order). borsh writes primitives
/// field-by-field, which matches Anchor's borsh instruction-arg encoding for these scalar
/// types. Honest-scaffolding caveat: this assumes the program decodes args as plain borsh
/// with no extra framing — `String` is borsh's `Vec<u8>` layout (u32 LE length prefix +
/// UTF-8 bytes) and custom types are skipped (raw fallback). Typed arms use `?`, so the
/// generated `to_instruction` returns `Result<Instruction, borsh::io::Error>`.
fn render_to_instruction_match(config: &FuzzerConfig) -> String {
    config
        .instructions
        .iter()
        .map(|ix| {
            let name = to_pascal_case(&ix.name);
            let discriminator = instruction_discriminator(&ix.name);
            let bytes = discriminator.iter().map(|byte| byte.to_string()).collect::<Vec<_>>().join(", ");
            match variant_shape(ix) {
                VariantShape::RawTuple => format!(
                    "            FuzzInstruction::{name}(data) => {{\n                let mut payload = vec![{bytes}];\n                payload.extend(data.iter().copied());\n                Ok(Instruction::new_with_bytes(program_id(), &payload, self.account_metas(payer, signer_pubkeys)))\n            }},\n"
                ),
                VariantShape::Typed(args) => {
                    let bindings = args.iter().map(|arg| arg.name.clone()).collect::<Vec<_>>().join(", ");
                    let serializers = args.iter().map(render_arg_serializer).collect::<String>();
                    format!(
                        "            // Honest scaffolding: args are borsh-serialized field-by-field, matching Anchor's\n            // borsh encoding of instruction args for these primitives (String = u32 length + UTF-8).\n            FuzzInstruction::{name} {{ {bindings} }} => {{\n                let mut payload = vec![{bytes}];\n{serializers}                Ok(Instruction::new_with_bytes(program_id(), &payload, self.account_metas(payer, signer_pubkeys)))\n            }},\n"
                    )
                }
                VariantShape::RawFallback => format!(
                    "            FuzzInstruction::{name} {{ raw }} => {{\n                let mut payload = vec![{bytes}];\n                payload.extend(raw.iter().copied());\n                Ok(Instruction::new_with_bytes(program_id(), &payload, self.account_metas(payer, signer_pubkeys)))\n            }},\n"
                ),
            }
        })
        .collect()
}

/// Renders one `payload.extend(borsh::to_vec(...)?);` line for a typed arg.
///
/// `?` propagates `borsh::io::Error` into the generated `Result<Instruction, borsh::io::Error>`
/// return; serializing these scalars cannot fail in practice. For `Pubkey` args the binding is
/// `[u8; 32]`, whose borsh bytes are identical to `Pubkey::to_bytes()`.
fn render_arg_serializer(arg: &FuzzerArgConfig) -> String {
    format!("                payload.extend(borsh::to_vec(&{})?);\n", arg.name)
}

/// Renders the `account_metas` match arms. Signer accounts resolve to
/// `signer_pubkeys[<ordinal>]` (ordinal = position among the instruction's
/// `is_signer` accounts, 0 = payer); PDA accounts resolve to their
/// IDL-seeded address via the generated `pda_<ix>_<acct>` helpers (keyed by
/// name so the address matches `seed_fuzz_accounts`); everything else goes
/// through `account_address` (well-known canonicals, else the sat-fuzz PDA).
fn render_account_meta_match(config: &FuzzerConfig) -> String {
    let pda_by_name = pda_helper_names(config);
    config
        .instructions
        .iter()
        .map(|ix| {
            let mut metas = String::new();
            let mut signer_ordinal = 0usize;
            for account in &ix.accounts {
                let constructor = if account.is_mut { "AccountMeta::new" } else { "AccountMeta::new_readonly" };
                let pubkey_expr = if account.is_signer {
                    let ordinal = signer_ordinal;
                    signer_ordinal += 1;
                    format!("signer_pubkeys[{ordinal}]")
                } else {
                    pda_by_name
                        .get(account.name.as_str())
                        .cloned()
                        .unwrap_or_else(|| format!("account_address(\"{}\", payer, signer_pubkeys)", account.name))
                };
                metas.push_str(&format!("                {constructor}({pubkey_expr}, {}),\n", account.is_signer));
            }
            format!(
                "            FuzzInstruction::{}{} => vec![\n{}            ],\n",
                to_pascal_case(&ix.name),
                variant_match_pattern(ix),
                metas
            )
        })
        .collect()
}

/// SPL token account data block for token-named accounts (owner `spl_token::ID`).
/// Minted against the resolved mint; owner is the payer (signer ordinal 0). The
/// `{{mint_address_expr}}` placeholder is substituted in `render_seed_accounts`.
const TOKEN_ACCOUNT_DATA: &str = "{\n                let acc = SplTokenAccount {\n                    mint: {mint_address_expr},\n                    owner: signer_pubkeys[0],\n                    amount: 1_000_000_000_000,\n                    delegate: COption::None,\n                    state: AccountState::Initialized,\n                    is_native: COption::None,\n                    delegated_amount: 0,\n                    close_authority: COption::None,\n                };\n                let mut data = vec![0u8; spl_token::state::Account::LEN];\n                spl_token::state::Account::pack(&acc, &mut data).expect(\"token account pack\");\n                data\n            }";

/// SPL mint data block for mint-named accounts (owner `spl_token::ID`).
const MINT_ACCOUNT_DATA: &str = "{\n                let mint = SplTokenMint {\n                    mint_authority: COption::Some(signer_pubkeys[0]),\n                    supply: 10_000_000_000_000_000,\n                    decimals: 9,\n                    is_initialized: true,\n                    freeze_authority: COption::None,\n                };\n                let mut data = vec![0u8; spl_token::state::Mint::LEN];\n                spl_token::state::Mint::pack(&mint, &mut data).expect(\"mint pack\");\n                data\n            }";

/// Registration block for the shared fuzz mint — emitted only when the IDL
/// declares no mint-named instruction account (then the resolved mint address
/// IS the `fuzz_mint` fallback). When a mint-named account exists, that
/// account's own registration is the mint, so the mint is never registered twice.
const FUZZ_MINT_BLOCK: &str = "    {\n        let mint_address = account_address(\"fuzz_mint\", payer, signer_pubkeys);\n        let mint = SplTokenMint {\n            mint_authority: COption::Some(signer_pubkeys[0]),\n            supply: 10_000_000_000_000_000,\n            decimals: 9,\n            is_initialized: true,\n            freeze_authority: COption::None,\n        };\n        let mut data = vec![0u8; spl_token::state::Mint::LEN];\n        spl_token::state::Mint::pack(&mint, &mut data).expect(\"mint pack\");\n        program_test.add_account(\n            mint_address,\n            Account { lamports: 10_000_000, data, owner: spl_token::ID, executable: false, rent_epoch: 0 },\n        );\n    }\n";

/// First instruction (in IDL order) that declares each PDA account name → the
/// generated `pda_<ix>_<acct>` call computing its IDL-seeded address.
///
/// Keyed by name (not per instruction) so a PDA account is addressed at the
/// same real PDA everywhere: Anchor IDLs often carry `seeds` on a single
/// instruction while later instructions reuse the same PDA account without
/// repeating the `pda` block (e.g. `vaultState` in the vault fixture).
/// `account_address` is *not* used for these names: it falls back to the
/// deterministic sat-fuzz PDA, which would not match the program's own
/// `find_program_address` and would fail every PDA constraint.
fn pda_helper_names(config: &FuzzerConfig) -> HashMap<&str, String> {
    let mut by_name = HashMap::new();
    for ix in &config.instructions {
        for account in &ix.accounts {
            if account.pda {
                by_name.entry(account.name.as_str()).or_insert_with(|| {
                    format!(
                        "pda_{}_{}(payer, &program_id(), signer_pubkeys).0",
                        seed_ident(&ix.name),
                        seed_ident(&account.name)
                    )
                });
            }
        }
    }
    by_name
}

/// Mirrors `fuzzer_seeds::sanitize_ident` so the harness references the exact
/// `seeds_<ix>_<acct>` / `pda_<ix>_<acct>` identifiers the seeds module emits
/// (keyword/digit/empty-name handling must stay in lockstep with that module).
fn seed_ident(name: &str) -> String {
    let mut out: String = name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if out.is_empty() {
        out.push('_');
    } else if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if RUST_KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

/// Name↔type matching heuristic used to pick the `accounts::build_*` factory
/// for a seeded account. An account name resolves to an IDL account type when:
/// 1. they match case-insensitively (`vaultState` ↔ `VaultState`), or
/// 2. they match after stripping `_` separators and casing (camelCase ↔
///    snake_case: `vault_state` ↔ `VaultState`), or
/// 3. either normalized name matches by (1)/(2) after stripping a common
///    suffix (`state`, `account`, `pda`, `info`, `data`).
///
/// Returns the IDL type name of the first match; `None` keeps the 1024-zero
/// placeholder. Honest scaffolding: a heuristic match can be wrong for
/// unusual names — the generated comment on the placeholder path documents it.
fn matching_account_type<'a>(name: &str, account_types: &'a [String]) -> Option<&'a str> {
    let normalized = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
    };
    let stripped = |s: &str| -> String {
        let n = normalized(s);
        for suffix in ["state", "account", "pda", "info", "data"] {
            if let Some(rest) = n.strip_suffix(suffix).filter(|rest| !rest.is_empty()) {
                return rest.to_string();
            }
        }
        n
    };
    let name_norm = normalized(name);
    account_types
        .iter()
        .find(|ty| normalized(ty) == name_norm || stripped(ty) == stripped(&name_norm))
        .map(String::as_str)
}

/// Derives the `build_<snake>` identifier the layout module emits for an IDL
/// account type, mirroring `fuzzer_layout::sanitize_type_name` followed by
/// `fuzzer_layout::to_snake_case` (e.g. `VaultState` → `build_vault_state`).
fn account_build_fn_name(type_name: &str) -> String {
    let mut ident: String = type_name.chars().filter(|ch| ch.is_ascii_alphanumeric()).collect();
    if ident.is_empty() {
        ident.push_str("Type");
    } else if ident.chars().next().is_some_and(|ch| ch.is_ascii_lowercase()) {
        let first = ident.remove(0).to_ascii_uppercase();
        ident.insert(0, first);
    } else if ident.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        ident.insert(0, 'T');
    }
    if RUST_KEYWORDS.contains(&ident.as_str()) {
        ident.push('_');
    }

    let chars: Vec<char> = ident.chars().collect();
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

/// True when at least one non-signer, non-well-known IDL account name contains
/// "token" — i.e. the generated code actually constructs SPL token accounts,
/// so the `SplTokenAccount`/`AccountState` imports are needed.
fn has_seeded_token_accounts(config: &FuzzerConfig) -> bool {
    config.instructions.iter().any(|ix| {
        ix.accounts.iter().any(|account| {
            !account.is_signer
                && !is_well_known_account_name(&account.name)
                && account.name.to_lowercase().contains("token")
        })
    })
}

/// How a seeded account's data is produced; the renderer picks the factory per
/// mode (`spl_token` vs the `token2022_accounts` factories).
enum AccountSeedKind {
    /// Token-named account → SPL token account (owner `spl_token::ID`) or
    /// `token2022_accounts::seed_token_account`.
    Token,
    /// Mint-named account → SPL mint (owner `spl_token::ID`) or
    /// `token2022_accounts::seed_fuzz_mint` (they ARE mints).
    Mint,
    /// Name matches an IDL account type → `accounts::build_<snake>` factory.
    Typed(String),
    /// No match → 1024-zero-byte placeholder.
    Placeholder,
}

/// Seeds real accounts into the `ProgramTest` environment:
///
/// - the fuzz mint at the *resolved mint address*: the first mint-named
///   instruction account (e.g. `mint`) when the program declares one, else
///   `account_address("fuzz_mint", ...)`. The mint is registered ONCE at that
///   address and every generated token account references it, so mint
///   consistency holds (`from.mint == mint`) even for programs that pass
///   their own `mint` account. In token-2022 mode the mint is a Token-2022
///   extension mint via `token2022_accounts::seed_fuzz_mint`; otherwise an
///   SPL `Mint` via `add_account` (owner `spl_token::ID`);
/// - one account per distinct non-signer, non-well-known IDL account name
///   (deduplicated across instructions): PDA accounts at their IDL-seeded
///   address via the generated `pda_<ix>_<acct>` helpers, everything else via
///   `account_address`;
/// - token/mint-named accounts as SPL token accounts / mints (owner
///   `spl_token::ID`); in token-2022 mode they use the `token2022_accounts`
///   factories (`seed_token_account` / `seed_fuzz_mint`, owner
///   `spl_token_2022::ID`);
/// - accounts whose name matches an IDL account type are seeded with
///   discriminator + borsh data (`accounts::build_*`); unknown account types
///   keep the 1024-zero-byte placeholder.
fn render_seed_accounts(config: &FuzzerConfig) -> String {
    let pda_by_name = pda_helper_names(config);
    // Mint consistency: token accounts and the fuzz mint share ONE mint
    // address — the first mint-named instruction account (e.g. `mint`), else
    // the `fuzz_mint` fallback. The address resolves like any seeded account
    // (PDA helpers included), so token accounts and the mint registration
    // always agree.
    let mint_account = config.instructions.iter().flat_map(|ix| ix.accounts.iter()).find(|account| {
        !account.is_signer && !is_well_known_account_name(&account.name) && account.name.to_lowercase().contains("mint")
    });
    let address_for = |account: &FuzzerAccountConfig| -> String {
        match pda_by_name.get(account.name.as_str()) {
            Some(expr) => expr.clone(),
            None => format!("account_address(\"{}\", payer, signer_pubkeys)", account.name),
        }
    };
    let mint_address_expr = match mint_account {
        Some(account) => address_for(account),
        None => "account_address(\"fuzz_mint\", payer, signer_pubkeys)".to_string(),
    };

    // name → (address expr, kind) — one registration per distinct name.
    let mut accounts: BTreeMap<&str, (String, AccountSeedKind)> = BTreeMap::new();
    let mut uses_rng = false;
    for ix in &config.instructions {
        for account in &ix.accounts {
            if account.is_signer || is_well_known_account_name(&account.name) {
                continue;
            }
            let lower = account.name.to_lowercase();
            let kind = if lower.contains("token") {
                AccountSeedKind::Token
            } else if lower.contains("mint") {
                AccountSeedKind::Mint
            } else if let Some(type_name) = matching_account_type(&account.name, &config.account_types) {
                uses_rng = true;
                AccountSeedKind::Typed(account_build_fn_name(type_name))
            } else {
                AccountSeedKind::Placeholder
            };
            accounts.entry(&account.name).or_insert((address_for(account), kind));
        }
    }

    let mut out = String::new();
    if config.has_token_2022 {
        out.push_str("    // Fuzz mint (Token-2022): shared mint for every generated token account,\n");
    } else {
        out.push_str("    // Fuzz mint (SPL): shared mint for every generated token account,\n");
    }
    out.push_str("    // registered ONCE at the resolved mint address: the first mint-named\n");
    out.push_str("    // instruction account (e.g. `mint`), else `account_address(\"fuzz_mint\", ...)`,\n");
    out.push_str("    // so token accounts reference this same address and mint consistency holds\n");
    out.push_str("    // (from.mint == mint) even for programs that pass their own mint account.\n");
    if mint_account.is_none() {
        if config.has_token_2022 {
            out.push_str(&format!(
                "    token2022_accounts::seed_fuzz_mint(program_test, &{mint_address_expr}, payer);\n"
            ));
        } else {
            out.push_str(FUZZ_MINT_BLOCK);
        }
    }
    if accounts.is_empty() {
        out.push_str("    // No other non-signer IDL accounts to seed.\n");
        return out;
    }
    out.push_str("    // One seeded account per distinct name (deduplicated across instructions).\n");
    out.push_str("    // PDA accounts are placed at their IDL-seeded address via the generated\n");
    out.push_str("    // `pda_<ix>_<acct>` helpers; `account_address` would fall back to the sat-fuzz\n");
    out.push_str("    // placeholder PDA for those names. Everything else resolves via `account_address`\n");
    out.push_str("    // (well-known canonicals, signer pubkeys, sat-fuzz PDA). Accounts without a\n");
    out.push_str("    // matching IDL account type keep the 1024-zero-byte placeholder — wire manually.\n");
    if uses_rng {
        out.push_str("    let mut rng = rand::thread_rng();\n");
    }
    for (name, (address_expr, kind)) in &accounts {
        if config.has_token_2022 && matches!(kind, AccountSeedKind::Token | AccountSeedKind::Mint) {
            if matches!(kind, AccountSeedKind::Token) {
                out.push_str(&format!(
                    "    // {name}\n    token2022_accounts::seed_token_account(program_test, &{address_expr}, &{mint_address_expr}, payer, 1_000_000_000_000);\n"
                ));
            } else {
                out.push_str(&format!(
                    "    // {name}\n    token2022_accounts::seed_fuzz_mint(program_test, &{address_expr}, payer);\n"
                ));
            }
            continue;
        }
        let (data_expr, owner_expr) = match kind {
            AccountSeedKind::Token => {
                (TOKEN_ACCOUNT_DATA.replace("{mint_address_expr}", &mint_address_expr), "spl_token::ID".to_string())
            }
            AccountSeedKind::Mint => (MINT_ACCOUNT_DATA.to_string(), "spl_token::ID".to_string()),
            AccountSeedKind::Typed(build_fn) => (format!("accounts::{build_fn}(&mut rng)"), "program_id()".to_string()),
            AccountSeedKind::Placeholder => (
                "/* unknown account type — placeholder data, wire manually */ vec![0; 1024]".to_string(),
                "program_id()".to_string(),
            ),
        };
        out.push_str(&format!(
            "    // {name}\n    program_test.add_account(\n        {address_expr},\n        Account {{\n            lamports: 10_000_000,\n            data: {data_expr},\n            owner: {owner_expr},\n            executable: false,\n            rent_epoch: 0,\n        }},\n    );\n"
        ));
    }
    out
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

/// Rust keywords that would break generated struct fields; suffixed with `_`.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
    "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while",
];

/// Arg names become struct field names verbatim, sanitized if needed (non-alphanumerics →
/// `_` via `sanitize_ident`, Rust keywords → `_` suffix, e.g. an arg named `type` becomes
/// `type_`).
fn sanitize_field_name(name: &str) -> String {
    let ident = sanitize_ident(name);
    if RUST_KEYWORDS.contains(&ident.as_str()) { format!("{ident}_") } else { ident }
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

/// True when `name` is a well-known program/sysvar, matching any casing and
/// separator spelling (`systemProgram`, `token_2022_program`, ...) the same way
/// `fuzzer_seeds::well_known_index` does. Kept here (instead of relying on
/// `account_address`) because seeding must *skip* these accounts entirely —
/// registering data at the canonical system-program address would clobber it.
fn is_well_known_account_name(name: &str) -> bool {
    let normalized: String =
        name.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    matches!(
        normalized.as_str(),
        "systemprogram" | "tokenprogram" | "token2022program" | "rent" | "clock" | "instructions"
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

use solana_sdk::{{pubkey::Pubkey, signature::Signer, signer::keypair::Keypair, transaction::Transaction}};

#[derive(Arbitrary, Debug)]
struct FuzzInput {{
    instructions: Vec<FuzzInstruction>,
}}

fuzz_target!(|input: FuzzInput| {{
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {{
        let (program_test, payer, keypairs) = set_up_program_test();
        let (mut banks_client, _start_payer, recent_blockhash) = program_test.start().await;

        let signer_pubkeys: Vec<Pubkey> =
            std::iter::once(payer.pubkey()).chain(keypairs.iter().map(|k| k.pubkey())).collect();

        let mut trace = Vec::new();
        for ix in &input.instructions {{
            let instruction =
                ix.to_instruction(&payer.pubkey(), &signer_pubkeys)
                    .expect("failed to serialize instruction");
            let before = snapshot_instruction_accounts(&mut banks_client, &instruction).await;

            let mut transaction = Transaction::new_with_payer(&[instruction.clone()], Some(&payer.pubkey()));
            // Extra signatures are harmless; every funded keypair signs.
            let signers: Vec<&Keypair> = std::iter::once(&payer).chain(keypairs.iter()).collect();
            transaction.sign(&signers, recent_blockhash);

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

// ── Adversarial replay harness ────────────────────────────────────────────────

/// Boundary argument value for a fuzzer arg type (typed variants).
fn boundary_arg_value(ty: FuzzerArgType) -> &'static str {
    match ty {
        FuzzerArgType::U64 => "u64::MAX",
        FuzzerArgType::U32 => "u32::MAX",
        FuzzerArgType::U16 => "u16::MAX",
        FuzzerArgType::U8 => "u8::MAX",
        FuzzerArgType::I64 => "i64::MIN",
        FuzzerArgType::I32 => "i32::MIN",
        FuzzerArgType::Bool => "false",
        FuzzerArgType::Pubkey => "[0u8; 32]",
        FuzzerArgType::String => "\"A\".repeat(64)",
        FuzzerArgType::Unsupported => "vec![]",
    }
}

/// Constructs one `FuzzInstruction` variant literal with adversarial values
/// (typed variants get boundary args; raw variants get an empty payload).
fn adversarial_variant_expr(ix: &FuzzerInstructionConfig) -> String {
    let name = to_pascal_case(&ix.name);
    match variant_shape(ix) {
        VariantShape::RawTuple => format!("FuzzInstruction::{name}(Vec::new())"),
        VariantShape::Typed(_) => {
            let fields = ix
                .args
                .iter()
                .map(|a| format!("{}: {}", sanitize_field_name(&a.name), boundary_arg_value(a.ty)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("FuzzInstruction::{name} {{ {fields} }}")
        }
        VariantShape::RawFallback => format!("FuzzInstruction::{name} {{ raw: vec![] }}"),
    }
}

/// The position of the first PDA account in an instruction's account list
/// (None when the instruction has no PDA account).
fn first_pda_position(ix: &FuzzerInstructionConfig) -> Option<usize> {
    ix.accounts.iter().position(|a| a.pda)
}

/// Whether the instruction has a signer account beyond the payer (which fills
/// signer ordinal 0), i.e. a droppable signature exists.
fn has_extra_signer(ix: &FuzzerInstructionConfig) -> bool {
    ix.accounts.iter().filter(|a| a.is_signer).count() > 1
}

/// Renders `fuzzer/tests/adversarial.rs`: deterministic exploit-shaped
/// transactions against the real program in solana-program-test.
///
/// Each test builds a VALID instruction and mutates exactly one property:
/// a dropped signature, wrong-seed PDA, boundary args, a double init, or a
/// cross-instruction account swap. A test that sees the program ACCEPT the
/// mutated transaction prints `SIGNAL` (a reachable path — reachable does NOT
/// mean exploitable; confirm in the source before escalating). A rejection is
/// a control, proving the harness itself works. Invariant violations (the
/// generated `check_invariants` family) panic.
fn render_adversarial_test(config: &FuzzerConfig) -> String {
    let date = chrono::Local::now().format("%Y-%m-%d");
    let tests = config
        .instructions
        .iter()
        .enumerate()
        .map(|(idx, ix)| render_adversarial_instruction_tests(config, ix, idx))
        .collect::<Vec<_>>()
        .join("\n");
    let swap_test = if config.instructions.len() >= 2 { render_swap_test(config) } else { String::new() };
    let double_init_test = if config.has_state_init_flag
        && config.instructions.iter().any(|ix| {
            let lower = ix.name.to_lowercase();
            lower.starts_with("init") || lower.starts_with("initialize")
        }) {
        render_double_init_test(config)
    } else {
        String::new()
    };

    format!(
        r#"// Auto-generated by `sat fuzz init` — {date}
// Program: {prog}
// Adversarial replay harness: deterministic exploit-shaped transactions
// against the real program in solana-program-test.
//
// Run with: cargo test -p {crate_name} --test adversarial
//
// Every test starts from a VALID instruction and mutates exactly one
// property. `SIGNAL` output means the program ACCEPTED the mutated
// transaction — a reachable path. Reachable is not exploitable: confirm
// the missing check in the source before escalating. A rejection prints
// `control` and is expected (the harness works).

use rand::rngs::SmallRng;
use rand::SeedableRng;
use solana_program_test::{{BanksClient, ProgramTest}};
use solana_sdk::{{
    account::Account,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::Signer,
    signer::keypair::Keypair,
    transaction::Transaction,
}};

use {crate_name}::{{
    check_invariants, program_id, seed_fuzz_accounts, set_up_program_test, snapshot_instruction_accounts, FuzzInstruction,
}};

const ADVERSARIAL_SEED: u64 = 0x5EED_BAD5;

fn signer_pubkeys(payer: &Keypair, keypairs: &[Keypair]) -> Vec<Pubkey> {{
    std::iter::once(payer.pubkey()).chain(keypairs.iter().map(|k| k.pubkey())).collect()
}}

fn all_signers<'a>(payer: &'a Keypair, keypairs: &'a [Keypair]) -> Vec<&'a Keypair> {{
    std::iter::once(payer).chain(keypairs.iter()).collect()
}}

async fn replay(
    banks: &mut BanksClient,
    payer: &Keypair,
    ix: &Instruction,
    sign_with: &[&Keypair],
    recent_blockhash: solana_sdk::hash::Hash,
    trace: &FuzzInstruction,
) {{
    let before = snapshot_instruction_accounts(banks, ix).await;
    let mut tx = Transaction::new_with_payer(std::slice::from_ref(ix), Some(&payer.pubkey()));
    tx.sign(sign_with, recent_blockhash);
    match banks.process_transaction(tx).await {{
        Ok(()) => {{
            let after = snapshot_instruction_accounts(banks, ix).await;
            if let Err(violations) = check_invariants(banks, payer, &before, &after, std::slice::from_ref(trace)) {{
                panic!("Invariant violation:\n{{}}", violations.join("\n"));
            }}
            println!("SIGNAL: program executed the mutated transaction");
        }}
        Err(err) => println!("control: program rejected ({{err:?}})"),
    }}
}}
{tests}
{swap_test}
{double_init_test}
"#,
        date = date,
        prog = config.program_name,
        crate_name = config.crate_name,
        tests = tests,
        swap_test = swap_test,
        double_init_test = double_init_test,
    )
}

/// The per-instruction adversarial tests: missing signer, boundary args and
/// wrong-seed PDA (when the instruction has the relevant account shapes).
fn render_adversarial_instruction_tests(config: &FuzzerConfig, ix: &FuzzerInstructionConfig, _idx: usize) -> String {
    let mut out = String::new();

    // 1. Missing signature: flip the first non-payer signer meta to
    //    `is_signer = false` and sign with only the payer. If the program
    //    still executes, its authority path never verified the signature.
    if has_extra_signer(ix) {
        out.push_str(&format!(
            r#"
#[tokio::test]
async fn {name}_missing_signer() {{
    let (mut program_test, payer, keypairs) = set_up_program_test();
    seed_fuzz_accounts(&mut program_test, &payer.pubkey(), &signer_pubkeys(&payer, &keypairs));
    let (mut banks, _start_payer, recent_blockhash) = program_test.start().await;
    let signers = signer_pubkeys(&payer, &keypairs);
    let base = {variant};
    let mut ix = base.to_instruction(&payer.pubkey(), &signers).expect("serialize");
    let mut flipped = false;
    for meta in &mut ix.accounts {{
        if meta.is_signer && meta.pubkey != payer.pubkey() {{
            meta.is_signer = false;
            flipped = true;
            break;
        }}
    }}
    assert!(flipped, "instruction has an extra signer by construction");
    println!("[{name}] dropping the signature on the authority account");
    replay(&mut banks, &payer, &ix, &[&payer], recent_blockhash, &base).await;
}}
"#,
            name = sanitize_ident(&ix.name),
            variant = adversarial_variant_expr(ix),
        ));
    }

    // 2. Boundary args: typed variants get u64::MAX/i64::MIN-scale values.
    if matches!(variant_shape(ix), VariantShape::Typed(_)) {
        out.push_str(&format!(
            r#"
#[tokio::test]
async fn {name}_boundary_args() {{
    let (mut program_test, payer, keypairs) = set_up_program_test();
    seed_fuzz_accounts(&mut program_test, &payer.pubkey(), &signer_pubkeys(&payer, &keypairs));
    let (mut banks, _start_payer, recent_blockhash) = program_test.start().await;
    let signers = signer_pubkeys(&payer, &keypairs);
    let base = {variant};
    let ix = base.to_instruction(&payer.pubkey(), &signers).expect("serialize");
    println!("[{name}] boundary args (MAX/MIN/0)");
    replay(&mut banks, &payer, &ix, &all_signers(&payer, &keypairs), recent_blockhash, &base).await;
}}
"#,
            name = sanitize_ident(&ix.name),
            variant = adversarial_variant_expr(ix),
        ));
    }

    // 3. Wrong-seed PDA: substitute a decoy account at a bogus derivation.
    if let Some(pda_pos) = first_pda_position(ix) {
        out.push_str(&format!(
            r#"
#[tokio::test]
async fn {name}_wrong_seed_pda() {{
    let (mut program_test, payer, keypairs) = set_up_program_test();
    seed_fuzz_accounts(&mut program_test, &payer.pubkey(), &signer_pubkeys(&payer, &keypairs));
    let (wrong, _bump) = Pubkey::find_program_address(&[b"pwned"], &program_id());
    program_test.add_account(
        wrong,
        Account {{ lamports: 5_000_000_000, data: vec![0u8; 1024], owner: program_id(), executable: false, rent_epoch: 0 }},
    );
    let (mut banks, _start_payer, recent_blockhash) = program_test.start().await;
    let signers = signer_pubkeys(&payer, &keypairs);
    let base = {variant};
    let mut ix = base.to_instruction(&payer.pubkey(), &signers).expect("serialize");
    ix.accounts[{pda_pos}].pubkey = wrong;
    println!("[{name}] substituting a wrong-seed PDA at meta index {pda_pos}");
    replay(&mut banks, &payer, &ix, &all_signers(&payer, &keypairs), recent_blockhash, &base).await;
}}
"#,
            name = sanitize_ident(&ix.name),
            variant = adversarial_variant_expr(ix),
            pda_pos = pda_pos,
        ));
    }

    let _ = config;
    out
}

/// Cross-instruction account swap: two instructions whose shared-shaped
/// accounts are confused by swapping their first non-signer, non-PDA meta.
fn render_swap_test(config: &FuzzerConfig) -> String {
    let (a, b) = (&config.instructions[0], &config.instructions[1]);
    let swap_pos_a = a.accounts.iter().position(|acc| !acc.is_signer && !acc.pda).unwrap_or(0);
    let swap_pos_b = b.accounts.iter().position(|acc| !acc.is_signer && !acc.pda).unwrap_or(0);
    format!(
        r#"
#[tokio::test]
async fn account_swap_between_instructions() {{
    let (mut program_test, payer, keypairs) = set_up_program_test();
    seed_fuzz_accounts(&mut program_test, &payer.pubkey(), &signer_pubkeys(&payer, &keypairs));
    let (mut banks, _start_payer, recent_blockhash) = program_test.start().await;
    let signers = signer_pubkeys(&payer, &keypairs);
    let base_a = {variant_a};
    let base_b = {variant_b};
    let mut ix_a = base_a.to_instruction(&payer.pubkey(), &signers).expect("serialize");
    let mut ix_b = base_b.to_instruction(&payer.pubkey(), &signers).expect("serialize");
    let swap = ix_a.accounts[{pos_a}].pubkey;
    ix_a.accounts[{pos_a}].pubkey = ix_b.accounts[{pos_b}].pubkey;
    ix_b.accounts[{pos_b}].pubkey = swap;
    println!("[account_swap] swapping metas {pos_a} <-> {pos_b} between the two instructions");
    replay(&mut banks, &payer, &ix_a, &all_signers(&payer, &keypairs), recent_blockhash, &base_a).await;
    replay(&mut banks, &payer, &ix_b, &all_signers(&payer, &keypairs), recent_blockhash, &base_b).await;
}}
"#,
        variant_a = adversarial_variant_expr(a),
        variant_b = adversarial_variant_expr(b),
        pos_a = swap_pos_a,
        pos_b = swap_pos_b,
    )
}

/// Double initialization: the initializer is invoked twice in one transaction.
fn render_double_init_test(config: &FuzzerConfig) -> String {
    let ix = config
        .instructions
        .iter()
        .find(|ix| {
            let lower = ix.name.to_lowercase();
            lower.starts_with("init") || lower.starts_with("initialize")
        })
        .unwrap_or(&config.instructions[0]);
    format!(
        r#"
#[tokio::test]
async fn {name}_double_init() {{
    let (mut program_test, payer, keypairs) = set_up_program_test();
    seed_fuzz_accounts(&mut program_test, &payer.pubkey(), &signer_pubkeys(&payer, &keypairs));
    let (mut banks, _start_payer, recent_blockhash) = program_test.start().await;
    let signers = signer_pubkeys(&payer, &keypairs);
    let base = {variant};
    let ix = base.to_instruction(&payer.pubkey(), &signers).expect("serialize");
    let mut tx = Transaction::new_with_payer(&[ix.clone(), ix], Some(&payer.pubkey()));
    tx.sign(&all_signers(&payer, &keypairs), recent_blockhash);
    match banks.process_transaction(tx).await {{
        Ok(()) => println!("SIGNAL: program accepted a double initialization"),
        Err(err) => println!("control: program rejected the second init ({{err:?}})"),
    }}
}}
"#,
        name = sanitize_ident(&ix.name),
        variant = adversarial_variant_expr(ix),
    )
}

/// Renders the generated fuzzer's README: what was generated, the honest scope
/// (covered primitives vs placeholder fallbacks), and how to run it.
fn render_readme(config: &FuzzerConfig) -> String {
    format!(
        r#"# Fuzzer for {program}

Auto-generated by `sat fuzz init` for the `{lib}` Anchor program (program ID `{pid}`).

## What was generated

- `src/lib.rs` — the fuzz harness:
  - `pub mod accounts` — IDL account layouts with Anchor discriminators
    (`sha256("account:<name>")[..8]`) and borsh-serialized `build_*` factories;
  - `account_address`, `seeds_<ix>_<acct>` and `pda_<ix>_<acct>` — real PDA
    addresses derived from the program's IDL seeds, plus `MAX_SIGNERS` and
    `signer_count_*` signer bookkeeping;
  - `set_up_program_test` — funds a payer plus additional signer keypairs
    (per `MAX_SIGNERS`) and seeds real accounts: the fuzz mint (SPL), SPL
    token accounts for token-named accounts, and IDL-typed accounts at their
    derived PDA addresses;
  - invariant hooks: `check_token_supply`, `check_vault_consistency`,
    `check_unexpected_account_drain`, `check_authority_immutability`,
    `check_state_integrity`.
- `fuzz_targets/instruction_fuzz.rs` — libFuzzer target: builds a transaction
  per fuzzed `FuzzInstruction`, executes it in `solana-program-test`, and runs
  the invariant checks after each instruction.
- `Cargo.toml` — dependency versions mirrored from `programs/{lib}/Cargo.toml`
  when available (falls back to defaults with a `# WARN` comment otherwise).

## Honest scope

- Covered automatically: primitive scalars and common containers (`Vec`,
  `Option`, `[T; N]`), `String`, `Pubkey`, enums, and IDL account structs.
- Not covered automatically: unsupported field types and Token-2022 extension
  accounts fall back to placeholder data that needs manual wiring.
- Arg-seeded PDAs are fixed placeholders (`vec![0u8; 32]`) — fuzzed args
  cannot be predicted, so wire them to the actual payload if those PDAs matter.
- Accounts whose name does not match an IDL account type are seeded with 1024
  zero bytes — extend `seed_fuzz_accounts` for those.

## Running

Requires `cargo-fuzz` (install once with `cargo install cargo-fuzz`):

    cd fuzzer
    cargo fuzz run instruction_fuzz
"#,
        program = config.program_name,
        lib = config.program_lib_name,
        pid = config.program_id,
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
    use tempfile::tempdir;

    fn test_config(instructions: Vec<FuzzerInstructionConfig>) -> FuzzerConfig {
        FuzzerConfig {
            program_name: "test_program".to_string(),
            program_lib_name: "test_program".to_string(),
            crate_name: "fuzzer_test_program".to_string(),
            program_id: DEFAULT_PROGRAM_ID.to_string(),
            instructions,
            account_types: vec![],
            has_vault: false,
            has_token: false,
            has_token_2022: false,
            has_state_init_flag: false,
        }
    }

    fn instruction_config(name: &str, args: Vec<FuzzerArgConfig>) -> FuzzerInstructionConfig {
        FuzzerInstructionConfig { name: name.to_string(), accounts: vec![], args }
    }

    fn arg(name: &str, ty: FuzzerArgType) -> FuzzerArgConfig {
        FuzzerArgConfig { name: name.to_string(), ty }
    }

    /// Parses the vault fixture and renders the config plus the three generated
    /// modules exactly as `fuzzer::init` does for an IDL-bearing workspace.
    fn vault_fixture() -> (FuzzerConfig, String, String, String) {
        let idl = idl::parse_idl("tests/fixtures/vault.json").expect("parse vault fixture");
        let layout = fuzzer_layout::render_account_factories(&idl);
        let pda_setup = fuzzer_seeds::render_pda_setup(&idl);
        let signer_info = fuzzer_seeds::render_signer_info(&idl);
        (config_from_idl(idl), layout, pda_setup, signer_info)
    }

    /// Parses the token-2022 fixture and renders the config plus the three
    /// generated modules exactly as `fuzzer::init` does for an IDL-bearing
    /// workspace. `config_from_idl` sets `has_token_2022` via the IDL
    /// account-name fallback (`token_2022_program`).
    fn token2022_fixture() -> (FuzzerConfig, String, String, String) {
        let idl = idl::parse_idl("tests/fixtures/token2022_fuzz.json").expect("parse token2022_fuzz fixture");
        let layout = fuzzer_layout::render_account_factories(&idl);
        let pda_setup = fuzzer_seeds::render_pda_setup(&idl);
        let signer_info = fuzzer_seeds::render_signer_info(&idl);
        (config_from_idl(idl), layout, pda_setup, signer_info)
    }

    #[test]
    fn token2022_mode_embeds_extension_factories() {
        let (config, layout, pda_setup, signer_info) = token2022_fixture();
        assert!(config.has_token_2022, "fixture must be detected as token-2022");
        let rendered = render_lib_rs(&config, &layout, &pda_setup, &signer_info);

        for needle in [
            "// Generated token-2022 account factories",
            "pub mod token2022_accounts",
            "TransferFeeConfig",
            "InterestBearingConfig",
            "PermanentDelegate",
            "spl_token_2022::ID",
        ] {
            assert!(rendered.contains(needle), "missing {needle:?} in rendered lib.rs");
        }
        // The fixture's `mint` account is the resolved mint and is seeded as a
        // Token-2022 extension mint at its own address.
        assert!(rendered.contains(
            "token2022_accounts::seed_fuzz_mint(program_test, &account_address(\"mint\", payer, signer_pubkeys), payer)"
        ));

        // The entire rendered lib.rs must parse as valid Rust.
        syn::parse_file(&rendered)
            .unwrap_or_else(|err| panic!("rendered lib.rs does not parse: {err}\n---\n{rendered}"));
    }

    #[test]
    fn spl_token_mode_omits_extension_factories() {
        let (mut config, layout, pda_setup, signer_info) = token2022_fixture();
        config.has_token_2022 = false;
        let rendered = render_lib_rs(&config, &layout, &pda_setup, &signer_info);

        for needle in ["// Generated token-2022 account factories", "pub mod token2022_accounts", "TransferFeeConfig"] {
            assert!(!rendered.contains(needle), "unexpected {needle:?} in spl-token-mode lib.rs");
        }
        assert!(rendered.contains("spl_token::ID"), "spl-token factories must still be emitted");
        syn::parse_file(&rendered)
            .unwrap_or_else(|err| panic!("rendered lib.rs does not parse: {err}\n---\n{rendered}"));
    }

    #[test]
    fn detects_token_2022_from_program_cargo_toml() {
        let dir = tempdir().expect("tempdir");
        let toml_path = dir.path().join("Cargo.toml");

        // [dependencies] key (plain version string).
        fs::write(&toml_path, "[dependencies]\nspl-token-2022 = \"7\"\n").expect("write temp Cargo.toml");
        assert!(program_has_token_2022(&toml_path), "spl-token-2022 in [dependencies]");

        // [workspace.dependencies] key, alternate spelling.
        fs::write(&toml_path, "[workspace.dependencies]\ntoken-2022 = { version = \"7\" }\n")
            .expect("write temp Cargo.toml");
        assert!(program_has_token_2022(&toml_path), "token-2022 in [workspace.dependencies]");

        // No token-2022 dependency → false.
        fs::write(&toml_path, "[dependencies]\nspl-token = \"7\"\nanchor-lang = \"0.30\"\n")
            .expect("write temp Cargo.toml");
        assert!(!program_has_token_2022(&toml_path), "spl-token alone must not match");

        // Unreadable path → false.
        assert!(!program_has_token_2022(&dir.path().join("nope").join("Cargo.toml")));
    }

    #[test]
    fn detects_token_2022_from_idl_account_names() {
        let idl = idl::parse_idl("tests/fixtures/token2022_fuzz.json").expect("parse token2022_fuzz fixture");
        let config = config_from_idl(idl);
        assert!(config.has_token_2022, "`token_2022_program` account name must trigger the IDL-name fallback");

        // Negative control: fixtures without a "2022" account name stay spl-token.
        let vault = idl::parse_idl("tests/fixtures/vault.json").expect("parse vault fixture");
        assert!(!config_from_idl(vault).has_token_2022);
    }

    #[test]
    fn token_accounts_reference_resolved_mint() {
        // A transfer-style instruction with its own `mint` account: token
        // accounts and the fuzz mint must resolve to the mint account's
        // address (not the `fuzz_mint` fallback), so from.mint == mint holds.
        let config = test_config(vec![FuzzerInstructionConfig {
            name: "transfer".to_string(),
            accounts: vec![
                FuzzerAccountConfig { name: "token_account".to_string(), is_mut: true, is_signer: false, pda: false },
                FuzzerAccountConfig { name: "mint".to_string(), is_mut: false, is_signer: false, pda: false },
            ],
            args: vec![],
        }]);

        let rendered = render_seed_accounts(&config);
        // The resolved-mint rule is documented in the generated code.
        assert!(rendered.contains("resolved mint"), "missing resolved-mint comment:\n{rendered}");
        // The mint is registered once at the mint account's address, and the
        // token account data references that same address — never the fallback.
        assert!(
            rendered.contains("mint: account_address(\"mint\", payer, signer_pubkeys)"),
            "token account must reference the resolved mint:\n{rendered}"
        );
        assert!(
            !rendered.contains("account_address(\"fuzz_mint\", payer, signer_pubkeys)"),
            "fuzz_mint fallback must not appear when the program passes its own mint:\n{rendered}"
        );

        // Token-2022 mode: the same resolved-mint rule through the factories.
        let mut token_2022 = config.clone();
        token_2022.has_token_2022 = true;
        let rendered = render_seed_accounts(&token_2022);
        assert!(rendered.contains("resolved mint"));
        assert!(rendered.contains(
            "token2022_accounts::seed_token_account(program_test, &account_address(\"token_account\", payer, signer_pubkeys), &account_address(\"mint\", payer, signer_pubkeys), payer, 1_000_000_000_000)"
        ));
        assert!(rendered.contains(
            "token2022_accounts::seed_fuzz_mint(program_test, &account_address(\"mint\", payer, signer_pubkeys), payer)"
        ));
        assert!(!rendered.contains("account_address(\"fuzz_mint\", payer, signer_pubkeys)"));

        // Without a mint-named account, the fuzz_mint fallback is still used.
        let plain = render_seed_accounts(&test_config(vec![]));
        assert!(plain.contains("account_address(\"fuzz_mint\", payer, signer_pubkeys)"), "{plain}");
        assert!(plain.contains("resolved mint"), "{plain}");
    }

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

    #[test]
    fn typed_variant_contains_idl_arg_fields() {
        let config = test_config(vec![
            instruction_config("deposit", vec![arg("amount", FuzzerArgType::U64)]),
            instruction_config(
                "update",
                vec![arg("signer", FuzzerArgType::Pubkey), arg("memo", FuzzerArgType::String)],
            ),
        ]);
        let rendered = render_arbitrary_enum_variants(&config);

        assert!(rendered.contains("Deposit { amount: u64 }"));
        // Pubkey args render as `[u8; 32]` (solana-sdk 4.x has no `Arbitrary` for `Pubkey`).
        assert!(rendered.contains("Update { signer: [u8; 32], memo: String }"));
    }

    #[test]
    fn typed_variant_serializes_with_borsh() {
        let config = test_config(vec![
            instruction_config(
                "deposit",
                vec![arg("amount", FuzzerArgType::U64), arg("basis_points", FuzzerArgType::U64)],
            ),
            instruction_config(
                "transfer",
                vec![arg("signer", FuzzerArgType::Pubkey), arg("memo", FuzzerArgType::String)],
            ),
        ]);
        let rendered = render_to_instruction_match(&config);

        assert!(rendered.contains("FuzzInstruction::Deposit { amount, basis_points }"));
        assert!(rendered.contains("payload.extend(borsh::to_vec(&amount)?);"));
        assert!(rendered.contains("payload.extend(borsh::to_vec(&basis_points)?);"));
        assert!(rendered.contains("FuzzInstruction::Transfer { signer, memo }"));
        assert!(rendered.contains("payload.extend(borsh::to_vec(&signer)?);"));
        assert!(rendered.contains("payload.extend(borsh::to_vec(&memo)?);"));

        // The discriminator is still prepended before the serialized args.
        let discriminator =
            instruction_discriminator("deposit").iter().map(|byte| byte.to_string()).collect::<Vec<_>>().join(", ");
        assert!(rendered.contains(&format!("let mut payload = vec![{discriminator}]")));
    }

    #[test]
    fn unsupported_args_fall_back_to_raw_payload() {
        let config = test_config(vec![instruction_config(
            "deposit",
            vec![arg("amount", FuzzerArgType::U64), arg("bump", FuzzerArgType::Unsupported)],
        )]);

        let variants = render_arbitrary_enum_variants(&config);
        assert!(variants.contains("Deposit { raw: Vec<u8> }"));
        assert!(variants.contains("bump")); // skipped-arg comment names the dropped arg

        let to_ix = render_to_instruction_match(&config);
        assert!(to_ix.contains("FuzzInstruction::Deposit { raw }"));
        assert!(to_ix.contains("payload.extend(raw.iter().copied());"));

        // `as_ix_name` and `account_metas` must use the struct-variant pattern.
        assert!(render_ix_name_match(&config).contains("FuzzInstruction::Deposit { .. }"));
        assert!(render_account_meta_match(&config).contains("FuzzInstruction::Deposit { .. }"));
    }

    #[test]
    fn no_args_keeps_raw_payload_variant() {
        let config = default_config();
        let variants = render_arbitrary_enum_variants(&config);

        assert!(variants.contains("Initialize(Vec<u8>)"));
        assert!(variants.contains("Update(Vec<u8>)"));
        assert!(variants.contains("Close(Vec<u8>)"));
    }

    #[test]
    fn idl_arg_types_map_to_fuzzer_arg_types() {
        let idl_json = idl::IdlJson {
            version: "0.30.0".to_string(),
            name: "test".to_string(),
            instructions: vec![idl::IdlInstruction {
                name: "deposit".to_string(),
                accounts: vec![],
                args: vec![
                    idl::IdlArg { name: "amount".to_string(), ty: serde_json::json!("u64") },
                    idl::IdlArg { name: "rate".to_string(), ty: serde_json::json!("u32") },
                    idl::IdlArg { name: "count".to_string(), ty: serde_json::json!("u16") },
                    idl::IdlArg { name: "byte".to_string(), ty: serde_json::json!("u8") },
                    idl::IdlArg { name: "delta".to_string(), ty: serde_json::json!("i64") },
                    idl::IdlArg { name: "offset".to_string(), ty: serde_json::json!("i32") },
                    idl::IdlArg { name: "enabled".to_string(), ty: serde_json::json!("bool") },
                    idl::IdlArg { name: "signer".to_string(), ty: serde_json::json!("publicKey") },
                    idl::IdlArg { name: "memo".to_string(), ty: serde_json::json!("string") },
                    idl::IdlArg { name: "defined".to_string(), ty: serde_json::json!({ "defined": "Foo" }) },
                    idl::IdlArg { name: "values".to_string(), ty: serde_json::json!({ "vec": "u8" }) },
                ],
                discriminator: None,
            }],
            accounts: vec![],
            types: vec![],
            metadata: None,
        };

        let config = config_from_idl(idl_json);
        let actual: Vec<FuzzerArgType> = config.instructions[0].args.iter().map(|arg| arg.ty).collect();
        let expected = [
            FuzzerArgType::U64,
            FuzzerArgType::U32,
            FuzzerArgType::U16,
            FuzzerArgType::U8,
            FuzzerArgType::I64,
            FuzzerArgType::I32,
            FuzzerArgType::Bool,
            FuzzerArgType::Pubkey,
            FuzzerArgType::String,
            FuzzerArgType::Unsupported,
            FuzzerArgType::Unsupported,
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn generated_lib_embeds_account_factories_and_pda_helpers() {
        let (config, layout, pda_setup, signer_info) = vault_fixture();
        let rendered = render_lib_rs(&config, &layout, &pda_setup, &signer_info);

        for needle in [
            "pub mod accounts",
            "pub fn account_address(name: &str, payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Pubkey",
            "pub fn seeds_initializeVault_vaultState",
            "pub fn pda_initializeVault_vaultState",
            "pub fn signer_count_initializeVault",
            "pub const MAX_SIGNERS: usize = 1;",
            "spl_token", // fuzz mint + token seeding
        ] {
            assert!(rendered.contains(needle), "missing {needle:?} in rendered lib.rs");
        }

        // The entire rendered lib.rs must parse as valid Rust.
        syn::parse_file(&rendered)
            .unwrap_or_else(|err| panic!("rendered lib.rs does not parse: {err}\n---\n{rendered}"));
    }

    #[test]
    fn generated_target_uses_funded_signer_keypairs() {
        let config = default_config();
        let target = render_fuzz_target(&config);

        assert!(target.contains("let (program_test, payer, keypairs) = set_up_program_test();"));
        assert!(
            target.contains("let (mut banks_client, _start_payer, recent_blockhash) = program_test.start().await;")
        );
        assert!(target.contains("let signer_pubkeys: Vec<Pubkey>"));
        assert!(target.contains("ix.to_instruction(&payer.pubkey(), &signer_pubkeys)"));
        assert!(target.contains("let signers: Vec<&Keypair>"));
        assert!(target.contains("transaction.sign(&signers, recent_blockhash)"));
    }

    #[test]
    fn no_idl_fallback_renders_placeholder_seeding() {
        let empty_idl = idl::IdlJson {
            version: "0.1.0".to_string(),
            name: "program".to_string(),
            instructions: vec![],
            accounts: vec![],
            types: vec![],
            metadata: None,
        };
        let layout = fuzzer_layout::render_account_factories(&empty_idl);
        let pda_setup = fuzzer_seeds::render_pda_setup(&empty_idl);
        let signer_info = fuzzer_seeds::render_signer_info(&empty_idl);
        let config = default_config();
        let rendered = render_lib_rs(&config, &layout, &pda_setup, &signer_info);

        assert!(rendered.contains("pub const MAX_SIGNERS: usize = 1;"));
        // No IDL account types: `state` resolves via account_address (which
        // falls back to fuzz_account_pubkey) and keeps the zero-byte placeholder.
        assert!(rendered.contains("account_address(\"state\", payer, signer_pubkeys)"));
        assert!(rendered.contains("vec![0; 1024]"));
        syn::parse_file(&rendered)
            .unwrap_or_else(|err| panic!("fallback lib.rs does not parse: {err}\n---\n{rendered}"));
    }

    #[test]
    fn cargo_toml_mirrors_program_versions() {
        let dir = tempdir().expect("tempdir");
        let toml_path = dir.path().join("Cargo.toml");
        fs::write(
            &toml_path,
            r#"[package]
name = "vault"
version = "0.1.0"

[dependencies]
anchor-lang = "0.30.1"
solana-program = "2.1.0"
solana-sdk = "2.1.0"
solana-program-test = "2.1.0"
spl-token = "7.1.0"
spl-token-2022 = "7.1.0"
"#,
        )
        .expect("write temp Cargo.toml");

        let versions = program_dependency_versions(&toml_path);
        assert_eq!(versions.get("anchor-lang").map(String::as_str), Some("0.30.1"));
        assert_eq!(versions.get("spl-token-2022").map(String::as_str), Some("7.1.0"));

        let config = test_config(vec![]);
        let rendered = render_cargo_toml(&config, &toml_path);
        assert!(rendered.contains("anchor-lang = \"0.30.1\""), "{rendered}");
        assert!(rendered.contains("solana-program = \"2.1.0\""), "{rendered}");
        assert!(rendered.contains("spl-token-2022 = \"7.1.0\""), "{rendered}");
        assert!(!rendered.contains("WARN"), "{rendered}");

        // Versions also resolve from [workspace.dependencies].
        let ws_dir = tempdir().expect("tempdir");
        let ws_toml = ws_dir.path().join("Cargo.toml");
        fs::write(&ws_toml, "[workspace.dependencies]\nsolana-program = \"1.18.26\"\n")
            .expect("write workspace Cargo.toml");
        let versions = program_dependency_versions(&ws_toml);
        assert_eq!(versions.get("solana-program").map(String::as_str), Some("1.18.26"));

        // Fallback: missing file → default versions + WARN comment.
        let missing = dir.path().join("nope").join("Cargo.toml");
        let rendered = render_cargo_toml(&config, &missing);
        assert!(rendered.contains("anchor-lang = \"0.29\""), "{rendered}");
        assert!(rendered.contains("solana-program = \"4\""), "{rendered}");
        assert!(rendered.contains("# WARN: could not read"), "{rendered}");
    }

    #[test]
    fn adversarial_harness_renders_and_parses() {
        let config = test_config(vec![
            FuzzerInstructionConfig {
                name: "initialize_vault".to_string(),
                accounts: vec![
                    FuzzerAccountConfig { name: "state".to_string(), is_mut: true, is_signer: false, pda: true },
                    FuzzerAccountConfig { name: "authority".to_string(), is_mut: false, is_signer: true, pda: false },
                    FuzzerAccountConfig { name: "fee_payer".to_string(), is_mut: false, is_signer: true, pda: false },
                ],
                args: vec![arg("amount", FuzzerArgType::U64)],
            },
            instruction_config("update", vec![arg("fee", FuzzerArgType::U32)]),
        ]);
        let rendered = render_adversarial_test(&config);
        if let Err(e) = syn::parse_file(&rendered) {
            panic!("generated adversarial.rs must parse: {e}");
        }
        assert!(rendered.contains("#[tokio::test]"), "{rendered}");
        assert!(rendered.contains("set_up_program_test"), "{rendered}");
        assert!(rendered.contains("missing_signer"), "{rendered}");
        assert!(rendered.contains("boundary_args"), "{rendered}");
        assert!(rendered.contains("check_invariants"), "{rendered}");
        assert!(rendered.contains("u64::MAX"), "boundary value must be rendered");
    }

    #[test]
    fn adversarial_harness_wrong_seed_only_for_pda_accounts() {
        let with_pda = test_config(vec![FuzzerInstructionConfig {
            name: "deposit".to_string(),
            accounts: vec![
                FuzzerAccountConfig { name: "escrow".to_string(), is_mut: true, is_signer: false, pda: true },
                FuzzerAccountConfig { name: "authority".to_string(), is_mut: false, is_signer: true, pda: false },
            ],
            args: vec![],
        }]);
        assert!(
            render_adversarial_test(&with_pda).contains("wrong_seed_pda"),
            "pda account must render the wrong-seed test"
        );

        let without_pda = test_config(vec![FuzzerInstructionConfig {
            name: "deposit".to_string(),
            accounts: vec![FuzzerAccountConfig {
                name: "authority".to_string(),
                is_mut: false,
                is_signer: true,
                pda: false,
            }],
            args: vec![],
        }]);
        assert!(
            !render_adversarial_test(&without_pda).contains("wrong_seed_pda"),
            "no pda account means no wrong-seed test"
        );
    }

    #[test]
    fn adversarial_harness_double_init_only_for_initializers() {
        let with_init = test_config(vec![FuzzerInstructionConfig {
            name: "initialize".to_string(),
            accounts: vec![FuzzerAccountConfig {
                name: "state".to_string(),
                is_mut: true,
                is_signer: false,
                pda: false,
            }],
            args: vec![],
        }]);
        let mut with_init = with_init;
        with_init.has_state_init_flag = true;
        assert!(
            render_adversarial_test(&with_init).contains("double_init"),
            "{:?}",
            render_adversarial_test(&with_init)
        );

        let plain = test_config(vec![FuzzerInstructionConfig {
            name: "update".to_string(),
            accounts: vec![FuzzerAccountConfig {
                name: "state".to_string(),
                is_mut: true,
                is_signer: false,
                pda: false,
            }],
            args: vec![],
        }]);
        assert!(
            !render_adversarial_test(&plain).contains("double_init"),
            "non-initializer must not render double-init"
        );
    }

    #[test]
    fn adversarial_harness_swap_requires_two_instructions() {
        let one = test_config(vec![FuzzerInstructionConfig {
            name: "update".to_string(),
            accounts: vec![FuzzerAccountConfig {
                name: "state".to_string(),
                is_mut: true,
                is_signer: false,
                pda: false,
            }],
            args: vec![],
        }]);
        assert!(
            !render_adversarial_test(&one).contains("account_swap"),
            "single instruction must not render the swap test"
        );

        let two = test_config(vec![
            FuzzerInstructionConfig {
                name: "update".to_string(),
                accounts: vec![FuzzerAccountConfig {
                    name: "state".to_string(),
                    is_mut: true,
                    is_signer: false,
                    pda: false,
                }],
                args: vec![],
            },
            instruction_config("close", vec![]),
        ]);
        assert!(render_adversarial_test(&two).contains("account_swap_between_instructions"));
    }
}
