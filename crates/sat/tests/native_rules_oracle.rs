//! R7 slice tests: SAT034 / SAT035 / SAT036 — oracle price-feed checks for
//! native programs, exercised via `oracle::check` directly on the pinned
//! model plus the parsed files from
//! `sat::native::analyze_source_and_files_for_test`.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{NativeInstruction, NativeProgram};
    }
    pub mod rules {
        pub mod validate {
            pub use sat::native::rules::validate::{FnIndex, collect_blocks};
        }
    }
}

#[path = "../src/native/rules/oracle.rs"]
mod oracle;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT034: &str = "Stale Oracle Price:";
const SAT035: &str = "Oracle Confidence Unvalidated:";
const SAT036: &str = "Oracle Decimals/Exponent Mismatch:";

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/oracle/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Analyze a source string and run only the oracle rules.
fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = oracle::check(&program, &files);
    (program, findings)
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
fn vuln_fixture_resolves_feed_account() {
    let (program, _) = run(&fixture_source("vuln.rs"));
    assert_eq!(program.instructions.len(), 1, "no-dispatch fallback instruction");
    account(&program.instructions[0], "price_feed");
}

// ── Finding shape ────────────────────────────────────────────────────────────

#[test]
fn vuln_fixture_fires_all_three_oracle_checks() {
    let source = fixture_source("vuln.rs");
    let (_, findings) = run(&source);

    for (prefix, severity) in [(SAT034, Severity::High), (SAT035, Severity::High), (SAT036, Severity::High)] {
        let flagged = by_rule(&findings, prefix);
        assert_eq!(flagged.len(), 1, "{prefix} must fire once: {findings:#?}");
        let f = flagged[0];
        assert_eq!(f.severity, severity);
        assert!(f.id.is_empty(), "id is filled by run() later");
        assert!(f.title.contains("`price_feed`"), "{}", f.title);
        assert!(!f.description.is_empty());
        assert!(f.suggestion.is_some());
        let expected_loc = format!("test.rs:{} (process_instruction)", line_of(&source, "pub fn process_instruction"));
        assert_eq!(f.location.as_deref(), Some(expected_loc.as_str()));
    }
}

// ── Clean gate ───────────────────────────────────────────────────────────────

#[test]
fn clean_yields_no_oracle_findings() {
    let (_, findings) = run(&fixture_source("clean.rs"));
    assert!(findings.is_empty(), "fully-guarded feed usage must not fire: {findings:#?}");
}

// ── FP filters (inline sources) ──────────────────────────────────────────────

/// A feed passed through to a CPI (never read in program) is suppressed.
#[test]
fn cpi_passed_only_feed_is_suppressed() {
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
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let price_feed = next_account_info(accounts_iter)?;
    let aggregator_program = next_account_info(accounts_iter)?;

    invoke(
        &solana_program::instruction::Instruction {
            program_id: *aggregator_program.key,
            accounts: vec![
                solana_program::instruction::AccountMeta::new_readonly(*price_feed.key, false),
            ],
            data: vec![1],
        },
        &[price_feed.clone(), aggregator_program.clone()],
    )?;
    msg!("forwarded");
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "CPI-passed-only feed must not fire: {findings:#?}");
}

/// Direct field consumption of every safety field keeps all three silent.
#[test]
fn deserialized_local_consumption_counts_as_read() {
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
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let price_feed = next_account_info(accounts_iter)?;

    let price = PythPrice::try_from_slice(&price_feed.data.borrow())?;
    let _ = price.publish_time;
    let _ = price.conf;
    let _ = price.expo;
    msg!("checked: {}", price.price);
    Ok(())
}

struct PythPrice {
    price: i64,
    conf: u64,
    expo: i32,
    publish_time: i64,
}

impl PythPrice {
    fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        Ok(PythPrice {
            price: i64::from_le_bytes(data[0..8].try_into().unwrap()),
            conf: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            expo: i32::from_le_bytes(data[16..20].try_into().unwrap()),
            publish_time: i64::from_le_bytes(data[24..32].try_into().unwrap()),
        })
    }
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "all safety fields consumed → silent: {findings:#?}");
}

/// Only one safety field consumed → exactly the other two fire.
#[test]
fn partial_consumption_fires_only_missing_checks() {
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
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let price_feed = next_account_info(accounts_iter)?;

    let price = PythPrice::try_from_slice(&price_feed.data.borrow())?;
    let _ = price.publish_time;
    msg!("price: {}", price.price);
    Ok(())
}

struct PythPrice {
    price: i64,
    conf: u64,
    expo: i32,
    publish_time: i64,
}

impl PythPrice {
    fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        Ok(PythPrice {
            price: i64::from_le_bytes(data[0..8].try_into().unwrap()),
            conf: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            expo: i32::from_le_bytes(data[16..20].try_into().unwrap()),
            publish_time: i64::from_le_bytes(data[24..32].try_into().unwrap()),
        })
    }
}
"#;
    let (_, findings) = run(source);
    assert!(by_rule(&findings, SAT034).is_empty(), "publish_time consumed → SAT034 silent");
    assert_eq!(by_rule(&findings, SAT035).len(), 1, "conf never consumed → SAT035 fires");
    assert_eq!(by_rule(&findings, SAT036).len(), 1, "expo never consumed → SAT036 fires");
}

/// Accounts with feed-like names that are never read are suppressed.
#[test]
fn unreferenced_feed_named_account_is_suppressed() {
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
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let price_feed = next_account_info(accounts_iter)?;
    msg!("feed key: {}", price_feed.key);
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(findings.is_empty(), "only the key is logged — feed data never read: {findings:#?}");
}

/// The Mango `read_oracle` shape: `oracle_ai.try_borrow_data()` →
/// `pyth_client::load_price(&data).unwrap()` → `price.agg.conf` /
/// `price.expo` consumed, but NO time field → SAT034 fires, 035/036 silent.
#[test]
fn mango_read_oracle_shape_fires_only_staleness() {
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
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let oracle_ai = next_account_info(accounts_iter)?;

    let price = read_oracle(oracle_ai)?;
    msg!("oracle price: {}", price);
    Ok(())
}

fn read_oracle(oracle_ai: &AccountInfo) -> Result<i64, ProgramError> {
    let oracle_data = oracle_ai.try_borrow_data()?;
    let price_account = pyth_client::load_price(&oracle_data).unwrap();

    // Confidence is validated...
    let value = price_account.agg.price;
    let conf = price_account.agg.conf;
    if conf > value.unsigned_abs() / 100 {
        return Err(ProgramError::InvalidAccountData);
    }

    // ...and the exponent is applied...
    let decimals = 6i32.checked_add(price_account.expo).unwrap();
    let scaled = (value as u128) * 10u128.pow(decimals as u32);

    // ...but NO time field is consumed anywhere: nothing bounds the feed's age.
    Ok(scaled as i64)
}

struct PythPrice {
    agg: PythAgg,
    expo: i32,
    publish_time: i64,
}

struct PythAgg {
    price: i64,
    conf: u64,
}

mod pyth_client {
    use super::PythPrice;
    pub fn load_price(data: &[u8]) -> Option<PythPrice> {
        Some(PythPrice {
            agg: super::PythAgg { price: 0, conf: 0 },
            expo: 0,
            publish_time: 0,
        })
    }
}
"#;
    let (_, findings) = run(source);
    assert_eq!(by_rule(&findings, SAT034).len(), 1, "no time-field consumption → staleness fires: {findings:#?}");
    assert!(by_rule(&findings, SAT035).is_empty(), "conf consumed → confidence silent");
    assert!(by_rule(&findings, SAT036).is_empty(), "expo consumed → exponent silent");
}
