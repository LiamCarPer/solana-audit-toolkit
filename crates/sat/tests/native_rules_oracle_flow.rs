//! R10 slice tests: SAT041 — Oracle/Price Value Flow (the Mango mark-price
//! class), exercised via `oracle_flow::check` on the pinned model + parsed
//! files from `sat::native::analyze_source_and_files_for_test`.

mod types {
    pub use sat::types::{Finding, Severity};
}

mod native {
    pub mod model {
        pub use sat::native::model::{NativeInstruction, NativeProgram};
    }
    pub mod rules {
        pub mod validate {
            pub use sat::native::rules::validate::{FnIndex, collect_blocks, for_each_anchor_instruction};
        }
    }
}

#[path = "../src/native/rules/oracle_flow.rs"]
mod oracle_flow;

use sat::native::model::NativeProgram;
use sat::types::{Finding, Severity};

const SAT041: &str = "Oracle Value Flow:";

fn run(source: &str) -> (NativeProgram, Vec<Finding>) {
    let (program, files) = sat::native::analyze_source_and_files_for_test(source);
    let findings = oracle_flow::check(&program, &files);
    (program, findings)
}

fn by_rule<'a>(findings: &'a [Finding], prefix: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.title.starts_with(prefix)).collect()
}

/// A price value read from a program-owned market account flows into a token-CPI
/// amount with no quality bound — SAT041 must fire (the Mango mark-price class).
#[test]
fn market_price_to_cpi_amount_fires() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub struct Market {
    pub version: u8,
    pub mark_price: u64,
}

impl Market {
    pub fn load(account: &AccountInfo) -> Result<Market, solana_program::program_error::ProgramError> {
        let data = account.data.borrow();
        Ok(Market { version: data[0], mark_price: u64::from_le_bytes(data[1..9].try_into().unwrap()) })
    }
}

fn spl_token_transfer(_src: &AccountInfo, _dst: &AccountInfo, _amount: u64, _disc: &[u8; 8]) -> Instruction {
    Instruction::new_with_borsh(solana_program::token::ID, _disc, vec![])
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let market = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let borrower = next_account_info(accounts_iter)?;

    let market_state = Market::load(market)?;
    let borrow_amount = market_state.mark_price;

    // The price value reaches the CPI as an amount argument.
    invoke(
        &spl_token_transfer(vault, borrower, borrow_amount, &[0u8; 8]),
        &[vault.clone(), borrower.clone()],
    )?;

    Ok(())}
"#;
    let (_, findings) = run(source);
    let flagged = by_rule(&findings, SAT041);
    assert!(!flagged.is_empty(), "market mark_price -> CPI amount with no bound must fire SAT041: {findings:#?}");
    assert!(
        flagged.iter().all(|f| f.severity == Severity::High),
        "SAT041 should be High: {:#?}",
        flagged.iter().map(|f| f.severity).collect::<Vec<_>>()
    );
}

/// A price value that passes a confidence/age bound before the sink is
/// validated usage — SAT041 must stay silent.
#[test]
fn bounded_price_does_not_fire() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub struct Market {
    pub version: u8,
    pub mark_price: u64,
    pub conf: u64,
    pub publish_time: u64,
}

impl Market {
    pub fn load(account: &AccountInfo) -> Result<Market, solana_program::program_error::ProgramError> {
        let data = account.data.borrow();
        Ok(Market { version: data[0], mark_price: u64::from_le_bytes(data[1..9].try_into().unwrap()), conf: u64::from_le_bytes(data[9..17].try_into().unwrap()), publish_time: u64::from_le_bytes(data[17..25].try_into().unwrap()) })
    }
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let market = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let borrower = next_account_info(accounts_iter)?;
    let token_prog = next_account_info(accounts_iter)?;

    let market_state = Market::load(market)?;

    // Quality bounds before the value decision.
    if market_state.conf * 100 > market_state.mark_price {
        return Err(solana_program::program_error::ProgramError::InvalidAccountData);
    }

    let borrow_amount = market_state.mark_price;

    let transfer = Instruction::new_with_borsh(
        *token_prog.key,
        &[1u8; 8],
        vec![
            AccountMeta::new(*vault.key, false),
            AccountMeta::new_readonly(*borrower.key, true),
        ],
    );
    invoke(&transfer, &[vault.clone(), borrower.clone()])?;

    let _ = borrow_amount;
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(by_rule(&findings, SAT041).is_empty(), "confidence-bounded price must not fire SAT041: {findings:#?}");
}

/// A feed-named oracle account whose price flows to a sink but has no bound is
/// still a SAT041 flow (feeds are also price sources).
#[test]
fn unbound_feed_price_to_sink_fires() {
    let source = r#"
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

fn spl_token_transfer(_src: &AccountInfo, _dst: &AccountInfo, _amount: u64, _disc: &[u8; 8]) -> Instruction {
    Instruction::new_with_borsh(solana_program::token::ID, _disc, vec![])
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let pyth_oracle = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let borrower = next_account_info(accounts_iter)?;
    let token_prog = next_account_info(accounts_iter)?;

    // A feed price field read directly (SAT034-036 would flag the missing
    // bound; SAT041 additionally flags the unbound value reaching a sink).
    let feed_price = pyth_oracle.price;

    invoke(
        &spl_token_transfer(vault, borrower, feed_price, &[0u8; 8]),
        &[vault.clone(), borrower.clone()],
    )?;

    let _ = token_prog;
    Ok(())
}
"#;
    let (_, findings) = run(source);
    assert!(
        !by_rule(&findings, SAT041).is_empty(),
        "feed price value reaching a sink with no bound must fire SAT041: {findings:#?}"
    );
}
