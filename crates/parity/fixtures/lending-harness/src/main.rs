//! `lending-harness` — runs a tiny lending program in `solana-program-test`
//! and emits a canonical `parity::Trace`, proving the P2 path: the differential
//! engine comparing a **real Solana program** against the reference model.
//!
//! Two program variants are registered: the correct one (ceil shares on
//! withdraw) and a buggy one (floor shares on withdraw). The buggy variant lets
//! `parity run --actual-trace` demonstrate divergence detection end to end.
//!
//! Usage: `lending-harness --program ok|bug [--out trace.json]`

use anyhow::{Context, Result};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::Signer,
    transaction::Transaction,
};

use parity::{Observables, Trace, TraceStep};

// ── On-chain program ─────────────────────────────────────────────────────────

const TAG_DEPOSIT: u8 = 0;
const TAG_WITHDRAW: u8 = 1;
const TAG_BORROW: u8 = 2;
const TAG_REPAY: u8 = 3;
const TAG_ACCRUE: u8 = 4;

/// Reserve account layout (48 bytes): four u64 counters + price + rate.
const RESERVE_LEN: usize = 48;
/// User account layout (16 bytes): shares + balance.
const USER_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Correct: shares burned on withdraw round UP (protects the pool).
    Correct,
    /// Bug: shares burned on withdraw round DOWN (free money).
    Buggy,
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn div_round(num: u64, den: u64, up: bool) -> u64 {
    if den == 0 {
        return 0;
    }
    let q = num / den;
    let r = num % den;
    if up && r != 0 { q + 1 } else { q }
}

fn process(accounts: &[AccountInfo], data: &[u8], mode: Mode) -> ProgramResult {
    let iter = &mut accounts.iter();
    let reserve_ai = next_account_info(iter)?;
    let user_ai = next_account_info(iter)?;

    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let tag = data[0];
    let arg = if data.len() >= 9 { read_u64(data, 1) } else { 0 };

    let mut reserve = reserve_ai.try_borrow_mut_data()?;
    let mut user = user_ai.try_borrow_mut_data()?;
    if reserve.len() < RESERVE_LEN || user.len() < USER_LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut total_deposits = read_u64(&reserve, 0) as u128;
    let mut total_borrows = read_u64(&reserve, 8) as u128;
    let mut total_shares = read_u64(&reserve, 16) as u128;
    let mut vault_balance = read_u64(&reserve, 24) as u128;
    let rate_bps = read_u64(&reserve, 40) as u128;
    let mut user_shares = read_u64(&user, 0) as u128;
    let mut user_balance = read_u64(&user, 8) as u128;
    let amount = arg as u128;

    match tag {
        TAG_DEPOSIT => {
            if amount > user_balance {
                return Err(ProgramError::InsufficientFunds);
            }
            let shares = if total_shares == 0 || total_deposits == 0 {
                amount
            } else {
                (amount * total_shares / total_deposits) as u128
            };
            user_balance -= amount;
            user_shares += shares;
            total_shares += shares;
            total_deposits += amount;
            vault_balance += amount;
        }
        TAG_WITHDRAW => {
            let shares = if total_shares == 0 || total_deposits == 0 {
                amount
            } else {
                let raw = amount * total_shares;
                let up = mode == Mode::Correct;
                div_round(raw as u64, total_deposits as u64, up) as u128
            };
            if shares > user_shares {
                return Err(ProgramError::InsufficientFunds);
            }
            user_shares -= shares;
            total_shares -= shares;
            total_deposits = total_deposits.saturating_sub(amount);
            vault_balance = vault_balance.saturating_sub(amount);
            user_balance += amount;
        }
        TAG_BORROW => {
            if amount > vault_balance {
                return Err(ProgramError::InsufficientFunds);
            }
            total_borrows += amount;
            vault_balance -= amount;
            user_balance += amount;
        }
        TAG_REPAY => {
            let amount = amount.min(total_borrows);
            total_borrows -= amount;
            vault_balance += amount;
            user_balance = user_balance.saturating_sub(amount);
        }
        TAG_ACCRUE => {
            let interest = total_borrows * rate_bps * (arg as u128) / 10_000;
            total_deposits += interest;
            total_borrows += interest;
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    write_u64(&mut reserve, 0, total_deposits as u64);
    write_u64(&mut reserve, 8, total_borrows as u64);
    write_u64(&mut reserve, 16, total_shares as u64);
    write_u64(&mut reserve, 24, vault_balance as u64);
    write_u64(&mut user, 0, user_shares as u64);
    write_u64(&mut user, 8, user_balance as u64);
    Ok(())
}

fn process_correct(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    process(accounts, data, Mode::Correct)
}

fn process_buggy(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    process(accounts, data, Mode::Buggy)
}

// ── Harness ──────────────────────────────────────────────────────────────────

/// The demo scenario ops (must match `parity demo`).
fn demo_ops() -> Vec<(u8, u64)> {
    vec![
        (TAG_DEPOSIT, 1_000),
        (TAG_DEPOSIT, 1_000),
        (TAG_BORROW, 500),
        (TAG_ACCRUE, 1_000),
        (TAG_WITHDRAW, 333),
    ]
}

/// Encode `[tag][arg][nonce]`. The nonce is ignored by the program but makes
/// each transaction unique, so repeated identical ops are not rejected as
/// duplicate signatures by the test bank.
fn encode(tag: u8, arg: u64, nonce: u64) -> Vec<u8> {
    let mut data = vec![tag];
    data.extend_from_slice(&arg.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    data
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut program = "ok".to_string();
    let mut out: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--program" => {
                program = args.get(i + 1).cloned().unwrap_or_else(|| "ok".to_string());
                i += 2;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                i += 2;
            }
            other => anyhow::bail!("unknown argument `{other}` (expected --program ok|bug [--out FILE])"),
        }
    }

    let program_id = Pubkey::new_from_array([7u8; 32]);
    let mut program_test = match program.as_str() {
        "ok" => ProgramTest::new("lending_ok", program_id, processor!(process_correct)),
        "bug" => ProgramTest::new("lending_bug", program_id, processor!(process_buggy)),
        other => anyhow::bail!("unknown program `{other}` (expected ok|bug)"),
    };

    // Reserve: zero counters, price=1, rate=1 bps/second (matches `parity demo`).
    let reserve_key = Pubkey::new_from_array([1u8; 32]);
    let mut reserve_data = vec![0u8; RESERVE_LEN];
    write_u64(&mut reserve_data, 32, 1); // price
    write_u64(&mut reserve_data, 40, 1); // rate_bps_per_second
    program_test.add_account(
        reserve_key,
        Account {
            lamports: 1_000_000_000,
            data: reserve_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // User: initial balance 1_000_000 (matches the scenario account spec).
    let user_key = Pubkey::new_from_array([2u8; 32]);
    let mut user_data = vec![0u8; USER_LEN];
    write_u64(&mut user_data, 8, 1_000_000);
    program_test.add_account(
        user_key,
        Account {
            lamports: 1_000_000_000,
            data: user_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let context = program_test.start_with_context().await;
    let mut banks_client = context.banks_client;
    let payer = context.payer;
    let recent_blockhash = context.last_blockhash;

    let mut steps = Vec::new();
    for (op_index, (tag, arg)) in demo_ops().into_iter().enumerate() {
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(reserve_key, false), AccountMeta::new(user_key, false)],
            data: encode(tag, arg, op_index as u64),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        let error = match banks_client.process_transaction(tx).await {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        };

        let reserve = banks_client
            .get_account(reserve_key)
            .await
            .context("fetch reserve")?
            .context("reserve missing")?;
        let user = banks_client
            .get_account(user_key)
            .await
            .context("fetch user")?
            .context("user missing")?;

        let observables = Observables {
            total_deposits: read_u64(&reserve.data, 0),
            total_borrows: read_u64(&reserve.data, 8),
            total_shares: read_u64(&reserve.data, 16),
            vault_balance: read_u64(&reserve.data, 24),
            user_shares: read_u64(&user.data, 0),
            user_balance: read_u64(&user.data, 8),
            price: read_u64(&reserve.data, 32),
        };
        steps.push(TraceStep { op_index, observables, error });
    }

    let trace = Trace {
        scenario: "lending-demo".to_string(),
        model: format!("lending-{program}"),
        steps,
    };

    let json = trace.to_json();
    match out {
        Some(path) => {
            std::fs::write(&path, &json).with_context(|| format!("failed to write {path}"))?;
            eprintln!("wrote trace to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}
