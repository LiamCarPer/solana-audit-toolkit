//! `parity` CLI — run differential scenarios and emit reports.

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use parity::model::Rounding;
use parity::scenario::{AccountSpec, Config, Invariant, Op, Role, Scenario};
use parity::{LendingModel, ProgramModel, compare, report};

#[derive(Parser)]
#[command(name = "parity", version, about = "Differential/behavioral engine for Solana protocol hunts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a scenario differentially (reference vs candidate) and report divergences.
    Run {
        /// Scenario JSON file.
        #[arg(long)]
        scenario: String,
        /// Candidate's share-burn rounding on withdraw (`up` protects the pool; `down` is the bug).
        #[arg(long, default_value = "up")]
        candidate_withdraw_rounding: String,
        /// Candidate's share-mint rounding on deposit.
        #[arg(long, default_value = "down")]
        candidate_deposit_rounding: String,
        /// Output report file (defaults to parity-report.md / .json).
        #[arg(long)]
        out: Option<String>,
        /// Output format: md or json.
        #[arg(long, default_value = "md")]
        format: String,
    },
    /// Run the built-in lending demo (reference vs a known rounding bug).
    Demo {
        /// Output report file (defaults to parity-demo.md).
        #[arg(long)]
        out: Option<String>,
    },
    /// Write a starter scenario JSON to edit (or hand to the AI).
    Init {
        /// Output path.
        #[arg(long, default_value = "parity-scenario.json")]
        out: String,
    },
}

fn parse_rounding(s: &str) -> Result<Rounding> {
    match s.to_ascii_lowercase().as_str() {
        "up" | "ceil" => Ok(Rounding::Up),
        "down" | "floor" => Ok(Rounding::Down),
        other => anyhow::bail!("unknown rounding `{other}` (expected up|down)"),
    }
}

fn run_and_report(
    scenario: &Scenario,
    expected: &mut dyn ProgramModel,
    actual: &mut dyn ProgramModel,
    out: Option<&str>,
    format: &str,
) -> Result<bool> {
    let report_data = compare(scenario, expected, actual);
    let (body, default_name) = if format.eq_ignore_ascii_case("json") {
        (report::render_json(&report_data, scenario), "parity-report.json")
    } else {
        (report::render_markdown(&report_data, scenario), "parity-report.md")
    };

    let path = out.unwrap_or(default_name);
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, body).with_context(|| format!("failed to write report to {path}"))?;

    if report_data.is_clean() {
        println!("CLEAN (parity) — {} op(s), report: {path}", scenario.ops.len());
    } else {
        println!(
            "DIVERGED — first divergence at op {} ({} divergence(s), {} violation(s)), report: {path}",
            report_data.first_divergence_op.map(|i| i.to_string()).unwrap_or_else(|| "?".to_string()),
            report_data.divergences.len(),
            report_data.violations.len()
        );
    }
    Ok(report_data.is_clean())
}

/// A built-in lending scenario that exercises interest accrual (which breaks
/// 1:1 share parity) and a non-exact withdrawal.
fn demo_scenario() -> Scenario {
    Scenario {
        name: "lending-demo".to_string(),
        description: "deposit, borrow, accrue interest, then a non-exact withdraw".to_string(),
        config: Config { price: 1, rate_bps_per_second: 1 },
        accounts: vec![AccountSpec { role: Role::User, name: "user".to_string(), initial: 1_000_000 }],
        ops: vec![
            Op::Deposit { user: "user".to_string(), amount: 1_000 },
            Op::Deposit { user: "user".to_string(), amount: 1_000 },
            Op::Borrow { user: "user".to_string(), amount: 500 },
            Op::Accrue { seconds: 1_000 },
            Op::Withdraw { user: "user".to_string(), amount: 333 },
        ],
        invariants: vec![Invariant::Solvency, Invariant::ShareConservation, Invariant::VaultBacking],
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { scenario, candidate_withdraw_rounding, candidate_deposit_rounding, out, format } => {
            let text =
                std::fs::read_to_string(&scenario).with_context(|| format!("failed to read scenario {scenario}"))?;
            let scenario = Scenario::from_json(&text).context("invalid scenario JSON")?;

            let w = parse_rounding(&candidate_withdraw_rounding)?;
            let d = parse_rounding(&candidate_deposit_rounding)?;

            // Reference: protocol-favourable rounding (ceil shares on withdraw).
            let mut expected = LendingModel::reference(&scenario).named("reference");
            let mut actual = LendingModel::with_rounding(&scenario, w, d).named("candidate");

            let clean = run_and_report(&scenario, &mut expected, &mut actual, out.as_deref(), &format)?;
            if !clean {
                std::process::exit(2);
            }
            Ok(())
        }
        Command::Demo { out } => {
            let scenario = demo_scenario();
            let mut expected = LendingModel::reference(&scenario).named("reference");
            // The candidate rounds shares DOWN on withdraw — it lets a user
            // burn fewer shares than the value withdrawn (free money).
            let mut actual =
                LendingModel::with_rounding(&scenario, Rounding::Down, Rounding::Down).named("candidate(buggy)");
            run_and_report(&scenario, &mut expected, &mut actual, out.as_deref(), "md")?;
            Ok(())
        }
        Command::Init { out } => {
            let scenario = demo_scenario();
            std::fs::write(&out, scenario.to_json()).with_context(|| format!("failed to write {out}"))?;
            println!("Wrote starter scenario to {out}");
            println!("Edit ops/invariants (or have the AI author them), then: parity run --scenario {out}");
            Ok(())
        }
    }
}
