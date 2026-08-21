use anyhow::Result;
use clap::{Parser, Subcommand};

mod analyzer;
mod audit;
mod calibrate;
mod cpi;
mod deserialization;
mod fuzzer;
mod fuzzer_layout;
mod fuzzer_seeds;
mod fuzzer_token2022;
mod idl;
mod init_guard;
mod native;
mod pda;
mod poc;
mod render;
mod reporter;
mod sarif;
mod serialization;
mod sysvar;
mod token2022;
mod token_cpi;
mod tx_report;
mod types;
mod ui;
mod verify;
mod watch;

#[derive(Parser)]
#[command(
    name = "sat",
    version = env!("CARGO_PKG_VERSION"),
    about = "Solana Audit Toolkit — vulnerability scanner and audit framework for Anchor-based Solana programs.",
    long_about = "The Solana Audit Toolkit (sat) is a command-line utility designed to aid \
                  security researchers, smart contract auditors, and developers in identifying \
                  vulnerabilities, performing advanced verification, and documenting findings \
                  in Anchor-based Solana programs."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze IDL or source code for vulnerabilities
    Analyze {
        #[command(subcommand)]
        target: AnalyzeTarget,
    },
    /// Generate and run state-machine fuzzers
    Fuzz {
        #[command(subcommand)]
        action: FuzzAction,
    },
    /// Create audit finding reports
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Generate an automated markdown audit report
    Audit {
        /// Path to the source directory or file (same as `analyze src`)
        path: Option<String>,
        /// Output markdown file
        #[arg(long, default_value = "audit-report.md")]
        out: String,
        /// Transaction analysis report JSON for correlation findings
        #[arg(long)]
        tx_report: Option<String>,
    },
    /// Diff findings across scans of watched program repos
    Watch {
        /// Watch configuration JSON (list of repos)
        config: String,
        /// Directory for scan state and clones
        #[arg(long, default_value = ".sat-watch")]
        out_dir: String,
    },
    /// Calibrate rule precision over a corpus of live programs
    Calibrate {
        /// Corpus configuration JSON (same shape as `watch`)
        config: String,
        /// Output precision report
        #[arg(long, default_value = "precision.md")]
        out: String,
    },
    /// Generate Kani formal-verification scaffolding
    Verify {
        #[command(subcommand)]
        action: VerifyAction,
    },
    /// Generate a runnable ProgramTest PoC for a finding
    Poc {
        /// Finding ID from a prior `sat analyze src` run (e.g. SAT-007)
        finding_id: String,
        /// Path to the source directory or file (same as `analyze src`)
        path: Option<String>,
        /// Output directory for the generated PoC crate
        #[arg(long, default_value = "pocs")]
        out_dir: String,
    },
    /// Print version information
    Version,
}

#[derive(Subcommand)]
enum AnalyzeTarget {
    /// Analyze Anchor IDL for state transition and reinitialization vulnerabilities
    Idl {
        /// Path to the idl.json file (defaults to ./target/idl/*.json)
        path: Option<String>,
    },
    /// Run AST-based static analysis on Rust source code
    Src {
        /// Path to the source directory or file (defaults to ./programs/)
        path: Option<String>,
        /// Output format: text or sarif
        #[arg(long, default_value = "text")]
        format: String,
        /// Show only prioritized findings with first manual verification step
        #[arg(long)]
        triage: bool,
        /// Path to transaction analysis report JSON for cross-tool correlation
        #[arg(long)]
        tx_report: Option<String>,
        /// Export source-derived native account expectations to a JSON file (consumable by rts)
        #[arg(long)]
        expectations: Option<String>,
        /// Filter confirmed-FP findings from a `sat calibrate` suppression export
        #[arg(long)]
        fp_suppressions: Option<String>,
    },
}

#[derive(Subcommand)]
enum FuzzAction {
    /// Initialize a ProgramTest cargo-fuzz harness in the workspace
    Init,
    /// Run the state-machine fuzzer against the local test environment
    Run,
}

#[derive(Subcommand)]
enum ReportAction {
    /// Interactively create a new audit finding report
    New,
}

#[derive(Subcommand)]
enum VerifyAction {
    /// Initialize a formal-verification crate in the workspace
    Init,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { target } => match target {
            AnalyzeTarget::Idl { path } => idl::run(path.as_deref()),
            AnalyzeTarget::Src { path, format, triage, tx_report, expectations, fp_suppressions } => analyzer::run(
                path.as_deref(),
                &format,
                triage,
                tx_report.as_deref(),
                expectations.as_deref(),
                fp_suppressions.as_deref(),
            ),
        },
        Commands::Fuzz { action } => match action {
            FuzzAction::Init => fuzzer::init(),
            FuzzAction::Run => fuzzer::run(),
        },
        Commands::Report { action } => match action {
            ReportAction::New => reporter::new_finding(),
        },
        Commands::Audit { path, out, tx_report } => audit::run(path.as_deref(), Some(&out), tx_report.as_deref()),
        Commands::Watch { config, out_dir } => watch::run(&config, &out_dir),
        Commands::Calibrate { config, out } => calibrate::run(&config, Some(&out)),
        Commands::Verify { action } => match action {
            VerifyAction::Init => verify::init(),
        },
        Commands::Poc { finding_id, path, out_dir } => poc::run(&finding_id, path.as_deref(), &out_dir),
        Commands::Version => {
            ui::print_banner();
            Ok(())
        }
    }
}
