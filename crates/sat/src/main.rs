use anyhow::Result;
use clap::{Parser, Subcommand};

mod analyzer;
mod cpi;
mod fuzzer;
mod idl;
mod reporter;
mod sarif;
mod token2022;
mod types;
mod ui;

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
        /// Path to transaction analysis report JSON for cross-tool correlation
        #[arg(long)]
        tx_report: Option<String>,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { target } => match target {
            AnalyzeTarget::Idl { path } => idl::run(path.as_deref()),
            AnalyzeTarget::Src { path, format, tx_report } => {
                analyzer::run(path.as_deref(), &format, tx_report.as_deref())
            }
        },
        Commands::Fuzz { action } => match action {
            FuzzAction::Init => fuzzer::init(),
            FuzzAction::Run => fuzzer::run(),
        },
        Commands::Report { action } => match action {
            ReportAction::New => reporter::new_finding(),
        },
        Commands::Version => {
            ui::print_banner();
            Ok(())
        }
    }
}
