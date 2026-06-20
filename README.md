# Solana Audit Toolkit (`sat`)

A command-line utility and framework for security researchers, smart contract auditors, and developers to identify vulnerabilities, perform advanced verification, and document findings in Anchor-based Solana programs.

## Features

- **IDL State Transition Analysis** — Build programmatic state-machine models from Anchor IDLs to detect reinitialization attacks, state lockouts, and access control gaps.
- **AST-Based Static Analysis** — Parse Rust source with `syn` to find missing signer/owner constraints, CPI depth overflows, discriminator collisions, sysvar misuse, and serialization mismatches.
- **ProgramTest Fuzzing Engine** — Generate and execute state-aware fuzzers with auto-generated security invariants.
- **Token-2022 Analysis** — Detect and audit Token-2022 extensions for transfer fee bypass, permanent delegate abuse, and integration issues.
- **Audit Findings Generator** — Interactive CLI to create structured markdown reports with YAML front-matter.

## Installation

```bash
cargo install --path crates/sat
```

## Usage

```bash
# Analyze Anchor IDL for state transition vulnerabilities
sat analyze idl [PATH_TO_IDL]

# Run AST-based static analysis with SARIF output
sat analyze src [PATH_TO_SRC] --format sarif

# Cross-tool correlation with transaction analysis reports
sat analyze src --tx-report path/to/report.json

# Initialize a ProgramTest cargo-fuzz harness
sat fuzz init

# Run the state-machine fuzzer
sat fuzz run

# Create a new audit finding report
sat report new
```

## Project Structure

```
solana-audit-toolkit/
├── crates/
│   └── sat/               # Main CLI crate
├── tests/
│   └── fixtures/          # Test fixtures (vulnerable + clean Anchor programs)
├── audit-findings/        # Pre-shipped audit finding writeups
├── .github/workflows/     # CI pipelines
├── Cargo.toml             # Workspace root
└── PRD.md                 # Product Requirements Document
```

## License

MIT
