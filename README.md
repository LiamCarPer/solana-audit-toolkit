# Solana Audit Toolkit (`sat`)

A static analysis and fuzzing toolkit for Anchor-based Solana programs. Parses IDL and Rust source via `syn` to find missing signer constraints, reinitialization vectors, overflow-prone arithmetic, CPI depth violations, Token-2022 extension risks, and more — before the program hits mainnet.

```
$ sat analyze src programs/vault/
Summary: 4 findings: [CRIT] 1 CRITICAL | [HIGH] 2 HIGH | [MED] 1 MEDIUM
```

## Installation

```bash
cargo install --path crates/sat
```

Requires Rust 1.85+ (edition 2024).

## Commands

### `sat analyze idl [PATH]`

Parses an Anchor IDL JSON to build a state-machine model of the contract.

- Identifies state structs and their fields (init flags, authority keys, status enums)
- Classifies every instruction as Initializer, Mutator, or Terminator
- Builds a directed state transition graph
- Detects: **reinitialization attacks**, **state lockouts**, **missing access control**, **discriminator collisions**, **missing initializers**

### `sat analyze src [PATH] [--format text|sarif] [--tx-report PATH]`

Parses Rust source with `syn` to analyze `#[derive(Accounts)]` and `#[program]` structures.

**Core checks:**
- **Missing signer** — authority-named fields without `#[account(signer)]` or `Signer<'info>`
- **Missing owner** — `AccountInfo` / `UncheckedAccount` without `#[account(owner = ...)]`
- **Missing `mut`** — accounts written to per IDL but not marked `#[account(mut)]`
- **Missing `has_one`** — Signer authorities not linked to their stored pubkey via `#[account(has_one = ...)]`
- **Reinitialization risk** — `#[account(mut)]` used where `#[account(init)]` is expected
- **Unsafe arithmetic** — `-=`, `+=`, `*` operators on account fields that may silently wrap in release mode
- **Discriminator collisions** — two instructions in the same program hashing to the same 8-byte prefix

**Advanced checks:**
- **CPI depth tracking** — traces `invoke()` / `invoke_signed()` call chains, flags depths exceeding Solana's limit of 4
- **Sysvar misuse** — instructions calling `Clock::get()`, `Rent::get()`, etc. without declaring the sysvar account, and sysvars incorrectly marked writable
- **Serialization mismatch** — field width differences between `#[account]` storage structs and instruction argument structs (e.g. `u32` in args, `u64` on-chain)

**Token-2022:**
- Detects usage via program ID, `Cargo.toml` dependency, and `InterfaceAccount<TokenAccount>` / `InterfaceAccount<Mint>` types
- Audits for **transfer fee bypass**, **permanent delegate abuse**, **interest-bearing token integration** issues

**Cross-tool:** `--tx-report <json>` ingests transaction analysis reports from [rust-security-toolkit](https://github.com/LiamCarPer/rust-security-toolkit) and flags runtime signer/writable mismatches against declared constraints.

**CI:** `--format sarif` exports to `sat-results.sarif` for GitHub Code Scanning.

### `sat fuzz init` / `sat fuzz run`

Generates a complete `fuzzer/` sub-crate from the Anchor IDL:

- `FuzzInstruction` enum with `#[derive(Arbitrary)]` — one variant per instruction
- Auto-generated security invariants: token supply preservation, vault balance consistency, no negative balances, authority immutability, state integrity
- `libfuzzer-sys` harness with `solana-program-test` + `BanksClient`
- `sat fuzz run` builds and executes with `cargo fuzz` (60s timeout)

### `sat report new`

Interactive CLI to create structured markdown audit findings with YAML front-matter. Auto-increments `SAT-XXX` IDs from existing files in `audit-findings/`. Outputs slugified filenames (e.g. `SAT-001-missing-signer-check.md`).

## Shipped Audit Findings

The `audit-findings/` directory contains three pre-written vulnerability analyses that demonstrate the toolkit's capabilities:

| ID | Title |
|----|-------|
| SAT-001 | Missing Signer Check on Authority Account |
| SAT-002 | PDA Seed Mismatch Enables Account Substitution |
| SAT-003 | Reinitialization Attack via Missing Initialization Guard |

Each includes YAML front-matter, exploit scenario, identification via `sat`, and remediation.

## Self-Audit

The toolkit runs against its own source in CI (`.github/workflows/sat-self-audit.yml`):

```bash
sat analyze src crates/sat/src --format sarif
```

## Project Structure

```
├── crates/sat/src/
│   ├── main.rs              CLI entry point (clap)
│   ├── analyzer.rs           Core source parsing + analysis passes
│   ├── render.rs             Terminal output rendering
│   ├── sysvar.rs             Sysvar misuse detection
│   ├── serialization.rs      Borsh/Anchor field width comparison
│   ├── tx_report.rs          Cross-tool transaction correlation
│   ├── cpi.rs                CPI depth tracking
│   ├── idl.rs                IDL parsing + state transition analysis
│   ├── token2022.rs          Token-2022 detection + auditing
│   ├── reporter.rs           Interactive finding generator
│   ├── fuzzer.rs             Fuzz harness generation
│   ├── sarif.rs              SARIF 2.1.0 export
│   ├── types.rs              Shared types (Finding, Severity)
│   └── ui.rs                 Colored terminal helpers
├── crates/sat/tests/
│   ├── idl_analysis.rs       18 tests (IDL parsing, state model, findings)
│   ├── ast_analysis.rs       21 tests (signer, owner, mut, seeds, SARIF)
│   └── fixtures/             IDL JSON + Anchor Rust fixtures
├── audit-findings/            Pre-shipped finding writeups
├── .github/workflows/
│   ├── test.yml               CI: fmt, clippy, build, test
│   └── sat-self-audit.yml     Self-audit pipeline
└── PRD.md                    Product Requirements Document
```

## License

MIT
