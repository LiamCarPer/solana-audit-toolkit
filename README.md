# Solana Audit Toolkit (`sat`)

[![Test](https://github.com/LiamCarPer/solana-audit-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/LiamCarPer/solana-audit-toolkit/actions/workflows/test.yml)
[![Self-Audit](https://github.com/LiamCarPer/solana-audit-toolkit/actions/workflows/sat-self-audit.yml/badge.svg)](https://github.com/LiamCarPer/solana-audit-toolkit/actions/workflows/sat-self-audit.yml)
[![watch](https://github.com/LiamCarPer/solana-audit-toolkit/actions/workflows/watch.yml/badge.svg)](https://github.com/LiamCarPer/solana-audit-toolkit/actions/workflows/watch.yml)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./README.md#license)

A static analysis and fuzzing toolkit for Anchor-based Solana programs. Parses IDL and Rust source via `syn` to find missing signer constraints, reinitialization vectors, CEI ordering violations, unsafe account closing, overflow-prone arithmetic, CPI depth violations, Token-2022 extension risks, and more — before the program hits mainnet.

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

### `sat analyze src [PATH] [--format text|json|sarif] [--triage] [--tx-report PATH] [--config sat.toml] [--fail-on SEV]`

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
- **CEI ordering violations** — walks instruction bodies, flags state writes that occur after `invoke()`/`invoke_signed()` calls. References the $320M Wormhole hack rationale.
- **Account closing safety** — detects `try_borrow_mut_lamports()` or direct `.lamports` manipulation when the program lacks `#[account(close = ...)]` constraints.
- **CPI depth tracking** — traces `invoke()` / `invoke_signed()` call chains, flags depths exceeding Solana's limit of 4
- **Sysvar misuse** — instructions calling `Clock::get()`, `Rent::get()`, etc. without declaring the sysvar account, and sysvars incorrectly marked writable
- **Serialization mismatch** — field width differences between `#[account]` storage structs and instruction argument structs (e.g. `u32` in args, `u64` on-chain)
- **PDA seed cross-check** — compares IDL-declared PDA seeds against `#[account(seeds = ...)]` constraints and flags divergences that enable account substitution
- **Init-if-needed audit** — flags authority-bearing accounts using `#[account(init_if_needed, ...)]` without an initialization guard; a front-running class where an attacker can initialize the account first with their own authority
- **Token-CPI authority verification** — `transfer` / `set_authority` CPIs whose authority account is not constrained as a signer
- **Manual deserialization audit** — account data deserialized from raw bytes without owner or discriminator validation

**Token-2022:**
- Detects usage via program ID, `Cargo.toml` dependency, and `InterfaceAccount<TokenAccount>` / `InterfaceAccount<Mint>` types
- Audits for **transfer fee bypass**, **permanent delegate abuse**, **interest-bearing token integration** issues

**Cross-tool:** `--tx-report <json>` ingests transaction analysis reports from [rust-security-toolkit](https://github.com/LiamCarPer/rust-security-toolkit) and flags runtime signer/writable mismatches against declared constraints.

**CI:** `--format sarif` exports to `sat-results.sarif` for GitHub Code Scanning; `--format json` prints a machine-readable report to stdout. `--fail-on <critical|high|medium|low|info|none>` exits non-zero (2) when any finding is at or above the threshold, so pipelines gate automatically.

**Baseline (adopt without noise):** snapshot the current accepted findings once, then report/gate only on regressions. Finding identity ignores line drift, so moved code is not a "new" finding.

```bash
# accept the current state once
sat analyze src programs/vault/src --baseline .sat-baseline.json --update-baseline
# CI: fail only on findings introduced after the baseline
sat analyze src programs/vault/src --baseline .sat-baseline.json --fail-on high
```

**Configuration (`sat.toml`):** tune the scan without recompiling — discovered from the working directory or passed via `--config`:

```toml
fail_on = "high"                     # default threshold (CLI --fail-on wins)
exclude = ["tests/", "migrations/"]  # drop findings whose location contains these
disabled_rules = ["SAT026"]          # rule ids to drop

[severity_overrides]
SAT012 = "low"                       # remap a rule's severity
```

**Bug bounty triage:** `--triage` suppresses the structural summaries and prints a prioritized queue with confidence, affected accounts, and the first manual verification step.

### `sat fuzz init` / `sat fuzz run`

Generates a `fuzzer/` sub-crate from the Anchor IDL:

- `FuzzInstruction` enum with `#[derive(Arbitrary)]` — one variant per instruction
- Anchor instruction discriminators prepended to generated instruction data
- IDL-derived account metas, deterministic placeholder accounts, and before/after account snapshots
- Baseline security invariants: account drain detection, authority immutability, state integrity
- Extension hooks for token supply preservation and vault balance consistency once program-specific account factories are filled in
- `libfuzzer-sys` harness with `solana-program-test` + `BanksClient`
- `sat fuzz run` builds and executes with `cargo fuzz` (60s timeout)

The generated fuzzer is intentionally honest: it is useful scaffolding immediately, but meaningful deep execution still requires replacing placeholder account data with target-specific account layouts.

### `sat verify init`

Generates a `formal-verification/` sub-crate for Kani-based formal verification:

- Kani mocks for `AccountInfo`, `Clock`, and `Rent` so proof harnesses run without a Solana runtime
- Checked-arithmetic templates covering overflow, underflow, and wrapping paths
- `#[kani::proof]` harnesses for security-sensitive instruction logic
- Run with `cargo kani` from the generated crate

The generated harnesses encode the same invariants the analyzer checks statically, giving a machine-checked second opinion before deploy.

### `sat audit [PATH] [--out FILE] [--format md|html] [--tx-report PATH]`

Runs the full analysis and writes a professional report — a metadata header, an executive summary with severity/confidence distributions, findings grouped by rule, and a fixed scope/honest-limitations section. `--format html` emits a **self-contained** HTML report (embedded CSS, no external assets), ready as a client deliverable or CI artifact.

```bash
sat audit programs/vault/src --out vault-audit.html --format html
```

### `sat hunt [PATH] [--out FILE] [--format md|json]`

Turns a raw finding dump into a **ranked, bounty-oriented lead brief**: each lead is annotated with the payout class it enables, the real-world precedent (`docs/EXPLOIT_CORPUS.md`), and the first manual-verification step. Ranking is payout class × severity × confidence, with high-confidence leads separated from a low-confidence coverage map.

```bash
sat hunt programs/vault/src --out hunt.md
```

This is the triage accelerator for a hunt cycle — not an autopilot. Every lead still needs manual confirmation and a PoC before submission.

### `sat report new`

Interactive CLI to create structured markdown audit findings with YAML front-matter. Auto-increments `SAT-XXX` IDs from existing files in `audit-findings/`. Outputs slugified filenames (e.g. `SAT-001-missing-signer-check.md`).

## GitHub Action

Use `sat` as a step in any Solana program repo — it builds the tool, scans, uploads SARIF to Code Scanning, and can gate the job on severity:

```yaml
name: security
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload

jobs:
  sat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: LiamCarPer/solana-audit-toolkit@main
        with:
          path: programs/vault/src
          format: sarif
          fail-on: high            # fail the job on HIGH/CRITICAL findings
          args: "--config sat.toml"
```

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `programs` | Source directory or file to scan |
| `format` | `sarif` | `text`, `json`, or `sarif` |
| `fail-on` | `none` | `critical\|high\|medium\|low\|info\|none` — non-zero exit above threshold |
| `args` | — | Extra args to `sat analyze src` (e.g. `--config sat.toml`) |

**Output:** `sarif-file` — path to the generated SARIF report.

## `parity` — Differential/Behavioral Engine

Static pattern rules find textbook bugs; audited code has none left. `parity` (a companion binary in this workspace) finds the bugs that **survive audits** — rounding asymmetries, interest/index accounting drift, sequence-dependent state — by running the **same normalized scenario** against two implementations of a primitive and reporting where their observable state diverges.

- **Reference model** — a small exact model of the protocol math (shares, index interest, explicit rounding direction), authored from source.
- **Candidate** — a sibling protocol or (roadmap) a `solana-program-test` adapter executing the real program.
- The engine does the mechanical work (execution, normalization, diffing, minimal repro, reporting); the AI does the protocol-logic reasoning.

```bash
# prove the engine works: reference vs a known rounding bug (free money)
cargo run -p parity -- demo

# run a scenario; exits 2 on divergence (CI-gateable)
cargo run -p parity -- run --scenario parity-scenario.json
```

See `docs/PARITY.md` for the design and the roadmap (cross-implementation parity, `program-test` backend, fork mode).

## Bug Bounty Workflow

See `docs/BUG_BOUNTY_WORKFLOW.md` for the recommended loop: triage, manual verification, PoC construction, false-positive control, and fuzzer follow-up.

**Bounty-finder checks:** the init-if-needed, token-CPI, and manual-deserialization audits target exploit classes tracked in `docs/EXPLOIT_CORPUS.md` — the corpus maps each finding class to the bounty root cause it enables.

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
│   ├── deserialization.rs     Manual deserialization audit
│   ├── tx_report.rs          Cross-tool transaction correlation
│   ├── cpi.rs                CPI depth tracking
│   ├── idl.rs                IDL parsing + state transition analysis
│   ├── init_guard.rs         Init-if-needed audit
│   ├── token2022.rs          Token-2022 detection + auditing
│   ├── token_cpi.rs          Token-CPI authority verification
│   ├── reporter.rs           Interactive finding generator
│   ├── fuzzer.rs             Fuzz harness generation
│   ├── pda.rs                PDA seed cross-check (IDL vs. Anchor constraints)
│   ├── sarif.rs              SARIF 2.1.0 export
│   ├── types.rs              Shared types (Finding, Severity)
│   ├── ui.rs                 Colored terminal helpers
│   └── verify.rs             Kani formal-verification scaffolding generator
├── crates/sat/tests/
│   ├── idl_analysis.rs       18 tests (IDL parsing, state model, findings)
│   ├── ast_analysis.rs       43 tests (signer, owner, mut, seeds, CEI, closing, SARIF)
│   ├── cei_analysis.rs       9 tests (CEI ordering incl. nested blocks)
│   ├── pda_seed_analysis.rs  6 tests (PDA seed cross-check)
│   ├── init_guard_analysis.rs      Init-if-needed audit tests
│   ├── token_cpi_analysis.rs       Token-CPI authority verification tests
│   ├── deserialization_analysis.rs Manual deserialization audit tests
│   ├── sarif_rules.rs        5 tests (SARIF rule classification)
│   └── fixtures/             IDL JSON + Anchor Rust fixtures
├── audit-findings/            Pre-shipped finding writeups
├── .github/workflows/
│   ├── test.yml               CI: fmt, clippy, build, test
│   └── sat-self-audit.yml     Self-audit pipeline
└── PRD.md                    Product Requirements Document
```

## License

MIT
