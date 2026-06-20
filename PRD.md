# Product Requirements Document (PRD): Solana Audit Toolkit (`sat`)
**Author:** Liam Carvajal  
**Date:** June 20, 2026
---

## 1. Overview & Goal

The **Solana Audit Toolkit (`sat`)** is a command-line utility and framework designed to aid security researchers, smart contract auditors, and developers in identifying vulnerabilities, performing advanced verification, and documenting findings in Anchor-based Solana programs.

### 1.1 Objectives
- **Professional Credibility:** Act as a portfolio highlight for a security-oriented CV, showcasing deep knowledge of Rust AST parsing, Solana program mechanics, fuzzing, and static analysis.
- **Audit Efficiency:** Provide automated analysis, functional state fuzzing, and reporting tooling that can be used directly in real-world public audits to find and document bugs quickly.
- **Zero-Friction Integration:** Operate zero-config out of the box by scanning and understanding the directory layouts of standard Anchor workspaces.

---

## 2. Core Features & Specifications

### 2.1 Anchor IDL State Transition & Reinitialization Analyzer
#### Goal
Parse the standard Anchor IDL (`idl.json`) to construct a programmatic state-machine model of the contract and detect logical transition vulnerabilities, with a specific focus on initialization safety.
#### Functional Requirements
1. **State Struct/Enum Identification:** Identify types within the IDL that represent persistent contract state (e.g., configurations, vault state, user account structs, status enums).
2. **Instruction Mapping:** Categorize instructions by their mutation properties:
   - *Initializers:* Instructions initializing critical state.
   - *Mutators:* Instructions modifying state fields.
   - *Terminators:* Instructions closing accounts or resetting state.
3. **Reinitialization & Transition Analysis:** Build a directed graph showing how instructions transition state variables:
   - **Reinitialization Check:** Detect if an initializer instruction can be invoked from any state other than `Uninitialized`. Flag code patterns where an initialize instruction does not verify account ownership/initialization status, allowing existing state to be overwritten.
   - **State Lockout Detection:** Identify states where no instruction is defined to transition out of a specific state.
   - **Access Control Audit:** Flag instructions modifying state fields that lack admin/authority signer requirements in their account definitions.

---

### 2.2 AST-Based Static Analysis (`syn`)
#### Goal
Parse the Rust source code of the Anchor program to identify missing validation constraints and excessive invocation depths before compiling.
#### Functional Requirements
1. **Macro Derivation Scanning:** Parse source files to find structures implementing `#[derive(Accounts)]`.
2. **Proper Constraint Parsing:**
   - **Anchor Attribute Inspection:** Do not rely on field name regexes. Use `syn` to parse the actual attribute arguments within `#[account(...)]`.
   - **Unchecked Accounts:** Highlight fields of type `AccountInfo` or `UncheckedAccount` that lack `#[account(owner = ...)]` or validation checks.
   - **Missing Signer Verification:** Inspect the token stream of the `#[account(...)]` attributes to ensure critical accounts requiring authorization explicitly declare the `signer` constraint.
   - **Missing Mutability Restrictions:** Detect instances where state is updated in the instruction logic, but the corresponding account structure field is not marked as `mut`.
3. **CPI Depth Limit Tracking:**
    - Trace the occurrences of `invoke()` and `invoke_signed()` within instruction bodies.
    - Recursively estimate and flag path depths that risk exceeding the Solana max CPI depth limit of 4.
    - **Limitation:** Macro-generated or dynamically dispatched call chains (e.g., via function pointers or FFI) cannot be statically resolved. The tool detects single-function chains up to depth 4 with high confidence and emits a `CPI_DEPTH_UNRESOLVED` warning for call targets it cannot trace.
4. **Anchor Discriminator Collision Detection:**
    - Compute the 8-byte discriminator (`sha256("global:<instruction_name>")[0..8]`) for every instruction in the IDL.
    - Detect collisions where two different instruction names hash to the same 8-byte prefix — which would cause the wrong instruction handler to execute at runtime.
    - Report collisions with severity `CRITICAL` and recommend renaming the conflicting instructions.
5. **Sysvar Misuse Detection:**
    - Flag instructions that call sysvar accessors (e.g., `Clock::get()`, `Rent::get()`, `EpochSchedule::get()`) but do not declare the corresponding sysvar account in their `#[derive(Accounts)]` struct.
    - Detect sysvar accounts marked as `#[account(mut)]` or `writable` when the sysvar is inherently read-only — a common fee-locking vector.
6. **Borsh/Anchor Serialization Mismatch Detection:**
    - Compare field types between the `#[account]` storage struct and corresponding instruction input structs.
    - Flag mismatches where a field is `u64` in the storage struct but `u32` in the instruction deserializer, or where field ordering differs — leading to silent data truncation or corruption.
7. **SARIF Output Format:**
    - Implement support for the Static Analysis Results Interchange Format (SARIF) standard.
    - Enable integration with CI systems and GitHub Code Scanning by exporting warnings to `sat-results.sarif`.
8. **Cross-Tool Transaction Correlation:**
    - Add a `--tx-report <json>` flag to ingest transaction analysis reports generated by the `rust-security-toolkit` transaction decoder.
    - Parse the JSON report to map actual runtime account indexes, PDA seeds, and signer configurations back to AST structures parsed from `#[derive(Accounts)]` to flag validation gaps (e.g., an account declared with `signer` constraint in code but `is_signer = false` in the transaction).

---

### 2.3 ProgramTest Fuzzing Engine (`sat fuzz`)
#### Goal
Generate and execute a runnable, state-machine fuzzer using `solana-program-test` and `cargo-fuzz` that executes instructions against a mock bank to find real crash cases.
#### Functional Requirements
1. **Pre-Wired Harness Generation (`sat fuzz init`):** Generate a complete fuzzer sub-crate inside the workspace that includes a fully-configured cargo fuzzing setup.
2. **Instruction Execution Interface (`sat fuzz run`):** 
   - Compile and execute the generated fuzzer with `solana-program-test` + `BanksClient`.
   - Generate an `Arbitrary` enum matching all instructions in the IDL to fuzz state sequences dynamically.
   - Perform transactions directly against the local test validator environment to detect panics, out-of-bounds math, and invalid state transitions.
3. **Auto-Generated Security Invariants:** The fuzzer harness automatically generates and asserts these invariants without requiring user configuration:
    - **Token Supply Preservation:** Sum of all token account balances before and after transaction execution must remain equal (no minting or burning without explicit MintTo/Burn instructions).
    - **Vault Balance Consistency:** For programs with a vault pattern, `vault_balance >= sum(all_user_deposits)` at all states.
    - **No Negative Balances:** No token or native SOL account may hold a negative balance after any instruction.
    - **Authority Immutability:** Account authority/owner fields must not change after instructions that lack explicit ownership-transfer semantics.
    - **State Integrity:** Boolean/is_initialized fields must never transition from `true` to `false` (accounts cannot be un-initialized).

---

### 2.4 Token-2022 & Extension Analysis
#### Goal
Support the modern SPL Token-2022 standard and identify vulnerabilities arising from new token extension types.
#### Functional Requirements
1. **Extension Detection:** Identify Token-2022 usage through three mechanisms:
    - **Program ID Matching:** Check if any instruction's `program_id` field equals `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
    - **Dependency Detection:** Scan `Cargo.toml` for `spl-token-2022` or `token-2022` crate dependencies.
    - **Account Type Heuristic:** Detect `InterfaceAccount<TokenAccount>` or `InterfaceAccount<Mint>` in Anchor structs, which indicate Token-2022 compatible account handling.
2. **Extension-Specific Vulnerability Auditing:**
   - **Transfer Fee Bypass:** Verify that instructions calculate and account for transfer fees when moving tokens.
   - **Permanent Delegate Abuse:** Highlight risks where a mint contains a permanent delegate extension, which could allow unauthorized transfer or burning of user tokens.
   - **Interest-Bearing Tokens:** Flag potential integration issues where interest-bearing calculations are not accurately reflected in internal state values.

---

### 2.5 Audit Findings Generator (`sat report new`)
#### Goal
Prompt the auditor through CLI inputs to quickly create structured markdown reports for audit writeups.
#### Functional Requirements
1. **Interactive Metadata Collection:** Prompt for finding title, severity (Critical, High, Medium, Low, Informational), description, exploit vector, and remediation steps.
2. **YAML Front-Matter:** Prepend YAML front-matter to the markdown containing classification tags for easy programmatic cataloging.
3. **File Output:** Write formatted files under the `audit-findings/` directory using standard filename slugs (e.g., `SAT-001-missing-signer-check.md`).

---

## 3. CLI Design & Commands

The command line tool `sat` supports the following execution paths:

```bash
# Analyze IDL state transitions and reinitialization vectors
sat analyze idl [PATH_TO_IDL]

# Run AST-based static analysis and export warnings (supports --format sarif and optional --tx-report correlation)
sat analyze src [PATH_TO_SRC] --format [text|sarif] --tx-report [PATH_TO_TX_REPORT_JSON]

# Initialize a working ProgramTest cargo-fuzz harness
sat fuzz init

# Run the state-machine fuzzer locally against the program test environment
sat fuzz run

# Interactively create a new audit finding template
sat report new
```

---

## 4. UI/UX & Output Presentation

1. **Rich Terminal Visuals:** Utilize clear formatting (using colored text, boxes, and bullet points) to present diagnostic findings.
2. **Finding Severities:** Use standardized terminal colors:
   - **Critical/High:** Red text / banners
   - **Medium:** Yellow text
   - **Low/Info:** Cyan/Blue text
3. **Actionable Suggestions:** When warnings are printed (e.g., missing `#[account(signer)]`), show the exact diff suggestion in the console.

---

## 5. Audit Findings Catalog (Pre-Shipped)

The repository ships with an `audit-findings/` directory containing pre-written, documented vulnerability analyses that demonstrate the toolkit's capabilities and serve as writing samples for recruiters:

- `SAT-001-missing-signer-check.md`: Anchor program with a `#[derive(Accounts)]` struct omitting `signer` constraint on an authority field — walkthrough of identification via static analysis and exploitation.
- `SAT-002-pda-seed-mismatch.md`: PDA derivation where runtime seeds diverge from IDL declaration, enabling account substitution — shows `sat fuzz run` reproducing the issue.
- `SAT-003-reinitialization-attack.md`: Initializer function that fails to check account discriminator, allowing state overwrite — demonstrates IDL state transition graph analysis.

## 6. Testing & CI/CD

### 6.1 Test Suite
- **AST Parser Tests:** `sat analyze src` tested against a curated `tests/fixtures/` directory of intentionally vulnerable Anchor programs (missing signer, missing owner constraint, uninitialized state, CPI overflow) and clean programs to verify zero false positives.
- **IDL Analyzer Tests:** State transition graph construction tested with IDL fixtures representing common DeFi patterns (vault, AMM, staking, governance) and edge cases (orphan states, unreachable transitions).
- **Fuzzer Integration Tests:** `sat fuzz run` integration tests that execute the generated fuzzer against a known-vulnerable test program and assert that specific crash conditions are reached within N iterations.

### 6.2 CI Pipeline
- `.github/workflows/test.yml`: Runs `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check` on every push and PR.
- `.github/workflows/sat-self-audit.yml`: Runs `sat analyze src` against the toolkit's own source code as a self-audit sanity check.

---

## 7. Future Roadmap & Stretch Goals
- **Kani Formal Verification Scaffolding (`sat verify init`):** Create a workspace folder `formal-verification/` with mock structures for `AccountInfo`, `Clock`, and basic runtime parameters to prove simple arithmetic invariants under the Kani model checker.
