# Native Backend Design Spec (`src/native/`)

**Status:** shipped — frontend, all rule slices (SAT019–SAT030), and CLI
integration landed 2026-08-08 (297 tests). Remaining items: section 11 Phase 3
(expectations JSON for `rts`, native corpus expansion).

**Status:** build contract — agents implement TO this document. Pinned types must
not change without updating this file and re-checking all downstream agents.

## 1. Goal

Extend `sat analyze src <path>` so it handles **native (non-Anchor) Solana
programs**: entrypoint-based, `process_instruction`-style, no `#[program]`/`#[derive(Accounts)]`.
Paradigm is auto-detected per workspace; Anchor and native backends can both run
(hybrid workspaces). Same CLI, same `Finding` model, same SARIF/render/dedup/IDs.

## 2. Integration points (owned by the integration slice, not by rule agents)

- `crates/sat/src/lib.rs`: add `pub mod native;` (alphabetical position).
- `crates/sat/src/main.rs`: add `mod native;` (same position) — **must stay in sync**.
- `analyzer.rs::run()`: after the `token2022::analyze(...)` call, add
  `all_findings.extend(native::analyze(&parsed_files));` — guarded by paradigm
  detection (see section 4). Everything downstream (dedupe, SAT-001 IDs, render, SARIF)
  is unchanged.
- `sarif.rs`: append rule entries SAT019–SAT030 to `RULES` and add
  `classify_finding_rule` arms for the new titles **above** any older arms whose
  substring could collide (ordering is load-bearing — see section 7 for the exact
  titles and their collision notes).

## 3. Output model (pinned — shared with `sat::types::Finding`)

Rules produce `sat::types::Finding`:

```rust
pub struct Finding {
    pub id: String,                  // filled by run() later — leave ""
    pub title: String,               // EXACT prefixes from section 7
    pub severity: Severity,
    pub description: String,         // what, why, exploit sketch
    pub location: Option<String>,    // "path:line (fn_name)" — same shape as Anchor backend
    pub suggestion: Option<String>,
}
```

## 4. Paradigm detection (frontend slice)

Per parsed file, detect native markers:
- `entrypoint!(...)` macro invocation, or
- a `pub fn process_instruction` with signature
  `(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult/Result<()>`.

`native::analyze` runs iff any file in the workspace has a native marker.
Anchor files in the same workspace are handled by the existing backend.

## 5. Frontend model (pinned — in `src/native/model.rs`)

```rust
pub struct NativeProgram {
    pub program_id: Option<String>,        // from declare_id!("...") literal if present
    pub entrypoint_file: String,
    pub entrypoint_line: usize,
    pub instructions: Vec<NativeInstruction>,
}

pub struct NativeInstruction {
    pub name: String,                      // dispatch name; fallback "instruction_0x<disc>"
    pub discriminator: Option<Vec<u8>>,    // 8-byte prefix, from match-arm byte arrays
    pub handler: String,                   // function name
    pub file: String,
    pub line: usize,
    pub accounts: Vec<ResolvedAccount>,    // positional order = AccountMeta order
}

pub struct ResolvedAccount {
    pub name: String,                      // variable name; fallback "account_{index}"
    pub index: usize,                      // position in the instruction's account list
    pub kind: AccountKind,                 // see below
    pub is_signer_checked: bool,           // is_signer guard reachable in call path
    pub owner_checked: bool,               // owner equality guard reachable
    pub key_checked: bool,                 // key-equality guard reachable
    pub written: bool,                     // borrowed mutably / deserialized mut
    pub seeds: Vec<String>,                // find_program_address seed expressions (source text)
    pub is_pda: bool,
}

pub enum AccountKind { Unchecked, Signer, State, TokenAccount, Mint, Program, Sysvar, SystemProgram }
```

### Resolution semantics (frontend slice implements all four)

1. **Positional iterator** (dominant pattern):
   `let accounts_iter = &mut accounts.iter();` … `let x = next_account_info(accounts_iter)?;`
   — position = call order in the handler. Tracks the iterator variable through
   `let` bindings; each `next_account_info` call increments the counter.
2. **Subscript**: `accounts[i]` / `&accounts[0..n]` with integer literal index.
3. **Struct `try_from`**: `let accs = MyAccounts::try_from(&accounts[..])?;` then field
   accesses `accs.authority` — resolve field order from the struct definition
   (`impl TryFrom<&[AccountInfo]> for MyAccounts` body or field declaration order),
   one index per field in declaration order.
4. **Helper call graph**: functions called from the handler that take
   `&[AccountInfo]`, `&mut AccountInfoIter`, or a single `&AccountInfo` — analyzed
   in call order, depth ≤ 2, cycle-guarded. Used for **check-presence** (section 6)
   and for continued positional resolution.

Dispatch recovery:
- `match instruction_data` / `match &instruction_data[0..8]` with arms binding
  `[a,b,c,d,e,f,g,h]` byte patterns → discriminator + handler name.
- `match instruction` on an enum whose variants carry `[u8; 8]`/u64 discriminators,
  or `instruction.tag`-style fields → map variant name → handler.
- Fallback: if the entrypoint matches on `instruction_data[0]` (u8 tag), record
  name as `"instruction_0x{tag:02x}"`.

Unknown/unresolvable constructs are **skipped silently** (never panic); the
frontend must parse Mango v3 `program/src` and all of SPL without crashing
(this is a hard gate).

## 6. Check-presence semantics (rules slice)

For a resolved account, "guard reachable" = the guard expression appears anywhere
in the handler body **or** any helper in its call graph (depth ≤ 2), regardless of
order (order-sensitivity is a documented approximation; manual steps cover it):

- `is_signer_checked`: `x.is_signer` referenced inside a condition/`require!`/
  `assert!`/`if !x.is_signer { return Err(...) }`.
- `owner_checked`: `x.owner == <expr>` / `<expr> == x.owner` / `x.owner != ...` in
  a guard, or `check_owner`-style helper calls taking `(owner, program_id)`.
- `key_checked`: `x.key == <expr>` (or `x.key_eq(...)`-style) in a guard.

Rules must treat guards in `if` conditions, `require!`, `assert!`, `invariant!`,
and early-return blocks. When the account is a PDA (`is_pda`), key-equality
against the derived address counts as a key check.

## 7. Rules (SAT019–SAT030) — exact titles, severities, triggers

| ID | Exact title prefix | Sev | Trigger (all in resolved model) | FP filters |
|---|---|---|---|---|
| SAT019 | `Unverified Signer Account:` | High | authority-named (`authority`, `owner`, `admin`, `payer`, `*_authority`, `signer`) account with `!is_signer_checked` used in a privileged path (any instruction) | skip if `kind == Signer`-by-construction or `key_checked` (fixed key/PDA) |
| SAT020 | `Unverified Owner Account:` | High | `kind != Unchecked` or data read/written, `!owner_checked`, `!key_checked` | skip sysvar/system program kinds |
| SAT021 | `Unchecked Authority Key:` | High | authority-named account with `!key_checked` (never compared to stored/derived key) | skip if `is_signer_checked` |
| SAT022 | `Seed Derivation Mismatch:` | High | `is_pda` account whose `invoke_signed` seeds (per CPI call site) differ from its `find_program_address` seeds | skip if no `invoke_signed` seeds visible |
| SAT023 | `State Write After CPI:` | High | mutation of a `written` state account after an `invoke`/`invoke_signed` call in the same handler | skip if state is closed or re-created after the call |
| SAT024 | `Account Reinit After Close:` | High | `realloc(0)`/`assign`/lamports-zeroing on an account that other instructions write, without a re-init guard (discriminator/init check) | skip if a `data_is_empty`/discriminator guard is present |
| SAT025 | `Unchecked Deserialization:` | Medium | `try_from_slice`/`unpack` on account data with `!owner_checked` and no discriminator validation | skip if owner check present |
| SAT026 | `Unsafe Arithmetic:` (reuse) | High | same as SAT012 pattern: `+`, `-`, `*`, `/`, `%` on u64/i64 with non-constant operand | reuse existing SAT012 checks where possible |
| SAT027 | `Writable Builtin Account:` | Medium | a known program/sysvar address (system program, token program, clock, rent) declared writable in an instruction's account list | skip if account data is never touched |
| SAT028 | `Token CPI Unverified Authority:` | High | token `transfer`/`mint_to`/`burn`/`set_authority` CPI whose authority `AccountMeta` maps to an account with `!key_checked` and `!is_signer_checked` (or `invoke` used where `invoke_signed` required for a PDA) | skip when authority is the program itself |
| SAT029 | `Self-Invocation:` | Medium | CPI where `invoke` program_id equals the declared program_id | — |
| SAT030 | `Cross-Instruction State Reuse:` | Medium | state account (same type, recovered layout) written by ≥2 instructions where one writes without discriminator/init guard | skip if all writers have init/guard |

Title wording is **load-bearing**: these exact prefixes avoid substring collisions
with existing SARIF classifier arms (`"Missing Signer"`, `"Missing Owner"`,
`"CEI Violation"`, `"PDA Seed"`, `"Reinitialization"`, `"Token Transfer CPI"`,
`"Sysvar"`, `"Unsafe Arithmetic"` — SAT026 intentionally collides with SAT012 and
reuses it). Do not rename prefixes.

## 8. Fixture contract (all rule slices)

- Location: `crates/sat/tests/fixtures_native/<rule_dir>/vuln.rs` + `clean.rs`.
- Every rule must have both; tests assert ≥1 finding on vuln, 0 on clean.
- Frontend fixtures: `crates/sat/tests/fixtures_native/frontend/` — one file per
  pattern (section 5 items 1–4 + dispatch recovery), parsed without error.
- Tests: each rule slice owns its own test file
  (`tests/native_rules_auth.rs`, `tests/native_rules_pda_cei.rs`,
  `tests/native_rules_lifecycle.rs`, `tests/native_rules_cpi.rs`); the
  integration slice creates `tests/native_analysis.rs` for end-to-end wiring
  tests; the frontend slice owns `tests/native_frontend.rs`.
- Fixture code need not compile against real solana crates — it is parsed with
  `syn` only. Use `use solana_program::{account_info::AccountInfo, ...};` style
  imports freely.

## 9. Hard gates (orchestrator runs between phases)

1. `cargo +stable fmt --check` (LF endings; run `sed -i 's/\r$//'` after writing).
2. `cargo +stable clippy --all-targets -- -D warnings` (0 errors).
3. `cargo +stable test` — the existing 209 must stay green; new tests green.
4. Frontend parse gate: `sat analyze src bench/programs/mango-v3/program/src`
   and the SPL tree parse without crash (findings may be empty/imperfect).

## 10. Agent slice assignments (disjoint write scopes)

| Slice | Files owned | Depends on |
|---|---|---|
| F (frontend) | `src/native/mod.rs`, `src/native/model.rs`, `src/native/frontend.rs` + frontend fixtures | — (contract checkpoint: model.rs compiling first) |
| R1 | `src/native/rules/auth.rs` (SAT019/020/021) + fixtures | pinned model only |
| R2 | `src/native/rules/pda_cei.rs` (SAT022/023) + fixtures | pinned model only |
| R3 | `src/native/rules/lifecycle.rs` (SAT024/025/026/027) + fixtures | pinned model only |
| R4 | `src/native/rules/cpi.rs` (SAT028/029/030) + fixtures | pinned model only |
| I (integration) | `lib.rs`, `main.rs`, `analyzer.rs` (run wiring), `sarif.rs`, `tests/native_analysis.rs` harness | all of the above landed |

Rule modules export `pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding>`.

## 11. Phase 3 (after integration lands)

- `sat analyze src <path> --expectations <out.json>`: export per-instruction
  account expectations mirroring RTS `IdlInstruction`/`IdlAccountItem` shape
  (name, signer, writable, pda seeds as strings) so `rts` can run its tier-1/tier-2
  runtime checks against native programs with no IDL. Owned by a new slice.
- Native benchmark: Mango v3 (cloned), SPL (cloned), plus live audited targets;
  extend `docs/BENCHMARK.md` with the native section; extend `EXPLOIT_CORPUS.md`
  with native incidents (Wormhole sysvar/instruction-loading class → NOT-DETECTED,
  Amulet/Cypher missing-auth class → target of SAT019/020/021).
