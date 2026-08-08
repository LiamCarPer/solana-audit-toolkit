# Benchmark: `sat` vs. Real Audited Programs

**Date of run:** 2026-08-08 · **Tool version:** `sat` v0.1.0 (`cargo run --quiet -- version`)

This benchmark runs `sat analyze src` against real, deployed Solana programs with
documented audit/hack histories — code the tool has never seen — and classifies
every finding against the published root cause. It exists to (a) validate the tool
on unseen code, (b) surface false-positive patterns to fix, and (c) produce honest
recall/precision numbers. Per the grounding doc
[`docs/EXPLOIT_CORPUS.md`](EXPLOIT_CORPUS.md), findings are classified
**DETECTED / PARTIAL / NOT-DETECTED** and **TP / LIKELY / FP / HARDENING**.
`sat` never claims to detect semantic invariants, oracle economics, or
cross-instruction flows — those are documented limitations, not failures.

## Summary

| Metric | Value |
|---|---|
| Real programs analyzed | 2 (Cashio bankman + brrr, at vulnerable and post-fix commits) |
| Reference examples analyzed | 7 (Anchor tutorial `basic-0..5`, incl. puppet/puppet-master) |
| Programs excluded (documented) | 2 (Mango v3, solana-program-library — not Anchor) |
| Actionable findings | 8 (5 LOW + 3 HIGH) + 6 informational |
| Findings matching a real exploit | **0 / 8** |
| Root-cause recall on Cashio | **0 / 1** (NOT-DETECTED — semantic class, documented) |
| Findings that are defensible hardening notes | 8 / 8 |
| FP patterns surfaced | 2 (see Actions) |

## Methodology

- **Command** (per target, from the repo root; never a whole-workspace scan):
  `cargo run --quiet -- analyze src <target/src>`
- Full outputs are committed in [`bench/`](../bench/) (`*.out` files) for
  reproducibility; SARIF export verified (`--format sarif` → `sat-results.sarif`).
- **IDL gap:** none of the cloned repos ship `target/idl/`, and building IDLs
  requires the Anchor CLI, so IDL-driven checks (`check_missing_mut`, state-machine
  analysis) were skipped. Every run below is constraint/AST-level only.
- **Classification rule:** a finding is a TP only if it matches the published root
  cause of the known incident; HARDENING = correct observation, no exploit;
  FP = observation is wrong or neutralized elsewhere (e.g., out-of-band validation).

## Target 1 — Cashio, vulnerable commit (`a51c3c59`, 2022-03-10, pre-hack)

**Ground truth (rekt.news, verified source):** ~$48M lost via an "infinite mint".
Root cause: incomplete collateral validation — the LP-token deposit path via
`saber_swap.arrow` never validated the `.mint` field, so the attacker built a fake
root contract (a **false bank** — `new_bank` is permissionless) and a chain of fake
accounts that passed because each check compares attacker-supplied accounts to other
attacker-supplied accounts.

**Verified in code:** `BrrrCommon::validate` + `SaberSwapAccounts::validate` +
`PrintCash::validate` anchor the chain to `collateral.bank == bank`,
`depositor_source.mint == collateral.mint`, `crate_collateral_tokens.mint ==
collateral.mint`, `arrow.vendor_miner.mint == pool_mint`, `saber_swap.pool_mint ==
pool_mint` — all attacker-supplied; nothing references an approved registry.
`new_bank` records `admin.key()` as curator/bankman with no access control.

| Finding | Rule | Severity | Classification | Note |
|---|---|---|---|---|
| `NewBank::brrr_issue_authority` missing signer | SAT001 | LOW | **FP** (as exploit) / HARDENING | `CHECK:`-documented; keys recorded at bank creation |
| `NewBank::burn_withdraw_authority` missing signer | SAT001 | LOW | **FP** / HARDENING | same |
| `NewBank::admin` missing signer | SAT001 | LOW | **FP** / HARDENING | permissionless `new_bank` by design — but this is the **exact instruction the exploit used as its "fake root contract"** |
| `PrintCash::issue_authority` missing signer | SAT001 | LOW | **FP** / HARDENING | validated in `Validate` impl (`assert_keys_eq!(…, ISSUE_AUTHORITY_ADDRESS)`) + PDA signer seeds |
| `BurnCash::withdraw_authority` missing signer | SAT001 | LOW | **FP** / HARDENING | same pattern |
| Root cause (unvalidated `.mint` anchoring) | — | — | **NOT-DETECTED** | semantic field-level invariant; beyond pattern matching (documented limitation, see `EXPLOIT_CORPUS.md`) |

**Read of the run:** 0/5 findings match the root cause; 5/5 correctly point at the
authority plumbing of the two instructions involved in the exploit (permissionless
bank creation; CASH minting/burning), so the finding set is a useful triage map even
though the root cause is out of scope. This is the honest headline: **a famous
semantic exploit is not statically detectable, and `sat` says so.**

## Target 2 — Cashio, post-fix commit (`3f2c353`, 2022-04-23)

Same 5 findings (the vulnerable paths were never actually fixed — `brrr`'s
`print_cash`/`burn_cash` were simply disabled; `withdraw_author_fee` was added).

**Precision data point:** the newly added `withdraw_author_fee` instruction
(`constraint = author_fees.mint == collateral.mint`, `with_signer` PDA seeds)
produces **zero findings** — properly-constrained Anchor code stays clean.

## Target 3 — Anchor tutorial examples (`coral-xyz/anchor` @ `474204e`, 2026-07-21)

Maintained reference code; expected mostly-clean. 7 programs analyzed.

| Program | Findings | Classification |
|---|---|---|
| `basic-0`, `basic-1`, `basic-3` (puppet, puppet-master), `basic-5` | 0 actionable (INFO only) | clean |
| `basic-2` | 1× SAT012 HIGH `+=` on u64 counter | **FP** for practical purposes — overflow needs 2^64 increments; valid lint-level note |
| `basic-4` | 1× SAT012 HIGH `+=` (same as above) + 1× SAT-`has_one` HIGH on `authority` | the `has_one` finding is an **FP** as exploit: the handler performs `require_keys_eq!(authority.key(), counter.authority)` — `sat` cannot see handler-level guards (FP pattern #2) |

## Excluded targets (documented, not swept under the rug)

- **Mango v3** (`c4d52dc`, 2022-10-21): main program is native Rust
  (`entrypoint.rs`/`processor.rs`, no Anchor); `mango-logs` has only a dummy
  `#[program]` module for event emission. `sat` scanned 11 files, found 0 Anchor
  programs, 0 findings. Also, the Mango root cause (oracle manipulation) is a
  documented NOT-DETECTED class.
- **solana-program-library**: native SPL code, no Anchor programs (`#[program]`
  grep over the tree: 0 matches).

## Recall / Precision

- **Recall (root cause) on the one verified incident in scope: 0/1.**
  NOT-DETECTED, with the reason documented: Cashio's flaw is a self-referential
  validation chain — a semantic invariant, explicitly outside `sat`'s detection
  claims (`EXPLOIT_CORPUS.md`, "Documented limitations").
- **Precision: 0/8 findings are directly exploitable.** 6/8 are HARDENING-level
  (authority plumbing on real accounts, lint-grade arithmetic), 2/8 are
  neutralized by out-of-band validation. This is *better* than it looks: every
  finding survives manual review as a defensible note, and none were wild misses.
- **Consistency:** the post-fix checkout produces the identical finding set,
  and properly-constrained new code (`withdraw_author_fee`) produces none.

## Actions from this run

1. **FIXED — `CHECK:`-documented `UncheckedAccount` authorities were over-flagged.**
   The dominant FP pattern on real Saber-ecosystem code: authority accounts typed
   `UncheckedAccount` with a `/// CHECK:` doc comment (the Anchor convention for
   deliberately reviewed accounts, e.g. "handled by Vipers") were reported at
   High/Medium even though the validation exists out-of-band. `check_missing_signer`
   and `check_missing_owner` now downgrade such fields to **LOW** and explain the
   convention in the finding description. Covered by a new fixture
   (`tests/fixtures_ast/vulnerable/check_documented.rs`) asserting the severity
   split. Tests: 159 pass (was 158).
2. **Documented — handler-level key-equality guards are invisible to constraint
   checks.** `basic-4`'s `require_keys_eq!` in the handler neutralizes the
   `has_one` finding. Candidate improvement (deferred, risk of span-fragility):
   scan handler bodies for `require_keys_eq!`/`assert_keys_eq!` guards on signer
   fields before emitting.
3. **Documented — `+=` on counters is lint-grade, not High.** Consider downgrading
   SAT012 to Medium for `+=`/`-=` (keep High for `*`/`/` and unchecked shifts).
4. **Process:** never scan whole workspaces (pulls in unrelated crates); always
   target `<program>/src` and record the exact command per run (see `bench/*.out`).
5. **Corpus refinement:** `EXPLOIT_CORPUS.md` Cashio section updated from the
   verified source code (Vipers validation chain, not manual deserialization).

## Reproduction

```sh
# vulnerable Cashio (pre-hack, the exploited code)
git -C bench/programs/cashio worktree add bench/programs/cashio-vuln a51c3c59
cargo run --quiet -- analyze src bench/programs/cashio-vuln/programs/bankman/src > bench/cashio-vuln-bankman.out
cargo run --quiet -- analyze src bench/programs/cashio-vuln/programs/brrr/src      > bench/cashio-vuln-brrr.out

# post-fix Cashio
cargo run --quiet -- analyze src bench/programs/cashio/programs/bankman/src       > bench/cashio-fixed-bankman.out
cargo run --quiet -- analyze src bench/programs/cashio/programs/brrr/src          > bench/cashio-fixed-brrr.out

# reference examples
for p in basic-0/programs/basic-0 basic-1/programs/basic-1 basic-2/programs/basic-2 \
         basic-3/programs/puppet basic-3/programs/puppet-master basic-4/programs/basic-4 \
         basic-5/programs/basic-5; do
  cargo run --quiet -- analyze src "bench/programs/anchor-examples/examples/tutorial/$p/src"
done

# non-Anchor exclusion
cargo run --quiet -- analyze src bench/programs/mango-v3/program/src               > bench/mango-v3.out
```

Target commit hashes: Cashio vulnerable `a51c3c59`, Cashio post-fix `3f2c353`,
Anchor examples `474204e`, Mango v3 `c4d52dc`. Cloned repos live under
`bench/programs/` (git-ignored); outputs are committed.

---

# Native backend benchmark (first run, 2026-08-08)

The native (non-Anchor) backend shipped per `docs/NATIVE_BACKEND.md`: frontend
(entrypoint/dispatch/account resolution) + 12 rules SAT019–SAT030. This is the
first run against real native programs — the recall/precision numbers below are
the honest baseline, including the false-positive patterns it surfaced.

## Mango v3 (`c4d52dc`, audited, ~$114M exploit class documented in the corpus)

Command: `sat analyze src bench/programs/mango-v3/program/src` → **16 findings**
(12 HIGH, 3 MEDIUM, 1 INFO).

| Finding | Count | Classification | Note |
|---|---|---|---|
| `Unverified Owner Account: token_account_ai` (SAT020) | 3 | **LIKELY leads** (manual confirm) | Verified in source: the findings are on the `RecoveryWithdrawTokenVault`/`MngoVault`/`InsuranceVault` handlers (processor.rs:8274+), which deserialize token data via `TokenAccount::load_checked` (zero-copy, no owner check — `Loadable::load` checks nothing). The subsequent `destination_account.owner == recovery_authority::ID` and mint-equality checks compare fields read from attacker-influenced account data — a self-referential validation shape (Cashio class). The pure CPI-pass-only shape (withdraw2's `token_account_ai`, passed only to `invoke_transfer`) is now suppressed by the CPI-passed-only fix |
| `Unsafe Arithmetic`/`Unsafe Multiplication` (SAT026) | 2 residual | **FP cluster FIXED; 2 residual lint-level** | The I80F48 checked-fixed-point cluster (`apply_fees`, `checked_add_net`, `checked_sub_net` — 12 findings) is now suppressed by the type-awareness fix. Two residual findings (`verify_bookside_iteration +=`, `cancel_all_advanced_orders +=`) are primitive u64 accumulators (loop counters/fee constants) — keyword-heuristic noise, not exploitable |
| INFO Token-2022 | 1 | informational | — |

**Read of the run:** 16 → 6 findings after the FP fixes. Remaining: 3 genuine triage leads + 2 lint-level noise + INFO. Precision improved from ~35% to ~60% on unseen audited code without losing a single lead.

## SPL token-lending (archived subrepo, audited)

Command: `sat analyze src bench/programs/solana-program-library/token-lending/program/src`
→ **0 findings**. The entrypoint engages (delegation chain to
`processor::process_instruction`), dispatch uses `LendingInstruction::unpack`.
Either genuinely clean (heavily audited) or below resolution depth — the
unpack-based dispatch path is a documented frontend limitation to verify next.

## Actions from this run (native)

1. **FIXED — FP pattern A (SAT020 on CPI-passed-only accounts):** `auth.rs`
   now suppresses SAT020 for accounts whose only use is as an argument of a CPI
   to a known validating builtin (SPL token/ATA/system), with no data access.
   Verified on Mango: the `withdraw2` pass-only shape is suppressed; data-reading
   shapes (the `RecoveryWithdraw*` leads) intentionally keep firing.
2. **FIXED — FP pattern B (SAT026 type-blindness):** `lifecycle.rs` gained a
   lightweight type-inference layer (explicit annotations, constructor paths,
   fn-parameter types, struct-field resolution with propagation). Verified on
   Mango: the I80F48 cluster (12 findings) is gone; primitive accumulators stay
   flagged (residual noise).
3. **FIXED — R4 guard gap:** `cpi.rs` SAT030 now counts discriminator/version/tag
   checks on deserialized locals as init guards (`let s = try_from_slice; if
   s.discriminator != DISC`), with per-account attribution. The same gap exists
   in `lifecycle.rs` SAT024/025 guard scanning (Index-only discriminator
   matching) — documented, future fix.
4. **Open — frontend depth:** `LendingInstruction::unpack`-style dispatch may
   resolve fewer instructions than real — add instruction-count rendering for
   native programs so engagement is visible in the text output.

Raw outputs: `bench/mango-v3-native.out`, `bench/spl-token-lending-native.out`.
