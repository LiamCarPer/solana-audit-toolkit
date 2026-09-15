# `parity` — Differential/Behavioral Engine

**Status:** P2 (real-program execution via `solana-program-test` trace) shipped.

## Why this exists

Static pattern rules find *textbook* bugs. Audited code has none left: after a
precision round, `sat` reports **0** findings on marginfi/kamino/drift/jito.
What survives an audit is **behavior**:

- rounding asymmetries (deposit vs withdraw share math),
- fee/index/interest accounting drift,
- sequence- and state-dependent bugs (stale caches, cross-instruction desync),
- oracle/economic compositions.

These cannot be found by pattern-matching source. They are found by *running*
the program across many inputs and comparing its observable behavior against a
reference.

## What `parity` does

Run one **normalized scenario** against two implementations of the same
primitive and report where their canonical observable state diverges:

- **Reference model** — a small, exact model of the protocol's math that the AI
  authors from source (shares, index interest, explicit rounding direction).
- **Candidate** — a sibling protocol, or a `program-test` adapter executing the
  real program.

The tool does the mechanical work (scenario execution, normalization, diffing,
minimal-repro minimisation, reporting). The AI does the protocol-logic
reasoning (authoring the reference model and adapters, interpreting
divergences, building the PoC).

## Model

- `Scenario` — program-agnostic: accounts (by role), an ordered `Op` sequence
  (`deposit`/`withdraw`/`borrow`/`repay`/`accrue`/`set_price`), `Invariant`s.
- `Observables` — the canonical, frozen diff surface: `total_deposits`,
  `total_borrows`, `total_shares`, `vault_balance`, `user_shares`,
  `user_balance`, `price`. Adapters **must** map their program onto these.
- `ProgramModel` — `apply(op)` mutates, `observe()` exposes `Observables`.
- `engine::compare` — applies each op to both models, checks invariants,
  records field divergences (only when a field actually moved), and tracks the
  first divergence for the minimal repro.

## Invariants (economics, not syntax)

`Solvency` (assets ≥ liabilities), `ShareConservation`, `VaultBacking`.
False-money is inherently **differential** (interest legitimately grows value),
so it is caught by the diff rather than an absolute bound.

## Commands

```bash
# prove the engine works: reference vs a known rounding bug
parity demo

# run a scenario; exits 2 on divergence (CI-gateable)
parity run --scenario parity-scenario.json
parity run --scenario s.json --candidate-withdraw-rounding down --format json

# emit a starter scenario to edit (or hand to the AI)
parity init --out parity-scenario.json
```

## P2 — differential against a real program

The engine can consume a **recorded execution trace** of a real program
(emitted by a `solana-program-test` harness) instead of an in-process model:

```bash
parity run --scenario parity-scenario.json --actual-trace trace.json
```

A reference harness lives in `crates/parity/fixtures/lending-harness/`
(standalone crate, pinned to the `solana-program-test` 3.x train; excluded from
the workspace because its Solana pin set conflicts with the workspace's agave
4.1.2 graph). It registers two variants of a tiny lending program — correct
(ceil shares on withdraw) and buggy (floor) — runs the demo scenario, and writes
a canonical `parity::Trace`:

```bash
cd crates/parity/fixtures/lending-harness
cargo build
./target/debug/lending-harness --program ok  --out trace-ok.json    # correct
./target/debug/lending-harness --program bug --out trace-bug.json   # buggy

cd ../../..
cargo run -p parity -- run --scenario demo-scenario.json --actual-trace trace-ok.json   # CLEAN
cargo run -p parity -- run --scenario demo-scenario.json --actual-trace trace-bug.json  # DIVERGED (exit 2)
```

For a **real target**, generate the harness against the target program's own
dependency versions (mirror the target `Cargo.toml`, as `sat fuzz` does) and
implement the adapter that maps scenario ops to that program's instructions and
state layout.

## P2.5 — target harness generator (`parity emit-harness`)

Real-target adapters are protocol-specific, so the tool scaffolds the crate and
leaves four clearly marked pieces for the author (the AI):

```bash
parity emit-harness --program-dir programs/klend --name klend --out klend-harness
```

The generated crate:

- is its own workspace root (won't join the target or parity workspace),
- **mirrors the target's dependency versions** — `anchor-lang`, `solana-program`,
  `solana-program-test`, `solana-sdk`, `spl-token` — read from the target manifest
  *and* its `[workspace.dependencies]` (workspace inheritance supported), so it
  builds in the target's own toolchain,
- path-depends on the target with `no-entrypoint`,
- emits a `Trace`-shaped JSON matching `parity::Trace` exactly.

### The adapter contract (the four TODOs)

1. `PROGRAM_ID` — the target's on-chain id (`declare_id!` value).
2. `seed_accounts` — create/seed the accounts each op touches (reserve, vault,
   user, oracle) with the target's real layout.
3. `build_op` — map a scenario `Op` to a target `Instruction` (account metas +
   serialized args). Return `Err` for unsupported ops so the engine reports a
   result divergence.
4. `observe` — read target state into the canonical `Observables`
   (`total_deposits`, `total_borrows`, `total_shares`, `vault_balance`,
   `user_shares`, `user_balance`, `price`).

Then: `cargo run` the harness with `--scenario`, and feed the trace to
`parity run --actual-trace`.

### Target toolchain note

Some audited targets pin old Solana stacks (e.g. Kamino klend: `solana ~1.17`,
`anchor 0.29`, `rustc 1.74.1` via `rust-toolchain.toml`). The generator mirrors
those versions so the harness builds **in the target's environment**; it cannot
be built in a workspace pinned to a newer Agave train. Build/run the generated
harness where the target's toolchain is available.

## Roadmap

- **P1 (done):** engine + lending reference model + invariants + reports.
- **P2 (done):** trace bridge (`Trace`/`TraceStep`, `compare_with_trace`) + a
  `solana-program-test` harness running a real program end to end.
- **P2.5 (done):** `parity emit-harness` scaffolds a target adapter, mirroring
  the target's dependency versions and leaving four AI-fillable TODOs.
- **P3 — real adapters:** fill the adapter for a live lending target (Kamino
  klend / Solend / Marginfi) and diff it against the reference model. Requires
  building the generated harness under the target's own toolchain.
- **P4 — fork mode:** adversarial sequences (flash-loan → oracle move → borrow)
  against forked mainnet state via RPC, reusing `rts` simulation.

## Honest limitations

- A reference model is only as good as its authoring; if the AI's model is wrong
  the divergence is noise. The engine reports the repro; a human confirms.
- P1's invariant set is single-user. Multi-user share accounting needs an
  extended model.
- Parity on narrow scenarios is not proof of safety — scenario coverage is the
  input that determines what can be found.
- This is a **lead generator**: a divergence is a candidate bug, not a proven
  exploit. A PoC and impact analysis are still required for a submission.
