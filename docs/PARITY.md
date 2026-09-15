# `parity` — Differential/Behavioral Engine

**Status:** P1 (engine + reference model + invariants) shipped.

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

## Roadmap

- **P1 (done):** engine + lending reference model + invariants + reports.
  Self-test: `parity demo` and `tests/differential.rs` inject a rounding bug and
  assert the engine catches it.
- **P2 — cross-implementation parity:** a `ProgramAdapter` trait that builds
  real instructions and reads real state, plus 2 adapters for one primitive
  (lending: Kamino vs Solend/Marginfi — clones available). `parity run` gains
  `--target kamino --target solend`.
- **P3 — `solana-program-test` backend:** generate a runnable harness crate
  (reusing `sat fuzz` generation: `ProgramTest`, account seeding, sequence
  execution) so `parity` executes the *real* program, not a model.
- **P4 — fork mode:** run adversarial sequences (flash-loan → oracle move →
  borrow) against forked mainnet state via RPC, reusing `rts` simulation.

## Honest limitations

- A reference model is only as good as its authoring; if the AI's model is wrong
  the divergence is noise. The engine reports the repro; a human confirms.
- P1's invariant set is single-user. Multi-user share accounting needs an
  extended model.
- Parity on narrow scenarios is not proof of safety — scenario coverage is the
  input that determines what can be found.
- This is a **lead generator**: a divergence is a candidate bug, not a proven
  exploit. A PoC and impact analysis are still required for a submission.
