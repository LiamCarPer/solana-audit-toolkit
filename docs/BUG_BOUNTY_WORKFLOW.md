# Bug Bounty Workflow

Use `sat` as a triage accelerator, not as proof by itself. The tool should produce a short list of leads that you manually validate with a transaction, unit test, or minimal PoC.

## 1. First Pass

```bash
sat analyze src programs/<target> --triage
sat analyze idl target/idl/<target>.json
```

Prioritize findings in this order:

1. High-confidence access control issues: missing signer, owner, or `has_one`.
2. Reinitialization and unsafe account substitution paths.
3. Arithmetic on balances, vault totals, shares, fees, rewards, or debt.
4. Token-2022 extension accounting drift.
5. Informational findings only when they connect to exploitable state changes.

## 2. Manual Verification

For each lead, write down:

- The exact privileged state transition or asset movement.
- The account that should authorize it.
- The validation that is missing or bypassable.
- The smallest transaction sequence that proves impact.
- The expected fix in Anchor constraints or handler logic.

Do not submit a bounty report from static output alone. Static findings are leads; reproducible exploitability is the differentiator.

## 3. False-Positive Control

Before escalating a finding:

- Search the handler for manual checks equivalent to the missing Anchor constraint.
- Check whether a PDA seed constraint proves the same authority relationship.
- Confirm whether arithmetic operands are attacker-controlled.
- Confirm whether a Token-2022 mint can actually be supplied by an attacker.

## 4. Fuzzing Follow-Up

Run:

```bash
sat fuzz init
sat fuzz run
```

The generated harness now includes Anchor discriminators, IDL-derived account metas, seeded placeholder accounts, before/after snapshots, and baseline invariants. For serious bounty work, replace placeholder account factories with program-specific account layouts so transactions reach meaningful handler logic.
