---
id: SAT-002
title: PDA Seed Mismatch Between IDL Declaration and Runtime Derivation Enables Account Substitution
severity: CRITICAL
date: 2026-06-20
tags:
  - pda
  - seed-mismatch
  - account-substitution
  - anchor
  - idl-analysis
---

# SAT-002: PDA Seed Mismatch Enables Account Substitution

**Severity:** CRITICAL

## Description

A program derives a PDA using seeds that differ from those declared in the Anchor IDL. The IDL declares seeds `["vault", authority.key().as_ref()]` but the runtime derivation uses `["vault"]` (omitting the authority), allowing any user's vault to be passed in place of another's. This creates an account substitution vulnerability where an attacker can supply a different user's vault PDA and manipulate its state.

The vulnerable pattern:

```rust
// IDL declaration (idl.json):
// { "name": "vault", "seeds": [{"kind": "const", "value": [118, 97, 117, 108, 116]},
//                               {"kind": "account", "path": "authority"}] }

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```

The `#[account(seeds = ...)]` constraint derives the PDA as `Pubkey::find_program_address(&[b"vault"], &program_id)`. Since the seeds lack an authority-specific component, the vault PDA is **global** — a single vault is shared across all users in a global singleton pattern.

When the IDL declares seeds `["vault", authority]` but the code uses `["vault"]`, the Anchor framework validates the runtime PDA against the IDL-declared seeds (in strict mode), creating a mismatch that causes the constraint check to fail. If the program relaxes this validation (e.g., using `seeds` without the authority component in both IDL and code), the program operates on a global vault where any user can withdraw any other user's deposits.

Even more critically: if the IDL correctly documents `["vault", authority]` but the on-chain program uses `["vault"]`, the two are divergent. External tools, indexers, and client libraries that rely on the IDL will derive incorrect addresses and may silently interact with wrong accounts.

## Exploit Scenario

1. A staking program uses PDAs for user stake accounts.
2. The IDL declares seeds as `["stake", user.key().as_ref()]` (correctly scoping each stake account to its user).
3. The on-chain program uses `["stake"]` (a global seed) — either by accident or due to a refactor that wasn't reflected in the IDL.
4. Alice stakes 1000 tokens. Her stake account PDA is derived from `["stake"]`.
5. Bob calls `unstake` with Alice's stake account (derived from the same global `["stake"]` seed).
6. Since the PDA is global and not user-scoped, the program accepts Bob's instruction and unstakes Alice's tokens into Bob's wallet.

This class of vulnerability is especially dangerous because:
- The IDL and source code both appear correct when reviewed independently.
- The `#[account(seeds = ...)]` constraint passes validation because the **code-level** seeds match.
- The discrepancy is only apparent when comparing the IDL declaration against the actual runtime derivation.

## Identification via `sat fuzz run`

The `sat fuzz init` / `sat fuzz run` pipeline reproduces this issue:

```
$ sat fuzz init   # generates fuzzer with Arbitrary enum for all IDL instructions
$ sat fuzz run    # executes state machine fuzzer

Fuzz Execution
───────────────

ℹ  Building fuzzer...
✓  Fuzzer built successfully.
ℹ  Running fuzzer (Ctrl+C to stop)...

Invariant violation:
Account 7xK... was de-initialized (true -> false)
```

The fuzzer:
1. Generates random sequences of instructions via the `FuzzInstruction` enum (derived from IDL).
2. Executes them against `solana-program-test` with a real BanksClient.
3. Asserts security invariants after each instruction:
   - **Authority Immutability** — catches unexpected ownership changes.
   - **State Integrity** — catches `is_initialized` flipping from `true` to `false`, which occurs when an account substitution overlays different state onto an existing account.

## Cross-Tool Correlation with `rts`

The Rust Security Toolkit (`rts`) transaction decoder complements this analysis:

```bash
$ rts TX_BYTES --idl target/idl/program.json --output-tx-report tx-report.json
$ sat analyze src --tx-report tx-report.json --format sarif
```

This produces `sat-results.sarif` with findings that flag:
- Accounts where `is_signer = false` in the transaction but `#[account(signer)]` is declared in the code.
- PDA seeds that differ between the transaction's actual derivation and the IDL declaration.

## Remediation

1. **Ensure IDL-code parity:** Always run `anchor build` after changing PDA seeds to regenerate the IDL. Use `anchor idl fetch` to deploy the updated IDL on-chain.

2. **Include the user/authority in PDA seeds:**
   ```rust
   #[account(
       seeds = [b"vault", authority.key().as_ref()],
       bump = vault.bump
   )]
   pub vault: Account<'info, Vault>,
   ```

3. **Use the `bump` seed to make each PDA unique:**
   The canonical bump ensures deterministic derivation. Including it in `seeds` prevents re-derivation attacks.

4. **Validate IDL against source:**
   ```bash
   sat analyze idl target/idl/program.json
   ```
   This builds a state transition graph from the IDL and flags structural risks including PDA seed well-formedness.

## See Also

- [Anchor PDA Documentation](https://docs.rs/anchor-lang/latest/anchor_lang/derive.Accounts.html#pda-accounts)
- [Solana PDA Best Practices](https://solanacookbook.com/core-concepts/pdas.html)
- SAT-001: Missing Signer Check on Authority Account
- `sat analyze idl` — IDL State Transition Analysis
