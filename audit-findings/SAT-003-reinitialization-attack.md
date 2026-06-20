---
id: SAT-003
title: Reinitialization Attack via Missing Initialization Guard Enables State Overwrite
severity: CRITICAL
date: 2026-06-20
tags:
  - reinitialization
  - state-overwrite
  - initialization-guard
  - anchor
  - idl-analysis
---

# SAT-003: Reinitialization Attack via Missing Initialization Guard

**Severity:** CRITICAL

## Description

The `initialize` instruction writes to a state account without checking whether the account has already been initialized. The storage struct lacks an `is_initialized` boolean field or an Anchor discriminator guard, and the instruction does not use Anchor's `#[account(init)]` constraint. This allows an attacker to call `initialize` on an already-initialized account, overwriting the existing state including the `authority` field and any stored balances or configuration.

The vulnerable code pattern:

```rust
#[account]
pub struct Config {
    pub authority: Pubkey,  // BUG: no is_initialized flag
    pub fee_rate: u64,
    pub paused: bool,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]  // BUG: should be #[account(init, payer = authority, space = ...)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>, fee_rate: u64) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.authority = ctx.accounts.authority.key();
    config.fee_rate = fee_rate;
    config.paused = false;
    Ok(())
}
```

Without `#[account(init)]`, Anchor does not:
- Allocate the account (the caller must pre-allocate).
- Set the 8-byte Anchor discriminator.
- Verify that the account is not already initialized.

Without an `is_initialized` guard, nothing prevents re-calling `initialize` on an existing account. The `authority` field can be overwritten with a new public key, effectively stealing ownership of the protocol configuration.

## Exploit Scenario

1. Protocol deployer calls `initialize`, setting `authority = DEPLOYER_KEY`.
2. Protocol operates normally — users deposit funds, fees accumulate.
3. Attacker calls `initialize` again on the same `config` account.
4. The account is reinitialized with `authority = ATTACKER_KEY`.
5. Attacker now controls the protocol configuration:
   - Sets `fee_rate` to 100%.
   - Sets `paused = true` to freeze user funds.
   - Calls any admin-gated instruction as the new authority.

In a vault scenario, the impact is even more severe: if the vault's `total_deposits` counter is reset to 0 during reinitialization, the program's accounting breaks and funds may be permanently locked or stolen.

## Identification via IDL State Transition Analysis

The `sat analyze idl` command detects this vulnerability without compiling the program:

```
$ sat analyze idl target/idl/config.json

┌
├─ State Model
ℹ  Identified 1 state type(s):
  • Config
     authority
     fields: authority, fee_rate, paused

┌
├─ Findings
#1 [CRITICAL] Reinitialization Risk: `initialize` may overwrite existing `Config`
  📍 Instruction: initialize → Account: Config

  The instruction `initialize` is classified as an initializer for `Config`, but `Config`
  has no `is_initialized` guard field. If this instruction is called on an already-
  initialized account, it will overwrite the existing state — a critical vulnerability
  commonly exploited in reinitialization attacks.

  Suggestion:
  Add an `is_initialized: bool` field to `Config` and guard the initialize instruction
  with a requires!(!config.is_initialized). Alternatively, use Anchor's
  `#[account(init)]` constraint which enforces this automatically.
```

The analysis works by:
1. Parsing the Anchor IDL JSON to build a programmatic state model.
2. Identifying account structs and their fields (detecting `is_initialized` flags).
3. Classifying instructions as Initializers, Mutators, or Terminators based on name heuristics and account mutability patterns.
4. Building a directed state transition graph.
5. Flagging initializer instructions that target state types lacking an `is_initialized` guard.

## AST-Level Confirmation with `sat analyze src`

Running the AST-based analysis confirms the finding from source code:

```
$ sat analyze src programs/config/

#1 [CRITICAL] Reinitialization Risk: `initialize` may overwrite existing `Config`
  📍 programs/config/src/instructions.rs:15 (Initialize::config)

  The instruction `initialize` is classified as an initializer for `Config`, but
  `Config` has no `is_initialized` guard field. The presence of a bump field suggests
  PDA derivation, but without an explicit is_initialized flag or Anchor `init`
  constraint, the account discriminator check alone may be bypassed if a different
  program owns the account.
```

The cross-analysis between IDL (Phase 2) and AST (Phase 3) provides defense-in-depth validation.

## Remediation

**Fix option 1 — Use Anchor's `#[account(init)]` (preferred):**

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1  // discriminator + Pubkey + u64 + bool
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

Anchor's `#[account(init)]` constraint:
- Allocates the account via CPI to the System Program.
- Writes the 8-byte discriminator (`sha256("account:Config")[0..8]`).
- Enforces that `init` can only be called on uninitialized accounts.
- Reverts with `AccountDiscriminatorMismatch` if called on an existing account.

**Fix option 2 — Manual `is_initialized` guard:**

```rust
#[account]
pub struct Config {
    pub is_initialized: bool,  // ADD THIS
    pub authority: Pubkey,
    pub fee_rate: u64,
    pub paused: bool,
}

pub fn initialize(ctx: Context<Initialize>, fee_rate: u64) -> Result<()> {
    let config = &mut ctx.accounts.config;
    require!(!config.is_initialized, ErrorCode::AlreadyInitialized);
    config.is_initialized = true;
    config.authority = ctx.accounts.authority.key();
    config.fee_rate = fee_rate;
    Ok(())
}
```

**Fix option 3 — Combine with discriminator check:**

Even with `is_initialized`, if the account is owned by a different program, the discriminator bytes won't match. Use `#[account(init)]` for the strongest guarantee — it checks both discriminator and initialization status atomically.

## See Also

- [Neodyme Reinitialization Attack Blog Post](https://blog.neodyme.io/posts/solana_common_pitfalls/#reinitialization-attacks)
- [Anchor `#[account(init)]` Documentation](https://docs.rs/anchor-lang/latest/anchor_lang/derive.Accounts.html#init)
- SAT-001: Missing Signer Check on Authority Account
- `sat analyze idl` — IDL State Transition Analysis
- `sat analyze src` — AST-Based Static Analysis
