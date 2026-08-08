---
id: SAT-005
title: Init-if-Needed on Authority-Bearing Account Enables Front-Run State Takeover
severity: HIGH
date: 2026-08-02
tags: [reinitialization, init-if-needed, account-takeover, anchor, static-analysis]
---

# SAT-005: Init-if-Needed on Authority-Bearing Account Enables Front-Run State Takeover

**Severity:** HIGH

## Description

`#[account(init_if_needed, ...)]` instructs Anchor to create the account only if it does not already exist. When the account exists, Anchor skips creation and the handler runs against the *existing* state. If that account stores an authority — or any privileged field — and the handler writes those fields unconditionally, the account is authority-bearing but has no initialization guard: any caller can re-authorize it, and the first caller to land on a fresh PDA controls what the account contains.

The vulnerable code pattern:

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    // BUG: init_if_needed lets an existing account pass through untouched
    #[account(
        init_if_needed,
        payer = signer,
        space = 8 + State::INIT_SPACE,
        seeds = [b"state"],
        bump
    )]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct State {
    pub authority: Pubkey,    // written on every call, even when the account exists
    pub initialized: bool,
    pub total_deposits: u64,
}

#[program]
impl StateProgram {
    pub fn initialize(ctx: Context<Initialize>, new_authority: Pubkey) -> Result<()> {
        // BUG: no is_initialized guard — the handler overwrites the
        // authority field even when the account already exists
        let state = &mut ctx.accounts.state;
        state.authority = new_authority;
        state.initialized = true;
        Ok(())
    }
}
```

`init_if_needed` exists for idempotent bootstrapping (e.g. config accounts that must survive re-invocation). It is unsafe when combined with unconditional writes to privileged fields: the handler cannot distinguish "I just created this account" from "this account already belonged to someone else".

## Exploit Scenario

1. Alice deploys a program that uses `init_if_needed` on a `state` PDA storing `authority`, and the initializer writes the authority field unconditionally.
2. Bob monitors the mempool for Alice's first `initialize` transaction. He front-runs it, submitting his own `initialize` with a higher priority fee so his transaction lands first and creates the PDA with *his* authority.
3. Alice's transaction lands next. `init_if_needed` is a no-op (the account already exists), but the handler — lacking an `is_initialized` guard — proceeds as if the account were fresh, overwriting the authority and other state fields.
4. Depending on the handler, the outcome is **authority takeover** (the overwritten fields end up attacker-chosen — e.g. the authority argument comes from the attacker's transaction, or stale attacker-seeded values persist) or **state overwrite** (victim state is clobbered by values written on the attacker's front-run path).
5. Even without mempool front-running, the same primitive is a reinitialization bug: a second caller can invoke the initializer against an already-initialized account and overwrite the first caller's authority.

The core danger: `init_if_needed` is treated as "safe initialization" during review, but on an authority-bearing account it is a race any attacker can win by ordering the mempool.

## Identification via Static Analysis

The `sat analyze src` command detects this vulnerability automatically:

```
$ sat analyze src programs/state/

#N [HIGH] Reinitialization Risk: `Initialize::state` uses init_if_needed on
          authority-bearing account `State` without an initialization guard
  📍 programs/state/src/instructions.rs:12 (Initialize::state)

  The state account stores an authority but is initialized with `init_if_needed`
  and the handler writes authority fields without an initialization guard.
  A front-runner can initialize the account first with their own authority.

  Suggestion:
  Use `#[account(init)]` when the account must be created fresh, or guard the
  authority write with an `is_initialized` check before overwriting.
```

The analysis works by:
1. Parsing `#[account(init_if_needed, ...)]` constraints from `#[derive(Accounts)]` structs via `syn`.
2. Resolving the constrained account's data type and checking whether it stores authority-bearing fields (`authority`, `owner`, `admin`, `fee_recipient`, ...).
3. Checking whether the handler writes those fields behind an `is_initialized` / `initialized` guard.
4. Flagging the combination as an `init-if-needed` finding with the account, location, and a fix suggestion.

## Remediation

1. **Prefer `#[account(init)]`** when the account must be created fresh. Anchor then fails the instruction if the account already exists, removing the race entirely:

   ```rust
   #[account(
       init,
       payer = signer,
       space = 8 + State::INIT_SPACE,
       seeds = [b"state"],
       bump
   )]
   pub state: Account<'info, State>,
   ```

2. **Guard the handler** if `init_if_needed` is genuinely required (idempotent bootstrap):

   ```rust
   let state = &mut ctx.accounts.state;
   if !state.initialized {
       state.authority = ctx.accounts.signer.key();
       state.initialized = true;
   }
   ```

3. **Never seed the authority from attacker-controlled instruction arguments** on a path that may run against an existing account. Derive it from the signer, or verify the account is fresh before accepting it.

4. **Verify before deploy:** run the check in CI:

   ```bash
   sat analyze src programs/state/ --format sarif
   ```

   This emits a `SAT016` (Init-if-Needed Risk) result in `sat-results.sarif`, failing the scan until the initialization guard is added.

## See Also

- [Anchor Account Constraints Documentation](https://docs.rs/anchor-lang/latest/anchor_lang/derive.Accounts.html)
- SAT-003: Reinitialization Attack via Missing Initialization Guard
- Tagged `reinitialization` / `init-if-needed` — the front-running variant of the reinitialization family (SAT-003, SAT-005)
