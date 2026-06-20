---
id: SAT-001
title: Missing Signer Check on Authority Account Allows Unauthorized State Modification
severity: HIGH
date: 2026-06-20
tags:
  - access-control
  - missing-signer
  - account-constraints
  - anchor
  - static-analysis
---

# SAT-001: Missing Signer Check on Authority Account

**Severity:** HIGH

## Description

The `UpdateConfig` instruction's `#[derive(Accounts)]` struct declares an `authority` field that is not constrained with `#[account(signer)]` and is not of type `Signer<'info>`. Without signer verification, any caller can supply an arbitrary public key for the `authority` account, bypassing all authorization checks and modifying critical protocol configuration parameters.

The vulnerable code pattern:

```rust
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    // BUG: authority field has no #[account(signer)] constraint
    pub authority: AccountInfo<'info>,
}
```

In the instruction handler, the program compares `ctx.accounts.authority.key()` against `config.authority`:

```rust
pub fn update_config(ctx: Context<UpdateConfig>, new_fee: u64) -> Result<()> {
    let config = &mut ctx.accounts.config;
    require!(
        ctx.accounts.authority.key() == config.authority,
        ErrorCode::Unauthorized
    );
    config.fee = new_fee;
    Ok(())
}
```

While a runtime check exists, it only verifies that the key matches. It does not verify that the account **signed** the transaction. An attacker can pass any public key — including one they don't control — as long as they know the expected authority's address. The runtime check passes because `authority.key()` returns the public key of the passed account, not a signature verification.

## Exploit Scenario

1. Alice deploys a vault program where the authority is a cold wallet (address `AUTH_PUBKEY`).
2. Bob creates a transaction calling `update_config`:
   - Passes `AUTH_PUBKEY` as the `authority` account (but does not sign for it).
   - The `require!` check passes because `AUTH_PUBKEY == AUTH_PUBKEY`.
   - Bob modifies the fee from 0.1% to 99%.
3. Bob drains the vault through inflated fees without ever needing the authority's private key.

The key insight: Anchor only validates constraints declared via `#[account(…)` attributes in the `#[derive(Accounts)]` struct. A manual `require!` in the handler body does **not** replace the structural `#[account(signer)]` constraint — it only checks key equality, not signature verification.

## Identification via Static Analysis

The `sat analyze src` command detects this vulnerability automatically:

```
#1 [HIGH] Missing Signer: `UpdateConfig::authority` authority field is missing signer
          constraint
  📍 programs/vault/src/instructions.rs:42 (UpdateConfig::authority)

  The field `authority` in `UpdateConfig` appears to represent an authority but is not
  constrained with `#[account(signer)]` and is not of type `Signer<'info>`. Without
  signer verification, this account's signature is not enforced, allowing unauthorized
  callers to supply arbitrary public keys for this account.

  Suggestion:
  Add `#[account(signer)]` to the `authority` field or change its type to `Signer<'info>`.
```

The analysis works by:
1. Parsing Rust source with `syn` to identify `#[derive(Accounts)]` structs.
2. Parsing `#[account(...)]` attributes via `syn::Attribute::parse_nested_meta` to extract constraints.
3. Matching field names against a dictionary of authority-like names (`authority`, `admin`, `owner`, etc.).
4. Flagging authority-named fields that lack both `#[account(signer)]` and `Signer<'info>` type.

## Remediation

**Fix option 1 — Use `#[account(signer)]` constraint:**

```rust
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}
```

**Fix option 2 — Use `Signer<'info>` type (preferred):**

```rust
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}
```

With either fix, Anchor's constraint engine will automatically verify that `authority` is a signer on the transaction before the instruction handler executes, preventing the bypass entirely.

## See Also

- [Anchor Account Constraints Documentation](https://docs.rs/anchor-lang/latest/anchor_lang/derive.Accounts.html)
- SAT-003: Reinitialization Attack via Missing Initialization Guard
- `sat analyze idl` — Cross-references instruction mutability against IDL declarations
