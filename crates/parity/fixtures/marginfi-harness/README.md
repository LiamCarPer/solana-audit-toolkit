# marginfi harness — a real-target `parity` adapter (P3)

This is the **AI-authored adapter** that records a canonical `parity` trace of
the real, audited **MarginFi** lending program running in
`solana-program-test`. It is the worked example for `parity emit-harness`.

## Result

Against a no-interest USDC `deposit, deposit, withdraw` scenario, the real
program is at **CLEAN parity** with the source-derived reference model:

```
ok 0 deposit  100000000  → total_deposits 100000000  vault 100000000  user_balance 900000000
ok 1 deposit  100000000  → total_deposits 200000000  vault 200000000  user_balance 800000000
ok 2 withdraw  50000000  → total_deposits 150000000  vault 150000000  user_balance 850000000
```

`parity run --scenario scenario.json --actual-trace trace.json` → `CLEAN (parity)`.

## Why this matters

This validates the P3 loop end to end on a **real audited program** (not a
fixture): real program execution → canonical observables → differential vs a
reference model. Divergence here would be a candidate real bug.

## Reproduce

MarginFi pins `solana =3.0.0`, `solana-program-test =3.1.12`, `anchor-lang 1.0.2`
(and a `rustc 1.90` toolchain), so this builds under stable.

```bash
# 1. Scaffold the harness (mirrors the target's dependency versions).
parity emit-harness \
  --program-dir <marginfi>/programs/marginfi \
  --name marginfi \
  --out /tmp/marginfi-harness

# 2. Drop in this adapter and add the fixture dependency it uses:
#    fixtures = { path = "<marginfi>/test-utils", package = "test-utilities" }
#    fixed = "1"
cp src/main.rs /tmp/marginfi-harness/src/main.rs

# 3. Build the harness (the FIRST build also compiles marginfi + deps, ~10 min).
cd /tmp/marginfi-harness && cargo build

# 4. Build the target program and the other programs TestFixture registers.
cd <marginfi>/programs/marginfi         && cargo build-sbf
cd <marginfi>/programs/mocks            && cargo build-sbf
cd <marginfi>/programs/test_transfer_hook && cargo build-sbf
cd <marginfi>/programs/kamino-mocks     && cargo build-sbf
cd <marginfi>/programs/drift-mocks      && cargo build-sbf
cd <marginfi>/programs/juplend-mocks    && cargo build-sbf
cd <marginfi>/programs/solend-mocks     && cargo build-sbf

# 5. Run the harness (BPF_OUT_DIR points ProgramTest at the built .so files).
export BPF_OUT_DIR=<marginfi>/target/deploy
/tmp/marginfi-harness/target/debug/marginfi-harness \
  --scenario scenario.json --out /tmp/marginfi-trace.json

# 6. Differential.
parity run --scenario scenario.json --actual-trace /tmp/marginfi-trace.json
```

## Adapter notes

- **Ops → instructions:** `try_bank_deposit` / `try_bank_withdraw` from
  `marginfi-test-utilities` (`TestFixture` sets up the group, banks and oracles).
- **Observables → assets:** MarginFi tracks I80F48 share values; the adapter maps
  shares into **asset terms** via `BankImpl::get_asset_amount` so they are
  comparable to the reference model's 1:1 share accounting.
- **Funding:** the user token account is funded with exactly the scenario's
  `accounts[user].initial` so `user_balance` is comparable.
- **Scope:** only `deposit`/`withdraw` are mapped. Extending to
  `borrow`/`repay`/`accrue` (`try_bank_borrow`, `try_bank_repay`, time advance)
  is how the differential reaches margin/interest math — at which point the
  reference model must encode MarginFi's own interest curve, not the generic
  linear model, or divergences are model mismatch rather than bugs.

## Honest limitation

CLEAN here means the simple deposit/withdraw accounting matches. It is **not**
proof of safety — parity on narrow input only rules out divergences in that
window. Widen scenarios (rounding boundaries, borrow/repay, interest accrual,
liquidations) and sharpen the reference model to move toward real findings.
