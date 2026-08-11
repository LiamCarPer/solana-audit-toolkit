//! R1 slice: authentication rules SAT019, SAT020 and SAT021.
//!
//! These rules target the missing-auth class of native Solana exploits (the
//! Amulet/Cypher incidents in `EXPLOIT_CORPUS.md`): privileged accounts used
//! without verifying their signature, their owner, or their expected key.
//!
//! The frontend model (`crate::native::model`) pre-resolves, per account and
//! per instruction, whether a signer guard, an owner-equality guard, or a
//! key-equality guard is reachable in the handler body or its helper call
//! graph (depth ≤ 2). These checks consume that resolved model plus the raw
//! syntax trees (`parsed`) for the SAT020 CPI-passed-only suppression; they do
//! not re-derive the model. Order-sensitivity of guards and cross-instruction
//! reasoning are documented approximations (see `docs/NATIVE_BACKEND.md`
//! section 6) — manual steps cover them.
//!
//! # Helper-guard recognition (SAT019/SAT020/SAT021 FP filter)
//!
//! A second, deliberately narrow layer scans each *handler body* for calls to
//! a curated whitelist of helper functions whose very name is a guard
//! contract. The frontend cannot see through these helpers (e.g. Jito's
//! `Config::load(program_id, config, ..)` is skipped because its first
//! parameter is a `Pubkey`, not an `AccountInfo`), so without this layer
//! guarded accounts fire SAT019/SAT020/SAT021 — the Jito restaking/vault
//! corpus is 100% false positives of exactly this shape.
//!
//! Whitelist → flag mapping (exact callee-name match + argument variable equal
//! to a resolved account name, both in the same handler body):
//! - Signer helpers `load_signer` / `require_signer` / `check_signer` /
//!   `assert_signer` → `is_signer_checked`.
//! - Owner-loading helpers: any `load_*` whose name contains a program-kind
//!   word (`system_account`, `token_account`, `token_mint`,
//!   `associated_token_account`, `mpl_metadata_program`) → `owner_checked`.
//!   This covers `load_system_account`, `load_token_account`,
//!   `load_token_mint`, `load_associated_token_account` and
//!   `load_mpl_metadata_program` exactly. Bare `load`/`load_checked` are
//!   NEVER treated as owner checks (Mango's `TokenAccount::load_checked` /
//!   `Loadable::load` check nothing and must keep firing SAT020).
//! - Owner-checking free helpers `check_account_owner` /
//!   `check_system_account` (SDI) → `owner_checked`.
//! - State-type loads `<StateType>::load(..)`: name exactly `load` (never
//!   `load_checked`), a receiver type segment that is not `Self`, and the
//!   account argument classified by the frontend as `AccountKind::State` or
//!   `AccountKind::Unchecked` → `owner_checked` + `key_checked` (the Jito/SDI
//!   `X::load` helpers verify owner, discriminator and canonical PDA).
//!   Token/mint/program-kind accounts are excluded so a bare `load` on a
//!   token account still fires. SDI's `Whitelist::load` / `Hopper::load` are
//!   covered by this pattern (their accounts resolve `Unchecked`).
//! - Authority-key helpers `check_admin` / `check_delegate_admin` /
//!   `check_staker` / `check_authority` / `check_owner` called with a
//!   `<account>.key` argument → `key_checked`.
//! - Canonical-PDA derivation checkers `check_deposit_stake_authority_address`
//!   / `check_deposit_receipt_address` (SDI) called with a `<account>.key`
//!   argument → `key_checked`: the helpers derive the canonical PDA with
//!   `create_program_address` and error on mismatch, pinning the key.
//!
//! The scan is per handler body only (no helper-body recursion): whitelisted
//! names are trusted as the guard contract, and anything else is handled by
//! the frontend's own reachability analysis.
//!
//! # SDI guard-shape extensions (2026-08 corpus round)
//!
//! The Stake-Deposit-Interceptor corpus (9 newly-resolved borsh enum-unpack
//! instructions) exposed three frontend gaps that this layer closes from
//! `auth.rs` alone (the frontend is frozen):
//!
//! - **`_info`-suffixed handler variables.** SDI binds `let x_info: &AccountInfo<'_> =
//!   next_account_info(..)` while the shank `#[account(N, name = "x")]` table
//!   names the same account `x`. All var-name matching here normalizes both
//!   sides (strip a leading `_` and a trailing `_info`) before comparing.
//! - **Annotated let-bindings are invisible to the frontend.** `let x: &AccountInfo<'_>`
//!   parses as a `Pat::Type`, which the frontend's `pat_ident` does not bind,
//!   so inline `if !x.is_signer { return Err(..) }` guards, `.key` compares
//!   and write detection on such variables never fire. This layer re-scans
//!   the handler's guard contexts (`if`/`while` conditions, guard macros,
//!   match scrutinees and arm guards) for `is_signer` / `key` / `owner`
//!   member accesses and maps them to accounts by normalized name.
//! - **Untracked consumption patterns.** SDI's annotated bindings also break
//!   the frontend's positional binding, so helper-call and CPI analysis that
//!   keys on the resolved variable name misses the account entirely. This
//!   layer re-enumerates the handler's positional bindings
//!   (`next_account_info` chains and slice destructuring; untracked patterns
//!   such as `split_at`/`array_refs` fall back to name matching) and runs its
//!   CPI-passed-only classification against the *binding variable*.
//!
//! Additional SDI-derived suppressions (all conservative and corpus-verified):
//! - **SAT019/SAT021 skip `Signer`-by-construction accounts** (runtime
//!   guarantees the signature — same exemption SAT019 already had; SDI's
//!   shank `signer` payer/user-transfer-authority accounts).
//! - **SAT019/SAT021 skip CPI-delegated authorities**: an authority-named
//!   account whose every use is a pass-through into an `invoke`/`invoke_signed`
//!   accounts list, an instruction-builder argument, or an `AccountMeta`
//!   constructor (relaxed CPI classification, any callee). The program never
//!   reads or compares the account; access control is delegated to the callee
//!   (SDI's `stake_pool_withdraw_authority` / `withdraw_authority` /
//!   `user_stake_authority` pass-throughs to the SPL stake-pool CPI). This
//!   deliberately does NOT extend SAT020, whose unknown-callee suppression is
//!   pinned conservative by `cpi_to_unknown_program_is_reported`.
//! - **SAT020 skips unreferenced accounts**: an account the handler never
//!   mentions (only its `next_account_info` binding exists) has no attack
//!   surface in the instruction (SDI's unused `associated_token_program`).
//! - **SAT019/SAT021 skip init-time authority records**: an authority-named
//!   account whose every use is an assignment RHS (`state.field = *acct.key`)
//!   into state deserialized from an account this handler freshly creates or
//!   empty-checks (`create_*` / `check_system_account` / `load_system_account`)
//!   is an init-time set by the creator — the value is data, not access
//!   control (SDI's `authority` recorded during `Init...`). Push-transfer
//!   records into *existing* state (Jito's `new_admin`/`new_owner`) keep
//!   firing — they are the intentionally-kept hardening family.
//!
//! Title prefixes are load-bearing for SARIF classification (section 7);
//! do not rename them.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use syn::punctuated::Punctuated;

use crate::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};
use crate::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT019_TITLE: &str = "Unverified Signer Account:";
const SAT020_TITLE: &str = "Unverified Owner Account:";
const SAT021_TITLE: &str = "Unchecked Authority Key:";

// ── Helper-guard whitelists ─────────────────────────────────────────────────
//
// Curated, exact-name whitelists for the handler-body helper scan (see the
// module docs). These names ARE the guard contract; anything not listed here
// is never treated as a guard by this layer.

/// Signer-requiring helpers (pattern 1): verified against Jito's
/// `jito_jsm_core::loader::load_signer`, which errors on `!info.is_signer`.
const SIGNER_HELPERS: [&str; 4] = ["load_signer", "require_signer", "check_signer", "assert_signer"];

/// Authority-key equality helpers (pattern 4): verified against Jito's
/// `check_admin` / `check_delegate_admin` / `check_staker` methods, which
/// compare the argument key to a stored authority key.
const AUTHORITY_KEY_HELPERS: [&str; 5] =
    ["check_admin", "check_delegate_admin", "check_staker", "check_authority", "check_owner"];

/// Canonical-PDA derivation checkers (SDI, pattern 4b): the account `.key`
/// argument is compared against `create_program_address`/`find_program_address`
/// seeds — `check_deposit_stake_authority_address` and
/// `check_deposit_receipt_address` derive the canonical PDA and error on
/// mismatch, pinning the account's key exactly like a `<StateType>::load`.
const PDA_KEY_HELPERS: [&str; 2] = ["check_deposit_stake_authority_address", "check_deposit_receipt_address"];

/// Owner-checking free helpers (SDI, pattern 2b): `check_account_owner` errors
/// on `*program_id != *account_info.owner`; `check_system_account` additionally
/// requires a system-owned, empty (uninitialized) account. Both pin the
/// account's owner.
const OWNER_CHECK_HELPERS: [&str; 2] = ["check_account_owner", "check_system_account"];

/// Account-creation / uninitialized-account helpers (pattern 5): their account
/// arguments are freshly created (or empty-checked) state within the handler,
/// so authority values recorded into them are init-time sets by the creator —
/// not access-control uses.
const FRESH_STATE_HELPERS: [&str; 6] = [
    "check_system_account",
    "load_system_account",
    "create_pda_account",
    "create_account",
    "create_associated_token_account",
    "create_associated_token_account_idempotent",
];

/// Guard macros whose arguments are guard contexts (mirrors the frontend's
/// `is_guard_macro` list).
const GUARD_MACROS: [&str; 11] = [
    "require",
    "require_keys_eq",
    "require_keys_neq",
    "require_eq",
    "assert",
    "assert_eq",
    "invariant",
    "debug_assert",
    "debug_assert_eq",
    "check",
    "check_eq",
];

/// Program-kind words (pattern 2): a `load_*` helper whose name contains one
/// of these verifies `owner == expected program`.
const PROGRAM_KIND_WORDS: [&str; 5] =
    ["system_account", "token_account", "token_mint", "associated_token_account", "mpl_metadata_program"];

/// True when the callee name is an owner-checking `load_*` helper.
fn is_owner_loader(name: &str) -> bool {
    name.starts_with("load_") && PROGRAM_KIND_WORDS.iter().any(|w| name.contains(w))
}

/// Whether the account name marks it as privileged. Mirrors the Anchor
/// backend's `check_missing_signer` name list plus the spec's suffix rules
/// (`_authority`/`_admin`/`_owner`/`_signer`).
fn is_authority_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXACT: [&str; 12] = [
        "authority",
        "owner",
        "admin",
        "payer",
        "creator",
        "manager",
        "operator",
        "governor",
        "signer",
        "upgrade_authority",
        "mint_authority",
        "freeze_authority",
    ];
    EXACT.contains(&lower.as_str())
        || lower.ends_with("_authority")
        || lower.ends_with("_admin")
        || lower.ends_with("_owner")
        || lower.ends_with("_signer")
}

/// Builtin accounts whose identity is fixed by the runtime; owner checks are
/// meaningless for them and would only produce false positives.
fn is_builtin(kind: AccountKind) -> bool {
    matches!(kind, AccountKind::Sysvar | AccountKind::Program | AccountKind::SystemProgram)
}

/// `"{file}:{line} ({instruction_name})"` — same shape as the Anchor backend.
fn location(ix: &NativeInstruction) -> String {
    let file = ix.file.as_str();
    let name = ix.name.as_str();
    format!("{file}:{} ({name})", ix.line)
}

/// SAT019: authority-named account used without any reachable `is_signer`
/// check. Skipped when the account is a `Signer` by construction (its
/// signature is guaranteed by the runtime) or when its key is pinned (fixed
/// key / PDA derivation makes the signer irrelevant).
fn sat019(ix: &NativeInstruction, account: &ResolvedAccount) -> Finding {
    let name = account.name.as_str();
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT019_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "The account `{name}` is used in instruction `{ix_name}` without any reachable \
             `is_signer` check. Its name identifies it as an authority, yet its signature is \
             never verified, so the runtime guarantees nothing about who supplied it. Exploit: \
             an attacker calls `{ix_name}` passing their own public key for `{name}` and the \
             victim's data accounts; every privileged transition gated on this account \
             (withdrawals, ownership changes, minting) is then authorized under the attacker's \
             identity."
        ),
        location: Some(location(ix)),
        suggestion: Some(format!(
            "Verify the signature before using the account, e.g. \
             `if !{name}.is_signer {{ return Err(ProgramError::MissingRequiredSignature); }}`, \
             or pin the account to a fixed key / PDA derivation."
        )),
    }
}

/// SAT020: stateful or written account whose owner is never verified and
/// whose key is not pinned. Skipped for runtime-builtin kinds (sysvars,
/// programs, system program) and for accounts that are CPI-passed-only (see
/// `CpiClassifier`): the program itself never reads the account and every use
/// is an argument of an `invoke`/`invoke_signed` against a known validating
/// builtin (SPL Token, Token-2022, AT program, system program), which checks
/// ownership at runtime.
fn sat020(ix: &NativeInstruction, account: &ResolvedAccount) -> Finding {
    let name = account.name.as_str();
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT020_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "The account `{name}` carries state or is written by instruction `{ix_name}` but is \
             never checked against the program's owner (`owner_checked = false`) and its key is \
             not pinned (`key_checked = false`). Any account owned by any program can be passed \
             here, so data the program treats as its own state can be substituted with an \
             attacker-crafted account owned by a malicious program. Exploit: supply a look-alike \
             account owned by a program the attacker controls, with forged data, and the \
             program's discriminator/state checks operate on attacker-controlled bytes."
        ),
        location: Some(location(ix)),
        suggestion: Some(format!(
            "Add an owner check before reading or writing the account, e.g. \
             `if {name}.owner != program_id {{ return Err(ProgramError::IllegalOwner); }}`."
        )),
    }
}

/// SAT021: authority-named account that is never compared to a stored/derived
/// key and is not signer-checked either, so the program cannot tell the real
/// authority apart from an arbitrary caller-supplied public key.
fn sat021(ix: &NativeInstruction, account: &ResolvedAccount) -> Finding {
    let name = account.name.as_str();
    let ix_name = ix.name.as_str();
    Finding {
        id: String::new(),
        title: format!("{SAT021_TITLE} `{name}`"),
        severity: Severity::High,
        description: format!(
            "The authority-named account `{name}` is used in instruction `{ix_name}` without \
             ever being compared to a stored or derived key (`key_checked = false`) and without \
             a signer check (`is_signer_checked = false`). Access control based on \"is this \
             the authority account?\" therefore degenerates to \"is this any account?\". \
             Exploit: pass any public key the program will accept for `{name}` and inherit the \
             authority role the account's name implies."
        ),
        location: Some(location(ix)),
        suggestion: Some(format!(
            "Compare the account key against the expected value before use, e.g. \
             `if {name}.key != expected_authority {{ return Err(ProgramError::InvalidAccountData); }}`, \
             or derive it with `find_program_address` and compare; alternatively require \
             `{name}.is_signer`."
        )),
    }
}

/// Run SAT019/SAT020/SAT021 over every instruction of `program`.
///
/// At most one finding per (rule, instruction, account): deduplication is
/// inherent to the iteration, and findings are never merged across
/// instructions even when they refer to the same account name.
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let index = Rc::new(FnIndex::build(parsed));
    let mut classifier = CpiClassifier::new(index.clone());
    let scanner = HelperGuardScanner { index };
    let mut findings = Vec::new();
    for ix in &program.instructions {
        // Handler-body helper guards (whitelisted names only, see module docs).
        let bindings = handler_binding_vars(&scanner.index, ix);
        let guards = scanner.guard_set(ix, &bindings);
        for account in &ix.accounts {
            let authority_named = is_authority_named(&account.name);
            let stateful = matches!(account.kind, AccountKind::State | AccountKind::TokenAccount | AccountKind::Mint);

            let signer_ok = account.is_signer_checked || guards.signer.contains(&account.name);
            let owner_ok = account.owner_checked || guards.owner.contains(&account.name);
            let key_ok = account.key_checked || guards.key.contains(&account.name);
            let recorded_ok = guards.recorded.contains(&account.name);

            // SAT019: authority-named, signature never verified, not a
            // `Signer` by construction, key not pinned, not an init-time
            // record into fresh state, and not delegated to a CPI callee.
            if authority_named
                && !signer_ok
                && account.kind != AccountKind::Signer
                && !key_ok
                && !recorded_ok
                && !classifier.is_cpi_passed_any(ix, account, &bindings)
            {
                findings.push(sat019(ix, account));
            }

            // SAT020: stateful or written account, owner never verified, key
            // not pinned, not a runtime builtin, not CPI-passed-only to a
            // known validating builtin, and referenced by the program at all.
            if !is_builtin(account.kind)
                && (stateful || account.written)
                && !owner_ok
                && !key_ok
                && !classifier.is_cpi_passed_only(ix, account, &bindings)
                && !classifier.is_unreferenced(ix, account, &bindings)
            {
                findings.push(sat020(ix, account));
            }

            // SAT021: authority-named, key never compared, signature never
            // verified (Signer-by-construction accounts have their signature
            // guaranteed by the runtime).
            if authority_named
                && !key_ok
                && !signer_ok
                && account.kind != AccountKind::Signer
                && !recorded_ok
                && !classifier.is_cpi_passed_any(ix, account, &bindings)
            {
                findings.push(sat021(ix, account));
            }
        }
    }
    findings
}

// ── Helper-guard recognition ────────────────────────────────────────────────
//
// Guard flags produced by whitelisted helper calls found in the handler body.
// See the module docs for the whitelist → flag mapping and its rationale.

#[derive(Debug, Clone, Default)]
struct GuardSet {
    /// Accounts passed to a whitelisted signer helper (`load_signer`, ...).
    signer: HashSet<String>,
    /// Accounts passed to a whitelisted owner-loading helper
    /// (`load_system_account`, `load_token_account`, ...).
    owner: HashSet<String>,
    /// Accounts passed to a whitelisted authority-key helper with a `.key`
    /// argument, or to a state-type `<StateType>::load`.
    key: HashSet<String>,
    /// Authority-named accounts recorded into freshly-created state
    /// (`state.field = *acct.key` assignment RHS only): init-time sets.
    recorded: HashSet<String>,
}

/// Normalized form of an identifier for account-variable matching: strips a
/// leading `_` and a trailing `_info` (SDI's `authority_info` ↔ shank
/// `authority` handler convention).
fn var_key(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name).strip_suffix("_info").unwrap_or(name)
}

/// True when an expression identifier refers to the resolved account `name`.
fn ident_matches(ident: &str, name: &str) -> bool {
    var_key(ident) == var_key(name)
}

/// The bare variable an expression peels to (`acct`, `&acct`, `(acct)`).
fn bare_var(e: &syn::Expr) -> Option<String> {
    match peel(e) {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// The account variable of a `<var>.key` argument (wrappers allowed):
/// `old_admin.key`, `&old_admin.key`.
fn key_var(e: &syn::Expr) -> Option<String> {
    match peel(e) {
        syn::Expr::Field(f) if member_name(&f.member) == "key" => bare_var(&f.base),
        _ => None,
    }
}

/// Scans handler bodies for whitelisted guard-helper calls.
struct HelperGuardScanner {
    index: Rc<FnIndex>,
}

impl HelperGuardScanner {
    /// Insert every resolved account that `var` could refer to (normalized
    /// `_info`-suffix matching), keyed by the canonical account name.
    fn insert_matching(&self, out: &mut HashSet<String>, var: &str, names: &HashSet<&str>) {
        for n in names {
            if ident_matches(var, n) {
                out.insert(n.to_string());
            }
        }
    }

    /// Attribute a guard hit for the handler variable `var` to the resolved
    /// account: positionally via the handler's binding enumeration first
    /// (bridges shank names that differ from the handler variable beyond the
    /// `_info` suffix, e.g. SDI's `deposit_stake_authority_info` ↔ shank
    /// `deposit_authority`), then by normalized name.
    fn attribute(
        &self,
        out: &mut HashSet<String>,
        var: &str,
        var_index: &HashMap<String, usize>,
        accounts: &[ResolvedAccount],
        names: &HashSet<&str>,
    ) {
        if let Some(&idx) = var_index.get(var)
            && let Some(account) = accounts.get(idx)
        {
            out.insert(account.name.clone());
            return;
        }
        self.insert_matching(out, var, names);
    }

    /// Kind of the resolved account `var` refers to (positional first, then
    /// normalized name).
    fn kind_of<'a>(
        &self,
        var: &str,
        var_index: &HashMap<String, usize>,
        accounts: &'a [ResolvedAccount],
        kinds: &HashMap<&'a str, AccountKind>,
    ) -> Option<AccountKind> {
        if let Some(&idx) = var_index.get(var) {
            return accounts.get(idx).map(|a| a.kind);
        }
        kinds.iter().find(|(n, _)| ident_matches(var, n)).map(|(_, k)| *k)
    }

    /// Guard sets for one instruction, from its handler body.
    fn guard_set(&self, ix: &NativeInstruction, bindings: &Option<Vec<Option<String>>>) -> GuardSet {
        let mut out = GuardSet::default();
        let Some(handler) = self.index.lookup(&ix.handler, &ix.file) else {
            return out;
        };
        // Name → frontend kind, for the pattern-3 State/Unchecked gate.
        let kinds: HashMap<&str, AccountKind> = ix.accounts.iter().map(|a| (a.name.as_str(), a.kind)).collect();
        let names: HashSet<&str> = ix.accounts.iter().map(|a| a.name.as_str()).collect();
        // Handler variable → account index (positional binding enumeration).
        let var_index: HashMap<String, usize> = bindings
            .as_ref()
            .map(|b| b.iter().enumerate().filter_map(|(idx, v)| v.as_deref().map(|v| (v.to_string(), idx))).collect())
            .unwrap_or_default();

        let mut signer = HashSet::new();
        let mut owner = HashSet::new();
        let mut key = HashSet::new();
        walk_all(&handler.block, &mut |e| match e {
            syn::Expr::Call(c) => {
                let Some(callee) = path_key(&c.func) else { return };
                let segments: Vec<&str> = callee.split("::").collect();
                let last = segments.last().copied().unwrap_or("");
                if SIGNER_HELPERS.contains(&last) {
                    for arg in &c.args {
                        if let Some(v) = bare_var(arg) {
                            self.attribute(&mut signer, &v, &var_index, &ix.accounts, &names);
                        }
                    }
                }
                if OWNER_CHECK_HELPERS.contains(&last) || is_owner_loader(last) {
                    for arg in &c.args {
                        if let Some(v) = bare_var(arg) {
                            self.attribute(&mut owner, &v, &var_index, &ix.accounts, &names);
                        }
                    }
                }
                // `<StateType>::load`: exact name `load` (never `load_checked`),
                // a receiver type segment that is not `Self`, and an account
                // classified `State`/`Unchecked` by the frontend.
                if segments.len() >= 2 && last == "load" && segments[segments.len() - 2] != "Self" {
                    for arg in &c.args {
                        if let Some(v) = bare_var(arg)
                            && matches!(
                                self.kind_of(&v, &var_index, &ix.accounts, &kinds),
                                Some(AccountKind::State | AccountKind::Unchecked)
                            )
                        {
                            self.attribute(&mut owner, &v, &var_index, &ix.accounts, &names);
                            self.attribute(&mut key, &v, &var_index, &ix.accounts, &names);
                        }
                    }
                }
                if AUTHORITY_KEY_HELPERS.contains(&last) || PDA_KEY_HELPERS.contains(&last) {
                    for arg in &c.args {
                        if let Some(v) = key_var(arg) {
                            self.attribute(&mut key, &v, &var_index, &ix.accounts, &names);
                        }
                    }
                }
            }
            syn::Expr::MethodCall(m) => {
                let method = m.method.to_string();
                if AUTHORITY_KEY_HELPERS.contains(&method.as_str()) || PDA_KEY_HELPERS.contains(&method.as_str()) {
                    for arg in &m.args {
                        if let Some(v) = key_var(arg) {
                            self.attribute(&mut key, &v, &var_index, &ix.accounts, &names);
                        }
                    }
                }
            }
            _ => {}
        });

        // Inline guard-context member accesses (`if !x.is_signer { .. }`,
        // `if derived != *x.key { .. }`, require!-style macros): mirrors the
        // frontend's guard-cond scan. The frontend misses SDI's annotated
        // `let x: &AccountInfo<'_>` bindings, so this layer re-scans names.
        for (member, var) in guard_member_accesses(&handler.block) {
            match member.as_str() {
                "is_signer" => self.attribute(&mut signer, &var, &var_index, &ix.accounts, &names),
                "key" => self.attribute(&mut key, &var, &var_index, &ix.accounts, &names),
                "owner" => self.attribute(&mut owner, &var, &var_index, &ix.accounts, &names),
                _ => {}
            }
        }

        // Init-time authority records: recorded-only into freshly-created
        // state (SDI's `authority` during `Init..`); keyed canonically.
        for var in init_recorded_accounts(&handler.block) {
            self.attribute(&mut out.recorded, &var, &var_index, &ix.accounts, &names);
        }

        out.signer = signer;
        out.owner = owner;
        out.key = key;
        out
    }
}

/// Member accesses (`x.is_signer`, `x.key`, `x.owner`) inside guard contexts
/// (if/while conditions, guard macros, match scrutinees and arm guards), as
/// `(member, base-variable)` pairs.
fn guard_member_accesses(block: &syn::Block) -> Vec<(String, String)> {
    let mut out = Vec::new();
    guard_block(block, &mut out);
    out
}

/// Collect guard-context member accesses over a block's statements.
fn guard_block(block: &syn::Block, out: &mut Vec<(String, String)>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => guard_stmt_expr(e, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    guard_stmt_expr(&init.expr, out);
                }
            }
            syn::Stmt::Macro(m) => {
                let last = m.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if GUARD_MACROS.contains(&last.as_str()) {
                    for arg in macro_exprs(&m.mac) {
                        cond_member_accesses(&arg, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Walk a statement-position expression, descending into guard constructs.
fn guard_stmt_expr(e: &syn::Expr, out: &mut Vec<(String, String)>) {
    match e {
        syn::Expr::If(i) => {
            cond_member_accesses(&i.cond, out);
            guard_block(&i.then_branch, out);
            if let Some((_, else_expr)) = &i.else_branch {
                guard_stmt_expr(else_expr, out);
            }
        }
        syn::Expr::While(w) => {
            cond_member_accesses(&w.cond, out);
            guard_block(&w.body, out);
        }
        syn::Expr::Match(m) => {
            cond_member_accesses(&m.expr, out);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    cond_member_accesses(guard, out);
                }
                guard_stmt_expr(&arm.body, out);
            }
        }
        syn::Expr::Block(b) => guard_block(&b.block, out),
        syn::Expr::Unsafe(u) => guard_block(&u.block, out),
        syn::Expr::Async(a) => guard_block(&a.block, out),
        syn::Expr::Const(c) => guard_block(&c.block, out),
        syn::Expr::TryBlock(tb) => guard_block(&tb.block, out),
        syn::Expr::Loop(l) => guard_block(&l.body, out),
        syn::Expr::ForLoop(fl) => guard_block(&fl.body, out),
        syn::Expr::Try(t) => guard_stmt_expr(&t.expr, out),
        syn::Expr::Paren(p) => guard_stmt_expr(&p.expr, out),
        syn::Expr::Group(g) => guard_stmt_expr(&g.expr, out),
        syn::Expr::Return(r) => {
            if let Some(x) = &r.expr {
                guard_stmt_expr(x, out);
            }
        }
        _ => {}
    }
}

/// Member accesses on bare variables inside one guard-condition expression.
fn cond_member_accesses(e: &syn::Expr, out: &mut Vec<(String, String)>) {
    match e {
        syn::Expr::Field(f) => {
            if matches!(member_name(&f.member).as_str(), "is_signer" | "key" | "owner")
                && let syn::Expr::Path(p) = peel(&f.base)
                && let Some(ident) = p.path.get_ident()
            {
                out.push((member_name(&f.member), ident.to_string()));
            }
            cond_member_accesses(&f.base, out);
        }
        syn::Expr::MethodCall(m) if m.method == "key_eq" => {
            if let syn::Expr::Path(p) = peel(&m.receiver)
                && let Some(ident) = p.path.get_ident()
            {
                out.push(("key".to_string(), ident.to_string()));
            }
        }
        syn::Expr::Unary(u) => cond_member_accesses(&u.expr, out),
        syn::Expr::Paren(p) => cond_member_accesses(&p.expr, out),
        syn::Expr::Group(g) => cond_member_accesses(&g.expr, out),
        syn::Expr::Reference(r) => cond_member_accesses(&r.expr, out),
        syn::Expr::Try(t) => cond_member_accesses(&t.expr, out),
        syn::Expr::Let(l) => cond_member_accesses(&l.expr, out),
        syn::Expr::Binary(b) => {
            cond_member_accesses(&b.left, out);
            cond_member_accesses(&b.right, out);
        }
        syn::Expr::Call(c) => {
            for arg in &c.args {
                cond_member_accesses(arg, out);
            }
        }
        syn::Expr::MethodCall(m) => {
            cond_member_accesses(&m.receiver, out);
            for arg in &m.args {
                cond_member_accesses(arg, out);
            }
        }
        _ => {}
    }
}

/// Accounts whose every use is an assignment RHS (`state.field = *acct.key`)
/// into state deserialized from an account this handler freshly creates or
/// empty-checks (`FRESH_STATE_HELPERS`): init-time authority records, keyed by
/// the handler's variable name.
fn init_recorded_accounts(block: &syn::Block) -> HashSet<String> {
    let bindings = top_level_bindings(block);

    // Freshly-created / empty-checked account variables.
    let mut fresh: HashSet<String> = HashSet::new();
    walk_all(block, &mut |e| {
        if let syn::Expr::Call(c) = e
            && let Some(callee) = path_key(&c.func)
            && let Some(last) = callee.rsplit("::").next()
            && FRESH_STATE_HELPERS.contains(&last)
        {
            for arg in &c.args {
                if let Some(v) = bare_var(arg) {
                    fresh.insert(v);
                }
            }
        }
    });

    // `data = acct.try_borrow[_mut]_data()` / `data = acct.data.borrow[_mut]()`
    // → data variable → source account variable.
    let mut data_source: HashMap<String, String> = HashMap::new();
    for (var, rhs) in &bindings {
        if let Some(acct) = data_source_acct(rhs) {
            data_source.insert(var.clone(), acct);
        }
    }
    // `local = Type::try_from_slice[_unchecked][_mut](&mut data | &data)` →
    // local variable → source account variable (through the data variable).
    let mut local_source: HashMap<String, String> = HashMap::new();
    for (var, rhs) in &bindings {
        if let Some(data_var) = deserialize_data_var(rhs)
            && let Some(acct) = data_source.get(&data_var)
        {
            local_source.insert(var.clone(), acct.clone());
        }
    }
    let source_of =
        |var: &str| -> Option<String> { local_source.get(var).cloned().or_else(|| data_source.get(var).cloned()) };

    // Every identifier mention, and every assignment-RHS identifier mention.
    let mut all_idents: Vec<String> = Vec::new();
    walk_all(block, &mut |e| {
        if let syn::Expr::Path(p) = e
            && let Some(ident) = p.path.get_ident()
        {
            all_idents.push(ident.to_string());
        }
    });
    let mut rhs_idents: Vec<String> = Vec::new();
    walk_all(block, &mut |e| {
        if let syn::Expr::Assign(a) = e {
            collect_idents_in_expr(&a.right, &mut rhs_idents);
        }
    });

    // `state.field = *acct.key` assignments whose state resolves to a fresh
    // account: the account is recorded, not enforced.
    let mut recorded: HashSet<String> = HashSet::new();
    walk_all(block, &mut |e| {
        if let syn::Expr::Assign(a) = e
            && let Some(var) = key_base_var(&a.right)
            && let syn::Expr::Field(f) = peel(&a.left)
            && let syn::Expr::Path(p) = peel(&f.base)
            && let Some(local) = p.path.get_ident()
            && let Some(src) = source_of(&local.to_string())
            && fresh.contains(&src)
            && all_idents.iter().filter(|i| *i == &var).count() == rhs_idents.iter().filter(|i| *i == &var).count()
        {
            recorded.insert(var);
        }
    });
    recorded
}

/// `acct.try_borrow[_mut]_data()` / `acct.data.borrow[_mut]()`: the source
/// account variable of a data-binding.
fn data_source_acct(rhs: &syn::Expr) -> Option<String> {
    match peel(rhs) {
        syn::Expr::MethodCall(m) if m.method.to_string().starts_with("try_borrow") => bare_var(&m.receiver),
        syn::Expr::MethodCall(m) if matches!(m.method.to_string().as_str(), "borrow" | "borrow_mut") => {
            match peel(&m.receiver) {
                syn::Expr::Field(f) if member_name(&f.member) == "data" => bare_var(&f.base),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The data variable of a `Type::try_from_slice[_unchecked][_mut](&data)`
/// call, with `.unwrap()`/`.expect()` wrappers peeled.
fn deserialize_data_var(rhs: &syn::Expr) -> Option<String> {
    let mut e = rhs;
    e = match peel(e) {
        syn::Expr::MethodCall(m) if matches!(m.method.to_string().as_str(), "unwrap" | "expect") => &m.receiver,
        other => other,
    };
    match peel(e) {
        syn::Expr::Call(c) => {
            let last = path_key(&c.func).and_then(|k| k.rsplit("::").next().map(|s| s.to_string()))?;
            if !(last.starts_with("try_from_slice") || last.starts_with("from_slice")) {
                return None;
            }
            c.args.first().and_then(bare_var)
        }
        _ => None,
    }
}

/// The account variable of an assignment RHS that peels to `*acct.key` /
/// `acct.key` (deref/ref wrappers allowed).
fn key_base_var(rhs: &syn::Expr) -> Option<String> {
    match peel(rhs) {
        syn::Expr::Field(f) if member_name(&f.member) == "key" => bare_var(&f.base),
        _ => None,
    }
}

/// Collect every path identifier of an expression into `out`.
fn collect_idents_in_expr(e: &syn::Expr, out: &mut Vec<String>) {
    if let syn::Expr::Path(p) = e
        && let Some(ident) = p.path.get_ident()
    {
        out.push(ident.to_string());
    }
    match e {
        syn::Expr::Call(c) => {
            for arg in &c.args {
                collect_idents_in_expr(arg, out);
            }
        }
        syn::Expr::MethodCall(m) => {
            collect_idents_in_expr(&m.receiver, out);
            for arg in &m.args {
                collect_idents_in_expr(arg, out);
            }
        }
        syn::Expr::Field(f) => collect_idents_in_expr(&f.base, out),
        syn::Expr::Unary(u) => collect_idents_in_expr(&u.expr, out),
        syn::Expr::Reference(r) => collect_idents_in_expr(&r.expr, out),
        syn::Expr::Paren(p) => collect_idents_in_expr(&p.expr, out),
        syn::Expr::Group(g) => collect_idents_in_expr(&g.expr, out),
        syn::Expr::Try(t) => collect_idents_in_expr(&t.expr, out),
        syn::Expr::Binary(b) => {
            collect_idents_in_expr(&b.left, out);
            collect_idents_in_expr(&b.right, out);
        }
        syn::Expr::Index(i) => {
            collect_idents_in_expr(&i.expr, out);
            collect_idents_in_expr(&i.index, out);
        }
        syn::Expr::Array(a) => {
            for el in &a.elems {
                collect_idents_in_expr(el, out);
            }
        }
        syn::Expr::Tuple(t) => {
            for el in &t.elems {
                collect_idents_in_expr(el, out);
            }
        }
        _ => {}
    }
}

// ── Positional handler bindings ─────────────────────────────────────────────
//
// SDI's `let x: &AccountInfo<'_> = next_account_info(..)` annotated bindings
// parse as `Pat::Type`, which the frozen frontend's `pat_ident` does not bind —
// so every guard/CPI analysis that keys on the resolved variable name misses
// those accounts entirely. This layer re-enumerates the handler's positional
// bindings from source and runs the CPI classification against the *binding
// variable* instead of the (possibly shank-renamed) account name.

/// True when the initializer consumes one positional account.
fn is_consumption(init: &syn::Expr) -> bool {
    let mut e = init;
    loop {
        match peel(e) {
            syn::Expr::MethodCall(m)
                if matches!(m.method.to_string().as_str(), "ok" | "ok_or" | "ok_or_else" | "unwrap" | "expect") =>
            {
                e = &m.receiver;
            }
            syn::Expr::Call(c) => return path_key(&c.func).as_deref() == Some("next_account_info"),
            syn::Expr::MethodCall(m) if m.method == "next" => return true,
            _ => return false,
        }
    }
}

/// The variable name of a binding pattern (peels `Pat::Type` annotations).
fn pat_ident_peel(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(i) => Some(i.ident.to_string()),
        syn::Pat::Type(t) => pat_ident_peel(&t.pat),
        syn::Pat::Wild(_) => Some("_".to_string()),
        _ => None,
    }
}

/// Positional binding variables of a `let [a, b, ..] = accounts` destructure.
fn slice_binding_vars(pat: &syn::Pat) -> Option<Vec<Option<String>>> {
    let syn::Pat::Slice(ps) = pat else { return None };
    let mut out = Vec::new();
    for elem in &ps.elems {
        match elem {
            syn::Pat::Ident(_) | syn::Pat::Type(_) | syn::Pat::Wild(_) => out.push(pat_ident_peel(elem)),
            syn::Pat::Rest(_) => break,
            _ => return None,
        }
    }
    Some(out)
}

/// Binding variable per account index for the instruction's handler. `None`
/// when the handler uses consumption patterns the enumeration does not track
/// (`split_at`, `array_refs`, iterator `.next()` loops), which makes the
/// positional mapping unreliable.
fn handler_binding_vars(index: &FnIndex, ix: &NativeInstruction) -> Option<Vec<Option<String>>> {
    let handler = index.lookup(&ix.handler, &ix.file)?;
    let block = &handler.block;
    // Untracked consumption patterns make the positional mapping unreliable.
    let mut tracked = true;
    walk_all(block, &mut |e| match e {
        syn::Expr::MethodCall(m) if matches!(m.method.to_string().as_str(), "split_at" | "next") => {
            tracked = false;
        }
        syn::Expr::Macro(mac) if mac.mac.path.segments.last().is_some_and(|s| s.ident == "array_refs") => {
            tracked = false;
        }
        _ => {}
    });
    if !tracked {
        return None;
    }
    let mut out: Vec<Option<String>> = Vec::new();
    for stmt in &block.stmts {
        if let syn::Stmt::Local(l) = stmt
            && let Some(init) = l.init.as_ref().map(|i| i.expr.as_ref())
        {
            if is_consumption(init) {
                out.push(pat_ident_peel(&l.pat));
            } else if let Some(vars) = slice_binding_vars(&l.pat)
                && let Some(init) = l.init.as_ref().map(|i| i.expr.as_ref())
                && matches!(peel(init), syn::Expr::Path(_) | syn::Expr::Reference(_) | syn::Expr::Index(_))
            {
                out.extend(vars);
            }
        }
    }
    Some(out)
}

// ── SAT020 CPI-passed-only suppression ───────────────────────────────────────
//
// An account that the program itself never reads, and that is only used as an
// argument of `invoke`/`invoke_signed` calls whose program id resolves to a
// known validating builtin (SPL Token, Token-2022, the Associated Token
// program, the system program), cannot be substituted: the callee verifies
// ownership at runtime. SAT020 is suppressed for such accounts.
//
// The analysis walks the handler body and its local helper call graph
// (depth ≤ 2, cycle-guarded, memoized) with the same semantics as
// `docs/NATIVE_BACKEND.md` section 6. An account is *not* suppressed when:
//   - any use is an argument of a CPI against an unknown program (or the
//     callee program id cannot be resolved),
//   - the program reads/deserializes the account's data (load/unpack/
//     try_from_slice/borrow/borrow_mut/... — in the handler or any helper),
//   - the account's fields are accessed directly in program code (outside the
//     CPI instruction-building context),
//   - any non-`clone` method is called on the account,
//   - the account is passed as anything other than a plain pass-through to a
//     local helper (e.g. `x.key` or `x.data` arguments are program uses).
//
// Known limitations (conservative: they bias toward firing): `let` bindings
// are only resolved at the top level of the function that contains the call;
// instruction `AccountMeta` lists built with `vec!`/macros are opaque; macro
// bodies that do not parse as comma-separated expressions are skipped; opaque
// `syn::Expr::Verbatim` nodes are skipped.

/// Known validating builtins: programs that enforce account ownership at
/// runtime, so passing an account to their CPI is itself an ownership check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownProgram {
    Token,
    Token2022,
    AssociatedToken,
    System,
}

/// Outcome of classifying every use of an account inside one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UseClass {
    /// Every use is a pass-through to a CPI against a known validating
    /// builtin (or a clone); the account is never read or field-accessed.
    CpiPassed,
    /// A program use that prevents SAT020 suppression.
    Used,
}

/// Walk context: `CpiArg` marks expressions inside a known-builtin CPI
/// instruction-building position, where bare variables, `clone()`s and
/// `.key`-style field reads are part of the CPI and therefore benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Normal,
    CpiArg,
}

/// Program ids of the known validating builtins (base58 string literals).
fn known_program_from_literal(lit: &str) -> Option<KnownProgram> {
    match lit {
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" => Some(KnownProgram::Token),
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => Some(KnownProgram::Token2022),
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" => Some(KnownProgram::AssociatedToken),
        "11111111111111111111111111111111" => Some(KnownProgram::System),
        _ => None,
    }
}

/// Program implied by a path key (`spl_token::ID`, `spl_token_2022::id()`,
/// `solana_program::system_program::ID`, `associated_token_account::id()`).
fn program_from_path_key(key: &str) -> Option<KnownProgram> {
    let k = key.to_ascii_lowercase();
    if k.contains("spl_token_2022") {
        Some(KnownProgram::Token2022)
    } else if k.contains("spl_token") {
        Some(KnownProgram::Token)
    } else if k.contains("associated_token_account") {
        Some(KnownProgram::AssociatedToken)
    } else if k.contains("system_program") || k.contains("system_instruction") {
        Some(KnownProgram::System)
    } else if k.contains("token") && !k.contains("account") {
        // `token::id()`-style alias paths.
        Some(KnownProgram::Token)
    } else {
        None
    }
}

/// True when the callee key is an instruction builder
/// (`spl_token::instruction::transfer`, `solana_program::system_instruction::…`).
fn is_instruction_builder(key: &str) -> bool {
    key.split("::").any(|seg| seg.contains("instruction"))
}

/// Callee last-segment names that read or deserialize account data.
const DATA_TOUCH_CALLS: [&str; 8] = [
    "try_from_slice",
    "try_from_slice_unchecked",
    "unpack",
    "unpack_unchecked",
    "load",
    "load_checked",
    "load_mut",
    "load_mut_checked",
];

const INVOKE_NAMES: [&str; 3] = ["invoke", "invoke_signed", "invoke_signed_unchecked"];

// ── Expression helpers ───────────────────────────────────────────────────────

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(i) => i.to_string(),
        syn::Member::Unnamed(i) => i.index.to_string(),
    }
}

/// Peel reference/paren/group/deref/try wrappers off an expression.
fn peel(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Reference(r) => peel(&r.expr),
        syn::Expr::Paren(p) => peel(&p.expr),
        syn::Expr::Group(g) => peel(&g.expr),
        syn::Expr::Unary(u) => peel(&u.expr),
        syn::Expr::Try(t) => peel(&t.expr),
        _ => e,
    }
}

/// `a::b::c` key of a callable path expression.
fn path_key(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => Some(p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")),
        _ => None,
    }
}

/// Top-level `let` bindings of a function block.
fn top_level_bindings(block: &syn::Block) -> HashMap<String, syn::Expr> {
    let mut map = HashMap::new();
    for stmt in &block.stmts {
        if let syn::Stmt::Local(local) = stmt
            && let Some(init) = &local.init
            && let syn::Pat::Ident(pat) = &local.pat
        {
            map.insert(pat.ident.to_string(), (*init.expr).clone());
        }
    }
    map
}

/// Local variables bound from `X::try_from(&accounts[..])` — struct-style
/// account bundles whose fields (`accs.authority`) denote resolved accounts.
fn struct_vars_of(bindings: &HashMap<String, syn::Expr>) -> HashSet<String> {
    bindings
        .iter()
        .filter_map(|(name, rhs)| {
            let is_try_from = matches!(rhs, syn::Expr::Call(c) if path_key(&c.func).as_deref()
                .is_some_and(|k| k == "try_from" || k.ends_with("::try_from")));
            is_try_from.then(|| name.clone())
        })
        .collect()
}

/// The account variable an expression chain is rooted at: `token_account`,
/// `token_account.key`, `token_account.data.borrow()`, or — for struct-style
/// bundles — `accs.authority` / `accs.authority.key`.
fn account_ident(e: &syn::Expr, struct_vars: &HashSet<String>) -> Option<String> {
    match peel(e) {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::MethodCall(m) => account_ident(&m.receiver, struct_vars),
        syn::Expr::Field(f) => {
            let member = member_name(&f.member);
            if matches!(member.as_str(), "key" | "data") {
                account_ident(&f.base, struct_vars)
            } else if matches!(&*f.base, syn::Expr::Path(p)
                if p.path.get_ident().is_some_and(|i| struct_vars.contains(&i.to_string())))
            {
                Some(member)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// True when the expression is a plain pass-through of `var` to a helper
/// call: `var`, `&var`, `var.clone()`, or `accs.var` (struct bundle field).
fn is_pass_through(e: &syn::Expr, var: &str, struct_vars: &HashSet<String>) -> bool {
    match peel(e) {
        syn::Expr::Path(p) => p.path.get_ident().is_some_and(|i| i == var),
        syn::Expr::MethodCall(m) if m.method == "clone" => is_pass_through(&m.receiver, var, struct_vars),
        syn::Expr::Field(f) => {
            let member = member_name(&f.member);
            matches!(&*f.base, syn::Expr::Path(p)
                if p.path.get_ident().is_some_and(|i| struct_vars.contains(&i.to_string()))
                    && member == var)
        }
        _ => false,
    }
}

/// Parse a macro body as comma-separated expressions, when possible.
fn macro_exprs(mac: &syn::Macro) -> Vec<syn::Expr> {
    mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        .map(|args| args.into_iter().collect())
        .unwrap_or_default()
}

/// The variable of a `var.key` field expression (wrappers allowed).
fn field_base_ident(e: &syn::Expr) -> Option<String> {
    match peel(e) {
        syn::Expr::Field(f) if member_name(&f.member) == "key" => path_ident(&f.base),
        _ => None,
    }
}

/// Single-ident of a path expression.
fn path_ident(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// Account variable of an array element: `x`, `x.clone()`, `&x`.
fn element_ident(e: &syn::Expr) -> Option<String> {
    match peel(e) {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::MethodCall(m) if m.method == "clone" => element_ident(&m.receiver),
        _ => None,
    }
}

/// Walk every expression of a block (nested blocks, match arms, closures,
/// guard macros), calling `f` for each one.
fn walk_all(block: &syn::Block, f: &mut dyn FnMut(&syn::Expr)) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => walk_expr_all(e, f),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    walk_expr_all(&init.expr, f);
                }
            }
            syn::Stmt::Macro(m) => {
                for arg in macro_exprs(&m.mac) {
                    walk_expr_all(&arg, f);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn walk_expr_all(e: &syn::Expr, f: &mut dyn FnMut(&syn::Expr)) {
    f(e);
    match e {
        syn::Expr::Call(c) => {
            walk_expr_all(&c.func, f);
            for arg in &c.args {
                walk_expr_all(arg, f);
            }
        }
        syn::Expr::MethodCall(m) => {
            walk_expr_all(&m.receiver, f);
            for arg in &m.args {
                walk_expr_all(arg, f);
            }
        }
        syn::Expr::Block(b) => walk_all(&b.block, f),
        syn::Expr::Unsafe(u) => walk_all(&u.block, f),
        syn::Expr::Async(a) => walk_all(&a.block, f),
        syn::Expr::Const(c) => walk_all(&c.block, f),
        syn::Expr::TryBlock(tb) => walk_all(&tb.block, f),
        syn::Expr::If(i) => {
            walk_expr_all(&i.cond, f);
            walk_all(&i.then_branch, f);
            if let Some((_, else_expr)) = &i.else_branch {
                walk_expr_all(else_expr, f);
            }
        }
        syn::Expr::While(w) => {
            walk_expr_all(&w.cond, f);
            walk_all(&w.body, f);
        }
        syn::Expr::Loop(l) => walk_all(&l.body, f),
        syn::Expr::ForLoop(fl) => walk_all(&fl.body, f),
        syn::Expr::Match(m) => {
            walk_expr_all(&m.expr, f);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    walk_expr_all(guard, f);
                }
                walk_expr_all(&arm.body, f);
            }
        }
        syn::Expr::Try(t) => walk_expr_all(&t.expr, f),
        syn::Expr::Paren(p) => walk_expr_all(&p.expr, f),
        syn::Expr::Group(g) => walk_expr_all(&g.expr, f),
        syn::Expr::Reference(r) => walk_expr_all(&r.expr, f),
        syn::Expr::RawAddr(r) => walk_expr_all(&r.expr, f),
        syn::Expr::Unary(u) => walk_expr_all(&u.expr, f),
        syn::Expr::Await(a) => walk_expr_all(&a.base, f),
        syn::Expr::Yield(y) => {
            if let Some(x) = &y.expr {
                walk_expr_all(x, f);
            }
        }
        syn::Expr::Let(l) => walk_expr_all(&l.expr, f),
        syn::Expr::Field(fl) => walk_expr_all(&fl.base, f),
        syn::Expr::Binary(b) => {
            walk_expr_all(&b.left, f);
            walk_expr_all(&b.right, f);
        }
        syn::Expr::Assign(a) => {
            walk_expr_all(&a.left, f);
            walk_expr_all(&a.right, f);
        }
        syn::Expr::Index(i) => {
            walk_expr_all(&i.expr, f);
            walk_expr_all(&i.index, f);
        }
        syn::Expr::Tuple(t) => {
            for el in &t.elems {
                walk_expr_all(el, f);
            }
        }
        syn::Expr::Array(a) => {
            for el in &a.elems {
                walk_expr_all(el, f);
            }
        }
        syn::Expr::Repeat(r) => {
            walk_expr_all(&r.expr, f);
            walk_expr_all(&r.len, f);
        }
        syn::Expr::Struct(s) => {
            for field in &s.fields {
                walk_expr_all(&field.expr, f);
            }
        }
        syn::Expr::Closure(cl) => walk_expr_all(&cl.body, f),
        syn::Expr::Cast(c) => walk_expr_all(&c.expr, f),
        syn::Expr::Range(r) => {
            if let Some(from) = &r.start {
                walk_expr_all(from, f);
            }
            if let Some(to) = &r.end {
                walk_expr_all(to, f);
            }
        }
        syn::Expr::Return(r) => {
            if let Some(x) = &r.expr {
                walk_expr_all(x, f);
            }
        }
        syn::Expr::Break(b) => {
            if let Some(x) = &b.expr {
                walk_expr_all(x, f);
            }
        }
        syn::Expr::Macro(mac) => {
            for arg in macro_exprs(&mac.mac) {
                walk_expr_all(&arg, f);
            }
        }
        syn::Expr::Lit(_) | syn::Expr::Path(_) | syn::Expr::Continue(_) | syn::Expr::Infer(_) => {}
        _ => {}
    }
}

// ── Function index ───────────────────────────────────────────────────────────

/// One local function definition (free fn or method) in the parsed files.
struct FnDef {
    /// `"{name}@{file_idx}"` — identity for memoization.
    key: String,
    file_idx: usize,
    params: Vec<String>,
    block: syn::Block,
}

struct FnIndex {
    files: Vec<String>,
    by_name: HashMap<String, Vec<Rc<FnDef>>>,
}

impl FnIndex {
    fn build(files: &[(syn::File, String)]) -> Self {
        let file_names: Vec<String> = files.iter().map(|(_, n)| n.clone()).collect();
        let mut by_name: HashMap<String, Vec<Rc<FnDef>>> = HashMap::new();
        for (file_idx, (file, _)) in files.iter().enumerate() {
            for item in &file.items {
                match item {
                    syn::Item::Fn(f) => {
                        push_fn(&mut by_name, f.sig.clone(), (*f.block).clone(), file_idx);
                    }
                    syn::Item::Impl(imp) => {
                        for member in &imp.items {
                            if let syn::ImplItem::Fn(f) = member {
                                push_fn(&mut by_name, f.sig.clone(), f.block.clone(), file_idx);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        FnIndex { files: file_names, by_name }
    }

    /// Look up a function by bare name, preferring a definition in the file
    /// that contains the caller.
    fn lookup(&self, name: &str, prefer_file: &str) -> Option<Rc<FnDef>> {
        let candidates = self.by_name.get(name)?;
        candidates.iter().find(|def| self.files[def.file_idx] == prefer_file).or_else(|| candidates.first()).cloned()
    }
}

fn push_fn(by_name: &mut HashMap<String, Vec<Rc<FnDef>>>, sig: syn::Signature, block: syn::Block, file_idx: usize) {
    let params: Vec<String> = sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Receiver(_) => None,
            syn::FnArg::Typed(pat) => match &*pat.pat {
                syn::Pat::Ident(p) => Some(p.ident.to_string()),
                _ => None,
            },
        })
        .collect();
    let def = Rc::new(FnDef { key: format!("{}@{file_idx}", sig.ident), file_idx, params, block });
    by_name.entry(sig.ident.to_string()).or_default().push(def);
}

// ── The classifier ───────────────────────────────────────────────────────────

/// Classifies how a resolved account is used inside its instruction's handler
/// call graph, to decide the CPI-passed-only suppressions (SAT020 strict —
/// known validating builtins only; SAT019/SAT021 relaxed — any callee, for
/// CPI-delegated authorities).
struct CpiClassifier {
    index: Rc<FnIndex>,
    memo: HashMap<(String, String, bool), UseClass>,
    computing: HashSet<(String, String)>,
}

/// Immutable context threaded through the classification walk.
struct Walk<'a> {
    var: &'a str,
    /// File of the function being walked (helper lookup preference).
    caller_file: &'a str,
    depth: usize,
    bindings: &'a HashMap<String, syn::Expr>,
    known_arrays: &'a HashSet<String>,
    key_checks: &'a HashMap<String, KnownProgram>,
    struct_vars: &'a HashSet<String>,
    /// Relaxed mode (SAT019/SAT021): every CPI construction context counts as
    /// a pass-through regardless of the callee's known-ness.
    relaxed: bool,
    /// Set when any usage of the account was found (even benign ones).
    seen: &'a mut bool,
    state: &'a mut UseClass,
}

impl CpiClassifier {
    fn new(index: Rc<FnIndex>) -> Self {
        CpiClassifier { index, memo: HashMap::new(), computing: HashSet::new() }
    }

    /// The variable to classify an account under: the handler's positional
    /// binding variable when the enumeration is reliable (SDI's annotated
    /// `_info` bindings), else the resolved account name.
    fn classify_var(&self, account: &ResolvedAccount, bindings: &Option<Vec<Option<String>>>) -> String {
        bindings
            .as_ref()
            .and_then(|b| b.get(account.index))
            .and_then(|b| b.as_deref())
            .unwrap_or(account.name.as_str())
            .to_string()
    }

    /// True when every use of `account` in `ix` is a pass-through to a CPI
    /// against a known validating builtin and the program never touches its
    /// data. Any unclassifiable use yields `false` (the finding fires).
    fn is_cpi_passed_only(
        &mut self,
        ix: &NativeInstruction,
        account: &ResolvedAccount,
        bindings: &Option<Vec<Option<String>>>,
    ) -> bool {
        let Some(handler) = self.index.lookup(&ix.handler, &ix.file) else { return false };
        let var = self.classify_var(account, bindings);
        self.classify(&handler, &var, 0, false) == UseClass::CpiPassed
    }

    /// True when every use of `account` is inside CPI construction
    /// (invoke/invoke_signed accounts, instruction-builder arguments,
    /// `AccountMeta` constructors) for *any* callee — the account is delegated
    /// to the CPI target, never read or compared by this program. Used for the
    /// SAT019/SAT021 authority suppressions.
    fn is_cpi_passed_any(
        &mut self,
        ix: &NativeInstruction,
        account: &ResolvedAccount,
        bindings: &Option<Vec<Option<String>>>,
    ) -> bool {
        let Some(handler) = self.index.lookup(&ix.handler, &ix.file) else { return false };
        let var = self.classify_var(account, bindings);
        self.classify(&handler, &var, 0, true) == UseClass::CpiPassed
    }

    /// True when the account's binding variable never appears in the handler
    /// or its helper call graph (depth ≤ 2): the program neither reads, nor
    /// writes, nor CPI-passes the account — no attack surface in this
    /// instruction (SAT020 skip).
    fn is_unreferenced(
        &mut self,
        ix: &NativeInstruction,
        account: &ResolvedAccount,
        bindings: &Option<Vec<Option<String>>>,
    ) -> bool {
        let Some(handler) = self.index.lookup(&ix.handler, &ix.file) else { return false };
        let Some(var) = bindings.as_ref().and_then(|b| b.get(account.index)).and_then(|b| b.as_deref()) else {
            return false;
        };
        let mut idents = HashSet::new();
        let mut visited = HashSet::new();
        collect_handler_idents(&handler.block, &self.index, &ix.file, 0, &mut visited, &mut idents);
        !idents.contains(var)
    }

    fn classify(&mut self, def: &FnDef, var: &str, depth: usize, relaxed: bool) -> UseClass {
        let key = (def.key.clone(), var.to_string(), relaxed);
        if self.computing.contains(&(def.key.clone(), var.to_string())) {
            // Call graph cycle: cannot see the full use — conservative.
            return UseClass::Used;
        }
        if let Some(class) = self.memo.get(&key) {
            return *class;
        }
        self.computing.insert((def.key.clone(), var.to_string()));
        let class = self.classify_inner(def, var, depth, relaxed);
        self.computing.remove(&(def.key.clone(), var.to_string()));
        self.memo.insert(key, class);
        class
    }

    fn classify_inner(&mut self, def: &FnDef, var: &str, depth: usize, relaxed: bool) -> UseClass {
        let bindings = top_level_bindings(&def.block);
        let struct_vars = struct_vars_of(&bindings);
        let key_checks = self.known_key_checks(def, &bindings);

        // Pre-scan every invoke site: a known callee makes its accounts
        // CPI-passed; an unknown callee marks them as program uses. The
        // relaxed mode (SAT019/SAT021) skips the unknown-callee marking —
        // any-callee CPI construction is a pass-through there.
        let mut known_arrays: HashSet<String> = HashSet::new();
        let mut unknown_vars: HashSet<String> = HashSet::new();
        if !relaxed {
            for (prog, accounts) in invoke_sites(&def.block) {
                let known = self.known_program(&prog, &bindings, &key_checks, 0);
                match accounts_of(&accounts, &bindings, 0) {
                    AccountsOf::Inline(names) => {
                        if known.is_none() {
                            unknown_vars.extend(names);
                        }
                    }
                    AccountsOf::BoundArray(name, names) => {
                        if known.is_some() {
                            known_arrays.insert(name);
                        } else {
                            unknown_vars.extend(names);
                        }
                    }
                    AccountsOf::Unresolved => {}
                }
            }
        }
        if unknown_vars.contains(var) {
            return UseClass::Used;
        }

        let mut seen = false;
        let mut state = UseClass::CpiPassed;
        let caller_file = self.index.files[def.file_idx].clone();
        let mut walk = Walk {
            var,
            caller_file: &caller_file,
            depth,
            bindings: &bindings,
            known_arrays: &known_arrays,
            key_checks: &key_checks,
            struct_vars: &struct_vars,
            relaxed,
            seen: &mut seen,
            state: &mut state,
        };
        self.walk_block(&def.block, Ctx::Normal, &mut walk);
        if !*walk.seen {
            // The account never appears in the handler expansion — no
            // evidence of CPI-passing, so keep the finding.
            return UseClass::Used;
        }
        state
    }

    /// `prog_var.key` variables that are checked against a known validating
    /// builtin somewhere in the function (comparisons or guard macros such as
    /// `check_eq!`/`require_keys_eq!`).
    fn known_key_checks(&self, def: &FnDef, bindings: &HashMap<String, syn::Expr>) -> HashMap<String, KnownProgram> {
        let empty: HashMap<String, KnownProgram> = HashMap::new();
        let mut pairs: Vec<(Option<String>, syn::Expr)> = Vec::new();
        walk_all(&def.block, &mut |e| match e {
            syn::Expr::Binary(b) if matches!(b.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) => {
                pairs.push((field_base_ident(&b.left), (*b.right).clone()));
                pairs.push((field_base_ident(&b.right), (*b.left).clone()));
            }
            syn::Expr::Macro(mac) => {
                let args = macro_exprs(&mac.mac);
                for a in &args {
                    for b in &args {
                        pairs.push((field_base_ident(a), b.clone()));
                    }
                }
            }
            _ => {}
        });
        let mut out = HashMap::new();
        for (var, other) in pairs {
            let Some(var) = var else { continue };
            if out.contains_key(&var) {
                continue;
            }
            if let Some(program) = self.known_program(&other, bindings, &empty, 0) {
                out.insert(var, program);
            }
        }
        out
    }

    /// Resolve a CPI program-id expression to a known validating builtin.
    fn known_program(
        &self,
        e: &syn::Expr,
        bindings: &HashMap<String, syn::Expr>,
        key_checks: &HashMap<String, KnownProgram>,
        depth: usize,
    ) -> Option<KnownProgram> {
        if depth > 4 {
            return None;
        }
        match peel(e) {
            syn::Expr::Lit(l) => match &l.lit {
                syn::Lit::Str(s) => known_program_from_literal(&s.value()),
                _ => None,
            },
            syn::Expr::Path(p) => {
                if p.path.segments.len() == 1
                    && let Some(bound) = bindings.get(&p.path.segments[0].ident.to_string())
                {
                    return self.known_program(bound, bindings, key_checks, depth + 1);
                }
                let key = p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
                program_from_path_key(&key)
            }
            syn::Expr::Call(c) => {
                let callee = path_key(&c.func).unwrap_or_default();
                if is_instruction_builder(&callee) {
                    return self.builder_program(&callee, &c.args, bindings, key_checks, depth);
                }
                if let Some(program) = program_from_path_key(&callee) {
                    return Some(program);
                }
                let last = callee.rsplit("::").next().unwrap_or(&callee);
                if matches!(last, "new_with_borsh" | "new_with_bytes" | "from_str") {
                    return c.args.first().and_then(|a| self.known_program(a, bindings, key_checks, depth + 1));
                }
                None
            }
            syn::Expr::MethodCall(m) if matches!(m.method.to_string().as_str(), "parse" | "unwrap" | "expect") => {
                self.known_program(&m.receiver, bindings, key_checks, depth + 1)
            }
            syn::Expr::Field(f) => {
                if member_name(&f.member) == "key"
                    && let Some(ident) = path_ident(&f.base)
                {
                    return key_checks.get(&ident).copied();
                }
                None
            }
            syn::Expr::Macro(mac) => {
                let last = mac.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if last == "pubkey" {
                    return macro_exprs(&mac.mac)
                        .first()
                        .and_then(|a| self.known_program(a, bindings, key_checks, depth + 1));
                }
                None
            }
            syn::Expr::Struct(s) => s.fields.iter().find_map(|field| {
                (member_name(&field.member) == "program_id")
                    .then(|| self.known_program(&field.expr, bindings, key_checks, depth + 1))
                    .flatten()
            }),
            _ => None,
        }
    }

    /// Program of an instruction-builder call: the path segments first
    /// (`spl_token::instruction::transfer`), then the builder's first
    /// argument (the program id).
    fn builder_program(
        &self,
        callee: &str,
        args: &Punctuated<syn::Expr, syn::Token![,]>,
        bindings: &HashMap<String, syn::Expr>,
        key_checks: &HashMap<String, KnownProgram>,
        depth: usize,
    ) -> Option<KnownProgram> {
        program_from_path_key(callee)
            .or_else(|| args.first().and_then(|a| self.known_program(a, bindings, key_checks, depth + 1)))
    }

    // ── The classification walk ─────────────────────────────────────────────

    fn walk_block(&mut self, block: &syn::Block, ctx: Ctx, walk: &mut Walk) {
        if *walk.state != UseClass::CpiPassed {
            return;
        }
        for stmt in &block.stmts {
            match stmt {
                syn::Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        let in_known_array = matches!(&local.pat, syn::Pat::Ident(p) if walk.known_arrays.contains(&p.ident.to_string()));
                        let lctx = if in_known_array { Ctx::CpiArg } else { ctx };
                        self.walk_expr(&init.expr, lctx, walk);
                    }
                }
                syn::Stmt::Expr(e, _) => self.walk_expr(e, ctx, walk),
                syn::Stmt::Macro(m) => {
                    for arg in macro_exprs(&m.mac) {
                        self.walk_expr(&arg, ctx, walk);
                    }
                }
                syn::Stmt::Item(_) => {}
            }
        }
    }

    fn walk_expr(&mut self, e: &syn::Expr, ctx: Ctx, walk: &mut Walk) {
        if *walk.state != UseClass::CpiPassed {
            return;
        }
        match e {
            syn::Expr::Path(p) => {
                if p.path.get_ident().is_some_and(|i| i == walk.var) {
                    *walk.seen = true;
                    if ctx == Ctx::Normal {
                        *walk.state = UseClass::Used;
                    }
                }
            }
            syn::Expr::Field(f) => {
                let member = member_name(&f.member);
                let struct_field = matches!(&*f.base, syn::Expr::Path(p)
                    if p.path.get_ident().is_some_and(|i| walk.struct_vars.contains(&i.to_string()))
                        && member == walk.var);
                let account_field = account_ident(&f.base, walk.struct_vars).as_deref() == Some(walk.var);
                if struct_field || account_field {
                    *walk.seen = true;
                    if ctx == Ctx::Normal {
                        *walk.state = UseClass::Used;
                    }
                }
                self.walk_expr(&f.base, ctx, walk);
            }
            syn::Expr::MethodCall(m) => {
                if account_ident(&m.receiver, walk.struct_vars).as_deref() == Some(walk.var) {
                    *walk.seen = true;
                    // `clone()` is a plain pass-through; any other method is a
                    // program use (including data reads such as `borrow_mut`).
                    if m.method != "clone" {
                        *walk.state = UseClass::Used;
                    }
                }
                // The clone receiver is a pass-through even in normal code
                // (relaxed mode: vec!-built CPI account lists).
                let rctx = if walk.relaxed && m.method == "clone" { Ctx::CpiArg } else { ctx };
                self.walk_expr(&m.receiver, rctx, walk);
                for arg in &m.args {
                    self.walk_expr(arg, ctx, walk);
                }
            }
            syn::Expr::Call(c) => self.walk_call(c, ctx, walk),
            syn::Expr::Macro(mac) => {
                for arg in macro_exprs(&mac.mac) {
                    self.walk_expr(&arg, ctx, walk);
                }
            }
            syn::Expr::Block(b) => self.walk_block(&b.block, ctx, walk),
            syn::Expr::Unsafe(u) => self.walk_block(&u.block, ctx, walk),
            syn::Expr::Async(a) => self.walk_block(&a.block, ctx, walk),
            syn::Expr::Const(c) => self.walk_block(&c.block, ctx, walk),
            syn::Expr::TryBlock(tb) => self.walk_block(&tb.block, ctx, walk),
            syn::Expr::If(i) => {
                self.walk_expr(&i.cond, ctx, walk);
                self.walk_block(&i.then_branch, ctx, walk);
                if let Some((_, else_expr)) = &i.else_branch {
                    self.walk_expr(else_expr, ctx, walk);
                }
            }
            syn::Expr::While(w) => {
                self.walk_expr(&w.cond, ctx, walk);
                self.walk_block(&w.body, ctx, walk);
            }
            syn::Expr::Loop(l) => self.walk_block(&l.body, ctx, walk),
            syn::Expr::ForLoop(fl) => self.walk_block(&fl.body, ctx, walk),
            syn::Expr::Match(m) => {
                self.walk_expr(&m.expr, ctx, walk);
                for arm in &m.arms {
                    if let Some((_, guard)) = &arm.guard {
                        self.walk_expr(guard, ctx, walk);
                    }
                    self.walk_expr(&arm.body, ctx, walk);
                }
            }
            syn::Expr::Try(t) => self.walk_expr(&t.expr, ctx, walk),
            syn::Expr::Paren(p) => self.walk_expr(&p.expr, ctx, walk),
            syn::Expr::Group(g) => self.walk_expr(&g.expr, ctx, walk),
            syn::Expr::Reference(r) => self.walk_expr(&r.expr, ctx, walk),
            syn::Expr::RawAddr(r) => self.walk_expr(&r.expr, ctx, walk),
            syn::Expr::Unary(u) => self.walk_expr(&u.expr, ctx, walk),
            syn::Expr::Await(a) => self.walk_expr(&a.base, ctx, walk),
            syn::Expr::Yield(y) => {
                if let Some(x) = &y.expr {
                    self.walk_expr(x, ctx, walk);
                }
            }
            syn::Expr::Let(l) => self.walk_expr(&l.expr, ctx, walk),
            syn::Expr::Binary(b) => {
                self.walk_expr(&b.left, ctx, walk);
                self.walk_expr(&b.right, ctx, walk);
            }
            syn::Expr::Assign(a) => {
                self.walk_expr(&a.left, ctx, walk);
                self.walk_expr(&a.right, ctx, walk);
            }
            syn::Expr::Index(i) => {
                self.walk_expr(&i.expr, ctx, walk);
                self.walk_expr(&i.index, ctx, walk);
            }
            syn::Expr::Tuple(t) => {
                for el in &t.elems {
                    self.walk_expr(el, ctx, walk);
                }
            }
            syn::Expr::Array(a) => {
                for el in &a.elems {
                    self.walk_expr(el, ctx, walk);
                }
            }
            syn::Expr::Repeat(r) => {
                self.walk_expr(&r.expr, ctx, walk);
                self.walk_expr(&r.len, ctx, walk);
            }
            syn::Expr::Struct(s) => {
                for field in &s.fields {
                    self.walk_expr(&field.expr, ctx, walk);
                }
            }
            syn::Expr::Closure(cl) => self.walk_expr(&cl.body, ctx, walk),
            syn::Expr::Cast(c) => self.walk_expr(&c.expr, ctx, walk),
            syn::Expr::Range(r) => {
                if let Some(from) = &r.start {
                    self.walk_expr(from, ctx, walk);
                }
                if let Some(to) = &r.end {
                    self.walk_expr(to, ctx, walk);
                }
            }
            syn::Expr::Return(r) => {
                if let Some(x) = &r.expr {
                    self.walk_expr(x, ctx, walk);
                }
            }
            syn::Expr::Break(b) => {
                if let Some(x) = &b.expr {
                    self.walk_expr(x, ctx, walk);
                }
            }
            syn::Expr::Continue(_) => {}
            syn::Expr::Lit(_) | syn::Expr::Infer(_) => {}
            // Opaque nodes (`Verbatim`): skipped — documented limitation.
            _ => {}
        }
    }

    fn walk_call(&mut self, c: &syn::ExprCall, ctx: Ctx, walk: &mut Walk) {
        if *walk.state != UseClass::CpiPassed {
            return;
        }
        let Some(callee) = path_key(&c.func) else {
            for arg in &c.args {
                self.walk_expr(arg, ctx, walk);
            }
            return;
        };
        let last = callee.rsplit("::").next().unwrap_or(&callee);

        // 1. `invoke`/`invoke_signed`: accounts are benign when the callee is
        //    a known validating builtin (unknown callees were already marked
        //    as program uses by the pre-scan) — or, in the relaxed mode, for
        //    any callee (SAT019/SAT021 CPI-delegated authorities).
        if INVOKE_NAMES.contains(&last) {
            let known = c.args.first().and_then(|prog| self.known_program(prog, walk.bindings, walk.key_checks, 0));
            let accounts_ctx = if walk.relaxed || known.is_some() { Ctx::CpiArg } else { Ctx::Normal };
            for (i, arg) in c.args.iter().enumerate() {
                let actx = if i == 1 { accounts_ctx } else { ctx };
                self.walk_expr(arg, actx, walk);
            }
            return;
        }

        // 2. Instruction builders (`spl_token::instruction::transfer`, ...):
        //    the `.key` reads that construct the CPI are benign when the
        //    builder's program is a known validating builtin — or, relaxed,
        //    for any builder.
        if is_instruction_builder(&callee) {
            let known = self.builder_program(&callee, &c.args, walk.bindings, walk.key_checks, 0);
            let builder_ctx = if walk.relaxed || known.is_some() { Ctx::CpiArg } else { Ctx::Normal };
            for arg in &c.args {
                self.walk_expr(arg, builder_ctx, walk);
            }
            return;
        }

        // 2b. `AccountMeta::new(..)` / `AccountMeta::new_readonly(..)`:
        //     CPI metadata construction — benign in the relaxed mode.
        if walk.relaxed && matches!(last, "new" | "new_readonly") && callee.contains("AccountMeta") {
            for arg in &c.args {
                self.walk_expr(arg, Ctx::CpiArg, walk);
            }
            return;
        }

        // 3. Data reads/deserialization on the account (also through field
        //    chains like `&token_account.data.borrow()`).
        if DATA_TOUCH_CALLS.contains(&last) {
            for arg in &c.args {
                if account_ident(arg, walk.struct_vars).as_deref() == Some(walk.var) {
                    *walk.seen = true;
                    *walk.state = UseClass::Used;
                } else {
                    self.walk_expr(arg, ctx, walk);
                }
            }
            return;
        }

        // 4. Local helper calls: a pass-through argument is classified by the
        //    helper's own parameter; anything else is walked as program code.
        if let Some(helper) = self.index.lookup(last, walk.caller_file) {
            for (i, arg) in c.args.iter().enumerate() {
                if is_pass_through(arg, walk.var, walk.struct_vars) {
                    *walk.seen = true;
                    if walk.depth >= 2 {
                        // Helper depth limit (spec section 6): conservative.
                        *walk.state = UseClass::Used;
                    } else if let Some(param) = helper.params.get(i) {
                        if self.classify(&helper, param, walk.depth + 1, walk.relaxed) == UseClass::Used {
                            *walk.state = UseClass::Used;
                        }
                    } else {
                        *walk.state = UseClass::Used;
                    }
                } else {
                    self.walk_expr(arg, ctx, walk);
                }
            }
            return;
        }

        // 5. Anything else: walk the arguments as program code.
        for arg in &c.args {
            self.walk_expr(arg, ctx, walk);
        }
    }
}
/// The accounts argument of an invoke call, resolved through bindings.
enum AccountsOf {
    /// Inline array literal elements.
    Inline(Vec<String>),
    /// A `let`-bound array literal (binding name + elements).
    BoundArray(String, Vec<String>),
    /// Unresolvable (macros, slices of the accounts param, ...).
    Unresolved,
}

/// Collect every path identifier mentioned in a handler and its local helper
/// call graph (depth ≤ 2, cycle-guarded): the reference set for the SAT020
/// unreferenced-account suppression.
fn collect_handler_idents(
    block: &syn::Block,
    index: &Rc<FnIndex>,
    caller_file: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    if depth > 2 {
        return;
    }
    walk_all(block, &mut |e| match e {
        syn::Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                out.insert(ident.to_string());
            }
        }
        syn::Expr::Call(c) => {
            let Some(callee) = path_key(&c.func) else { return };
            let Some(last) = callee.rsplit("::").next() else { return };
            if !visited.insert(last.to_string()) {
                return;
            }
            if let Some(helper) = index.lookup(last, caller_file) {
                collect_handler_idents(&helper.block, index, caller_file, depth + 1, visited, out);
            }
            visited.remove(last);
        }
        _ => {}
    });
}

fn accounts_of(e: &syn::Expr, bindings: &HashMap<String, syn::Expr>, depth: usize) -> AccountsOf {
    if depth > 4 {
        return AccountsOf::Unresolved;
    }
    match peel(e) {
        syn::Expr::Array(a) => {
            let names = a.elems.iter().filter_map(element_ident).collect();
            AccountsOf::Inline(names)
        }
        syn::Expr::Path(p) => {
            let Some(name) = p.path.get_ident().map(|i| i.to_string()) else {
                return AccountsOf::Unresolved;
            };
            match bindings.get(&name) {
                Some(bound) => match accounts_of(bound, bindings, depth + 1) {
                    AccountsOf::Inline(names) => AccountsOf::BoundArray(name, names),
                    other => other,
                },
                None => AccountsOf::Unresolved,
            }
        }
        _ => AccountsOf::Unresolved,
    }
}

/// Collect all `invoke`-family call sites of a block: (program id, accounts).
fn invoke_sites(block: &syn::Block) -> Vec<InvokeSite> {
    let mut sites = Vec::new();
    walk_all(block, &mut |e| {
        if let syn::Expr::Call(c) = e
            && let Some(callee) = path_key(&c.func)
            && let Some(last) = callee.rsplit("::").next()
            && INVOKE_NAMES.contains(&last)
            && c.args.len() >= 2
        {
            sites.push((c.args[0].clone(), c.args[1].clone()));
        }
    });
    sites
}

/// One `invoke`-family call site: (program_id expression, accounts expression).
type InvokeSite = (syn::Expr, syn::Expr);
