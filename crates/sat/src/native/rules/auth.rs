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
    let mut classifier = CpiClassifier::new(parsed);
    let mut findings = Vec::new();
    for ix in &program.instructions {
        for account in &ix.accounts {
            let authority_named = is_authority_named(&account.name);
            let stateful = matches!(account.kind, AccountKind::State | AccountKind::TokenAccount | AccountKind::Mint);

            // SAT019: authority-named, signature never verified, not a
            // `Signer` by construction, key not pinned.
            if authority_named
                && !account.is_signer_checked
                && account.kind != AccountKind::Signer
                && !account.key_checked
            {
                findings.push(sat019(ix, account));
            }

            // SAT020: stateful or written account, owner never verified, key
            // not pinned, not a runtime builtin, and not CPI-passed-only to a
            // known validating builtin.
            if !is_builtin(account.kind)
                && (stateful || account.written)
                && !account.owner_checked
                && !account.key_checked
                && !classifier.is_cpi_passed_only(ix, account)
            {
                findings.push(sat020(ix, account));
            }

            // SAT021: authority-named, key never compared, signature never
            // verified.
            if authority_named && !account.key_checked && !account.is_signer_checked {
                findings.push(sat021(ix, account));
            }
        }
    }
    findings
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
/// call graph, to decide SAT020's CPI-passed-only suppression.
struct CpiClassifier {
    index: FnIndex,
    memo: HashMap<(String, String), UseClass>,
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
    /// Set when any usage of the account was found (even benign ones).
    seen: &'a mut bool,
    state: &'a mut UseClass,
}

impl CpiClassifier {
    fn new(files: &[(syn::File, String)]) -> Self {
        CpiClassifier { index: FnIndex::build(files), memo: HashMap::new(), computing: HashSet::new() }
    }

    /// True when every use of `account` in `ix` is a pass-through to a CPI
    /// against a known validating builtin and the program never touches its
    /// data. Any unclassifiable use yields `false` (the finding fires).
    fn is_cpi_passed_only(&mut self, ix: &NativeInstruction, account: &ResolvedAccount) -> bool {
        let Some(handler) = self.index.lookup(&ix.handler, &ix.file) else { return false };
        self.classify(&handler, &account.name, 0) == UseClass::CpiPassed
    }

    fn classify(&mut self, def: &FnDef, var: &str, depth: usize) -> UseClass {
        let key = (def.key.clone(), var.to_string());
        if self.computing.contains(&key) {
            // Call graph cycle: cannot see the full use — conservative.
            return UseClass::Used;
        }
        if let Some(class) = self.memo.get(&key) {
            return *class;
        }
        self.computing.insert(key.clone());
        let class = self.classify_inner(def, var, depth);
        self.computing.remove(&key);
        self.memo.insert(key, class);
        class
    }

    fn classify_inner(&mut self, def: &FnDef, var: &str, depth: usize) -> UseClass {
        let bindings = top_level_bindings(&def.block);
        let struct_vars = struct_vars_of(&bindings);
        let key_checks = self.known_key_checks(def, &bindings);

        // Pre-scan every invoke site: a known callee makes its accounts
        // CPI-passed; an unknown callee marks them as program uses.
        let mut known_arrays: HashSet<String> = HashSet::new();
        let mut unknown_vars: HashSet<String> = HashSet::new();
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
                self.walk_expr(&m.receiver, ctx, walk);
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
        //    as program uses by the pre-scan).
        if INVOKE_NAMES.contains(&last) {
            let known = c.args.first().and_then(|prog| self.known_program(prog, walk.bindings, walk.key_checks, 0));
            let accounts_ctx = if known.is_some() { Ctx::CpiArg } else { Ctx::Normal };
            for (i, arg) in c.args.iter().enumerate() {
                let actx = if i == 1 { accounts_ctx } else { ctx };
                self.walk_expr(arg, actx, walk);
            }
            return;
        }

        // 2. Instruction builders (`spl_token::instruction::transfer`, ...):
        //    the `.key` reads that construct the CPI are benign when the
        //    builder's program is a known validating builtin.
        if is_instruction_builder(&callee) {
            let known = self.builder_program(&callee, &c.args, walk.bindings, walk.key_checks, 0);
            let builder_ctx = if known.is_some() { Ctx::CpiArg } else { Ctx::Normal };
            for arg in &c.args {
                self.walk_expr(arg, builder_ctx, walk);
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
                        if self.classify(&helper, param, walk.depth + 1) == UseClass::Used {
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
