//! Token-accounting drift simulator (`sat accounting`, rule SAT039).
//!
//! Models the ordering relationship between a program's token-CPI calls and
//! its internal balance accounting, flagging two drift shapes:
//!
//! 1. **Stale balance** — a token account's `.amount` is read BEFORE a
//!    token CPI touches that account, the pre-read binding keeps being used
//!    afterwards, and the account's balance is never re-read. Fee-on-transfer,
//!    transfer-hook and Token-2022 extension accounting all change the actual
//!    delta versus the assumed one; using the stale read silently diverges.
//!    Severity: Medium.
//!
//! 2. **Ledger mirrors the transfer amount** — an internal ledger field is
//!    updated (`+=` / `checked_add` / plain assignment) with the SAME value
//!    that was passed to a token transfer in the same flow. If the token
//!    program applies fees or hooks, internal accounting and on-chain
//!    balances diverge by design.
//!    Severity: High.
//!
//! Honest scope: heuristic shape detection over the flattened handler + helper
//! blocks (depth ≤ 2), not an interprocedural symbolic executor. Manual
//! verification required before escalating.

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use syn::Expr;

use crate::native::model::{NativeInstruction, NativeProgram};
use crate::native::rules::validate::{FnIndex, collect_blocks};
use crate::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT039_TITLE: &str = "Accounting Drift:";

/// Callee last-segments that constitute a token-program CPI.
const TOKEN_CPI_CALLEES: &[&str] = &[
    "transfer",
    "transfer_checked",
    "mint_to",
    "mint_to_checked",
    "burn",
    "burn_checked",
    "token_transfer",
    "token_transfer_checked",
];

/// Ledger-ish field names whose writes mirror token movements.
const LEDGER_FIELDS: &[&str] =
    &["amount", "balance", "total", "deposited", "deposit", "supply", "shares", "staked", "vault_amount"];

// ── Event collection ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Event {
    /// `let v = <acct>.amount` / `<acct>.data.borrow()` — a read of a token
    /// account's balance bound to a local.
    BalanceRead { local: String, account: String },
    /// A token CPI touching the given accounts with the given amount idents.
    TokenCpi { accounts: Vec<String>, amount_idents: Vec<String> },
    /// A later reference to an ident inside any expression.
    Use,
    /// An internal-ledger update target: `<X>.<ledger_field> = ...`.
    LedgerWrite { field: String },
}

struct Collector {
    events: Vec<(Event, usize)>,
    /// ident → account name (`let d = vault.data.borrow_mut()`).
    aliases: HashMap<String, String>,
    stmt_idx: usize,
}

impl Collector {
    fn record(&mut self, event: Event) {
        self.events.push((event, self.stmt_idx));
    }
}

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(n) => n.to_string(),
        syn::Member::Unnamed(i) => i.index.to_string(),
    }
}

/// The root ident of a receiver chain: `vault.data.borrow_mut()` → `vault`.
fn chain_root(e: &Expr) -> Option<String> {
    let mut cur = e;
    loop {
        match cur {
            Expr::Field(f) => cur = &f.base,
            Expr::MethodCall(m) => cur = &m.receiver,
            Expr::Reference(r) => cur = &r.expr,
            Expr::Paren(p) => cur = &p.expr,
            Expr::Group(g) => cur = &g.expr,
            Expr::Index(i) => cur = &i.expr,
            Expr::Path(p) => return p.path.get_ident().map(|i| i.to_string()),
            _ => return None,
        }
    }
}

fn collect_idents(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                out.push(ident.to_string());
            }
        }
        Expr::Field(f) => {
            // `<x>.amount` records the field name too (ledger mirror check),
            // but base idents are what flow tracking needs.
            collect_idents(&f.base, out);
        }
        Expr::MethodCall(m) => {
            collect_idents(&m.receiver, out);
            for a in &m.args {
                collect_idents(a, out);
            }
        }
        Expr::Call(c) => {
            for a in &c.args {
                collect_idents(a, out);
            }
        }
        Expr::Binary(b) => {
            collect_idents(&b.left, out);
            collect_idents(&b.right, out);
        }
        Expr::Unary(u) => collect_idents(&u.expr, out),
        Expr::Reference(r) => collect_idents(&r.expr, out),
        Expr::Paren(p) => collect_idents(&p.expr, out),
        Expr::Group(g) => collect_idents(&g.expr, out),
        Expr::Try(t) => collect_idents(&t.expr, out),
        Expr::Cast(c) => collect_idents(&c.expr, out),
        Expr::Index(i) => {
            collect_idents(&i.expr, out);
            collect_idents(&i.index, out);
        }
        Expr::Await(a) => collect_idents(&a.base, out),
        Expr::Let(l) => collect_idents(&l.expr, out),
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                collect_idents(x, out);
            }
        }
        Expr::Break(br) => {
            if let Some(x) = &br.expr {
                collect_idents(x, out);
            }
        }
        Expr::Yield(y) => {
            if let Some(x) = &y.expr {
                collect_idents(x, out);
            }
        }
        Expr::Macro(m) => {
            for arg in macro_args(&m.mac) {
                collect_idents(&arg, out);
            }
        }
        Expr::Struct(s) => {
            for f in &s.fields {
                collect_idents(&f.expr, out);
            }
        }
        _ => {}
    }
}

/// The ledger field an assignment target writes (`escrow.amount = v` →
/// `amount`), when it names one.
fn ledger_field_of(target: &Expr) -> Option<String> {
    let mut cur = target;
    let mut last_field = None;
    loop {
        match cur {
            Expr::Field(f) => {
                last_field = Some(member_name(&f.member));
                cur = &f.base;
            }
            Expr::Index(_) => return last_field,
            Expr::MethodCall(m) if matches!(m.method.to_string().as_str(), "borrow_mut" | "borrow") => {
                cur = &m.receiver;
            }
            _ => return last_field,
        }
    }
}

// ── Statement-order scan ─────────────────────────────────────────────────────

fn scan_block(block: &syn::Block, ix: &NativeInstruction, col: &mut Collector) {
    for stmt in &block.stmts {
        col.stmt_idx += 1;
        match stmt {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    let init_expr = &init.expr;
                    // Balance read: any known-account ident referenced inside
                    // the initializer expression binds as a balance read.
                    if let syn::Pat::Ident(pi) = &l.pat {
                        let mut idents = Vec::new();
                        collect_idents(init_expr, &mut idents);
                        for ident in &idents {
                            if account_exists(ix, ident) && !col.aliases.contains_key(ident) {
                                col.record(Event::BalanceRead { local: pi.ident.to_string(), account: ident.clone() });
                                break;
                            }
                        }
                        // Generic alias: `let d = vault.data.borrow_mut()`.
                        if let Some(root) = chain_root(init_expr)
                            && account_exists(ix, &root)
                            && root != pi.ident.to_string().as_str()
                        {
                            col.aliases.insert(pi.ident.to_string(), root);
                        }
                    }
                    scan_expr(init_expr, ix, col);
                }
            }
            syn::Stmt::Expr(e, _) => scan_expr(e, ix, col),
            syn::Stmt::Macro(m) => {
                for arg in macro_args(&m.mac) {
                    scan_expr(&arg, ix, col);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn scan_expr(e: &Expr, ix: &NativeInstruction, col: &mut Collector) {
    match e {
        Expr::Call(c) => {
            let callee = match &*c.func {
                Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                Expr::MethodCall(m) => m.method.to_string(),
                _ => String::new(),
            };
            if TOKEN_CPI_CALLEES.contains(&callee.as_str()) && !c.args.is_empty() {
                let mut accounts = Vec::new();
                let mut amount_idents = Vec::new();
                for arg in &c.args {
                    if let Some(root) = chain_root(arg)
                        && account_exists(ix, &root)
                        && !accounts.contains(&root)
                    {
                        accounts.push(root.clone());
                    }
                    collect_idents(arg, &mut amount_idents);
                }
                col.record(Event::TokenCpi { accounts, amount_idents });
            }
            for arg in &c.args {
                scan_expr(arg, ix, col);
            }
        }
        Expr::MethodCall(m) => {
            let callee = m.method.to_string();
            // copy_from_slice/fill on a known account = ledger write sink.
            if matches!(callee.as_str(), "copy_from_slice" | "fill" | "clone_from_slice") {
                let mut idents = Vec::new();
                collect_idents(&m.receiver, &mut idents);
                for id in &idents {
                    if account_exists(ix, id) {
                        col.record(Event::LedgerWrite { field: id.clone() });
                        break;
                    }
                }
            }
            if TOKEN_CPI_CALLEES.contains(&callee.as_str()) {
                let mut accounts = Vec::new();
                let amount_idents = Vec::new();
                let mut refs = Vec::new();
                collect_idents(&m.receiver, &mut refs);
                for a in &m.args {
                    collect_idents(a, &mut refs);
                }
                for r in refs {
                    if account_exists(ix, &r) && !accounts.contains(&r) {
                        accounts.push(r);
                    }
                }
                col.record(Event::TokenCpi { accounts, amount_idents });
            }
            scan_expr(&m.receiver, ix, col);
            for a in &m.args {
                scan_expr(a, ix, col);
            }
        }
        Expr::Assign(a) => {
            if let Some(field) = ledger_field_of(&a.left)
                && LEDGER_FIELDS.contains(&field.as_str())
            {
                col.record(Event::LedgerWrite { field });
            }
            scan_expr(&a.left, ix, col);
            scan_expr(&a.right, ix, col);
        }
        Expr::Binary(b) => {
            scan_expr(&b.left, ix, col);
            scan_expr(&b.right, ix, col);
        }
        Expr::Unary(u) => scan_expr(&u.expr, ix, col),
        Expr::Reference(r) => scan_expr(&r.expr, ix, col),
        Expr::Paren(p) => scan_expr(&p.expr, ix, col),
        Expr::Group(g) => scan_expr(&g.expr, ix, col),
        Expr::Try(t) => scan_expr(&t.expr, ix, col),
        Expr::Cast(c) => scan_expr(&c.expr, ix, col),
        Expr::Index(i) => {
            scan_expr(&i.expr, ix, col);
            scan_expr(&i.index, ix, col);
        }
        Expr::Field(f) => {
            // `<acct>.amount` read outside a binding still counts as a use.
            let field = member_name(&f.member);
            if (field == "amount" || field == "balance")
                && let Some(root) = chain_root(&f.base)
                && account_exists(ix, &root)
            {
                col.record(Event::Use);
            }
            scan_expr(&f.base, ix, col);
        }
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                let ident = ident.to_string();
                if col.aliases.contains_key(&ident) || ix.accounts.iter().any(|a| a.name == ident) {
                    col.record(Event::Use);
                }
            }
        }
        _ => {}
    }
}

fn macro_args(mac: &syn::Macro) -> Vec<Expr> {
    syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
        mac.tokens.clone(),
    )
    .map(|args| args.into_iter().collect())
    .unwrap_or_default()
}

fn account_exists(ix: &NativeInstruction, name: &str) -> bool {
    ix.accounts.iter().any(|a| a.name == name)
}

// ── Drift checks over the ordered event stream ───────────────────────────────

/// Check 1 (stale balance, Medium): a token CPI touches account A; an
/// `.amount` read of A was bound before the CPI and used after; and A's
/// balance is never re-read after the CPI.
fn stale_balance_findings(ix: &NativeInstruction, events: &[(Event, usize)]) -> Option<Finding> {
    for (ci, (cpi_event, _cpi_idx)) in events.iter().enumerate() {
        let Event::TokenCpi { accounts, .. } = cpi_event else { continue };
        for account in accounts {
            let pre_read = events
                .iter()
                .take(ci)
                .find(|(e, _)| matches!(e, Event::BalanceRead { local: _, account: a } if a == account));
            let Some((Event::BalanceRead { local, .. }, _)) = pre_read else {
                continue;
            };
            // Re-read after the CPI clears the finding.
            let re_read = events
                .iter()
                .skip(ci + 1)
                .any(|(e, _)| matches!(e, Event::BalanceRead { account: a, .. } if a == account));
            if re_read {
                continue;
            }
            // Any subsequent statement referencing the pre-read value means
            // stale data is carried across the CPI boundary.
            return Some(Finding {
                id: String::new(),
                title: format!("{SAT039_TITLE} `{account}`"),
                severity: Severity::Medium,
                description: format!(
                    "Instruction `{}` reads `{account}`.amount into `{local}`, then performs a token \
                     transfer touching `{account}` — and never re-reads the balance afterwards. \
                     Fee-on-transfer, transfer-hook and Token-2022 extension accounting change the \
                     actual balance delta versus the assumed one, so `{local}` is stale the moment \
                     the CPI lands. Confirm the exact token program semantics before escalating.",
                    ix.name
                ),
                location: Some(format!("{}:{} ({})", ix.file, ix.line, ix.name)),
                suggestion: Some(format!(
                    "Re-read `{account}`.amount after the CPI (or use the CPI return value) instead of \
                     carrying `{local}` across it."
                )),
            });
        }
    }
    None
}

/// Check 2 (ledger mirror, High): an internal-ledger field is updated with an
/// ident that also fed a token-CPI amount in the same instruction.
fn ledger_mirror_findings(ix: &NativeInstruction, events: &[(Event, usize)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut cpi_amounts: HashMap<String, ()> = HashMap::new();
    for (event, _) in events {
        if let Event::TokenCpi { amount_idents, .. } = event {
            for id in amount_idents {
                cpi_amounts.insert(id.clone(), ());
            }
        }
    }
    if cpi_amounts.is_empty() {
        return findings;
    }
    let mut seen_fields = HashSet::new();
    for (event, _) in events {
        if let Event::LedgerWrite { field } = event
            && seen_fields.insert(field.clone())
            && cpi_amounts.contains_key(field)
        {
            findings.push(Finding {
                id: String::new(),
                title: format!("{SAT039_TITLE} `{field}`"),
                severity: Severity::High,
                description: format!(
                    "Instruction `{}` updates the internal ledger field `{field}` using the same \
                         value that feeds a token-program transfer/mint/burn. If the token program \
                         applies fees, hooks or extension accounting, the on-chain delta diverges from \
                         `{field}` by design — internal accounting silently drifts from real balances.",
                    ix.name
                ),
                location: Some(location(ix)),
                suggestion: Some(format!(
                    "Re-read the actual post-CPI balance and reconcile `{field}` against it, or use \
                         `transfer_checked` with explicit decimals and fee-aware math."
                )),
            });
        }
    }
    findings
}

fn location(ix: &NativeInstruction) -> String {
    format!("{}:{} ({})", ix.file, ix.line, ix.name)
}

/// SAT039 for one instruction over its ordered event stream.
fn analyze_instruction(ix: &NativeInstruction, blocks: &[&syn::Block]) -> Vec<Finding> {
    let mut col = Collector { events: Vec::new(), aliases: HashMap::new(), stmt_idx: 0 };
    for block in blocks {
        scan_block(block, ix, &mut col);
    }
    let mut findings = Vec::new();
    if let Some(f) = stale_balance_findings(ix, &col.events) {
        findings.push(f);
    }
    findings.extend(ledger_mirror_findings(ix, &col.events));
    findings
}

/// SAT039: flag token-accounting drift shapes. Native-model path.
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    use std::collections::HashSet;

    let index = FnIndex::build(parsed);
    let mut findings = Vec::new();

    for ix in &program.instructions {
        let Some((handler, file_idx)) = index.lookup(&ix.handler, &ix.file) else { continue };
        let mut visited = HashSet::new();
        visited.insert((file_idx, ix.handler.clone()));
        let mut blocks: Vec<&syn::Block> = Vec::new();
        collect_blocks(handler, &index, &mut visited, 0, &mut blocks, &[]);
        findings.extend(analyze_instruction(ix, &blocks));
    }

    findings
}

// ── Subcommand surface ───────────────────────────────────────────────────────

/// `sat accounting <src>`: run the drift simulator standalone.
pub fn run(src_path: Option<&str>) -> Result<()> {
    use crate::ui;

    ui::print_banner();
    ui::print_section_header("Token Accounting Drift");

    let output = crate::analyzer::collect(src_path, None, None)?;
    if output.parsed_files.is_empty() {
        anyhow::bail!("No Rust source files found under the given path.");
    }

    let Some(program) = output.native_program.as_ref() else {
        anyhow::bail!("No native program found (no `entrypoint!` / `process_instruction` marker).");
    };

    let findings = check(program, &output.parsed_files);
    if findings.is_empty() {
        ui::print_success("No accounting drift shapes detected.");
        return Ok(());
    }

    for f in &findings {
        println!("[{}] {}", f.severity, f.title);
        println!("  at {}", f.location.as_deref().unwrap_or("?"));
        println!("  {}", f.description);
        if let Some(s) = &f.suggestion {
            println!("  Suggestion: {s}");
        }
        println!();
    }
    ui::print_success(&format!("{} accounting drift shape(s) reported.", findings.len()));
    Ok(())
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn probe_events() {
        let source = std::fs::read_to_string("tests/fixtures_native/accounting/vuln.rs").unwrap();
        let (program, files) = crate::native::analyze_source_and_files_for_test(&source);
        let index = FnIndex::build(&files);

        for ix in &program.instructions {
            println!("IX: {} accounts: {:?}", ix.name, ix.accounts.iter().map(|a| a.name.clone()).collect::<Vec<_>>());
            let Some((handler, _)) = index.lookup(&ix.handler, &ix.file) else {
                println!("NO HANDLER");
                continue;
            };
            let mut blocks = Vec::new();
            let mut visited = std::collections::HashSet::new();
            visited.insert((0usize, ix.handler.clone()));
            collect_blocks(handler, &index, &mut visited, 0, &mut blocks, &[]);
            println!("BLOCKS: {}", blocks.len());

            let mut col = Collector { events: Vec::new(), aliases: HashMap::new(), stmt_idx: 0 };
            for block in &blocks {
                scan_block(block, ix, &mut col);
            }
            for (e, idx) in &col.events {
                println!("EVENT[{idx}]: {e:?}");
            }
        }
    }
}
