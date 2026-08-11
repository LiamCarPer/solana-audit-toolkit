//! R7 slice: oracle rules SAT034 / SAT035 / SAT036 — the Mango-class
//! code-level gaps (the *economics* of oracle manipulation stay documented as
//! out of scope in EXPLOIT_CORPUS.md; these rules attack the missing
//! staleness/confidence/exponent handling).
//!
//! For each instruction, price-feed accounts are identified by name; their
//! data is then inspected across the handler + helper call graph (depth ≤ 2):
//! - SAT034 Stale Oracle Price — the feed's time field (`publish_time`,
//!   `last_updated`, `timestamp`, …) is never consumed, so nothing can
//!   bound the feed's age. High.
//! - SAT035 Oracle Confidence Unvalidated — the feed's confidence field
//!   (`conf`) is never consumed, so nothing bounds price quality. High.
//! - SAT036 Oracle Decimals/Exponent Mismatch — the feed's exponent field
//!   (`expo`/`decimal`) is never consumed, so price values are used without
//!   their scale, the classic decimals-mismatch family. High.
//!
//! FP control: a feed that is CPI-passed-only (its data is never read in
//! program) is suppressed — the callee program validates it. Deserialized
//! locals (`let p = Price::try_from_slice(&feed.data.borrow())?; p.price`)
//! are tainted back to the feed account so real-world Pyth/Switchboard usage
//! is seen.
//!
//! Honest scope (v1): "never consumed" is the signal; consuming a field
//! without a *bound* (e.g. reading `conf` but never comparing it) is not yet
//! distinguished — that refinement is documented in `docs/NATIVE_BACKEND.md`.
//!
//! Title prefixes are load-bearing for SARIF classification (section 7 of
//! `docs/NATIVE_BACKEND.md`); do not rename them.

use std::collections::{HashMap, HashSet};

use syn::Expr;

use crate::native::model::{NativeInstruction, NativeProgram};
use crate::native::rules::validate::{FnIndex, collect_blocks};
use crate::types::{Finding, Severity};

/// Exact title prefixes from `docs/NATIVE_BACKEND.md` section 7.
const SAT034_TITLE: &str = "Stale Oracle Price:";
const SAT035_TITLE: &str = "Oracle Confidence Unvalidated:";
const SAT036_TITLE: &str = "Oracle Decimals/Exponent Mismatch:";

/// Account-name patterns that identify a price-feed account.
fn is_feed_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("feed")
        || lower.contains("oracle")
        || lower == "price"
        || lower.ends_with("_price")
        || lower.starts_with("price_")
}

/// Time fields whose consumption enables a staleness bound.
const TIME_FIELDS: &[&str] =
    &["publish_time", "last_updated", "last_updated_time", "latest_price_time", "timestamp", "publish_time_seconds"];

/// Confidence fields whose consumption enables a quality bound.
const CONFIDENCE_FIELDS: &[&str] = &["conf", "confidence", "confidence_interval"];

/// Exponent/decimals fields whose consumption applies the price scale.
const EXPONENT_FIELDS: &[&str] = &["expo", "decimal", "decimals", "exponent"];

/// Member accesses collected per account index across the flattened blocks,
/// plus aliases and deserialized locals resolved back to their source account.
struct AccessCollector {
    /// account index → accessed member names.
    accesses: HashMap<usize, HashSet<String>>,
}

impl AccessCollector {
    fn record(&mut self, acc: usize, member: &str) {
        self.accesses.entry(acc).or_default().insert(member.to_string());
    }

    fn has_member(&self, acc: usize, member: &str) -> bool {
        self.accesses.get(&acc).is_some_and(|set| set.contains(member))
    }

    fn any_member(&self, acc: usize, fields: &[&str]) -> bool {
        fields.iter().any(|f| self.has_member(acc, f))
    }
}

/// Account-info members that are identity/account plumbing, not feed data
/// reads: touching only these does not count as consuming the feed payload.
const IDENTITY_MEMBERS: &[&str] = &["key", "lamports", "owner", "executable", "rent_epoch", "is_signer", "data_len"];

/// Walk the flattened handler + helper blocks, collecting per-account member
/// accesses with alias and deserialized-local tainting.
fn collect_accesses(blocks: &[&syn::Block], ix: &NativeInstruction) -> AccessCollector {
    let mut collector = AccessCollector { accesses: HashMap::new() };
    for block in blocks {
        let mut aliases = HashMap::new();
        scan_block_accesses(block, ix, &mut aliases, &mut collector);
    }
    collector
}

impl AccessCollector {
    /// Whether any non-identity member of the account was accessed (a real
    /// payload read).
    fn is_read(&self, acc: usize) -> bool {
        self.accesses.get(&acc).is_some_and(|set| set.iter().any(|m| !IDENTITY_MEMBERS.contains(&m.as_str())))
    }
}

fn scan_block_accesses(
    block: &syn::Block,
    ix: &NativeInstruction,
    aliases: &mut HashMap<String, usize>,
    collector: &mut AccessCollector,
) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    let init_expr = &init.expr;
                    // `let p = Price::try_from_slice(&feed.data.borrow())?;` /
                    // `let price = pyth_client::load_price(&data).unwrap();` /
                    // `let data = feed.try_borrow_data()?;` — taint the local
                    // with the feed account the bytes come from.
                    if let syn::Pat::Ident(pi) = &l.pat
                        && let Some(acc) = deser_source_account(init_expr, ix, aliases)
                            .or_else(|| borrow_source_account(init_expr, ix, aliases))
                    {
                        aliases.insert(pi.ident.to_string(), acc);
                    }
                    scan_expr_accesses(init_expr, ix, aliases, collector);
                }
            }
            syn::Stmt::Expr(e, _) => scan_expr_accesses(e, ix, aliases, collector),
            syn::Stmt::Macro(m) => {
                if let Ok(args) = syn::parse::Parser::parse2(
                    syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                    m.mac.tokens.clone(),
                ) {
                    for arg in args {
                        scan_expr_accesses(&arg, ix, aliases, collector);
                    }
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

fn scan_expr_accesses(
    e: &Expr,
    ix: &NativeInstruction,
    aliases: &mut HashMap<String, usize>,
    collector: &mut AccessCollector,
) {
    match e {
        Expr::Field(f) => {
            // Walk the full member chain (`price_account.agg.conf` → members
            // `agg`, `conf`) and record every member on the resolved account
            // (direct, aliased, `self.`/`ctx.accounts.` chains, or a local
            // tainted from a deserialization call).
            let mut members = vec![member_name(&f.member)];
            let mut base = &f.base;
            while let Expr::Field(inner) = &**base {
                members.push(member_name(&inner.member));
                base = &inner.base;
            }
            if let Some(acc) = base_account(base, ix, aliases) {
                for member in &members {
                    collector.record(acc, member);
                }
            }
            scan_expr_accesses(&f.base, ix, aliases, collector);
        }
        Expr::Call(c) => {
            scan_expr_accesses(&c.func, ix, aliases, collector);
            for arg in &c.args {
                scan_expr_accesses(arg, ix, aliases, collector);
            }
        }
        Expr::MethodCall(m) => {
            scan_expr_accesses(&m.receiver, ix, aliases, collector);
            for arg in &m.args {
                scan_expr_accesses(arg, ix, aliases, collector);
            }
        }
        Expr::Block(b) => scan_block_accesses(&b.block, ix, aliases, collector),
        Expr::Unsafe(u) => scan_block_accesses(&u.block, ix, aliases, collector),
        Expr::Const(c) => scan_block_accesses(&c.block, ix, aliases, collector),
        Expr::Async(a) => scan_block_accesses(&a.block, ix, aliases, collector),
        Expr::TryBlock(tb) => scan_block_accesses(&tb.block, ix, aliases, collector),
        Expr::If(i) => {
            scan_expr_accesses(&i.cond, ix, aliases, collector);
            scan_block_accesses(&i.then_branch, ix, aliases, collector);
            if let Some((_, else_expr)) = &i.else_branch {
                scan_expr_accesses(else_expr, ix, aliases, collector);
            }
        }
        Expr::While(w) => {
            scan_expr_accesses(&w.cond, ix, aliases, collector);
            scan_block_accesses(&w.body, ix, aliases, collector);
        }
        Expr::Loop(l) => scan_block_accesses(&l.body, ix, aliases, collector),
        Expr::ForLoop(fl) => scan_block_accesses(&fl.body, ix, aliases, collector),
        Expr::Match(m) => {
            scan_expr_accesses(&m.expr, ix, aliases, collector);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    scan_expr_accesses(guard, ix, aliases, collector);
                }
                scan_expr_accesses(&arm.body, ix, aliases, collector);
            }
        }
        Expr::Try(t) => scan_expr_accesses(&t.expr, ix, aliases, collector),
        Expr::Paren(p) => scan_expr_accesses(&p.expr, ix, aliases, collector),
        Expr::Group(g) => scan_expr_accesses(&g.expr, ix, aliases, collector),
        Expr::Reference(r) => scan_expr_accesses(&r.expr, ix, aliases, collector),
        Expr::RawAddr(r) => scan_expr_accesses(&r.expr, ix, aliases, collector),
        Expr::Unary(u) => scan_expr_accesses(&u.expr, ix, aliases, collector),
        Expr::Await(a) => scan_expr_accesses(&a.base, ix, aliases, collector),
        Expr::Closure(c) => scan_expr_accesses(&c.body, ix, aliases, collector),
        Expr::Binary(b) => {
            scan_expr_accesses(&b.left, ix, aliases, collector);
            scan_expr_accesses(&b.right, ix, aliases, collector);
        }
        Expr::Assign(a) => {
            scan_expr_accesses(&a.left, ix, aliases, collector);
            scan_expr_accesses(&a.right, ix, aliases, collector);
        }
        Expr::Index(i) => {
            scan_expr_accesses(&i.expr, ix, aliases, collector);
            scan_expr_accesses(&i.index, ix, aliases, collector);
        }
        Expr::Tuple(t) => {
            for el in &t.elems {
                scan_expr_accesses(el, ix, aliases, collector);
            }
        }
        Expr::Array(a) => {
            for el in &a.elems {
                scan_expr_accesses(el, ix, aliases, collector);
            }
        }
        Expr::Struct(s) => {
            for f in &s.fields {
                scan_expr_accesses(&f.expr, ix, aliases, collector);
            }
        }
        Expr::Cast(c) => scan_expr_accesses(&c.expr, ix, aliases, collector),
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                scan_expr_accesses(x, ix, aliases, collector);
            }
        }
        Expr::Break(br) => {
            if let Some(x) = &br.expr {
                scan_expr_accesses(x, ix, aliases, collector);
            }
        }
        Expr::Macro(m) => {
            if let Ok(args) = syn::parse::Parser::parse2(
                syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                m.mac.tokens.clone(),
            ) {
                for arg in args {
                    scan_expr_accesses(&arg, ix, aliases, collector);
                }
            }
        }
        _ => {}
    }
}

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(n) => n.to_string(),
        syn::Member::Unnamed(i) => i.index.to_string(),
    }
}

/// Resolve a field base expression to an account index: `feed`,
/// `self.feed`, `ctx.accounts.feed`, aliases, and deserialized locals.
fn base_account(base: &Expr, ix: &NativeInstruction, aliases: &HashMap<String, usize>) -> Option<usize> {
    match base {
        Expr::Path(p) => {
            let ident = p.path.get_ident()?.to_string();
            if let Some(acc) = aliases.get(&ident) {
                return Some(*acc);
            }
            account_index(ix, &ident)
        }
        Expr::Field(f) => {
            let syn::Member::Named(member) = &f.member else { return None };
            match &*f.base {
                // `self.<account>`
                Expr::Path(p) if p.path.is_ident("self") => account_index(ix, &member.to_string()),
                // `ctx.accounts.<account>`
                Expr::Field(inner) => {
                    let syn::Member::Named(inner_member) = &inner.member else { return None };
                    if inner_member == "accounts" && matches!(&*inner.base, Expr::Path(p) if p.path.is_ident("ctx")) {
                        return account_index(ix, &member.to_string());
                    }
                    None
                }
                _ => None,
            }
        }
        Expr::Reference(r) => base_account(&r.expr, ix, aliases),
        Expr::Paren(p) => base_account(&p.expr, ix, aliases),
        Expr::Group(g) => base_account(&g.expr, ix, aliases),
        _ => None,
    }
}

/// The account whose data feeds a deserialization call:
/// `Price::try_from_slice(&feed.data.borrow())` → `feed` (index). Peels
/// `?`/`unwrap()`/`expect()` wrappers.
fn deser_source_account(expr: &Expr, ix: &NativeInstruction, aliases: &HashMap<String, usize>) -> Option<usize> {
    let call = match expr {
        Expr::Call(c) => c,
        Expr::Try(t) => return deser_source_account(&t.expr, ix, aliases),
        Expr::Paren(p) => return deser_source_account(&p.expr, ix, aliases),
        Expr::MethodCall(m) if matches!(m.method.to_string().as_str(), "unwrap" | "expect") => {
            return deser_source_account(&m.receiver, ix, aliases);
        }
        _ => return None,
    };
    let name = match &*call.func {
        Expr::Path(p) => p.path.segments.last()?.ident.to_string(),
        _ => return None,
    };
    if !matches!(
        name.as_str(),
        "try_from_slice"
            | "try_from_slice_unchecked"
            | "load"
            | "load_checked"
            | "load_mut"
            | "unpack"
            | "load_price_account"
            | "get_price_account"
            | "load_price"
            | "get_price"
    ) {
        return None;
    }
    // First argument references the account data (possibly via borrows).
    let first = call.args.first()?;
    account_in_expr(first, ix, aliases)
}

/// The account a borrow-style method call reads its bytes from:
/// `feed.try_borrow_data()` / `feed.data.borrow()` → `feed` (index).
fn borrow_source_account(expr: &Expr, ix: &NativeInstruction, aliases: &HashMap<String, usize>) -> Option<usize> {
    let method = match expr {
        Expr::MethodCall(m)
            if matches!(m.method.to_string().as_str(), "try_borrow_data" | "try_borrow" | "borrow" | "data") =>
        {
            m
        }
        Expr::Try(t) => return borrow_source_account(&t.expr, ix, aliases),
        Expr::Paren(p) => return borrow_source_account(&p.expr, ix, aliases),
        Expr::Field(f) => return account_in_expr(&f.base, ix, aliases),
        _ => return None,
    };
    base_account(&method.receiver, ix, aliases)
}

/// Find an account index anywhere inside an expression (the deser argument
/// may be `&feed.data.borrow()` / `feed.try_borrow_data()?` etc.).
fn account_in_expr(e: &Expr, ix: &NativeInstruction, aliases: &HashMap<String, usize>) -> Option<usize> {
    match e {
        Expr::Field(f) => {
            if let Some(acc) = base_account(&f.base, ix, aliases) {
                return Some(acc);
            }
            account_in_expr(&f.base, ix, aliases)
        }
        Expr::Call(c) => account_in_expr(&c.func, ix, aliases)
            .or_else(|| c.args.iter().find_map(|a| account_in_expr(a, ix, aliases))),
        Expr::MethodCall(m) => account_in_expr(&m.receiver, ix, aliases)
            .or_else(|| m.args.iter().find_map(|a| account_in_expr(a, ix, aliases))),
        Expr::Reference(r) => account_in_expr(&r.expr, ix, aliases),
        Expr::Paren(p) => account_in_expr(&p.expr, ix, aliases),
        Expr::Group(g) => account_in_expr(&g.expr, ix, aliases),
        Expr::Try(t) => account_in_expr(&t.expr, ix, aliases),
        Expr::Path(p) => {
            let ident = p.path.get_ident()?.to_string();
            aliases.get(&ident).copied().or_else(|| account_index(ix, &ident))
        }
        _ => None,
    }
}

fn account_index(ix: &NativeInstruction, name: &str) -> Option<usize> {
    ix.accounts.iter().position(|a| a.name == name)
}

fn location(ix: &NativeInstruction) -> String {
    format!("{}:{} ({})", ix.file, ix.line, ix.name)
}

/// Run the oracle checks for one instruction: identify feed accounts and
/// emit one finding per missing consumption class.
fn analyze_instruction(ix: &NativeInstruction, blocks: &[&syn::Block]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let feeds: Vec<usize> =
        ix.accounts.iter().enumerate().filter(|(_, acc)| is_feed_named(&acc.name)).map(|(i, _)| i).collect();
    if feeds.is_empty() {
        return findings;
    }

    let accesses = collect_accesses(blocks, ix);

    for feed_idx in feeds {
        let name = ix.accounts[feed_idx].name.clone();
        // CPI-passed-only feeds (data never read in program) are suppressed:
        // the callee program validates them. Touching only identity members
        // (`key`, `owner`, ...) is not a payload read.
        if !accesses.is_read(feed_idx) {
            continue;
        }

        if !accesses.any_member(feed_idx, TIME_FIELDS) {
            findings.push(Finding {
                id: String::new(),
                title: format!("{SAT034_TITLE} `{name}`"),
                severity: Severity::High,
                description: format!(
                    "Instruction `{}` reads the price feed `{name}` but never consumes its time \
                     field (`publish_time`/`last_updated`/`timestamp`), so nothing bounds the feed's \
                     age. A stale price can be used as if fresh — the Mango-class code-level gap. \
                     Confirm a staleness bound exists elsewhere before escalating.",
                    ix.name
                ),
                location: Some(location(ix)),
                suggestion: Some(format!(
                    "Require a maximum age before using the price, e.g. \
                     `require!(now - {name}.publish_time <= MAX_AGE, StaleOracle)`."
                )),
            });
        }
        if !accesses.any_member(feed_idx, CONFIDENCE_FIELDS) {
            findings.push(Finding {
                id: String::new(),
                title: format!("{SAT035_TITLE} `{name}`"),
                severity: Severity::High,
                description: format!(
                    "Instruction `{}` reads the price feed `{name}` but never consumes its \
                     confidence field (`conf`), so price quality is unbounded. Manipulated or \
                     illiquid feeds can pass with arbitrarily wide confidence.",
                    ix.name
                ),
                location: Some(location(ix)),
                suggestion: Some(format!(
                    "Validate the confidence before using the price, e.g. \
                     `require!({name}.conf < {name}.price.abs() / 100, BadConfidence)`."
                )),
            });
        }
        if !accesses.any_member(feed_idx, EXPONENT_FIELDS) {
            findings.push(Finding {
                id: String::new(),
                title: format!("{SAT036_TITLE} `{name}`"),
                severity: Severity::High,
                description: format!(
                    "Instruction `{}` reads the price feed `{name}` but never consumes its \
                     exponent/decimals field (`expo`/`decimal`), so raw feed integers are used \
                     without their scale. Price-vs-amount and cross-feed math then silently differ \
                     by powers of ten — the decimals-mismatch family of exploits.",
                    ix.name
                ),
                location: Some(location(ix)),
                suggestion: Some(format!(
                    "Apply the feed exponent before arithmetic, e.g. \
                     `price.to_scaled_price(...)` or `10u64.pow({name}.expo as u32)`."
                )),
            });
        }
    }

    findings
}

/// SAT034/035/036: flag price feeds whose staleness/confidence/exponent data
/// is never consumed. Native-model path (the Anchor path is a documented
/// follow-up — see docs/NATIVE_BACKEND.md).
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let index = FnIndex::build(parsed);
    let mut findings = Vec::new();

    for ix in &program.instructions {
        let Some((handler, file_idx)) = index.lookup(&ix.handler, &ix.file) else {
            continue;
        };
        let mut blocks: Vec<&syn::Block> = Vec::new();
        let mut visited = HashSet::new();
        visited.insert((file_idx, ix.handler.clone()));
        collect_blocks(handler, &index, &mut visited, 0, &mut blocks, &[]);
        findings.extend(analyze_instruction(ix, &blocks));
    }

    findings
}
