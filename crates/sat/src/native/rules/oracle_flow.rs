//! SAT041 — Oracle/Price Value Flow (the Mango mark-price class).
//!
//! SAT034–036 look at *feed-named* accounts (`oracle`, `price`, `*_feed`) and
//! flag staleness/confidence/exponent data never consumed. They do **not**
//! cover the Mango root cause: a program-owned market/price account (`market`,
//! `price_cache`, `perp_market`) whose price value an attacker can drive (via
//! self-trades on the program's own order book) flows into a value-decision
//! sink (a token-CPI amount, a borrow/withdraw quantity) with **no quality
//! bound** on the path — no confidence/staleness/scale consumption, no
//! threshold comparison.
//!
//! SAT038 (unvalidated-flow taint) also misses this class: its sources are
//! *unanchored account indices*, and a program-owned price cache is not
//! unanchored, so the value does not taint. SAT041 therefore records price-style
//! values read from program state (or feed accounts) and flags them when they
//! reach a value-decision sink with no bound.
//!
//! Findings are heuristic leads — the auditor verifies whether the price
//! source is attacker-influenceable (cross-instruction) before escalating.

use std::collections::{HashMap, HashSet};

use crate::native::model::{NativeInstruction, NativeProgram};
use crate::native::rules::validate::{FnIndex, collect_blocks};
use crate::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
pub const SAT041_TITLE: &str = "Oracle Value Flow:";

/// Price-style fields whose value feeds a decision, even when the account is
/// not feed-named (the Mango `market.mark_price` / `price_cache[..].price`
/// class). SAT034-036's feed-name detector misses these.
const PRICE_FIELDS: &[&str] = &[
    "market_price",
    "mark_price",
    "price_cache",
    "last_price",
    "oracle_price",
    "stored_price",
    "price",
    "base_price",
    "quote_price",
];

/// Fields whose consumption bounds a price value (a "quality bound"). If any
/// of these is read from the same price source, the value is considered
/// validated and SAT041 stays silent.
const BOUND_FIELDS: &[&str] = &[
    "conf",
    "confidence",
    "confidence_interval",
    "publish_time",
    "last_updated",
    "last_updated_time",
    "latest_price_time",
    "timestamp",
    "delay",
    "expo",
    "decimal",
    "decimals",
    "exponent",
    "valid_slot",
];

/// Value-decision sinks: arguments that become an amount/quantity whose value
/// a caller influences via the price.
fn is_value_sink(callee: &str) -> bool {
    matches!(
        callee,
        "invoke" | "invoke_signed" | "invoke_unchecked" | "transfer" | "transfer_checked" | "withdraw" | "borrow"
    )
}

/// One price value flowing to a sink.
#[derive(Debug, Clone)]
struct PriceFlow {
    /// Account name the price was read from (for the finding title).
    source: String,
    /// The sink site.
    sink: String,
}

/// Track ident → account-name of a local (or field path's base) that holds a
/// price-style value.
struct FlowState {
    /// ident → source account name the price value was read from.
    price_idents: HashMap<String, String>,
    /// ident → source account name for a struct loaded from that account
    /// (e.g. `let state = Market::load(market)`), so `state.mark_price`
    /// resolves back to `market`.
    struct_loads: HashMap<String, String>,
    /// price-source account names that had a bound field consumed.
    bounded: HashSet<String>,
}

impl FlowState {
    fn new() -> Self {
        FlowState { price_idents: HashMap::new(), struct_loads: HashMap::new(), bounded: HashSet::new() }
    }
}

/// Run SAT041 for one instruction over its flattened blocks.
fn analyze_instruction(ix: &NativeInstruction, blocks: &[&syn::Block]) -> Vec<Finding> {
    let mut flows = Vec::new();
    let mut state = FlowState::new();
    for block in blocks {
        scan_block(block, ix, &mut state, &mut flows);
    }

    let mut seen = HashSet::new();
    let mut findings = Vec::new();
    for flow in flows {
        if state.bounded.contains(&flow.source) {
            continue;
        }
        if !seen.insert((flow.source.clone(), flow.sink.clone())) {
            continue;
        }
        findings.push(Finding {
            id: String::new(),
            title: format!("{SAT041_TITLE} `{}`", flow.source),
            severity: Severity::High,
            description: format!(
                "Instruction `{}` reads a price value from `{}` and passes it into {} \
                 with no confidence/staleness/scale bound on the path. If the price source \
                 is caller-drivable (e.g. a program-owned market account updated by an \
                 unrelated instruction), an attacker can inflate the value to gain \
                 borrows/withdrawals — the Mango mark-price class. Confirm the price \
                 source's influence and whether a bound exists elsewhere before escalating.",
                ix.name, flow.source, flow.sink
            ),
            location: Some(format!("{}:{} ({})", ix.file, ix.line, ix.name)),
            suggestion: Some(
                "Bound the price before the value decision: require a maximum age and confidence, \
                 e.g. `require!(price.conf < price.abs() / 100, BadConf)` and \
                 `require!(now - price.publish_time <= MAX_AGE, StalePrice)`."
                    .to_string(),
            ),
        });
    }
    findings
}

fn scan_block(block: &syn::Block, ix: &NativeInstruction, state: &mut FlowState, out: &mut Vec<PriceFlow>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    // `let mark = market.mark_price;` → bind `mark` to the price
                    // source account.
                    if let syn::Pat::Ident(pi) = &l.pat {
                        if let Some((src_name, is_price)) = price_source_of(&init.expr, ix, state)
                            && is_price
                        {
                            state.price_idents.insert(pi.ident.to_string(), src_name);
                        }
                        // `let state = Market::load(market)` — record the struct
                        // local→account mapping so `state.mark_price` resolves.
                        if let Some(acc) = struct_load_account_of(&init.expr, ix, state) {
                            state.struct_loads.insert(pi.ident.to_string(), acc);
                        }
                    }
                    scan_expr(&init.expr, ix, state, out);
                }
            }
            syn::Stmt::Expr(e, _) => scan_expr(e, ix, state, out),
            syn::Stmt::Macro(m) => {
                if let Ok(args) = syn::parse::Parser::parse2(
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
                    m.mac.tokens.clone(),
                ) {
                    for arg in args {
                        scan_expr(&arg, ix, state, out);
                    }
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

/// Resolve `expr` to `(source_account_name, is_price_value)` when it reads a
/// price-style field off an account or a bound into a price-valued local.
fn price_source_of(e: &syn::Expr, ix: &NativeInstruction, state: &FlowState) -> Option<(String, bool)> {
    // `account.field` where field is a price field.
    if let syn::Expr::Field(f) = e {
        let member = match &f.member {
            syn::Member::Named(n) => n.to_string(),
            syn::Member::Unnamed(_) => return None,
        };
        if is_price_field(&member)
            && let Some(name) = account_name_of(&f.base, ix, state)
        {
            return Some((name, true));
        }
        if is_bound_field(&member)
            && let Some(name) = account_name_of(&f.base, ix, state)
        {
            return Some((name, false));
        }
    }
    // `price_cache[i].price` — index into a price cache.
    if let syn::Expr::Index(idx) = e {
        return price_source_of(&idx.expr, ix, state);
    }
    // A local that already holds a price value.
    if let syn::Expr::Path(p) = e
        && let Some(ident) = p.path.get_ident()
        && let Some(name) = state.price_idents.get(&ident.to_string())
    {
        return Some((name.clone(), true));
    }
    None
}

/// Resolve `let state = Market::load(market)` → the source account name
/// (`market`), so later `state.price` fields resolve back to `market`.
fn struct_load_account_of(e: &syn::Expr, ix: &NativeInstruction, state: &FlowState) -> Option<String> {
    match e {
        syn::Expr::Try(t) => struct_load_account_of(&t.expr, ix, state),
        syn::Expr::Paren(p) => struct_load_account_of(&p.expr, ix, state),
        syn::Expr::Reference(r) => struct_load_account_of(&r.expr, ix, state),
        syn::Expr::Call(c) => {
            // `Market::load(market)` — first account-shaped argument.
            c.args.iter().find_map(|a| account_name_of(a, ix, state))
        }
        syn::Expr::MethodCall(m) => {
            if !matches!(m.method.to_string().as_str(), "unwrap" | "expect") {
                return None;
            }
            account_name_of(&m.receiver, ix, state)
        }
        _ => None,
    }
}

/// The account name an expression's base resolves to (a plain account path or
/// a `ctx.accounts.<name>` / `self.<name>` chain).
fn account_name_of(e: &syn::Expr, ix: &NativeInstruction, state: &FlowState) -> Option<String> {
    match e {
        syn::Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                // A bare account path.
                let name = ident.to_string();
                if ix.accounts.iter().any(|a| a.name == name) {
                    return Some(name);
                }
                // A local holding a price value.
                if let Some(n) = state.price_idents.get(&name) {
                    return Some(n.clone());
                }
                // A local holding a struct loaded from an account.
                if let Some(n) = state.struct_loads.get(&name) {
                    return Some(n.clone());
                }
            }
            None
        }
        syn::Expr::Field(f) => {
            // `ctx.accounts.<name>` base.
            let syn::Member::Named(member) = &f.member else { return None };
            match &*f.base {
                syn::Expr::Path(p) if p.path.is_ident("ctx") => {
                    // treat member as field name fallback
                    let name = member.to_string();
                    if ix.accounts.iter().any(|a| a.name == name) {
                        return Some(name);
                    }
                    None
                }
                _ => None,
            }
        }
        syn::Expr::Paren(p) => account_name_of(&p.expr, ix, state),
        syn::Expr::Group(g) => account_name_of(&g.expr, ix, state),
        syn::Expr::Reference(r) => account_name_of(&r.expr, ix, state),
        _ => None,
    }
}

fn scan_expr(e: &syn::Expr, ix: &NativeInstruction, state: &mut FlowState, out: &mut Vec<PriceFlow>) {
    match e {
        syn::Expr::Call(c) => {
            let callee = match &*c.func {
                syn::Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                _ => String::new(),
            };
            if is_value_sink(&callee) {
                // Any price value reaching the sink (directly or nested inside
                // an arg subtree, e.g. `invoke(&transfer(amount), ...)`) is a
                // flow. Walk the whole arg subtree for price-ident sources.
                for arg in &c.args {
                    let mut srcs = Vec::new();
                    price_sources_in_expr(arg, ix, state, &mut srcs);
                    for src in srcs {
                        out.push(PriceFlow { source: src, sink: format!("{callee}(...)") });
                    }
                }
            }
            for arg in &c.args {
                scan_expr(arg, ix, state, out);
            }
        }
        syn::Expr::MethodCall(m) => {
            // Record a bound field consumption on the receiver's price source.
            if is_bound_field(&m.method.to_string())
                && let Some(name) = account_name_of(&m.receiver, ix, state)
            {
                state.bounded.insert(name);
            }
            scan_expr(&m.receiver, ix, state, out);
            for arg in &m.args {
                scan_expr(arg, ix, state, out);
            }
        }
        syn::Expr::Assign(a) => {
            // `price_cache.mark_price = <price value>` — recompute the source.
            if let syn::Expr::Field(f) = &*a.left {
                let member = match &f.member {
                    syn::Member::Named(n) => n.to_string(),
                    syn::Member::Unnamed(_) => unreachable!(),
                };
                if is_price_field(&member)
                    && let Some(name) = account_name_of(&f.base, ix, state)
                    && let Some((vsrc, true)) = price_source_of(&a.right, ix, state)
                {
                    // Source of the assignment is `vsrc`, the value written.
                    state.price_idents.insert(name, vsrc);
                }
            }
            scan_expr(&a.left, ix, state, out);
            scan_expr(&a.right, ix, state, out);
        }
        syn::Expr::Binary(b) => {
            scan_expr(&b.left, ix, state, out);
            scan_expr(&b.right, ix, state, out);
        }
        syn::Expr::Field(f) => {
            // `account.price` read → record; `account.conf` read → bound.
            if let Some((name, is_price)) = price_source_of(e, ix, state) {
                if is_price {
                    // a bare price read alone is not a flow; only feeds sinks
                } else {
                    state.bounded.insert(name);
                }
            }
            scan_expr(&f.base, ix, state, out);
        }
        syn::Expr::If(i) => {
            scan_expr(&i.cond, ix, state, out);
            scan_block(&i.then_branch, ix, state, out);
            if let Some((_, else_expr)) = &i.else_branch {
                scan_expr(else_expr, ix, state, out);
            }
        }
        syn::Expr::Block(b) => scan_block(&b.block, ix, state, out),
        syn::Expr::Paren(p) => scan_expr(&p.expr, ix, state, out),
        syn::Expr::Reference(r) => scan_expr(&r.expr, ix, state, out),
        syn::Expr::Try(t) => scan_expr(&t.expr, ix, state, out),
        syn::Expr::Index(i) => {
            scan_expr(&i.expr, ix, state, out);
            scan_expr(&i.index, ix, state, out);
        }
        _ => {}
    }
}

fn is_price_field(name: &str) -> bool {
    PRICE_FIELDS.contains(&name)
}

fn is_bound_field(name: &str) -> bool {
    BOUND_FIELDS.contains(&name)
}

/// Collect every price-source account name appearing anywhere in an expression
/// subtree (including references, parens, nested calls).
fn price_sources_in_expr(e: &syn::Expr, ix: &NativeInstruction, state: &FlowState, out: &mut Vec<String>) {
    match e {
        syn::Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident()
                && let Some(name) = state.price_idents.get(&ident.to_string())
            {
                out.push(name.clone());
            }
        }
        syn::Expr::Field(f) => {
            if let Some((name, is_price)) = price_source_of(e, ix, state)
                && is_price
            {
                out.push(name);
            }
            price_sources_in_expr(&f.base, ix, state, out);
        }
        syn::Expr::Index(i) => {
            price_sources_in_expr(&i.expr, ix, state, out);
            price_sources_in_expr(&i.index, ix, state, out);
        }
        syn::Expr::Call(c) => {
            price_sources_in_expr(&c.func, ix, state, out);
            for arg in &c.args {
                price_sources_in_expr(arg, ix, state, out);
            }
        }
        syn::Expr::MethodCall(m) => {
            price_sources_in_expr(&m.receiver, ix, state, out);
            for arg in &m.args {
                price_sources_in_expr(arg, ix, state, out);
            }
        }
        syn::Expr::Reference(r) => price_sources_in_expr(&r.expr, ix, state, out),
        syn::Expr::Paren(p) => price_sources_in_expr(&p.expr, ix, state, out),
        syn::Expr::Group(g) => price_sources_in_expr(&g.expr, ix, state, out),
        syn::Expr::Try(t) => price_sources_in_expr(&t.expr, ix, state, out),
        syn::Expr::Array(a) => {
            for el in &a.elems {
                price_sources_in_expr(el, ix, state, out);
            }
        }
        syn::Expr::Tuple(t) => {
            for el in &t.elems {
                price_sources_in_expr(el, ix, state, out);
            }
        }
        syn::Expr::Binary(b) => {
            price_sources_in_expr(&b.left, ix, state, out);
            price_sources_in_expr(&b.right, ix, state, out);
        }
        syn::Expr::Struct(s) => {
            for f in &s.fields {
                price_sources_in_expr(&f.expr, ix, state, out);
            }
        }
        syn::Expr::Cast(c) => price_sources_in_expr(&c.expr, ix, state, out),
        _ => {}
    }
}

/// SAT041: flag price values from program state (or feeds) flowing into value
/// sinks with no quality bound. Native path plus the Anchor fallback.
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

    // Anchor path: price reads resolve through the shared Anchor extraction.
    crate::native::rules::validate::for_each_anchor_instruction(
        parsed,
        &mut |ix, _bundles, _ms, _extra, roots, _aa, _state_accs| {
            let Some((handler, file_idx)) = index.lookup(&ix.handler, &ix.file) else { return };
            let mut blocks: Vec<&syn::Block> = Vec::new();
            let mut visited = HashSet::new();
            visited.insert((file_idx, ix.handler.clone()));
            collect_blocks(handler, &index, &mut visited, 0, &mut blocks, roots);
            findings.extend(analyze_instruction(ix, &blocks));
        },
    );

    findings
}
