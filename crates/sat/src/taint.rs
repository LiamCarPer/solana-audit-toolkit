//! Validation-completeness engine (`sat taint`, rule SAT038).
//!
//! Flags attacker-influenced values that flow into privileged sinks with no
//! anchoring validation anywhere on the path:
//!
//! ```text
//! source                              sink
//! ────────────────────────────────────────────────────────────────
//! unanchored account field  ───►  token-CPI amount / authority
//! unanchored account field  ───►  state write (data.borrow_mut)
//! instruction argument      ───►  invoke_signed seeds
//! ```
//!
//! A value is attacker-influenced when it originates from an account that has
//! NO canonical anchoring: no owner/signer/key pin, not a sysvar/program
//! account, not a literal-seed PDA. The canonical model is SAT031's
//! (`seed_canonical` + `reachable_canonical` + owner-checked accounts), so an
//! account whose `.owner`/`.key` is compared against an anchor counts as
//! program-controlled and its flows are validated.
//!
//! Sinks:
//! - token-CPI fields: anchor-spl `Transfer`/`MintTo`/`Burn` accounts structs
//!   (amounts, authorities, mints) and native `invoke` amount arguments
//! - state writes: `data.borrow_mut()` mutations, `try_from_slice_mut`,
//!   `load_mut`, `realloc`, `assign`, lamports writes
//! - `invoke_signed` seed arrays
//!
//! Severity: High for token-CPI and state-write sinks; Medium for the rest.
//!
//! Findings are leads, not proof — manual verification required.

use std::collections::{HashMap, HashSet};

use syn::Expr;

use anyhow::Result;

use crate::native::model::{AccountKind, NativeInstruction, NativeProgram};
use crate::native::rules::validate::{Bundles, FnIndex, InstructionGraph, analyze_instruction_graph};
use crate::types::{Finding, Severity};

/// Exact title prefix from `docs/NATIVE_BACKEND.md` section 7.
const SAT038_TITLE: &str = "Unvalidated Flow:";

/// How dangerous the reached sink is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkKind {
    /// A token-CPI amount / authority / mint position.
    TokenCpi,
    /// A state write on an unanchored account's data or lamports.
    StateWrite,
    /// An `invoke_signed` seed position.
    Seeds,
    /// Any other privileged call argument.
    CallArg,
}

impl SinkKind {
    fn severity(self) -> Severity {
        match self {
            SinkKind::TokenCpi | SinkKind::StateWrite => Severity::High,
            SinkKind::Seeds | SinkKind::CallArg => Severity::Medium,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            SinkKind::TokenCpi => "a token-CPI argument",
            SinkKind::StateWrite => "a state write",
            SinkKind::Seeds => "an `invoke_signed` seed list",
            SinkKind::CallArg => "a privileged call argument",
        }
    }
}

/// One detected flow from an unanchored source to a sink.
struct Flow {
    /// Account indices contributing attacker-influenced values.
    sources: Vec<usize>,
    kind: SinkKind,
    /// Short description of the sink site.
    sink: String,
}

// ── Taint state ──────────────────────────────────────────────────────────────

/// Directional taint tracking across one flattened block list.
///
/// Tainted idents are locals whose value derives from an unanchored account
/// (field access, deserialization, borrow) or from another tainted local via
/// arithmetic/assignment. Untainted locals (literals, canonical accounts)
/// never become tainted here — the anchor check filters at bind time.
struct TaintState {
    /// Local ident → the unanchored account indices it derives from.
    tainted: HashMap<String, HashSet<usize>>,
    /// Unanchored account indices (the sources).
    sources: HashSet<usize>,
    /// Program-controlled (canonical) account indices: pollution targets.
    canonical: HashSet<usize>,
    /// Sources that appeared inside a guard/bound condition (`amount <= MAX`)
    /// — bounded values are validated usage, not unchecked flows.
    bounded: HashSet<usize>,
}

impl TaintState {
    fn new(ix: &NativeInstruction, canonical: &HashSet<usize>) -> Self {
        let sources: HashSet<usize> = ix
            .accounts
            .iter()
            .enumerate()
            .filter(|(i, acc)| !canonical.contains(i) && is_source_kind(acc.kind))
            .map(|(i, _)| i)
            .collect();
        TaintState { tainted: HashMap::new(), sources, canonical: canonical.clone(), bounded: HashSet::new() }
    }

    /// Mark every source account referenced in a guard condition as bounded.
    fn mark_bounded(&mut self, refs: &HashSet<usize>) {
        self.bounded.extend(refs.iter().filter(|i| self.sources.contains(i)).copied());
    }

    fn bind_ident(&mut self, ident: &str, accounts: &HashSet<usize>) {
        if accounts.is_empty() {
            return;
        }
        self.tainted.entry(ident.to_string()).or_default().extend(accounts.iter().copied());
    }

    /// The unanchored sources an expression draws from, given current taint.
    fn sources_in(&self, e: &Expr, ix: &NativeInstruction) -> Vec<usize> {
        let mut found = HashSet::new();
        collect_sources(e, ix, &self.tainted, &self.sources, &mut found);
        let mut v: Vec<usize> = found.into_iter().collect();
        v.sort();
        v
    }

    /// Union of sources across several expressions.
    fn sources_in_args(&self, args: &[Expr], ix: &NativeInstruction) -> Vec<usize> {
        let mut found = HashSet::new();
        for a in args {
            collect_sources(a, ix, &self.tainted, &self.sources, &mut found);
        }
        found.into_iter().collect()
    }
}

fn is_source_kind(kind: AccountKind) -> bool {
    !matches!(kind, AccountKind::Sysvar | AccountKind::Program | AccountKind::SystemProgram | AccountKind::Signer)
}

/// Collect the unanchored account indices an expression reads from.
fn collect_sources(
    e: &Expr,
    ix: &NativeInstruction,
    tainted: &HashMap<String, HashSet<usize>>,
    sources: &HashSet<usize>,
    out: &mut HashSet<usize>,
) {
    match e {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                if let Some(set) = tainted.get(ident.to_string().as_str()) {
                    // A local can be bound to canonical accounts too (the Local
                    // arm binds every referenced account so pollution sinks can
                    // attribute writes back). Only unanchored sources count as
                    // value sources — a container/state account referenced via a
                    // local is not attacker-influenced.
                    out.extend(set.iter().copied().filter(|i| sources.contains(i)));
                } else if let Some(acc) = account_index(ix, &ident.to_string())
                    && sources.contains(&acc)
                {
                    out.insert(acc);
                }
            }
        }
        Expr::Field(f) => {
            // `<base>.<field>` — attribute to the base account when the base
            // resolves to an unanchored source; recurse into the base either way.
            if let Some(base_acc) = base_account_index(&f.base, ix, tainted)
                && sources.contains(&base_acc)
            {
                out.insert(base_acc);
            }
            collect_sources(&f.base, ix, tainted, sources, out);
        }
        Expr::MethodCall(m) => {
            collect_sources(&m.receiver, ix, tainted, sources, out);
            for arg in &m.args {
                collect_sources(arg, ix, tainted, sources, out);
            }
        }
        Expr::Call(c) => {
            collect_sources(&c.func, ix, tainted, sources, out);
            for arg in &c.args {
                collect_sources(arg, ix, tainted, sources, out);
            }
        }
        Expr::Binary(b) => {
            collect_sources(&b.left, ix, tainted, sources, out);
            collect_sources(&b.right, ix, tainted, sources, out);
        }
        Expr::Unary(u) => collect_sources(&u.expr, ix, tainted, sources, out),
        Expr::Reference(r) => collect_sources(&r.expr, ix, tainted, sources, out),
        Expr::Paren(p) => collect_sources(&p.expr, ix, tainted, sources, out),
        Expr::Group(g) => collect_sources(&g.expr, ix, tainted, sources, out),
        Expr::Try(t) => collect_sources(&t.expr, ix, tainted, sources, out),
        Expr::Cast(c) => collect_sources(&c.expr, ix, tainted, sources, out),
        Expr::Index(i) => {
            collect_sources(&i.expr, ix, tainted, sources, out);
            collect_sources(&i.index, ix, tainted, sources, out);
        }
        Expr::Await(a) => collect_sources(&a.base, ix, tainted, sources, out),
        Expr::Assign(a) => {
            collect_sources(&a.left, ix, tainted, sources, out);
            collect_sources(&a.right, ix, tainted, sources, out);
        }
        Expr::Tuple(t) => {
            for el in &t.elems {
                collect_sources(el, ix, tainted, sources, out);
            }
        }
        Expr::Array(a) => {
            for el in &a.elems {
                scan_into(el, ix, tainted, sources, out);
            }
        }
        _ => {}
    }
}

fn scan_into(
    e: &Expr,
    ix: &NativeInstruction,
    tainted: &HashMap<String, HashSet<usize>>,
    sources: &HashSet<usize>,
    out: &mut HashSet<usize>,
) {
    collect_sources(e, ix, tainted, sources, out)
}

/// Resolve a field-base expression to an account index (direct ident or
/// alias). Mirrors the oracle slice's resolution.
fn base_account_index(base: &Expr, ix: &NativeInstruction, tainted: &HashMap<String, HashSet<usize>>) -> Option<usize> {
    match base {
        Expr::Path(p) => {
            let ident = p.path.get_ident()?.to_string();
            if tainted.contains_key(&ident) {
                return tainted.get(&ident).and_then(|s| s.iter().next().copied());
            }
            account_index(ix, &ident)
        }
        Expr::Field(f) => {
            if let Expr::Path(p) = &*f.base {
                let ident = p.path.get_ident()?.to_string();
                if ident == "self" || ident == "ctx" {
                    return None; // receiver chains are handled by the caller's graph
                }
            }
            None
        }
        _ => None,
    }
}

fn account_index(ix: &NativeInstruction, name: &str) -> Option<usize> {
    ix.accounts.iter().position(|a| a.name == name)
}

// ── Block scanning: taint propagation + sink detection ───────────────────────

/// Token-CPI accounts-struct shapes whose fields are privileged sinks.
const CPI_SINK_STRUCTS: &[&str] =
    &["Transfer", "TransferChecked", "MintTo", "MintToChecked", "Burn", "BurnChecked", "Approve"];

fn scan_block(block: &syn::Block, ix: &NativeInstruction, state: &mut TaintState, out: &mut Vec<Flow>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    // Bind the local to every account its initializer derives
                    // from — including CANONICAL accounts (`let data =
                    // state.data.borrow_mut()`) — so pollution sinks can
                    // attribute writes back to the trusted account. Unwrap a
                    // type annotation (`let x: T = ...` is `Pat::Type`).
                    let pat = match &l.pat {
                        syn::Pat::Type(pt) => &*pt.pat,
                        p => p,
                    };
                    if let syn::Pat::Ident(pi) = pat {
                        let mut refs = HashSet::new();
                        referenced_accounts(&init.expr, ix, &state.tainted, &mut refs);
                        if !refs.is_empty() {
                            state.bind_ident(&pi.ident.to_string(), &refs);
                        }
                    }
                    scan_expr_sinks(&init.expr, ix, state, out);
                }
            }
            syn::Stmt::Expr(e, _) => scan_expr_sinks(e, ix, state, out),
            syn::Stmt::Macro(m) => {
                for arg in macro_args(&m.mac) {
                    scan_expr_sinks(&arg, ix, state, out);
                }
            }
            syn::Stmt::Item(_) => {}
        }
    }
}

/// Parse a macro body as comma-separated expressions (empty on failure).
fn macro_args(mac: &syn::Macro) -> Vec<Expr> {
    syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
        mac.tokens.clone(),
    )
    .map(|args| args.into_iter().collect())
    .unwrap_or_default()
}

fn scan_expr_sinks(e: &Expr, ix: &NativeInstruction, state: &mut TaintState, out: &mut Vec<Flow>) {
    match e {
        Expr::Struct(s) => {
            let struct_name = s.path.segments.last().map(|seg| seg.ident.to_string()).unwrap_or_default();
            if CPI_SINK_STRUCTS.contains(&struct_name.as_str()) {
                for f in &s.fields {
                    let sources = state.sources_in(&f.expr, ix);
                    if !sources.is_empty() {
                        let field = match &f.member {
                            syn::Member::Named(n) => n.to_string(),
                            syn::Member::Unnamed(i) => i.index.to_string(),
                        };
                        out.push(Flow { sources, kind: SinkKind::TokenCpi, sink: format!("{struct_name}.{field}") });
                    }
                }
            }
            for f in &s.fields {
                scan_expr_sinks(&f.expr, ix, state, out);
            }
        }
        Expr::Call(c) => {
            let callee = match &*c.func {
                Expr::Path(p) => p.path.segments.last().map(|seg| seg.ident.to_string()).unwrap_or_default(),
                _ => String::new(),
            };
            if matches!(callee.as_str(), "invoke" | "invoke_signed" | "invoke_unchecked") {
                let signed = callee == "invoke_signed";
                for (idx, arg) in c.args.iter().enumerate() {
                    // CPI plumbing: idx 0 is the `Instruction`, idx 1 the account
                    // metas (passing accounts is normal, never attacker value).
                    // The only privileged invoke argument is the `invoke_signed`
                    // seed list (idx 2) — a tainted seed is a poisoned PDA.
                    let kind = match (signed, idx) {
                        (_, 1) => continue,
                        (true, 0) => continue,
                        (true, 2) => SinkKind::Seeds,
                        _ => SinkKind::CallArg,
                    };
                    let sources = state.sources_in(arg, ix);
                    if !sources.is_empty() {
                        out.push(Flow { sources, kind, sink: format!("{callee}(...)") });
                    }
                }
            } else if matches!(callee.as_str(), "realloc" | "assign" | "transfer_lamports" | "create_account")
                && c.args.iter().any(|a| !state.sources_in(a, ix).is_empty())
            {
                let mut all = HashSet::new();
                for arg in &c.args {
                    all.extend(state.sources_in(arg, ix));
                }
                let mut v: Vec<usize> = all.into_iter().collect();
                v.sort();
                out.push(Flow { sources: v, kind: SinkKind::CallArg, sink: format!("{callee}(...)") });
            }
            for arg in &c.args {
                scan_expr_sinks(arg, ix, state, out);
            }
        }
        Expr::MethodCall(m) => {
            // `<tainted borrow>[range].copy_from_slice(..)` / `.fill(..)` /
            // `.clone_from_slice(..)` — byte-level state writes.
            if matches!(m.method.to_string().as_str(), "copy_from_slice" | "fill" | "clone_from_slice") {
                // Byte writes into a CANONICAL account's data with
                // attacker-influenced bytes = state pollution.
                if let Some(target) = pollutes_canonical(&m.receiver, ix, &state.tainted, &state.canonical) {
                    let mut value_sources: Vec<usize> = Vec::new();
                    for a in &m.args {
                        let mut s = HashSet::new();
                        collect_sources(a, ix, &state.tainted, &state.sources, &mut s);
                        value_sources.extend(s);
                    }
                    if !value_sources.is_empty() {
                        value_sources.sort();
                        out.push(Flow {
                            sources: value_sources,
                            kind: SinkKind::StateWrite,
                            sink: format!("data write into `{target}`"),
                        });
                    }
                }
            }
            if matches!(m.method.to_string().as_str(), "try_borrow_mut_lamports" | "borrow_mut_lamports") {
                let sources = state.sources_in(&m.receiver, ix);
                if !sources.is_empty() {
                    out.push(Flow { sources, kind: SinkKind::StateWrite, sink: "lamports write".to_string() });
                }
            }
            if m.method == "realloc" {
                let sources = state.sources_in(&m.receiver, ix);
                if !sources.is_empty() {
                    out.push(Flow { sources, kind: SinkKind::StateWrite, sink: "realloc".to_string() });
                }
            }
            scan_expr_sinks(&m.receiver, ix, state, out);
            for arg in &m.args {
                scan_expr_sinks(arg, ix, state, out);
            }
        }
        Expr::Assign(a) => {
            // State-write pollution: attacker-influenced VALUES written into a
            // program-controlled (canonical) account. Writes to unanchored
            // accounts are normal user-state handling and never fire.
            let value_sources = state.sources_in_args(std::slice::from_ref(&a.right), ix);
            if !value_sources.is_empty()
                && let Some(target) = pollutes_canonical(&a.left, ix, &state.tainted, &state.canonical)
            {
                out.push(Flow {
                    sources: value_sources,
                    kind: SinkKind::StateWrite,
                    sink: format!("write into `{target}`"),
                });
            }
            scan_expr_sinks(&a.left, ix, state, out);
            scan_expr_sinks(&a.right, ix, state, out);
        }
        Expr::Binary(b) => {
            scan_expr_sinks(&b.left, ix, state, out);
            scan_expr_sinks(&b.right, ix, state, out);
        }
        Expr::Unary(u) => scan_expr_sinks(&u.expr, ix, state, out),
        Expr::Reference(r) => scan_expr_sinks(&r.expr, ix, state, out),
        Expr::Paren(p) => scan_expr_sinks(&p.expr, ix, state, out),
        Expr::Group(g) => scan_expr_sinks(&g.expr, ix, state, out),
        Expr::Try(t) => scan_expr_sinks(&t.expr, ix, state, out),
        Expr::Cast(c) => scan_expr_sinks(&c.expr, ix, state, out),
        Expr::Block(b) => scan_block(&b.block, ix, state, out),
        Expr::Unsafe(u) => scan_block(&u.block, ix, state, out),
        Expr::If(i) => {
            // Guard conditions bound their operands: a value checked against
            // a threshold/constant here is validated usage.
            let mut refs = HashSet::new();
            collect_sources(&i.cond, ix, &state.tainted, &state.sources, &mut refs);
            state.mark_bounded(&refs);
            scan_expr_sinks(&i.cond, ix, state, out);
            scan_block(&i.then_branch, ix, state, out);
            if let Some((_, else_expr)) = &i.else_branch {
                scan_expr_sinks(else_expr, ix, state, out);
            }
        }
        Expr::While(w) => {
            scan_expr_sinks(&w.cond, ix, state, out);
            scan_block(&w.body, ix, state, out);
        }
        Expr::Loop(l) => scan_block(&l.body, ix, state, out),
        Expr::ForLoop(fl) => scan_block(&fl.body, ix, state, out),
        Expr::Match(m) => {
            scan_expr_sinks(&m.expr, ix, state, out);
            for arm in &m.arms {
                if let Some((_, guard)) = &arm.guard {
                    scan_expr_sinks(guard, ix, state, out);
                }
                scan_expr_sinks(&arm.body, ix, state, out);
            }
        }
        Expr::Index(i) => {
            scan_expr_sinks(&i.expr, ix, state, out);
            scan_expr_sinks(&i.index, ix, state, out);
        }
        Expr::Await(a) => scan_expr_sinks(&a.base, ix, state, out),
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                scan_expr_sinks(x, ix, state, out);
            }
        }
        Expr::Macro(m) => {
            for arg in macro_args(&m.mac) {
                scan_expr_sinks(&arg, ix, state, out);
            }
        }
        _ => {}
    }
}

// ── Rule entry ───────────────────────────────────────────────────────────────

fn location(ix: &NativeInstruction) -> String {
    format!("{}:{} ({})", ix.file, ix.line, ix.name)
}

/// SAT038 for one instruction: collect unanchored→sink flows across the
/// flattened handler + helper blocks, then drop flows whose sources are
/// validated by the anchor model (any anchored comparison touching the
/// source account, or canonical membership).
fn analyze_instruction(
    ix: &NativeInstruction,
    graph: &InstructionGraph,
    state_accounts: &HashSet<usize>,
) -> Vec<Finding> {
    // Program-owned state accounts (`pub state: Account<'info, X>` without
    // seeds) are pollution targets even though SAT031's chain-anchoring
    // canonical set leaves them unanchored. Union them in.
    let mut canonical = graph.canonical.clone();
    canonical.extend(state_accounts.iter().copied());
    let mut state = TaintState::new(ix, &canonical);
    if state.sources.is_empty() {
        return Vec::new();
    }

    let mut flows = Vec::new();

    // Known-validator recognition: external-crate helpers (load_signer,
    // check_admin, …) that prove validation on specific accounts. Sources
    // validated this way are removed from the unanchored source set.
    let validated_by_helpers = crate::native::rules::known_validators::scan_known_validators(&graph.blocks, ix);
    let helper_validated: HashSet<usize> = validated_by_helpers.iter().map(|(_, idx)| *idx).collect();
    state.sources.retain(|i| !helper_validated.contains(i));
    if state.sources.is_empty() {
        return Vec::new();
    }

    for block in &graph.blocks {
        scan_block(block, ix, &mut state, &mut flows);
    }

    // Validation gate: a source account is validated when any comparison in
    // the graph touches it (owner/key/field anchoring) or when the frontend
    // recorded an owner/signer/key check.
    let validated: HashSet<usize> = graph
        .comparisons
        .iter()
        .flat_map(|c| [&c.left_node, &c.right_node].into_iter().flatten().map(|(a, _)| *a).collect::<Vec<_>>())
        .collect();

    let mut seen = HashSet::new();
    let mut findings = Vec::new();
    for flow in flows {
        let live: Vec<usize> =
            flow.sources.iter().copied().filter(|a| !validated.contains(a) && !state.bounded.contains(a)).collect();
        if live.is_empty() {
            continue;
        }
        if !seen.insert((flow.kind as u8, live.clone())) {
            continue;
        }
        let names: Vec<String> = live.iter().map(|a| format!("`{}`", ix.accounts[*a].name)).collect();
        findings.push(Finding {
            id: String::new(),
            title: format!("{SAT038_TITLE} `{}`", ix.accounts[live[0]].name),
            severity: flow.kind.severity(),
            description: format!(
                "Instruction `{}` passes attacker-influenced values derived from {} into {}. \
                 No comparison or guard anywhere in the handler's validation graph anchors these \
                 values to canonical program state, so an attacker can drive privileged behavior \
                 with fabricated inputs. Confirm whether a validation exists outside the analyzed \
                 path before escalating.",
                ix.name,
                names.join(", "),
                flow.kind.describe()
            ),
            location: Some(location(ix)),
            suggestion: Some(format!(
                "Anchor the value before use: compare the source field against a constant / \
                 program id / owner-checked account, or verify the authority signature at the \
                 {} site.",
                flow.sink
            )),
        });
    }

    findings
}

/// SAT038: flag attacker-influenced values flowing into privileged sinks
/// without anchoring validation. Native path plus the Anchor `#[program]`
/// fallback (via [`crate::native::rules::validate::for_each_anchor_instruction`]).
pub fn check(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let index = FnIndex::build(parsed);
    let bundles = Bundles::empty();
    let mut findings = Vec::new();

    for ix in &program.instructions {
        if let Some(graph) = analyze_instruction_graph(ix, &index, &bundles, &[], None, &HashSet::new()) {
            findings.extend(analyze_instruction(ix, &graph, &HashSet::new()));
        }
    }

    // Anchor path: reuse the shared Anchor extraction so bundles, method
    // scope and constant-seed canonical accounts resolve the same way they
    // do for SAT031 (this is what makes Anchor programs analyzable).
    crate::native::rules::validate::for_each_anchor_instruction(
        parsed,
        &mut |ix, bundles, ms, extra, roots, _aa, state_accounts| {
            if let Some(graph) = analyze_instruction_graph(ix, &index, bundles, roots, Some(ms), extra) {
                findings.extend(analyze_instruction(ix, &graph, state_accounts));
            }
        },
    );

    findings
}

// ── Canonical target resolution (state-pollution sinks) ─────────────────────

/// Every resolved account index referenced anywhere in an expression,
/// consulting direct account names and tainted aliases.
fn referenced_accounts(
    e: &Expr,
    ix: &NativeInstruction,
    aliases: &HashMap<String, HashSet<usize>>,
    out: &mut HashSet<usize>,
) {
    match e {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                let ident = ident.to_string();
                if let Some(set) = aliases.get(&ident) {
                    out.extend(set.iter().copied());
                } else if let Some(acc) = account_index(ix, &ident) {
                    out.insert(acc);
                }
            }
        }
        Expr::Field(f) => {
            // `ctx.accounts.<name>` — resolve the inner account name.
            if let Expr::Field(inner) = &*f.base
                && matches!(&*inner.base, Expr::Path(p) if p.path.is_ident("ctx"))
                && matches!(&inner.member, syn::Member::Named(n) if n == "accounts")
                && let syn::Member::Named(name) = &f.member
                && let Some(acc) = account_index(ix, &name.to_string())
            {
                out.insert(acc);
                return;
            }
            referenced_accounts(&f.base, ix, aliases, out);
        }
        Expr::MethodCall(m) => {
            referenced_accounts(&m.receiver, ix, aliases, out);
            for arg in &m.args {
                referenced_accounts(arg, ix, aliases, out);
            }
        }
        Expr::Call(c) => {
            referenced_accounts(&c.func, ix, aliases, out);
            for arg in &c.args {
                referenced_accounts(arg, ix, aliases, out);
            }
        }
        Expr::Index(i) => {
            referenced_accounts(&i.expr, ix, aliases, out);
            referenced_accounts(&i.index, ix, aliases, out);
        }
        Expr::Binary(b) => {
            referenced_accounts(&b.left, ix, aliases, out);
            referenced_accounts(&b.right, ix, aliases, out);
        }
        Expr::Unary(u) => referenced_accounts(&u.expr, ix, aliases, out),
        Expr::Reference(r) => referenced_accounts(&r.expr, ix, aliases, out),
        Expr::Paren(p) => referenced_accounts(&p.expr, ix, aliases, out),
        Expr::Group(g) => referenced_accounts(&g.expr, ix, aliases, out),
        Expr::Try(t) => referenced_accounts(&t.expr, ix, aliases, out),
        Expr::Cast(c2) => referenced_accounts(&c2.expr, ix, aliases, out),
        Expr::Assign(a) => {
            referenced_accounts(&a.left, ix, aliases, out);
            referenced_accounts(&a.right, ix, aliases, out);
        }
        Expr::Tuple(t2) => {
            for el in &t2.elems {
                referenced_accounts(el, ix, aliases, out);
            }
        }
        Expr::Array(a2) => {
            for el in &a2.elems {
                referenced_accounts(el, ix, aliases, out);
            }
        }
        _ => {}
    }
}

/// The write-target expression pollutes a CANONICAL account when any account
/// it references is program-controlled. Returns that account's name.
fn pollutes_canonical(
    left: &Expr,
    ix: &NativeInstruction,
    aliases: &HashMap<String, HashSet<usize>>,
    canonical: &HashSet<usize>,
) -> Option<String> {
    let mut touched = HashSet::new();
    referenced_accounts(left, ix, aliases, &mut touched);
    let hit = touched.iter().copied().find(|i| canonical.contains(i))?;
    Some(ix.accounts[hit].name.clone())
}

// ── Subcommand surface ───────────────────────────────────────────────────────

/// `sat taint <src>`: run the validation-completeness engine standalone and
/// print every unvalidated flow.
pub fn run(src_path: Option<&str>) -> Result<()> {
    use crate::ui;

    ui::print_banner();
    ui::print_section_header("Validation Completeness");

    let output = crate::analyzer::collect(src_path, None, None)?;
    if output.parsed_files.is_empty() {
        anyhow::bail!("No Rust source files found under the given path.");
    }

    // `check` handles both the native model and the Anchor `#[program]`
    // fallback (via the shared Anchor extraction), so an empty native
    // program is fine when the workspace is Anchor-only.
    let program = output.native_program.as_ref().cloned().unwrap_or_default();
    let findings = check(&program, &output.parsed_files);
    if findings.is_empty() {
        ui::print_success("No unvalidated flows detected.");
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
    ui::print_success(&format!("{} unvalidated flow(s) reported.", findings.len()));
    Ok(())
}
