//! Frontend for the native (non-Anchor) Solana backend.
//!
//! Builds the pinned [`NativeProgram`] model (`docs/NATIVE_BACKEND.md`
//! section 5) from raw `syn`-parsed sources:
//!
//! * **Paradigm detection** — `entrypoint!(...)` macro invocation or a
//!   `process_instruction` with the canonical signature (spec section 4).
//! * **Entrypoint discovery** — the handler named by `entrypoint!`, with
//!   `declare_id!("...")` captured as `program_id`.
//! * **Dispatch recovery** — `match instruction_data` / `match
//!   &instruction_data[0..8]` with `[a, b, c, d, e, f, g, h, ..]` byte
//!   patterns, u8 tag matches (`match instruction_data[0]` /
//!   `instruction.tag`-style), and enum-variant matches
//!   (`match instruction { Instruction::Deposit { .. } => ... }`, with
//!   variant → tag mapping recovered from `unpack`/`try_from`/`from`/
//!   `try_from_slice` impls, falling back to borsh declaration order);
//!   the single-callee delegation chain is followed (entrypoint →
//!   `Processor::process`-style impl methods), and when no entrypoint
//!   marker exists at all, dispatch tables embedded in framework macro
//!   invocations (`solitaire!`-class, `Name(DataType) => handler` rows)
//!   are recovered from the macro's tokens.
//! * **Account resolution** — all four strategies from spec section 5:
//!   1. positional iterator (`next_account_info` / `iter.next()` over a
//!      tracked iterator, call order = position);
//!   2. subscript (`accounts[i]` / `&accounts[i..n]` with literal indices);
//!   3. struct `try_from` (`X::try_from(&accounts[..])` — one index per
//!      field in declaration order, field accesses resolved afterwards);
//!   4. helper call graph — helpers taking `&[AccountInfo]`,
//!      `&mut AccountInfoIter`, or `&AccountInfo` are analyzed in call
//!      order, depth ≤ 2, cycle-guarded.
//!      Plus two structural sources: shank `#[account(N, ...)]` attributes on
//!      dispatched enum variants (authoritative positional names with
//!      `account_N` fallbacks, merged with handler guard flags by index) and
//!      `accounts.split_at(N)` tuple destructuring (both halves tracked as
//!      positional slices, continuation across the split).
//! * **Guard flags** — `is_signer` / `.key` / `.owner` member accesses
//!   inside `if`/`while` conditions, `require!`/`assert!`/`invariant!`
//!   macros, and match scrutinees, plus `check_owner`-style helper calls;
//!   write detection via `&mut` borrows and `borrow_mut`/`load_mut`-style
//!   calls; `find_program_address` seeds captured as source text and
//!   associated to accounts via key-equality guards.
//!
//! Unknown or unresolvable constructs are **skipped silently** — the
//! frontend never panics (hard gate: Mango v3 / SPL parse coverage).

use std::collections::{HashMap, HashSet};

use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

use crate::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};

// ── Paradigm detection (spec section 4) ─────────────────────────────────────

/// Whether the file carries a native marker: an `entrypoint!(...)` macro
/// invocation, a `process_instruction` with the canonical signature, or a
/// framework macro invocation (`solitaire!`-class) whose tokens carry a
/// dispatch table.
pub(crate) fn has_native_marker(file: &syn::File) -> bool {
    find_entrypoint_macro(file).is_some()
        || find_process_instruction_fn(file).is_some()
        || find_framework_dispatch(file).is_some()
}

/// `entrypoint!(handler)` macro invocation anywhere in the file (modules
/// included). Returns the handler name and the macro line.
fn find_entrypoint_macro(file: &syn::File) -> Option<(String, usize)> {
    file.items.iter().find_map(entrypoint_in_item)
}

fn entrypoint_in_item(item: &syn::Item) -> Option<(String, usize)> {
    match item {
        syn::Item::Macro(m) => {
            let name = m.mac.path.segments.last().map(|s| s.ident.to_string());
            if name.as_deref() != Some("entrypoint") {
                return None;
            }
            let first = m.mac.tokens.clone().into_iter().next()?;
            let proc_macro2::TokenTree::Ident(handler) = first else { return None };
            Some((handler.to_string(), m.mac.span().start().line))
        }
        syn::Item::Mod(m) => match &m.content {
            Some((_, items)) => items.iter().find_map(entrypoint_in_item),
            None => None,
        },
        _ => None,
    }
}

/// A `process_instruction` function with the canonical signature anywhere in
/// the file. Returns the function name and line.
fn find_process_instruction_fn(file: &syn::File) -> Option<(String, usize)> {
    file.items.iter().find_map(process_instruction_in_item)
}

fn process_instruction_in_item(item: &syn::Item) -> Option<(String, usize)> {
    match item {
        syn::Item::Fn(f) if is_process_instruction_sig(f) => {
            Some((f.sig.ident.to_string(), f.sig.ident.span().start().line))
        }
        syn::Item::Mod(m) => match &m.content {
            Some((_, items)) => items.iter().find_map(process_instruction_in_item),
            None => None,
        },
        _ => None,
    }
}

/// `(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8])`
/// returning `ProgramResult` / `Result<()>`.
fn is_process_instruction_sig(f: &syn::ItemFn) -> bool {
    if f.sig.ident != "process_instruction" {
        return false;
    }
    let inputs: Vec<&syn::PatType> = f
        .sig
        .inputs
        .iter()
        .filter_map(|a| match a {
            syn::FnArg::Typed(t) => Some(t),
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    if inputs.len() != 3 {
        return false;
    }
    let t0 = inputs[0].ty.to_token_stream().to_string();
    let t1 = inputs[1].ty.to_token_stream().to_string();
    let t2 = inputs[2].ty.to_token_stream().to_string();
    if !(t0.contains("Pubkey") && t1.contains("AccountInfo") && t2.contains("[u8]")) {
        return false;
    }
    let ret = f.sig.output.to_token_stream().to_string();
    ret.contains("ProgramResult") || (ret.contains("Result") && ret.contains("()"))
}

/// `declare_id!("...")` literal anywhere in the file (modules included).
fn find_declare_id(file: &syn::File) -> Option<String> {
    file.items.iter().find_map(declare_id_in_item)
}

fn declare_id_in_item(item: &syn::Item) -> Option<String> {
    match item {
        syn::Item::Macro(m) => {
            let name = m.mac.path.segments.last().map(|s| s.ident.to_string());
            if name.as_deref() != Some("declare_id") {
                return None;
            }
            m.mac
                .parse_body_with(|input: syn::parse::ParseStream<'_>| -> syn::Result<syn::LitStr> { input.parse() })
                .ok()
                .map(|lit| lit.value())
        }
        syn::Item::Mod(m) => match &m.content {
            Some((_, items)) => items.iter().find_map(declare_id_in_item),
            None => None,
        },
        _ => None,
    }
}

// ── Framework-macro dispatch recovery (solitaire!-class) ────────────────────

/// Framework macros whose invocation tokens embed a dispatch table of
/// `Name(DataType) => handler_fn` rows. The macro expansion generates the
/// entrypoint and a `#[repr(u8)]` instruction enum with variants in
/// declaration order (borsh tags), so the rows are recoverable without
/// expanding the macro. Extensible: add macro names here.
const FRAMEWORK_DISPATCH_MACROS: [&str; 1] = ["solitaire"];

fn is_framework_dispatch_macro(name: &str) -> bool {
    FRAMEWORK_DISPATCH_MACROS.contains(&name)
}

/// Find a recognized framework-macro invocation with a dispatch-table shape
/// anywhere in the file (modules included). Returns the `(name, handler)`
/// rows and the macro line.
fn find_framework_dispatch(file: &syn::File) -> Option<(Vec<(String, String)>, usize)> {
    file.items.iter().find_map(framework_dispatch_in_item)
}

fn framework_dispatch_in_item(item: &syn::Item) -> Option<(Vec<(String, String)>, usize)> {
    match item {
        syn::Item::Macro(m) => {
            let name = m.mac.path.segments.last().map(|s| s.ident.to_string());
            if !name.as_deref().is_some_and(is_framework_dispatch_macro) {
                return None;
            }
            let rows = macro_dispatch_rows(&m.mac)?;
            Some((rows, m.mac.span().start().line))
        }
        syn::Item::Mod(m) => match &m.content {
            Some((_, items)) => items.iter().find_map(framework_dispatch_in_item),
            None => None,
        },
        _ => None,
    }
}

/// Walk a macro invocation's tokens for `Name(DataType) => handler` pairs
/// (the `solitaire!` dispatch-table shape). `=>` is tokenized as `=` `>`
/// puncts; each row's name and handler are idents, the data type is a
/// parenthesized group. Non-conforming tokens are skipped, so stray
/// punctuation (trailing commas, doc fragments) does not derail recovery.
fn macro_dispatch_rows(mac: &syn::Macro) -> Option<Vec<(String, String)>> {
    use proc_macro2::TokenTree;
    let tokens: Vec<TokenTree> = mac.tokens.clone().into_iter().collect();
    let mut rows = Vec::new();
    let mut i = 0;
    while i + 4 < tokens.len() {
        let name = match &tokens[i] {
            TokenTree::Ident(id) => id.to_string(),
            _ => {
                i += 1;
                continue;
            }
        };
        let data_type_ok = matches!(
            &tokens[i + 1],
            TokenTree::Group(g) if g.delimiter() == proc_macro2::Delimiter::Parenthesis && !g.stream().is_empty()
        );
        let eq = matches!(&tokens[i + 2], TokenTree::Punct(p) if p.as_char() == '=');
        let gt = matches!(&tokens[i + 3], TokenTree::Punct(p) if p.as_char() == '>');
        let handler = match &tokens[i + 4] {
            TokenTree::Ident(id) => id.to_string(),
            _ => String::new(),
        };
        if data_type_ok && eq && gt && !handler.is_empty() {
            rows.push((name, handler));
            i += 5;
        } else {
            i += 1;
        }
    }
    if rows.is_empty() { None } else { Some(rows) }
}

/// Build the pinned program from framework-macro rows: one instruction per
/// row, tag = declaration order (borsh `#[repr(u8)]` enum order). Accounts
/// are deliberately left unresolved — the framework macro peels the account
/// list in its expansion, so resolution is framework-limited.
fn macro_program_from_rows(rows: &[(String, String)], line: usize, file: String) -> NativeProgram {
    let mut program = NativeProgram {
        program_id: None,
        entrypoint_file: file.clone(),
        entrypoint_line: line,
        instructions: Vec::new(),
    };
    for (tag, (name, handler)) in rows.iter().enumerate() {
        program.instructions.push(NativeInstruction {
            name: name.clone(),
            discriminator: Some(vec![tag as u8]),
            handler: handler.clone(),
            file: file.clone(),
            line,
            accounts: Vec::new(),
        });
    }
    program
}

// ── File index ──────────────────────────────────────────────────────────────

/// Free functions and structs collected per parsed file (modules included).
/// Impl members are deliberately excluded — `State::load`-style methods are
/// not part of the helper call graph.
struct FileIndex<'a> {
    files: &'a [(syn::File, String)],
    fns: HashMap<String, Vec<(syn::ItemFn, usize)>>,
    structs: HashMap<String, Vec<(syn::ItemStruct, usize)>>,
    /// Module-level `const NAME = <expr>;` values (literals and simple
    /// arithmetic over other consts, resolved to a fixpoint).
    consts: HashMap<String, u64>,
}

impl<'a> FileIndex<'a> {
    fn build(files: &'a [(syn::File, String)]) -> Self {
        let mut fns: HashMap<String, Vec<(syn::ItemFn, usize)>> = HashMap::new();
        let mut structs: HashMap<String, Vec<(syn::ItemStruct, usize)>> = HashMap::new();
        let mut consts: HashMap<String, u64> = HashMap::new();
        let mut const_exprs: Vec<(String, syn::Expr)> = Vec::new();
        for (i, (file, _)) in files.iter().enumerate() {
            collect_items(&file.items, i, &mut fns, &mut structs, &mut const_exprs);
        }
        for _ in 0..5 {
            let mut changed = false;
            for (name, expr) in const_exprs.iter() {
                if !consts.contains_key(name)
                    && let Some(v) = eval_const_expr(expr, &consts)
                {
                    consts.insert(name.clone(), v);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        FileIndex { files, fns, structs, consts }
    }

    /// Best candidate for `name`: a definition in `prefer_file` if one
    /// exists, otherwise the first definition overall.
    fn lookup_fn(&'a self, name: &str, prefer_file: &str) -> Option<&'a (syn::ItemFn, usize)> {
        let candidates = self.fns.get(name)?;
        candidates.iter().find(|(_, i)| self.files[*i].1 == prefer_file).or_else(|| candidates.first())
    }

    fn lookup_struct(&'a self, name: &str, prefer_file: &str) -> Option<&'a (syn::ItemStruct, usize)> {
        let candidates = self.structs.get(name)?;
        candidates.iter().find(|(_, i)| self.files[*i].1 == prefer_file).or_else(|| candidates.first())
    }
}

fn collect_items(
    items: &[syn::Item],
    file_idx: usize,
    fns: &mut HashMap<String, Vec<(syn::ItemFn, usize)>>,
    structs: &mut HashMap<String, Vec<(syn::ItemStruct, usize)>>,
    const_exprs: &mut Vec<(String, syn::Expr)>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                fns.entry(f.sig.ident.to_string()).or_default().push((f.clone(), file_idx));
            }
            syn::Item::Const(c) => const_exprs.push((c.ident.to_string(), *c.expr.clone())),
            syn::Item::Struct(s) => structs.entry(s.ident.to_string()).or_default().push((s.clone(), file_idx)),
            syn::Item::Impl(imp) => {
                let self_name = match imp.self_ty.as_ref() {
                    syn::Type::Path(tp) => path_ident_str(&tp.path),
                    _ => None,
                };
                // Impl methods are indexed both bare and qualified
                // (`load_mut` and `State::load_mut`) so calls like
                // `State::load_mut(...)` and `Self::handler(...)` resolve.
                for member in &imp.items {
                    if let syn::ImplItem::Fn(f) = member {
                        let fname = f.sig.ident.to_string();
                        let item = syn::ItemFn {
                            attrs: f.attrs.clone(),
                            vis: f.vis.clone(),
                            sig: f.sig.clone(),
                            block: Box::new(f.block.clone()),
                        };
                        fns.entry(fname.clone()).or_default().push((item.clone(), file_idx));
                        if let Some(sn) = &self_name {
                            fns.entry(format!("{sn}::{fname}")).or_default().push((item, file_idx));
                        }
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_items(inner, file_idx, fns, structs, const_exprs);
                }
            }
            _ => {}
        }
    }
}

// ── Dispatch recovery (spec section 5) ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchKind {
    ByteSlice,
    Tag,
    Enum,
}

struct DispatchArm {
    name: String,
    discriminator: Option<Vec<u8>>,
    handler: String,
    line: usize,
    /// Matched enum type name (Enum dispatch only) — enables shank
    /// `#[account(N)]` recovery from the enum variant's attributes.
    enum_name: Option<String>,
}

/// Find the dispatch match in the handler body and recover one arm per
/// resolvable case. Returns `None` when the handler does not dispatch.
fn find_dispatch(f: &syn::ItemFn, files: &[(syn::File, String)]) -> Option<Vec<DispatchArm>> {
    let mut matches = Vec::new();
    walk_matches_in_block(&f.block, &mut matches);
    for m in matches {
        if let Some(arms) = dispatch_arms(&m, files)
            && !arms.is_empty()
        {
            return Some(arms);
        }
    }
    None
}

/// Follow the single-callee delegation chain from the entrypoint handler
/// (e.g. `entrypoint!(process_instruction)` delegating to
/// `Processor::process(...)`) and return the first dispatch match found.
/// Depth ≤ 3, cycle-guarded by function name.
fn follow_dispatch(f: &syn::ItemFn, index: &FileIndex, files: &[(syn::File, String)]) -> Option<Vec<DispatchArm>> {
    let mut seen = HashSet::new();
    let mut current = f;
    for _ in 0..3 {
        if !seen.insert(current.sig.ident.to_string()) {
            return None;
        }
        if let Some(arms) = find_dispatch(current, files)
            && !arms.is_empty()
        {
            return Some(arms);
        }
        let delegates = delegated_callees(current, index);
        if delegates.len() != 1 {
            return None;
        }
        let (next, _) = index.lookup_fn(&delegates[0], "")?;
        current = next;
    }
    None
}

/// Distinct local-function callees called from a body (delegation targets).
fn delegated_callees(f: &syn::ItemFn, index: &FileIndex) -> Vec<String> {
    let mut out = Vec::new();
    collect_callees_in_block(&f.block, index, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_callees_in_block(block: &syn::Block, index: &FileIndex, out: &mut Vec<String>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => collect_callees_in_expr(e, index, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    collect_callees_in_expr(&init.expr, index, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_callees_in_expr(e: &syn::Expr, index: &FileIndex, out: &mut Vec<String>) {
    match e {
        syn::Expr::Call(c) => {
            if let Some(name) = expr_path_name(&c.func)
                && !is_known_builtin(&name)
                && !matches!(name.as_str(), "msg" | "Ok" | "Err")
            {
                let key = callee_key(&c.func).unwrap_or(name);
                let key = key.strip_prefix("Self::").unwrap_or(&key).to_string();
                if index.fns.contains_key(&key) {
                    out.push(key);
                }
            }
            for arg in &c.args {
                collect_callees_in_expr(arg, index, out);
            }
        }
        syn::Expr::MethodCall(m) => {
            collect_callees_in_expr(&m.receiver, index, out);
            for arg in &m.args {
                collect_callees_in_expr(arg, index, out);
            }
        }
        syn::Expr::Block(b) => collect_callees_in_block(&b.block, index, out),
        syn::Expr::If(i) => {
            collect_callees_in_expr(&i.cond, index, out);
            collect_callees_in_block(&i.then_branch, index, out);
            if let Some((_, else_expr)) = &i.else_branch {
                collect_callees_in_expr(else_expr, index, out);
            }
        }
        syn::Expr::While(w) => {
            collect_callees_in_expr(&w.cond, index, out);
            collect_callees_in_block(&w.body, index, out);
        }
        syn::Expr::Loop(l) => collect_callees_in_block(&l.body, index, out),
        syn::Expr::ForLoop(fl) => collect_callees_in_block(&fl.body, index, out),
        syn::Expr::Try(t) => collect_callees_in_expr(&t.expr, index, out),
        syn::Expr::Let(l) => collect_callees_in_expr(&l.expr, index, out),
        syn::Expr::Paren(p) => collect_callees_in_expr(&p.expr, index, out),
        syn::Expr::Reference(r) => collect_callees_in_expr(&r.expr, index, out),
        syn::Expr::Binary(b) => {
            collect_callees_in_expr(&b.left, index, out);
            collect_callees_in_expr(&b.right, index, out);
        }
        syn::Expr::Unary(u) => collect_callees_in_expr(&u.expr, index, out),
        syn::Expr::Assign(a) => {
            collect_callees_in_expr(&a.left, index, out);
            collect_callees_in_expr(&a.right, index, out);
        }
        syn::Expr::Return(r) => {
            if let Some(x) = &r.expr {
                collect_callees_in_expr(x, index, out);
            }
        }
        syn::Expr::Index(i) => {
            collect_callees_in_expr(&i.expr, index, out);
            collect_callees_in_expr(&i.index, index, out);
        }
        syn::Expr::Field(f) => collect_callees_in_expr(&f.base, index, out),
        syn::Expr::Tuple(t) => {
            for x in &t.elems {
                collect_callees_in_expr(x, index, out);
            }
        }
        syn::Expr::Array(a) => {
            for x in &a.elems {
                collect_callees_in_expr(x, index, out);
            }
        }
        syn::Expr::Repeat(r) => {
            collect_callees_in_expr(&r.expr, index, out);
            collect_callees_in_expr(&r.len, index, out);
        }
        syn::Expr::Struct(s) => {
            for field in &s.fields {
                collect_callees_in_expr(&field.expr, index, out);
            }
        }
        syn::Expr::Closure(c) => collect_callees_in_expr(&c.body, index, out),
        syn::Expr::Cast(c) => collect_callees_in_expr(&c.expr, index, out),
        syn::Expr::Range(r) => {
            if let Some(start) = &r.start {
                collect_callees_in_expr(start, index, out);
            }
            if let Some(end) = &r.end {
                collect_callees_in_expr(end, index, out);
            }
        }
        syn::Expr::Async(a) => collect_callees_in_block(&a.block, index, out),
        syn::Expr::Group(g) => collect_callees_in_expr(&g.expr, index, out),
        syn::Expr::Break(b) => {
            if let Some(x) = &b.expr {
                collect_callees_in_expr(x, index, out);
            }
        }
        _ => {}
    }
}

fn dispatch_arms(m: &syn::ExprMatch, files: &[(syn::File, String)]) -> Option<Vec<DispatchArm>> {
    let kind = classify_match(m)?;
    let mut arms = Vec::new();
    match kind {
        DispatchKind::ByteSlice => {
            for arm in &m.arms {
                if let Some(a) = arm_from_slice(arm) {
                    arms.push(a);
                }
            }
        }
        DispatchKind::Tag => {
            for arm in &m.arms {
                if let Some(a) = arm_from_tag(arm) {
                    arms.push(a);
                }
            }
        }
        DispatchKind::Enum => {
            let enum_name = enum_name_from_arms(&m.arms)?;
            let tags = find_variant_tags(files, &enum_name);
            for arm in &m.arms {
                if let Some(a) = arm_from_enum(arm, &tags) {
                    arms.push(DispatchArm { enum_name: Some(enum_name.clone()), ..a });
                }
            }
        }
    }
    Some(arms)
}

fn classify_match(m: &syn::ExprMatch) -> Option<DispatchKind> {
    let first_arm = m.arms.iter().find(|a| !matches!(a.pat, syn::Pat::Wild(_)))?;
    match &first_arm.pat {
        syn::Pat::Slice(_) if is_instruction_data_scrutinee(&m.expr) => Some(DispatchKind::ByteSlice),
        syn::Pat::Lit(_) if is_tag_scrutinee(&m.expr) => Some(DispatchKind::Tag),
        _ => {
            if let Some(path) = pat_path(&first_arm.pat)
                && path.segments.len() >= 2
                && is_enum_scrutinee(&m.expr)
            {
                Some(DispatchKind::Enum)
            } else {
                None
            }
        }
    }
}

fn is_instruction_data_scrutinee(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Path(p) => path_ident_str(&p.path).is_some_and(|n| is_data_name(&n)),
        syn::Expr::Index(i) => expr_path_name(&i.expr).is_some_and(|n| is_data_name(&n)),
        syn::Expr::Reference(r) => is_instruction_data_scrutinee(&r.expr),
        syn::Expr::Paren(p) => is_instruction_data_scrutinee(&p.expr),
        _ => false,
    }
}

fn is_tag_scrutinee(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Index(i) => expr_path_name(&i.expr).is_some_and(|n| is_data_name(&n)),
        syn::Expr::Field(f) => member_ident(&f.member).is_some_and(|m| m == "tag"),
        syn::Expr::Path(p) => path_ident_str(&p.path).is_some_and(|n| n == "tag" || is_data_name(&n)),
        syn::Expr::Reference(r) => is_tag_scrutinee(&r.expr),
        syn::Expr::Paren(p) => is_tag_scrutinee(&p.expr),
        _ => false,
    }
}

fn is_enum_scrutinee(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Path(_) | syn::Expr::Field(_) => true,
        syn::Expr::Reference(r) => is_enum_scrutinee(&r.expr),
        syn::Expr::Paren(p) => is_enum_scrutinee(&p.expr),
        _ => false,
    }
}

fn is_data_name(name: &str) -> bool {
    matches!(name, "instruction_data" | "data" | "ix_data" | "input" | "ix")
}

/// Byte-slice arm: `[a, b, c, d, e, f, g, h, ..]` or a literal byte prefix.
fn arm_from_slice(arm: &syn::Arm) -> Option<DispatchArm> {
    let syn::Pat::Slice(ps) = &arm.pat else { return None };
    let mut bytes: Vec<u8> = Vec::new();
    for elem in ps.elems.iter().take(8) {
        if let syn::Pat::Lit(pl) = elem {
            match &pl.lit {
                syn::Lit::Byte(b) => bytes.push(b.value()),
                syn::Lit::Int(i) => {
                    if let Some(v) = int_lit_value(i)
                        && v <= 255
                    {
                        bytes.push(v as u8);
                    }
                }
                _ => {}
            }
        }
    }
    let handler = arm_handler(&arm.body);
    let name = match &handler {
        Some(h) => h.clone(),
        None => {
            if bytes.is_empty() {
                return None;
            }
            format!("instruction_0x{}", hex_bytes(&bytes))
        }
    };
    let discriminator = if bytes.is_empty() { None } else { Some(bytes) };
    Some(DispatchArm {
        name,
        discriminator,
        handler: handler.unwrap_or_default(),
        line: arm.span().start().line,
        enum_name: None,
    })
}

/// u8 tag arm: `0 => handler(...)`. Name falls back to `instruction_0x<tag>`.
fn arm_from_tag(arm: &syn::Arm) -> Option<DispatchArm> {
    let syn::Pat::Lit(pl) = &arm.pat else { return None };
    let tag: u8 = match &pl.lit {
        syn::Lit::Byte(b) => b.value(),
        syn::Lit::Int(i) => int_lit_value(i)?.try_into().ok()?,
        _ => return None,
    };
    let handler = arm_handler(&arm.body).unwrap_or_default();
    Some(DispatchArm {
        name: format!("instruction_0x{tag:02x}"),
        discriminator: Some(vec![tag]),
        handler,
        line: arm.span().start().line,
        enum_name: None,
    })
}

/// Enum-variant arm: `Instruction::Deposit { .. } => handler(...)`.
fn arm_from_enum(arm: &syn::Arm, variant_tags: &HashMap<String, u8>) -> Option<DispatchArm> {
    let path = pat_path(&arm.pat)?;
    let variant = path_ident_str(path)?;
    let discriminator = variant_tags.get(&variant).map(|tag| vec![*tag]);
    let handler = arm_handler(&arm.body).unwrap_or_default();
    Some(DispatchArm { name: variant, discriminator, handler, line: arm.span().start().line, enum_name: None })
}

fn enum_name_from_arms(arms: &[syn::Arm]) -> Option<String> {
    for arm in arms {
        let Some(path) = pat_path(&arm.pat) else { continue };
        if path.segments.len() >= 2 {
            return path.segments.first().map(|s| s.ident.to_string());
        }
    }
    None
}

/// Variant → u8 tag mapping recovered from `unpack`/`try_from`/`from`/
/// `try_from_slice` functions inside `impl <EnumName>` blocks, falling back
/// to borsh declaration order when no manual decoder exists in the source.
fn find_variant_tags(files: &[(syn::File, String)], enum_name: &str) -> HashMap<String, u8> {
    let mut tags = HashMap::new();
    for (file, _) in files {
        for item in &file.items {
            let syn::Item::Impl(imp) = item else { continue };
            let syn::Type::Path(tp) = imp.self_ty.as_ref() else { continue };
            if path_ident_str(&tp.path).as_deref() != Some(enum_name) {
                continue;
            }
            for member in &imp.items {
                let syn::ImplItem::Fn(f) = member else { continue };
                if !matches!(
                    f.sig.ident.to_string().as_str(),
                    "unpack" | "try_from" | "from" | "try_from_slice" | "try_from_slice_unchecked"
                ) {
                    continue;
                }
                let mut matches = Vec::new();
                walk_matches_in_block(&f.block, &mut matches);
                for m in matches {
                    for arm in &m.arms {
                        let syn::Pat::Lit(pl) = &arm.pat else { continue };
                        let tag: u8 = match &pl.lit {
                            syn::Lit::Byte(b) => b.value(),
                            syn::Lit::Int(i) => {
                                let Some(v) = int_lit_value(i) else { continue };
                                let Ok(v) = u8::try_from(v) else { continue };
                                v
                            }
                            _ => continue,
                        };
                        if let Some(variant) = variant_from_construct(&arm.body) {
                            tags.entry(variant).or_insert(tag);
                        }
                    }
                }
            }
        }
    }
    if tags.is_empty() {
        // Borsh-derive fallback: `#[derive(BorshDeserialize)]` generates a
        // `try_from_slice` that reads the variant tag as the declaration
        // index (u8, borsh order) — the same order shank instruction
        // builders and `#[repr(u8)]` solitaire-style enums rely on. Applies
        // when no manual decoder impl exists in the workspace (SDI,
        // jito-sdk enum dispatch, etc.).
        for (file, _) in files {
            for item in &file.items {
                let syn::Item::Enum(en) = item else { continue };
                if en.ident != enum_name {
                    continue;
                }
                for (idx, variant) in en.variants.iter().enumerate() {
                    tags.entry(variant.ident.to_string()).or_insert(idx as u8);
                }
            }
        }
    }
    tags
}

fn variant_from_construct(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => {
            if p.path.segments.len() < 2 {
                return None;
            }
            path_ident_str(&p.path)
        }
        syn::Expr::Struct(s) => {
            if s.path.segments.len() < 2 {
                return None;
            }
            path_ident_str(&s.path)
        }
        syn::Expr::Call(c) => {
            if expr_path_name(&c.func).is_some_and(|n| n == "Ok" || n == "Err") {
                c.args.first().and_then(variant_from_construct)
            } else {
                variant_from_construct(&c.func)
            }
        }
        syn::Expr::Block(b) => {
            let syn::Stmt::Expr(e, _) = b.block.stmts.last()? else { return None };
            variant_from_construct(e)
        }
        syn::Expr::Try(t) => variant_from_construct(&t.expr),
        syn::Expr::Paren(p) => variant_from_construct(&p.expr),
        _ => None,
    }
}

/// Handler function name called from an arm body, if any.
fn arm_handler(body: &syn::Expr) -> Option<String> {
    match body {
        syn::Expr::Call(c) => callee_name(&c.func),
        syn::Expr::Block(b) => first_call_in_block(&b.block),
        syn::Expr::Return(r) => r.expr.as_deref().and_then(arm_handler),
        syn::Expr::Paren(p) => arm_handler(&p.expr),
        syn::Expr::Try(t) => arm_handler(&t.expr),
        _ => None,
    }
}

fn callee_name(e: &syn::Expr) -> Option<String> {
    let name = expr_path_name(e)?;
    if matches!(name.as_str(), "Ok" | "Err" | "try_from" | "TryFrom" | "unpack") { None } else { Some(name) }
}

fn first_call_in_block(block: &syn::Block) -> Option<String> {
    for stmt in &block.stmts {
        let call = match stmt {
            syn::Stmt::Expr(e, _) => arm_handler(e),
            syn::Stmt::Local(l) => l.init.as_ref().and_then(|i| arm_handler(&i.expr)),
            _ => None,
        };
        if call.is_some() {
            return call;
        }
    }
    None
}

fn walk_matches_in_block(block: &syn::Block, out: &mut Vec<syn::ExprMatch>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(e, _) => walk_matches_in_expr(e, out),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    walk_matches_in_expr(&init.expr, out);
                }
            }
            _ => {}
        }
    }
}

fn walk_matches_in_expr(e: &syn::Expr, out: &mut Vec<syn::ExprMatch>) {
    match e {
        syn::Expr::Match(m) => {
            out.push(m.clone());
            for arm in &m.arms {
                walk_matches_in_expr(&arm.body, out);
            }
        }
        syn::Expr::Block(b) => walk_matches_in_block(&b.block, out),
        syn::Expr::If(i) => {
            walk_matches_in_expr(&i.cond, out);
            walk_matches_in_block(&i.then_branch, out);
            if let Some((_, else_expr)) = &i.else_branch {
                walk_matches_in_expr(else_expr, out);
            }
        }
        syn::Expr::While(w) => {
            walk_matches_in_expr(&w.cond, out);
            walk_matches_in_block(&w.body, out);
        }
        syn::Expr::Loop(l) => walk_matches_in_block(&l.body, out),
        syn::Expr::ForLoop(fl) => walk_matches_in_block(&fl.body, out),
        syn::Expr::Call(c) => {
            for arg in &c.args {
                walk_matches_in_expr(arg, out);
            }
        }
        syn::Expr::MethodCall(m) => {
            walk_matches_in_expr(&m.receiver, out);
            for arg in &m.args {
                walk_matches_in_expr(arg, out);
            }
        }
        syn::Expr::Try(t) => walk_matches_in_expr(&t.expr, out),
        syn::Expr::Let(l) => walk_matches_in_expr(&l.expr, out),
        syn::Expr::Paren(p) => walk_matches_in_expr(&p.expr, out),
        syn::Expr::Reference(r) => walk_matches_in_expr(&r.expr, out),
        syn::Expr::Binary(b) => {
            walk_matches_in_expr(&b.left, out);
            walk_matches_in_expr(&b.right, out);
        }
        syn::Expr::Unary(u) => walk_matches_in_expr(&u.expr, out),
        syn::Expr::Assign(a) => {
            walk_matches_in_expr(&a.left, out);
            walk_matches_in_expr(&a.right, out);
        }
        syn::Expr::Return(r) => {
            if let Some(x) = &r.expr {
                walk_matches_in_expr(x, out);
            }
        }
        syn::Expr::Index(i) => {
            walk_matches_in_expr(&i.expr, out);
            walk_matches_in_expr(&i.index, out);
        }
        syn::Expr::Field(f) => walk_matches_in_expr(&f.base, out),
        syn::Expr::Tuple(t) => {
            for x in &t.elems {
                walk_matches_in_expr(x, out);
            }
        }
        syn::Expr::Array(a) => {
            for x in &a.elems {
                walk_matches_in_expr(x, out);
            }
        }
        syn::Expr::Repeat(r) => {
            walk_matches_in_expr(&r.expr, out);
            walk_matches_in_expr(&r.len, out);
        }
        syn::Expr::Struct(s) => {
            for field in &s.fields {
                walk_matches_in_expr(&field.expr, out);
            }
        }
        syn::Expr::Closure(c) => walk_matches_in_expr(&c.body, out),
        syn::Expr::Cast(c) => walk_matches_in_expr(&c.expr, out),
        syn::Expr::Range(r) => {
            if let Some(start) = &r.start {
                walk_matches_in_expr(start, out);
            }
            if let Some(end) = &r.end {
                walk_matches_in_expr(end, out);
            }
        }
        syn::Expr::Async(a) => walk_matches_in_block(&a.block, out),
        syn::Expr::Group(g) => walk_matches_in_expr(&g.expr, out),
        syn::Expr::Break(b) => {
            if let Some(x) = &b.expr {
                walk_matches_in_expr(x, out);
            }
        }
        _ => {}
    }
}

// ── Account resolution (spec section 5) ─────────────────────────────────────

/// First-parameter classification for helper analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamKind {
    Slice,
    Iterator,
    SingleAccount,
    Other,
}

fn classify_param(ty: &syn::Type) -> ParamKind {
    let mut t = ty;
    while let syn::Type::Reference(r) = t {
        t = &r.elem;
    }
    match t {
        syn::Type::Slice(_) => ParamKind::Slice,
        syn::Type::Path(p) => {
            let s = p.to_token_stream().to_string();
            if s.contains("Vec") && s.contains("AccountInfo") {
                ParamKind::Slice
            } else if s.contains("AccountInfoIter") || (s.contains("Iter") && s.contains("AccountInfo")) {
                ParamKind::Iterator
            } else if s.contains("AccountInfo") {
                ParamKind::SingleAccount
            } else {
                ParamKind::Other
            }
        }
        _ => ParamKind::Other,
    }
}

#[derive(Debug, Clone, Copy)]
enum RangeStart {
    Literal(usize),
    Current,
}

/// Per-instruction resolution state. One instance per instruction; the
/// account table is emitted sorted by position at the end.
struct ResolutionState<'a> {
    index: &'a FileIndex<'a>,
    files: &'a [(syn::File, String)],
    table: HashMap<usize, ResolvedAccount>,
    next_index: usize,
    /// Positional base for the currently analyzed function's slice.
    base: usize,
    /// Name of the current function's `&[AccountInfo]` parameter.
    accounts_param: Option<String>,
    /// Tracked iterators / slices → next unconsumed position.
    slices: HashMap<String, usize>,
    /// Variable name → account index.
    named: HashMap<String, usize>,
    /// Struct `try_from` variable → field name → account index.
    struct_vars: HashMap<String, HashMap<String, usize>>,
    /// `find_program_address` result variable → seed expressions.
    pda_vars: HashMap<String, Vec<String>>,
    /// `const NAME: usize = <lit>;` values from the current function.
    consts: HashMap<String, u64>,
    current_file: String,
    /// Helper call depth (handler = 0, helpers ≤ 2).
    depth: usize,
    /// Helper cycle guard.
    visited: HashSet<String>,
}

impl<'a> ResolutionState<'a> {
    fn new(index: &'a FileIndex<'a>, files: &'a [(syn::File, String)]) -> Self {
        ResolutionState {
            index,
            files,
            table: HashMap::new(),
            next_index: 0,
            base: 0,
            accounts_param: None,
            slices: HashMap::new(),
            named: HashMap::new(),
            struct_vars: HashMap::new(),
            pda_vars: HashMap::new(),
            consts: index.consts.clone(),
            current_file: String::new(),
            depth: 0,
            visited: HashSet::new(),
        }
    }

    fn ensure(&mut self, idx: usize) -> &mut ResolvedAccount {
        self.table.entry(idx).or_insert_with(|| ResolvedAccount {
            name: format!("account_{idx}"),
            index: idx,
            kind: AccountKind::Unchecked,
            is_signer_checked: false,
            owner_checked: false,
            key_checked: false,
            written: false,
            seeds: Vec::new(),
            is_pda: false,
        })
    }

    /// Bind a variable to the account at `idx`, applying kind inference.
    fn bind(&mut self, name: &str, idx: usize, kind: Option<AccountKind>) {
        let entry = self.ensure(idx);
        if entry.name == format!("account_{idx}") {
            entry.name = name.to_string();
        }
        let inferred = kind.unwrap_or_else(|| kind_from_name(name));
        if entry.kind == AccountKind::Unchecked && inferred != AccountKind::Unchecked {
            entry.kind = inferred;
        }
        self.named.insert(name.to_string(), idx);
        self.next_index = self.next_index.max(idx + 1);
    }

    /// Bind a struct-field account (not reachable by bare variable name).
    fn bind_field(&mut self, name: &str, idx: usize, kind: AccountKind) {
        let entry = self.ensure(idx);
        if entry.name == format!("account_{idx}") {
            entry.name = name.to_string();
        }
        let inferred = if kind == AccountKind::Unchecked { kind_from_name(name) } else { kind };
        if entry.kind == AccountKind::Unchecked && inferred != AccountKind::Unchecked {
            entry.kind = inferred;
        }
    }

    fn set_signer_checked(&mut self, idx: usize) {
        self.ensure(idx).is_signer_checked = true;
    }

    fn set_owner_checked(&mut self, idx: usize) {
        self.ensure(idx).owner_checked = true;
    }

    fn set_key_checked(&mut self, idx: usize) {
        self.ensure(idx).key_checked = true;
    }

    fn set_written(&mut self, idx: usize) {
        self.ensure(idx).written = true;
    }

    fn set_pda(&mut self, idx: usize, seeds: &[String]) {
        let entry = self.ensure(idx);
        entry.is_pda = true;
        for seed in seeds {
            if !entry.seeds.contains(seed) {
                entry.seeds.push(seed.clone());
            }
        }
    }

    /// Consume one position from the given iterator ("" = the current
    /// function's inline `accounts.iter()`), returning its index.
    fn consume(&mut self, iter: &str) -> usize {
        let idx = if iter.is_empty() { self.base } else { self.slices.get(iter).copied().unwrap_or(self.base) };
        self.ensure(idx);
        if !iter.is_empty() {
            self.slices.insert(iter.to_string(), idx + 1);
        }
        self.base = self.base.max(idx + 1);
        self.next_index = self.next_index.max(idx + 1);
        idx
    }

    /// Emit the account table as a Vec ordered by position, filling gaps.
    fn finish_accounts(&mut self) -> Vec<ResolvedAccount> {
        if let Some(max) = self.table.keys().copied().max() {
            for i in 0..=max {
                self.ensure(i);
            }
        }
        let mut accounts: Vec<ResolvedAccount> = self.table.drain().map(|(_, a)| a).collect();
        accounts.sort_by_key(|a| a.index);
        accounts
    }

    fn resolve_block(&mut self, block: &syn::Block) {
        for stmt in &block.stmts {
            match stmt {
                syn::Stmt::Local(local) => self.resolve_local(local),
                syn::Stmt::Expr(e, _) => self.walk_expr(e),
                syn::Stmt::Macro(sm) => self.walk_guard_macro(&sm.mac),
                syn::Stmt::Item(syn::Item::Const(c)) => {
                    if let Some(v) = const_value(c) {
                        self.consts.insert(c.ident.to_string(), v);
                    }
                }
                syn::Stmt::Item(_) => {}
            }
        }
    }

    fn resolve_local(&mut self, local: &syn::Local) {
        let Some(init) = local.init.as_ref().map(|i| i.expr.as_ref()) else { return };

        if let Some(seeds) = find_pda_call(init) {
            let var = tuple_first_ident(&local.pat).or_else(|| pat_ident(&local.pat));
            if let Some(var) = var {
                self.pda_vars.insert(var, seeds);
            }
            return;
        }

        // `let [a, b, ..] = accounts;` slice destructuring (Mango/SPL style):
        // bind each named element to its positional index.
        if let syn::Pat::Slice(ps) = &local.pat
            && let Some(base) = self.slice_binding_base(init)
        {
            let mut count = 0usize;
            for elem in &ps.elems {
                match elem {
                    syn::Pat::Ident(pi) => {
                        self.bind(&pi.ident.to_string(), base + count, None);
                        count += 1;
                    }
                    syn::Pat::Wild(_) => count += 1,
                    syn::Pat::Rest(_) => break,
                    _ => return,
                }
            }
            let end = base + count;
            self.base = self.base.max(end);
            self.next_index = self.next_index.max(end);
            return;
        }

        // `let (fixed_ais, open_orders_ais) = array_refs![accounts, N, M];`
        // window split (Mango style): track each window as a slice variable.
        if let syn::Pat::Tuple(tp) = &local.pat
            && let Some(sizes) = self.array_refs_windows(init)
        {
            let mut start = self.base;
            for (elem, size) in tp.elems.iter().zip(sizes.iter()) {
                if let syn::Pat::Ident(pi) = elem {
                    self.slices.insert(pi.ident.to_string(), start);
                }
                start += *size as usize;
            }
            return;
        }

        // `let (required, optional) = accounts.split_at(N);` (Jito style):
        // track both halves as positional slices — the fixed head starts at
        // the current position and the tail continues after the split, so a
        // later `let [a, b, ..] = required` / `optional.first()` keeps the
        // account index sequence unbroken.
        if let syn::Pat::Tuple(tp) = &local.pat
            && let Some((first, second)) = self.split_at_slices(init)
        {
            let mut elems = tp.elems.iter();
            if let Some(syn::Pat::Ident(pi)) = elems.next() {
                self.slices.insert(pi.ident.to_string(), first);
            }
            if let Some(syn::Pat::Ident(pi)) = elems.next() {
                self.slices.insert(pi.ident.to_string(), second);
            }
            self.base = self.base.max(second);
            self.next_index = self.next_index.max(second);
            return;
        }

        let Some(name) = pat_ident(&local.pat) else {
            self.walk_expr(init);
            return;
        };

        if let Some((idx, written)) = subscript_index(init, &self.accounts_param) {
            self.bind(&name, idx, None);
            if written {
                self.set_written(idx);
            }
            return;
        }

        if let Some(start) = range_slice(init, &self.accounts_param) {
            let pos = match start {
                RangeStart::Literal(i) => i,
                RangeStart::Current => self.base,
            };
            self.slices.insert(name.clone(), pos);
            return;
        }

        if self.is_iter_init(init) {
            self.slices.insert(name.clone(), self.base);
            return;
        }

        if let Some(struct_name) = try_from_call(init) {
            self.bind_struct(&name, &struct_name);
            return;
        }

        if let Some(iter) = scan_consumption(init) {
            let idx = self.consume(&iter);
            self.bind(&name, idx, None);
            return;
        }

        self.walk_expr(init);
    }

    fn bind_struct(&mut self, var: &str, struct_name: &str) {
        let found = {
            let idx = self.index;
            let current = self.current_file.clone();
            idx.lookup_struct(struct_name, &current)
        };
        let Some((s, _)) = found else { return };
        let start = self.next_index;
        let mut field_map = HashMap::new();
        for (k, field) in s.fields.iter().enumerate() {
            let idx = start + k;
            let fname = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_else(|| format!("account_{idx}"));
            let kind = kind_from_type(&field.ty);
            self.bind_field(&fname, idx, kind);
            field_map.insert(fname, idx);
        }
        self.struct_vars.insert(var.to_string(), field_map);
        self.next_index = start + s.fields.len();
        self.base = self.base.max(self.next_index);
    }

    fn walk_expr(&mut self, e: &syn::Expr) {
        match e {
            syn::Expr::Try(t) => self.walk_expr(&t.expr),
            syn::Expr::Paren(p) => self.walk_expr(&p.expr),
            syn::Expr::Group(g) => self.walk_expr(&g.expr),
            syn::Expr::Reference(r) => {
                if r.mutability.is_some()
                    && let Some(idx) = self.resolve_account_expr(&r.expr)
                {
                    self.set_written(idx);
                }
                self.walk_expr(&r.expr);
            }
            syn::Expr::Call(c) => {
                let callee = expr_path_name(&c.func);
                if let Some(name) = &callee {
                    if is_owner_check_call(name)
                        && let Some(idx) = c.args.first().and_then(|a| self.resolve_account_expr(a))
                    {
                        self.set_owner_checked(idx);
                    }
                    if name == "next_account_info" {
                        let iter = c.args.first().and_then(iterator_var).unwrap_or_default();
                        self.consume(&iter);
                    }
                    if (name.contains("load_mut") || name.ends_with("unpack_mut"))
                        && let Some(idx) = c.args.first().and_then(|a| self.resolve_account_expr(a))
                    {
                        self.set_written(idx);
                    }
                    if self.depth < 2 && !is_known_builtin(name) {
                        let key = callee_key(&c.func).unwrap_or_else(|| name.clone());
                        let key = key.strip_prefix("Self::").unwrap_or(&key).to_string();
                        let found = {
                            let idx = self.index;
                            let current = self.current_file.clone();
                            idx.lookup_fn(&key, &current)
                        };
                        if let Some((f, file_idx)) = found {
                            let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
                            self.analyze_helper(f, *file_idx, &args);
                        }
                    }
                }
                for arg in &c.args {
                    self.walk_expr(arg);
                }
            }
            syn::Expr::MethodCall(m) => {
                let mname = m.method.to_string();
                if matches!(
                    mname.as_str(),
                    "borrow_mut" | "try_borrow_mut" | "try_from_slice_mut" | "unpack_mut" | "realloc"
                ) && let Some(idx) = self.resolve_account_expr(&m.receiver)
                {
                    self.set_written(idx);
                }
                if m.method == "next"
                    && let Some(iter) = iterator_var(&m.receiver)
                {
                    self.consume(&iter);
                }
                if m.method == "first"
                    && let Some(iter) = iterator_var(&m.receiver)
                    && !iter.is_empty()
                    && self.slices.contains_key(&iter)
                {
                    // `optional_accounts.first()` style peek over a tracked
                    // slice (Jito `split_at` tail) — one positional account.
                    self.consume(&iter);
                }
                self.walk_expr(&m.receiver);
                for arg in &m.args {
                    self.walk_expr(arg);
                }
            }
            syn::Expr::Index(i) => {
                self.walk_expr(&i.expr);
                self.walk_expr(&i.index);
            }
            syn::Expr::Field(f) => self.walk_expr(&f.base),
            syn::Expr::Binary(b) => {
                self.walk_expr(&b.left);
                self.walk_expr(&b.right);
            }
            syn::Expr::Assign(a) => {
                self.walk_expr(&a.left);
                self.walk_expr(&a.right);
            }
            syn::Expr::Unary(u) => self.walk_expr(&u.expr),
            syn::Expr::Cast(c) => self.walk_expr(&c.expr),
            syn::Expr::Range(r) => {
                if let Some(start) = &r.start {
                    self.walk_expr(start);
                }
                if let Some(end) = &r.end {
                    self.walk_expr(end);
                }
            }
            syn::Expr::Tuple(t) => {
                for el in &t.elems {
                    self.walk_expr(el);
                }
            }
            syn::Expr::Array(a) => {
                for el in &a.elems {
                    self.walk_expr(el);
                }
            }
            syn::Expr::Repeat(r) => {
                self.walk_expr(&r.expr);
                self.walk_expr(&r.len);
            }
            syn::Expr::Struct(s) => {
                for field in &s.fields {
                    self.walk_expr(&field.expr);
                }
            }
            syn::Expr::Closure(c) => self.walk_expr(&c.body),
            syn::Expr::Block(b) => self.resolve_block(&b.block),
            syn::Expr::If(i) => {
                self.walk_guard_cond(&i.cond);
                self.resolve_block(&i.then_branch);
                if let Some((_, else_expr)) = &i.else_branch {
                    self.walk_expr(else_expr);
                }
            }
            syn::Expr::While(w) => {
                self.walk_guard_cond(&w.cond);
                self.resolve_block(&w.body);
            }
            syn::Expr::Loop(l) => self.resolve_block(&l.body),
            syn::Expr::ForLoop(fl) => self.resolve_block(&fl.body),
            syn::Expr::Match(m) => {
                self.walk_guard_cond(&m.expr);
                if !is_dispatch_scrutinee(&m.expr) {
                    for arm in &m.arms {
                        if let Some((_, guard)) = &arm.guard {
                            self.walk_guard_cond(guard);
                        }
                        self.walk_expr(&arm.body);
                    }
                }
            }
            syn::Expr::Macro(mac) => self.walk_guard_macro(&mac.mac),
            syn::Expr::Return(r) => {
                if let Some(x) = &r.expr {
                    self.walk_expr(x);
                }
            }
            syn::Expr::Break(b) => {
                if let Some(x) = &b.expr {
                    self.walk_expr(x);
                }
            }
            syn::Expr::Async(a) => self.resolve_block(&a.block),
            syn::Expr::Let(l) => self.walk_expr(&l.expr),
            syn::Expr::Path(_) | syn::Expr::Lit(_) => {}
            _ => {}
        }
    }

    /// Walk a guard context (if/while condition, require!/assert!/invariant!
    /// args, match scrutinee, arm guard) and mark reachable checks.
    fn walk_guard_cond(&mut self, e: &syn::Expr) {
        match e {
            syn::Expr::Binary(b) => {
                let left = side_info(&b.left, self);
                let right = side_info(&b.right, self);
                if left.1
                    && let Some(li) = left.0
                    && let Some(seeds) = &right.2
                {
                    self.set_pda(li, seeds);
                }
                if right.1
                    && let Some(ri) = right.0
                    && let Some(seeds) = &left.2
                {
                    self.set_pda(ri, seeds);
                }
                self.walk_guard_cond(&b.left);
                self.walk_guard_cond(&b.right);
            }
            syn::Expr::Unary(u) => self.walk_guard_cond(&u.expr),
            syn::Expr::Let(l) => self.walk_guard_cond(&l.expr),
            syn::Expr::Paren(p) => self.walk_guard_cond(&p.expr),
            syn::Expr::Reference(r) => self.walk_guard_cond(&r.expr),
            syn::Expr::Try(t) => self.walk_guard_cond(&t.expr),
            syn::Expr::Call(c) => {
                for arg in &c.args {
                    self.walk_guard_cond(arg);
                }
            }
            syn::Expr::MethodCall(m) => {
                if m.method == "key_eq"
                    && let Some(idx) = self.resolve_account_expr(&m.receiver)
                {
                    self.set_key_checked(idx);
                }
                self.walk_guard_cond(&m.receiver);
                for arg in &m.args {
                    self.walk_guard_cond(arg);
                }
            }
            syn::Expr::Field(f) => {
                if let Some(member) = member_ident(&f.member).map(|i| i.to_string())
                    && let Some(idx) = self.resolve_base_account(&f.base)
                {
                    match member.as_str() {
                        "is_signer" => self.set_signer_checked(idx),
                        "key" => self.set_key_checked(idx),
                        "owner" => self.set_owner_checked(idx),
                        _ => {}
                    }
                }
                self.walk_guard_cond(&f.base);
            }
            syn::Expr::Path(_) | syn::Expr::Lit(_) => {}
            _ => {}
        }
    }

    fn walk_guard_macro(&mut self, mac: &syn::Macro) {
        let name = mac.path.segments.last().map(|s| s.ident.to_string());
        let Some(name) = name else { return };
        if !is_guard_macro(&name) {
            return;
        }
        if let Ok(exprs) = mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
            for expr in exprs {
                self.walk_guard_cond(&expr);
            }
        }
    }

    /// Analyze a helper called from the current function: bind its first
    /// parameter (single account / slice continuation / shared iterator),
    /// resolve its body, then restore the caller's scope.
    fn analyze_helper(&mut self, f: &'a syn::ItemFn, file_idx: usize, args: &[syn::Expr]) {
        if self.depth >= 2 {
            return;
        }
        let fname = f.sig.ident.to_string();
        if !self.visited.insert(fname.clone()) {
            return;
        }

        let first_param = f.sig.inputs.first().and_then(|a| match a {
            syn::FnArg::Typed(t) => Some((t, classify_param(&t.ty))),
            syn::FnArg::Receiver(_) => None,
        });

        // Resolve the parameter binding against the *caller's* scope before
        // snapshotting it (the snapshots below empty the maps).
        let binding: Option<(String, usize, ParamKind)> = first_param.and_then(|(first, kind)| {
            let param = pat_ident(&first.pat)?;
            match kind {
                ParamKind::SingleAccount => {
                    args.first().and_then(|a| self.resolve_account_expr(a)).map(|idx| (param, idx, kind))
                }
                ParamKind::Slice => {
                    let base = args.first().and_then(range_start_literal).unwrap_or(self.next_index);
                    Some((param, base, kind))
                }
                ParamKind::Iterator => args.first().and_then(iterator_var).map(|iter| {
                    let pos =
                        if iter.is_empty() { self.base } else { self.slices.get(&iter).copied().unwrap_or(self.base) };
                    (param, pos, kind)
                }),
                ParamKind::Other => None,
            }
        });

        let Some((param, pos, kind)) = binding else {
            self.visited.remove(&fname);
            return;
        };

        let saved_named = std::mem::take(&mut self.named);
        let saved_structs = std::mem::take(&mut self.struct_vars);
        let saved_pdas = std::mem::take(&mut self.pda_vars);
        let saved_slices = std::mem::take(&mut self.slices);
        let saved_base = self.base;
        let saved_param = self.accounts_param.clone();
        let saved_file = self.current_file.clone();

        match kind {
            ParamKind::SingleAccount => {
                self.named.insert(param.clone(), pos);
            }
            ParamKind::Slice => {
                self.base = pos;
                self.accounts_param = Some(param.clone());
            }
            ParamKind::Iterator => {
                self.slices.insert(param.clone(), pos);
            }
            ParamKind::Other => {}
        }

        self.current_file = self.files[file_idx].1.clone();
        self.depth += 1;
        self.resolve_block(&f.block);
        self.depth -= 1;

        if kind == ParamKind::Iterator
            && let Some(iter) = args.first().and_then(iterator_var)
            && !iter.is_empty()
            && let Some(&advanced) = self.slices.get(&param)
        {
            self.slices.insert(iter, advanced);
        }

        self.named = saved_named;
        self.struct_vars = saved_structs;
        self.pda_vars = saved_pdas;
        self.slices = saved_slices;
        self.base = saved_base;
        self.accounts_param = saved_param;
        self.current_file = saved_file;
        self.visited.remove(&fname);
    }

    fn is_iter_init(&self, e: &syn::Expr) -> bool {
        match e {
            syn::Expr::Reference(r) => self.is_iter_init(&r.expr),
            syn::Expr::Paren(p) => self.is_iter_init(&p.expr),
            syn::Expr::MethodCall(m) => m.method == "iter" && expr_path_name(&m.receiver) == self.accounts_param,
            _ => false,
        }
    }

    /// Window sizes for an `array_refs![accounts, N, M]` binding, resolved
    /// against the current function's `const`s.
    fn array_refs_windows(&self, init: &syn::Expr) -> Option<Vec<u64>> {
        let e = unwrap_expr(init);
        let syn::Expr::Macro(m) = e else { return None };
        let name = m.mac.path.segments.last().map(|s| s.ident.to_string())?;
        if name != "array_refs" {
            return None;
        }
        let Ok(args) = m.mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) else {
            return None;
        };
        if args.first().and_then(expr_path_name).as_deref() != self.accounts_param.as_deref() {
            return None;
        }
        let mut sizes = Vec::new();
        for arg in args.iter().skip(1) {
            let size = literal_usize(arg)
                .map(|v| v as u64)
                .or_else(|| expr_path_name(arg).and_then(|name| self.consts.get(&name).copied()));
            sizes.push(size?);
        }
        Some(sizes)
    }

    /// Base position for a `let [a, b, ..] = <init>;` destructuring: the
    /// current function's slice (`accounts`), a tracked slice/iterator
    /// variable, or a literal range over the accounts slice.
    fn slice_binding_base(&self, init: &syn::Expr) -> Option<usize> {
        match init {
            syn::Expr::Path(p) => {
                let name = path_ident_str(&p.path)?;
                if self.accounts_param.as_ref().is_some_and(|param| param == &name) {
                    Some(self.base)
                } else {
                    self.slices.get(&name).copied()
                }
            }
            syn::Expr::Reference(r) => self.slice_binding_base(&r.expr),
            syn::Expr::Paren(p) => self.slice_binding_base(&p.expr),
            syn::Expr::Index(i) if expr_path_name(&i.expr) == self.accounts_param => {
                if let syn::Expr::Range(r) = i.index.as_ref() {
                    match &r.start {
                        Some(start) => literal_usize(start),
                        None => Some(self.base),
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Positions of the two halves of an `<accounts | tracked-slice>.split_at(N)`
    /// binding: `(base, base + N)`.
    fn split_at_slices(&self, init: &syn::Expr) -> Option<(usize, usize)> {
        let e = unwrap_expr(init);
        let syn::Expr::MethodCall(m) = e else { return None };
        if m.method != "split_at" {
            return None;
        }
        let base = match expr_path_name(&m.receiver) {
            Some(name) if self.accounts_param.as_ref().is_some_and(|p| p == &name) => self.base,
            Some(name) => *self.slices.get(&name)?,
            None => return None,
        };
        let n = literal_usize(m.args.first()?)?;
        Some((base, base + n))
    }

    /// Resolve an expression to an account index: named variable, struct
    /// `try_from` field access, or subscript of the accounts slice.
    fn resolve_base_account(&self, e: &syn::Expr) -> Option<usize> {
        match e {
            syn::Expr::Path(p) => {
                let name = path_ident_str(&p.path)?;
                self.named.get(&name).copied()
            }
            syn::Expr::Field(f) => {
                if let syn::Expr::Path(base) = f.base.as_ref() {
                    let var = path_ident_str(&base.path)?;
                    if let Some(fields) = self.struct_vars.get(&var) {
                        let member = member_ident(&f.member)?.to_string();
                        if let Some(idx) = fields.get(&member) {
                            return Some(*idx);
                        }
                    }
                }
                self.resolve_base_account(&f.base)
            }
            syn::Expr::Index(i) => {
                if expr_path_name(&i.expr) == self.accounts_param {
                    return literal_usize(&i.index);
                }
                None
            }
            syn::Expr::Reference(r) => self.resolve_base_account(&r.expr),
            syn::Expr::Paren(p) => self.resolve_base_account(&p.expr),
            _ => None,
        }
    }

    fn resolve_account_expr(&self, e: &syn::Expr) -> Option<usize> {
        match e {
            syn::Expr::Reference(r) => self.resolve_account_expr(&r.expr),
            syn::Expr::Paren(p) => self.resolve_account_expr(&p.expr),
            _ => self.resolve_base_account(e),
        }
    }
}

// ── Shank `#[account(N)]` attributes ────────────────────────────────────────

/// One shank `#[account(N, writable, signer, name = "x", ...)]` attribute:
/// `(position, explicit name, signer flag)`. `None` when the attribute is
/// not a shank account annotation.
fn shank_account_meta(attr: &syn::Attribute) -> Option<(usize, Option<String>, bool)> {
    if attr.path().segments.last()?.ident != "account" {
        return None;
    }
    let syn::Meta::List(ml) = &attr.meta else { return None };
    // syn 2 removed `NestedMeta`; parse the attribute body as expressions and
    // fold the shapes (bare int literal, bare path, `name = value`) back.
    let Ok(metas) = ml.parse_args_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) else {
        return None;
    };
    let mut position: Option<usize> = None;
    let mut name: Option<String> = None;
    let mut signer = false;
    for meta in metas {
        match meta {
            syn::Expr::Lit(expr_lit) => {
                if let syn::Lit::Int(i) = expr_lit.lit {
                    position = Some(i.base10_parse::<usize>().ok()?);
                }
            }
            syn::Expr::Path(p) => {
                if p.path.is_ident("signer") {
                    signer = true;
                }
            }
            syn::Expr::Assign(assign) => {
                let syn::Expr::Path(p) = &*assign.left else { continue };
                if p.path.is_ident("name")
                    && let syn::Expr::Lit(expr_lit) = &*assign.right
                    && let syn::Lit::Str(s) = &expr_lit.lit
                {
                    name = Some(s.value());
                }
            }
            _ => {}
        }
    }
    Some((position?, name, signer))
}

/// Positional account table declared by shank `#[account(N)]` attributes on
/// an enum variant. Positions are the contract; gaps are filled with
/// `account_N` fallback names, and the `signer` flag maps to
/// [`AccountKind::Signer`] (signer-by-construction, like Anchor's `Signer`).
fn shank_variant_accounts(
    files: &[(syn::File, String)],
    enum_name: &str,
    variant: &str,
) -> Option<Vec<ResolvedAccount>> {
    let mut rows: Vec<(usize, String, AccountKind)> = Vec::new();
    for (file, _) in files {
        for item in &file.items {
            let syn::Item::Enum(en) = item else { continue };
            if en.ident != enum_name {
                continue;
            }
            let Some(v) = en.variants.iter().find(|v| v.ident == variant) else {
                continue;
            };
            for attr in &v.attrs {
                if let Some((pos, name, signer)) = shank_account_meta(attr) {
                    let name = name.unwrap_or_else(|| format!("account_{pos}"));
                    let kind = if signer { AccountKind::Signer } else { AccountKind::Unchecked };
                    rows.push((pos, name, kind));
                }
            }
        }
    }
    if rows.is_empty() {
        return None;
    }
    let max = rows.iter().map(|(p, _, _)| *p).max()?;
    let mut table: HashMap<usize, ResolvedAccount> = HashMap::new();
    for i in 0..=max {
        table.insert(
            i,
            ResolvedAccount {
                name: format!("account_{i}"),
                index: i,
                kind: AccountKind::Unchecked,
                is_signer_checked: false,
                owner_checked: false,
                key_checked: false,
                written: false,
                seeds: Vec::new(),
                is_pda: false,
            },
        );
    }
    for (pos, name, kind) in rows {
        if let Some(e) = table.get_mut(&pos) {
            e.name = name;
            e.kind = kind;
        }
    }
    let mut accounts: Vec<ResolvedAccount> = table.into_values().collect();
    accounts.sort_by_key(|a| a.index);
    Some(accounts)
}

/// Merge a shank-declared positional table into handler-resolved accounts:
/// shank names (when not `account_N` fallbacks) and kinds win — they are the
/// positional contract — while handler analysis contributes guard flags
/// (signer/owner/key checks, writes, PDAs) by index.
fn merge_shank_accounts(handler: Vec<ResolvedAccount>, shank: Vec<ResolvedAccount>) -> Vec<ResolvedAccount> {
    let mut merged: HashMap<usize, ResolvedAccount> = HashMap::new();
    for a in handler {
        merged.insert(a.index, a);
    }
    for s in shank {
        let e = merged.entry(s.index).or_insert_with(|| s.clone());
        let fallback = format!("account_{}", s.index);
        if s.name != fallback {
            e.name = s.name.clone();
        }
        if e.kind == AccountKind::Unchecked {
            e.kind = s.kind;
        }
    }
    let mut accounts: Vec<ResolvedAccount> = merged.into_values().collect();
    accounts.sort_by_key(|a| a.index);
    accounts
}

/// One side of a comparison: the account index when the side is an account's
/// `.key` member, and the seeds when the side is a derived-PDA variable.
type SideInfo = (Option<usize>, bool, Option<Vec<String>>);

fn side_info(e: &syn::Expr, state: &ResolutionState<'_>) -> SideInfo {
    match e {
        syn::Expr::Field(f) if member_ident(&f.member).is_some_and(|i| i == "key") => {
            match state.resolve_base_account(&f.base) {
                Some(idx) => (Some(idx), true, None),
                None => (None, false, None),
            }
        }
        syn::Expr::Path(p) => match path_ident_str(&p.path) {
            Some(name) => match state.pda_vars.get(&name) {
                Some(seeds) => (None, false, Some(seeds.clone())),
                None => (None, false, None),
            },
            None => (None, false, None),
        },
        syn::Expr::Reference(r) => side_info(&r.expr, state),
        syn::Expr::Paren(p) => side_info(&p.expr, state),
        _ => (None, false, None),
    }
}

// ── Expression helpers ──────────────────────────────────────────────────────

fn pat_path(pat: &syn::Pat) -> Option<&syn::Path> {
    match pat {
        syn::Pat::Path(p) => Some(&p.path),
        syn::Pat::Struct(p) => Some(&p.path),
        syn::Pat::TupleStruct(p) => Some(&p.path),
        _ => None,
    }
}

fn member_ident(m: &syn::Member) -> Option<&syn::Ident> {
    match m {
        syn::Member::Named(i) => Some(i),
        syn::Member::Unnamed(_) => None,
    }
}

fn expr_path_name(e: &syn::Expr) -> Option<String> {
    if let syn::Expr::Path(p) = e { path_ident_str(&p.path) } else { None }
}

/// Callee lookup key: `A::b` for qualified paths (impl methods), bare `b`
/// for single-segment paths (free functions).
fn callee_key(e: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(p) = e else { return None };
    if p.path.segments.len() >= 2 {
        let first = p.path.segments.first()?.ident.to_string();
        let last = p.path.segments.last()?.ident.to_string();
        Some(format!("{first}::{last}"))
    } else {
        path_ident_str(&p.path)
    }
}

fn path_ident_str(p: &syn::Path) -> Option<String> {
    p.segments.last().map(|s| s.ident.to_string())
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    if let syn::Pat::Ident(i) = pat { Some(i.ident.to_string()) } else { None }
}

fn tuple_first_ident(pat: &syn::Pat) -> Option<String> {
    if let syn::Pat::Tuple(t) = pat { t.elems.first().and_then(pat_ident) } else { None }
}

fn literal_usize(e: &syn::Expr) -> Option<usize> {
    if let syn::Expr::Lit(l) = e
        && let syn::Lit::Int(i) = &l.lit
    {
        return i.base10_parse::<usize>().ok();
    }
    None
}

/// Value of a `const NAME: usize = <literal>;` item.
fn const_value(c: &syn::ItemConst) -> Option<u64> {
    let e = unwrap_expr(&c.expr);
    if let syn::Expr::Lit(l) = e
        && let syn::Lit::Int(i) = &l.lit
    {
        return int_lit_value(i);
    }
    None
}

/// Evaluate a const initializer: integer literal, reference to an already
/// known const, or simple `+ - * /` arithmetic over those.
fn eval_const_expr(e: &syn::Expr, consts: &HashMap<String, u64>) -> Option<u64> {
    let e = unwrap_expr(e);
    match e {
        syn::Expr::Lit(l) => {
            if let syn::Lit::Int(i) = &l.lit {
                int_lit_value(i)
            } else {
                None
            }
        }
        syn::Expr::Path(p) => {
            let name = path_ident_str(&p.path)?;
            consts.get(&name).copied()
        }
        syn::Expr::Binary(b) => {
            let left = eval_const_expr(&b.left, consts)?;
            let right = eval_const_expr(&b.right, consts)?;
            match b.op {
                syn::BinOp::Add(_) => left.checked_add(right),
                syn::BinOp::Sub(_) => left.checked_sub(right),
                syn::BinOp::Mul(_) => left.checked_mul(right),
                syn::BinOp::Div(_) => left.checked_div(right),
                _ => None,
            }
        }
        syn::Expr::Paren(p) => eval_const_expr(&p.expr, consts),
        _ => None,
    }
}

/// Parse an integer literal value, handling `0x`/`0o`/`0b` prefixes and
/// digit separators (syn's `base10_parse` only handles base-10).
fn int_lit_value(i: &syn::LitInt) -> Option<u64> {
    if let Ok(v) = i.base10_parse::<u64>() {
        return Some(v);
    }
    let raw = i.base10_digits().replace('_', "");
    let (radix, digits) = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        (16, hex)
    } else if let Some(oct) = raw.strip_prefix("0o").or_else(|| raw.strip_prefix("0O")) {
        (8, oct)
    } else {
        let bin = raw.strip_prefix("0b").or_else(|| raw.strip_prefix("0B"))?;
        (2, bin)
    };
    u64::from_str_radix(digits, radix).ok()
}

/// Strip `?` / parens / references around an expression.
fn unwrap_expr(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Try(t) => unwrap_expr(&t.expr),
        syn::Expr::Paren(p) => unwrap_expr(&p.expr),
        syn::Expr::Reference(r) => unwrap_expr(&r.expr),
        syn::Expr::Group(g) => unwrap_expr(&g.expr),
        _ => e,
    }
}

/// `accounts[i]` / `&accounts[i]` / `&mut accounts[i]` with a literal index.
/// Returns (index, written).
fn subscript_index(e: &syn::Expr, accounts_param: &Option<String>) -> Option<(usize, bool)> {
    match e {
        syn::Expr::Reference(r) => {
            let (idx, _) = subscript_index(&r.expr, accounts_param)?;
            Some((idx, r.mutability.is_some()))
        }
        syn::Expr::Paren(p) => subscript_index(&p.expr, accounts_param),
        syn::Expr::Index(i) => {
            if expr_path_name(&i.expr) != *accounts_param {
                return None;
            }
            let idx = literal_usize(&i.index)?;
            Some((idx, false))
        }
        syn::Expr::MethodCall(m) if m.method == "clone" => subscript_index(&m.receiver, accounts_param),
        _ => None,
    }
}

/// `&accounts[i..]` / `&accounts[i..j]` range slices.
fn range_slice(e: &syn::Expr, accounts_param: &Option<String>) -> Option<RangeStart> {
    match e {
        syn::Expr::Reference(r) => range_slice(&r.expr, accounts_param),
        syn::Expr::Paren(p) => range_slice(&p.expr, accounts_param),
        syn::Expr::Index(i) => {
            if expr_path_name(&i.expr) != *accounts_param {
                return None;
            }
            let syn::Expr::Range(r) = i.index.as_ref() else { return None };
            match &r.start {
                Some(start) => literal_usize(start).map(RangeStart::Literal),
                None => Some(RangeStart::Current),
            }
        }
        _ => None,
    }
}

/// The iterator variable consumed by a positional call: a tracked path, or
/// "" for an inline `&mut accounts.iter()`.
fn iterator_var(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) => path_ident_str(&p.path),
        syn::Expr::Reference(r) => iterator_var(&r.expr),
        syn::Expr::Paren(p) => iterator_var(&p.expr),
        syn::Expr::MethodCall(m) if m.method == "iter" => Some(String::new()),
        _ => None,
    }
}

/// Detect `next_account_info(iter)?` / `iter.next().ok_or(...)?` style
/// positional consumption. Returns the iterator variable ("" = inline).
fn scan_consumption(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Try(t) => scan_consumption(&t.expr),
        syn::Expr::Paren(p) => scan_consumption(&p.expr),
        syn::Expr::Reference(r) => scan_consumption(&r.expr),
        syn::Expr::Call(c) => {
            let name = expr_path_name(&c.func)?;
            if name != "next_account_info" {
                return None;
            }
            c.args.first().and_then(iterator_var)
        }
        syn::Expr::MethodCall(m) => match m.method.to_string().as_str() {
            "next" => iterator_var(&m.receiver),
            "ok_or" | "ok_or_else" | "unwrap" | "expect" => scan_consumption(&m.receiver),
            _ => None,
        },
        _ => None,
    }
}

/// `find_program_address` / `create_program_address` calls; returns the seed
/// expressions as source text.
fn find_pda_call(e: &syn::Expr) -> Option<Vec<String>> {
    let e = unwrap_expr(e);
    let syn::Expr::Call(c) = e else { return None };
    let name = expr_path_name(&c.func)?;
    if name != "find_program_address" && name != "create_program_address" {
        return None;
    }
    let seeds_arg = unwrap_expr(c.args.first()?);
    let syn::Expr::Array(a) = seeds_arg else { return None };
    Some(a.elems.iter().map(expr_source_text).collect())
}

/// `X::try_from(&accounts[..])`-style calls; returns the struct name.
fn try_from_call(e: &syn::Expr) -> Option<String> {
    let e = unwrap_expr(e);
    let syn::Expr::Call(c) = e else { return None };
    let syn::Expr::Path(p) = c.func.as_ref() else { return None };
    let last = p.path.segments.last()?;
    if last.ident != "try_from" {
        return None;
    }
    let first = p.path.segments.first()?;
    if first.ident == "try_from" || first.ident == "TryFrom" {
        return None;
    }
    Some(first.ident.to_string())
}

fn range_start_literal(e: &syn::Expr) -> Option<usize> {
    let e = unwrap_expr(e);
    if let syn::Expr::Index(i) = e
        && let syn::Expr::Range(r) = i.index.as_ref()
        && let Some(start) = &r.start
    {
        return literal_usize(start);
    }
    None
}

/// Compact source text for an expression (used for PDA seed capture).
/// `TokenStream::to_string` inserts spaces around punctuation (`a . b`),
/// which is not what rules want to compare against — render manually.
fn expr_source_text(e: &syn::Expr) -> String {
    match e {
        syn::Expr::Path(p) => path_source_text(&p.path),
        syn::Expr::Field(f) => format!("{}.{}", expr_source_text(&f.base), member_source_text(&f.member)),
        syn::Expr::MethodCall(m) => {
            format!("{}.{}({})", expr_source_text(&m.receiver), m.method, expr_comma_list(&m.args))
        }
        syn::Expr::Call(c) => format!("{}({})", expr_source_text(&c.func), expr_comma_list(&c.args)),
        syn::Expr::Reference(r) => {
            if r.mutability.is_some() {
                format!("&mut {}", expr_source_text(&r.expr))
            } else {
                format!("&{}", expr_source_text(&r.expr))
            }
        }
        syn::Expr::Paren(p) => format!("({})", expr_source_text(&p.expr)),
        syn::Expr::Group(g) => expr_source_text(&g.expr),
        syn::Expr::Lit(l) => lit_source_text(&l.lit),
        syn::Expr::Index(i) => format!("{}[{}]", expr_source_text(&i.expr), expr_source_text(&i.index)),
        syn::Expr::Array(a) => format!("[{}]", expr_comma_list(&a.elems)),
        syn::Expr::Tuple(t) => format!("({})", expr_comma_list(&t.elems)),
        syn::Expr::Unary(u) => format!("{}{}", u.op.to_token_stream(), expr_source_text(&u.expr)),
        syn::Expr::Cast(c) => format!("{} as {}", expr_source_text(&c.expr), c.ty.to_token_stream()),
        syn::Expr::Range(r) => {
            let start = r.start.as_deref().map(expr_source_text).unwrap_or_default();
            let end = r.end.as_deref().map(expr_source_text).unwrap_or_default();
            let op = match r.limits {
                syn::RangeLimits::HalfOpen(_) => "..",
                syn::RangeLimits::Closed(_) => "..=",
            };
            format!("{start}{op}{end}")
        }
        syn::Expr::Binary(b) => {
            format!("{} {} {}", expr_source_text(&b.left), b.op.to_token_stream(), expr_source_text(&b.right))
        }
        _ => e.to_token_stream().to_string(),
    }
}

fn path_source_text(p: &syn::Path) -> String {
    p.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
}

fn member_source_text(m: &syn::Member) -> String {
    match m {
        syn::Member::Named(i) => i.to_string(),
        syn::Member::Unnamed(i) => i.index.to_string(),
    }
}

fn expr_comma_list(elems: &Punctuated<syn::Expr, syn::Token![,]>) -> String {
    elems.iter().map(expr_source_text).collect::<Vec<_>>().join(", ")
}

fn lit_source_text(l: &syn::Lit) -> String {
    match l {
        syn::Lit::Str(s) => format!("{:?}", s.value()),
        syn::Lit::ByteStr(s) => byte_str_source(&s.value()),
        syn::Lit::Byte(b) => format!("b'{}'", escape_byte(b.value())),
        syn::Lit::Char(c) => format!("'{}'", c.value()),
        syn::Lit::Int(i) => i.base10_digits().to_string(),
        syn::Lit::Float(f) => f.base10_digits().to_string(),
        syn::Lit::Bool(b) => b.value.to_string(),
        _ => l.to_token_stream().to_string(),
    }
}

fn byte_str_source(bytes: &[u8]) -> String {
    let mut s = String::from("b\"");
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s.push('"');
    s
}

fn escape_byte(b: u8) -> String {
    match b {
        b'\'' => "\\'".to_string(),
        b'\\' => "\\\\".to_string(),
        b'\n' => "\\n".to_string(),
        0x20..=0x7e => (b as char).to_string(),
        _ => format!("\\x{b:02x}"),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Kind inference ──────────────────────────────────────────────────────────

/// Kind from the account's declared type (struct `try_from` fields).
fn kind_from_type(ty: &syn::Type) -> AccountKind {
    let s = ty.to_token_stream().to_string();
    if s.contains("Signer") {
        AccountKind::Signer
    } else if s.contains("UncheckedAccount") {
        AccountKind::Unchecked
    } else if s.contains("Sysvar") {
        AccountKind::Sysvar
    } else if s.contains("TokenAccount") {
        AccountKind::TokenAccount
    } else if s.contains("Mint") {
        AccountKind::Mint
    } else if s.contains("System") {
        AccountKind::SystemProgram
    } else if s.contains("Program") {
        AccountKind::Program
    } else if s.contains("Account<") {
        AccountKind::State
    } else {
        AccountKind::Unchecked
    }
}

/// Conservative name-based heuristic used when no type evidence exists.
fn kind_from_name(name: &str) -> AccountKind {
    if name == "system_program" {
        return AccountKind::SystemProgram;
    }
    if name.contains("sysvar")
        || matches!(name, "clock" | "rent" | "slot_hashes" | "epoch_schedule" | "recent_blockhashes")
    {
        return AccountKind::Sysvar;
    }
    if name.contains("token_program") {
        return AccountKind::Program;
    }
    if name.contains("mint") {
        return AccountKind::Mint;
    }
    if name.contains("token") {
        return AccountKind::TokenAccount;
    }
    if name.ends_with("_program") || name.ends_with("_program_id") {
        return AccountKind::Program;
    }
    AccountKind::Unchecked
}

// ── Guard/check helpers ─────────────────────────────────────────────────────

fn is_owner_check_call(name: &str) -> bool {
    const PREFIXES: [&str; 4] = ["check_owner", "assert_owner", "require_owner", "verify_owner"];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_guard_macro(name: &str) -> bool {
    matches!(
        name,
        "require"
            | "require_keys_eq"
            | "require_keys_neq"
            | "require_eq"
            | "assert"
            | "assert_eq"
            | "invariant"
            | "debug_assert"
            | "debug_assert_eq"
            | "check"
            | "check_eq"
    )
}

fn is_known_builtin(name: &str) -> bool {
    matches!(
        name,
        "next_account_info"
            | "find_program_address"
            | "create_program_address"
            | "invoke"
            | "invoke_signed"
            | "invoke_signed_unchecked"
    )
}

fn is_dispatch_scrutinee(e: &syn::Expr) -> bool {
    is_instruction_data_scrutinee(e) || is_tag_scrutinee(e)
}

/// The `&[AccountInfo]` parameter of a handler (where subscripts and inline
/// iterators anchor).
fn accounts_param_name(f: &syn::ItemFn) -> Option<String> {
    for input in &f.sig.inputs {
        let syn::FnArg::Typed(t) = input else { continue };
        let kind = classify_param(&t.ty);
        if matches!(kind, ParamKind::Slice | ParamKind::Iterator) {
            return pat_ident(&t.pat);
        }
    }
    None
}

// ── Program building ────────────────────────────────────────────────────────

/// Build the [`NativeProgram`] model for a workspace of parsed files.
pub(crate) fn build_program(files: &[(syn::File, String)]) -> NativeProgram {
    let index = FileIndex::build(files);

    // Entrypoint: the `entrypoint!` macro target first, then the canonical
    // `process_instruction` function.
    let mut entrypoint = None;
    for (i, (file, _)) in files.iter().enumerate() {
        if let Some((handler, line)) = find_entrypoint_macro(file) {
            entrypoint = Some((handler, line, i));
            break;
        }
    }
    if entrypoint.is_none() {
        for (i, (file, _)) in files.iter().enumerate() {
            if let Some((handler, line)) = find_process_instruction_fn(file) {
                entrypoint = Some((handler, line, i));
                break;
            }
        }
    }
    let Some((entrypoint_handler, entrypoint_line, entrypoint_file_idx)) = entrypoint else {
        // Framework-macro dispatch recovery (wormhole `solitaire!` class): no
        // entrypoint!/process_instruction marker exists — the entrypoint and
        // dispatch table are both generated by the macro, whose invocation
        // tokens carry `Name(DataType) => handler` rows.
        for (i, (file, _)) in files.iter().enumerate() {
            if let Some((rows, line)) = find_framework_dispatch(file) {
                return macro_program_from_rows(&rows, line, files[i].1.clone());
            }
        }
        return NativeProgram::default();
    };

    let program_id = files.iter().find_map(|(file, _)| find_declare_id(file));
    let entrypoint_file = files[entrypoint_file_idx].1.clone();

    let entrypoint_fn =
        index.fns.get(&entrypoint_handler).and_then(|candidates| candidates.first()).map(|(f, i)| (f.clone(), *i));

    let dispatch =
        entrypoint_fn.as_ref().and_then(|(f, _)| follow_dispatch(f, &index, files)).filter(|arms| !arms.is_empty());

    let mut program = NativeProgram {
        program_id,
        entrypoint_file: entrypoint_file.clone(),
        entrypoint_line,
        instructions: Vec::new(),
    };

    if let Some(arms) = dispatch {
        for arm in arms {
            let mut state = ResolutionState::new(&index, files);
            let mut file = entrypoint_file.clone();
            let accounts = if let Some((f, file_idx)) = index.lookup_fn(&arm.handler, &entrypoint_file) {
                file = files[*file_idx].1.clone();
                state.current_file = file.clone();
                state.accounts_param = accounts_param_name(f);
                state.resolve_block(&f.block);
                let handler_accounts = state.finish_accounts();
                // Shank `#[account(N)]` annotations on the dispatched enum
                // variant supply the authoritative positional table (names
                // with `account_N` fallbacks); handler guard flags survive
                // the merge by index.
                if let Some(enum_name) = &arm.enum_name
                    && let Some(shank) = shank_variant_accounts(files, enum_name, &arm.name)
                {
                    merge_shank_accounts(handler_accounts, shank)
                } else {
                    handler_accounts
                }
            } else if let Some(enum_name) = &arm.enum_name {
                // Handler not in the workspace: the shank table alone.
                shank_variant_accounts(files, enum_name, &arm.name).unwrap_or_default()
            } else {
                Vec::new()
            };
            program.instructions.push(NativeInstruction {
                name: arm.name,
                discriminator: arm.discriminator,
                handler: arm.handler,
                file,
                line: arm.line,
                accounts,
            });
        }
    } else {
        let mut state = ResolutionState::new(&index, files);
        let accounts = if let Some((f, file_idx)) = index.lookup_fn(&entrypoint_handler, &entrypoint_file) {
            state.current_file = files[*file_idx].1.clone();
            state.accounts_param = accounts_param_name(f);
            state.resolve_block(&f.block);
            state.finish_accounts()
        } else {
            Vec::new()
        };
        let line = entrypoint_fn.map(|(f, _)| f.sig.ident.span().start().line).unwrap_or(entrypoint_line);
        program.instructions.push(NativeInstruction {
            name: entrypoint_handler.clone(),
            discriminator: None,
            handler: entrypoint_handler,
            file: entrypoint_file,
            line,
            accounts,
        });
    }

    program
}

// ── In-module tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> syn::File {
        syn::parse_file(src).expect("test source should parse")
    }

    fn build(src: &str) -> NativeProgram {
        let file = parse(src);
        build_program(&[(file, "test.rs".to_string())])
    }

    #[test]
    fn has_native_marker_recognizes_framework_macro_dispatch() {
        let file = parse(
            "solitaire! { Initialize(InitializeData) => initialize, PostMessage(PostMessageData) => post_message }",
        );
        assert!(has_native_marker(&file), "solitaire! token table is a native marker");
    }

    #[test]
    fn has_native_marker_ignores_unrecognized_macros() {
        let file = parse("some_macro! { Initialize(InitializeData) => initialize }");
        assert!(!has_native_marker(&file));
    }

    #[test]
    fn macro_dispatch_rows_recovers_solitaire_rows() {
        let file = parse(
            r#"solitaire! {
                Initialize(InitializeData)      => initialize,
                PostVAA(PostVAAData)            => post_vaa,
                VerifySignatures(VerifySignaturesData) => verify_signatures,
            }"#,
        );
        let (rows, _line) = find_framework_dispatch(&file).expect("dispatch rows recovered");
        assert_eq!(
            rows,
            vec![
                ("Initialize".to_string(), "initialize".to_string()),
                ("PostVAA".to_string(), "post_vaa".to_string()),
                ("VerifySignatures".to_string(), "verify_signatures".to_string()),
            ]
        );
    }

    #[test]
    fn macro_recovery_builds_ordered_borsh_instructions() {
        let p = build(
            r#"solitaire! {
                Initialize(InitializeData)   => initialize,
                PostMessage(PostMessageData) => post_message,
                PostVAA(PostVAAData)         => post_vaa,
            }"#,
        );
        assert_eq!(p.instructions.len(), 3);
        for (i, ix) in p.instructions.iter().enumerate() {
            assert_eq!(ix.discriminator, Some(vec![i as u8]), "borsh order = declaration order");
            assert!(ix.accounts.is_empty(), "framework-peeled accounts stay unresolved");
        }
        assert_eq!(p.instructions[0].name, "Initialize");
        assert_eq!(p.instructions[0].handler, "initialize");
        assert_eq!(p.instructions[2].name, "PostVAA");
        assert_eq!(p.instructions[2].handler, "post_vaa");
        assert!(p.entrypoint_line >= 1);
    }

    #[test]
    fn variant_tags_fall_back_to_borsh_declaration_order() {
        let file = parse("pub enum Instruction { Alpha, Beta, Gamma }");
        let tags = find_variant_tags(&[(file, "test.rs".to_string())], "Instruction");
        assert_eq!(tags.get("Alpha"), Some(&0));
        assert_eq!(tags.get("Beta"), Some(&1));
        assert_eq!(tags.get("Gamma"), Some(&2));
    }

    #[test]
    fn variant_tags_recognize_try_from_slice_decoder() {
        // Manual `try_from_slice` decoders (borsh-style) are recognized the
        // same way `unpack` impls are.
        let file = parse(
            r#"
            pub enum Instruction { A, B }
            impl Instruction {
                pub fn try_from_slice(input: &[u8]) -> Result<Self, ()> {
                    match input[0] {
                        7 => Ok(Instruction::A),
                        9 => Ok(Instruction::B),
                        _ => Err(()),
                    }
                }
            }
            "#,
        );
        let tags = find_variant_tags(&[(file, "test.rs".to_string())], "Instruction");
        assert_eq!(tags.get("A"), Some(&7));
        assert_eq!(tags.get("B"), Some(&9));
    }

    #[test]
    fn shank_account_meta_parses_position_name_and_signer() {
        let file = parse(
            r#"
            pub enum E {
                #[account(4, signer, name = "base", desc = "Base for PDA seed")]
                V,
            }
            "#,
        );
        let syn::Item::Enum(en) = &file.items[0] else { panic!("enum expected") };
        let attr = en.variants[0].attrs.first().expect("account attr");
        let (pos, name, signer) = shank_account_meta(attr).expect("shank meta parsed");
        assert_eq!(pos, 4);
        assert_eq!(name.as_deref(), Some("base"));
        assert!(signer);
    }
}
