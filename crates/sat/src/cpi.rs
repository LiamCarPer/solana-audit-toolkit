use std::collections::{HashMap, HashSet};

use crate::types::{Finding, Severity};

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CpiCall {
    caller: String,
    callee: String,
    depth: u32,
    is_internal: bool,
    resolved: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CallNode {
    name: String,
    calls: Vec<String>,
    visited: bool,
    in_stack: bool,
}

pub fn analyze_cpi_depth(parsed_files: &[(syn::File, String)], instruction_names: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let program_ix_set: HashSet<&str> = instruction_names.iter().map(|s| s.as_str()).collect();

    let mut call_graph: HashMap<String, Vec<CpiCall>> = HashMap::new();

    for (file, _file_path) in parsed_files {
        for item in &file.items {
            if let syn::Item::Mod(item_mod) = item {
                if !item_mod.attrs.iter().any(|a| a.path().is_ident("program")) {
                    continue;
                }
                if let Some((_, items)) = &item_mod.content {
                    for mod_item in items {
                        if let syn::Item::Fn(func) = mod_item
                            && matches!(func.vis, syn::Visibility::Public(_))
                        {
                            let ix_name = func.sig.ident.to_string();
                            let calls = extract_invoke_calls(&func.block, &program_ix_set);
                            call_graph.insert(ix_name, calls);
                        }
                    }
                }
            }
        }
    }

    let mut max_depths: HashMap<String, u32> = HashMap::new();
    let mut unresolved: Vec<String> = Vec::new();

    for calls in call_graph.values() {
        for call in calls {
            if !call.resolved && call.is_internal {
                unresolved.push(format!("{} → (unknown target)", call.caller));
            }
        }
    }

    for ix_name in call_graph.keys() {
        let depth = compute_max_depth(ix_name, &call_graph, 0, &mut HashSet::new());
        max_depths.insert(ix_name.clone(), depth);
    }

    if !unresolved.is_empty() {
        findings.push(Finding {
            id: String::new(),
            title: format!("CPI Depth Unresolved: {} call(s) could not be statically traced", unresolved.len()),
            severity: Severity::Informational,
            description: format!(
                "The following CPI call targets could not be resolved statically: {}. \
                 These may involve dynamically constructed instruction data, \
                 function pointers, or macro-generated dispatch logic.",
                unresolved.join("; ")
            ),
            location: Some("Source: #[program] module".to_string()),
            suggestion: Some(
                "Manually audit these CPI call sites to verify the aggregate CPI depth does not exceed 4.".to_string(),
            ),
        });
    }

    for (ix_name, depth) in &max_depths {
        if *depth > 4 {
            findings.push(Finding {
                id: String::new(),
                title: format!("CPI Depth Overflow: `{ix_name}` reaches depth {depth} (limit is 4)"),
                severity: Severity::Critical,
                description: format!(
                    "The instruction `{ix_name}` has a CPI depth of {depth} which exceeds the Solana \
                     maximum CPI depth of 4. This will cause the transaction to fail at runtime. \
                     Nested program invocations accumulate depth, and each `invoke()` or `invoke_signed()` \
                     call within the same transaction adds 1 to the depth counter."
                ),
                location: Some(format!("Instruction: {ix_name}")),
                suggestion: Some(format!(
                    "Reduce the call chain depth from {depth} to ≤4 by flattening or restructuring \
                     the CPI call chain. Consider merging adjacent instructions or performing \
                     operations sequentially in a single instruction."
                )),
            });
        }
    }

    findings
}

fn extract_invoke_calls(block: &syn::Block, program_ix_set: &HashSet<&str>) -> Vec<CpiCall> {
    let mut calls = Vec::new();
    extract_invoke_calls_recursive(&block.stmts, program_ix_set, &mut calls);
    calls
}

fn extract_invoke_calls_recursive(stmts: &[syn::Stmt], program_ix_set: &HashSet<&str>, calls: &mut Vec<CpiCall>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                find_invoke_in_expr(expr, program_ix_set, calls);
            }
            syn::Stmt::Local(local) => {
                if let Some(ref init) = local.init {
                    find_invoke_in_expr(&init.expr, program_ix_set, calls);
                }
            }
            _ => {}
        }
    }
}

fn find_invoke_in_expr(expr: &syn::Expr, program_ix_set: &HashSet<&str>, calls: &mut Vec<CpiCall>) {
    match expr {
        syn::Expr::Call(expr_call) => {
            let callee = expr_to_call_target(&expr_call.func);

            if callee_contains_invoke(&callee) {
                let resolved_target = try_resolve_invoke_target(expr_call);
                let is_internal = resolved_target.as_ref().is_some_and(|t| program_ix_set.contains(t.as_str()));
                let resolved = resolved_target.is_some();
                let callee_name = resolved_target.unwrap_or_else(|| "unknown".to_string());

                calls.push(CpiCall { caller: String::new(), callee: callee_name, depth: 0, is_internal, resolved });
            }
        }
        syn::Expr::Block(block_expr) => {
            extract_invoke_calls_recursive(&block_expr.block.stmts, program_ix_set, calls);
        }
        syn::Expr::If(expr_if) => {
            find_invoke_in_expr(&expr_if.cond, program_ix_set, calls);
            extract_invoke_calls_recursive(&expr_if.then_branch.stmts, program_ix_set, calls);
            if let Some((_, else_branch)) = &expr_if.else_branch {
                find_invoke_in_expr(else_branch, program_ix_set, calls);
            }
        }
        syn::Expr::Match(expr_match) => {
            for arm in &expr_match.arms {
                find_invoke_in_expr(&arm.body, program_ix_set, calls);
            }
        }
        syn::Expr::Try(expr_try) => {
            find_invoke_in_expr(&expr_try.expr, program_ix_set, calls);
        }
        syn::Expr::MethodCall(method_call) => {
            find_invoke_in_expr(&method_call.receiver, program_ix_set, calls);
        }
        syn::Expr::Let(expr_let) => {
            find_invoke_in_expr(&expr_let.expr, program_ix_set, calls);
        }
        _ => {}
    }
}

fn callee_contains_invoke(callee: &str) -> bool {
    callee == "invoke"
        || callee == "invoke_signed"
        || callee.ends_with("::invoke")
        || callee.ends_with("::invoke_signed")
}

fn expr_to_call_target(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(path) => path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"),
        syn::Expr::Call(call) => expr_to_call_target(&call.func),
        _ => String::new(),
    }
}

fn try_resolve_invoke_target(call: &syn::ExprCall) -> Option<String> {
    let mut ix_data: Option<Vec<u8>> = None;

    for arg in &call.args {
        if let syn::Expr::Reference(ref_expr) = arg
            && let syn::Expr::Path(path) = &*ref_expr.expr
        {
            let name = path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
            if name.ends_with("_instruction") || name.ends_with("_ix") || name.to_lowercase().contains("ix_data") {
                continue;
            }
        }
    }

    if !call.args.is_empty()
        && let syn::Expr::Reference(ref_expr) = &call.args[0]
    {
        if let syn::Expr::Struct(expr_struct) = &*ref_expr.expr {
            for field in &expr_struct.fields {
                let field_name = member_to_string(&field.member);
                if field_name == "data" {
                    if let syn::Expr::MethodCall(mc) = &field.expr {
                        let method = mc.method.to_string();
                        if (method == "try_to_vec" || method == "data")
                            && let syn::Expr::Reference(inner_ref) = &*mc.receiver
                            && let syn::Expr::Path(inner_path) = &*inner_ref.expr
                        {
                            let target = inner_path
                                .path
                                .segments
                                .iter()
                                .map(|s| s.ident.to_string())
                                .collect::<Vec<_>>()
                                .join("::");
                            return Some(target);
                        }
                    } else if let syn::Expr::Lit(lit) = &field.expr {
                        ix_data = Some(lit_to_bytes(&lit.lit));
                    }
                }
            }
        }

        if let syn::Expr::MethodCall(mc) = &*ref_expr.expr {
            let method = mc.method.to_string();
            if method == "try_to_vec" || method == "data" {
                let receiver = expr_to_string_expr(&mc.receiver);
                if receiver.ends_with("_instruction") {
                    return Some(receiver.replace("_instruction", ""));
                }
            }
        }
    }

    ix_data.map(|d| format!("<data:{d:?}>"))
}

fn member_to_string(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(ident) => ident.to_string(),
        syn::Member::Unnamed(index) => index.index.to_string(),
    }
}

pub(crate) fn expr_to_string_expr(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(path) => path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"),
        syn::Expr::Reference(r) => expr_to_string_expr(&r.expr),
        _ => String::new(),
    }
}

fn lit_to_bytes(lit: &syn::Lit) -> Vec<u8> {
    match lit {
        syn::Lit::ByteStr(b) => b.value(),
        syn::Lit::Str(s) => s.value().into_bytes(),
        _ => Vec::new(),
    }
}

fn compute_max_depth(
    node: &str,
    graph: &HashMap<String, Vec<CpiCall>>,
    current_depth: u32,
    visiting: &mut HashSet<String>,
) -> u32 {
    if current_depth > 10 {
        return current_depth;
    }

    if !visiting.insert(node.to_string()) {
        return current_depth;
    }

    let mut max = current_depth;

    if let Some(calls) = graph.get(node) {
        for call in calls {
            if call.is_internal && call.resolved {
                let next_depth = compute_max_depth(&call.callee, graph, current_depth + 1, visiting);
                if next_depth > max {
                    max = next_depth;
                }
            }
        }
    }

    visiting.remove(node);
    max
}
