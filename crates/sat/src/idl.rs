use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;

use crate::types::{Finding, Severity};
use crate::ui;

// ── Anchor IDL JSON types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlJson {
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub instructions: Vec<IdlInstruction>,
    #[serde(default)]
    pub accounts: Vec<IdlAccountDef>,
    #[serde(default)]
    pub types: Vec<IdlTypeDef>,
    #[serde(default)]
    pub metadata: Option<IdlMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlMetadata {
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlInstruction {
    pub name: String,
    #[serde(default)]
    pub accounts: Vec<IdlAccountItem>,
    #[serde(default)]
    pub args: Vec<IdlArg>,
    #[serde(default)]
    pub discriminator: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountItem {
    pub name: String,
    #[serde(rename = "isMut")]
    pub is_mut: bool,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
    #[serde(default)]
    pub pda: Option<IdlPda>,
    #[serde(default)]
    pub desc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlPda {
    #[serde(default)]
    pub seeds: Vec<IdlSeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlSeed {
    pub kind: String,
    #[serde(default)]
    pub value: Option<Vec<u8>>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlArg {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountDef {
    pub name: String,
    #[serde(default)]
    #[serde(rename = "type")]
    pub ty: IdlTypeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdlTypeKind {
    pub kind: String,
    #[serde(default)]
    pub fields: Vec<IdlField>,
    #[serde(default)]
    pub variants: Vec<IdlEnumVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlEnumVariant {
    pub name: String,
    #[serde(default)]
    pub fields: Option<Vec<IdlField>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlTypeDef {
    pub name: String,
    #[serde(default)]
    #[serde(rename = "type")]
    pub ty: IdlTypeKind,
}

// ── Analysis data structures ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StateInfo {
    pub name: String,
    pub field_names: Vec<String>,
    pub has_init_flag: bool,
    pub has_bump: bool,
    pub has_authority: bool,
    pub has_status_enum: bool,
    pub status_field: Option<String>,
    pub status_variants: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionRole {
    Initializer,
    Mutator,
    Terminator,
    ReadOnly,
}

impl fmt::Display for InstructionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstructionRole::Initializer => write!(f, "INIT"),
            InstructionRole::Mutator => write!(f, "MUT"),
            InstructionRole::Terminator => write!(f, "TERM"),
            InstructionRole::ReadOnly => write!(f, "READ"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstructionInfo {
    pub name: String,
    pub role: InstructionRole,
    pub writable_states: Vec<String>,
    pub readable_states: Vec<String>,
    pub has_signer: bool,
    pub has_pda: bool,
    pub target_accounts: Vec<InstructionAccountInfo>,
}

#[allow(dead_code)]
impl InstructionInfo {
    pub fn is_initializer(&self) -> bool {
        self.role == InstructionRole::Initializer
    }
    pub fn is_mutator(&self) -> bool {
        self.role == InstructionRole::Mutator
    }
    pub fn is_terminator(&self) -> bool {
        self.role == InstructionRole::Terminator
    }
    pub fn is_readonly(&self) -> bool {
        self.role == InstructionRole::ReadOnly
    }
    pub fn is_writable_for(&self, state_name: &str) -> bool {
        self.writable_states.contains(&state_name.to_string())
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InstructionAccountInfo {
    pub name: String,
    pub is_mut: bool,
    pub is_signer: bool,
    pub is_pda: bool,
}

#[derive(Debug, Clone)]
pub struct TransitionEdge {
    pub from_state: String,
    pub to_state: String,
    pub instruction: String,
}

#[derive(Debug, Clone)]
pub struct StateGraph {
    pub account_name: String,
    pub states: Vec<String>,
    pub edges: Vec<TransitionEdge>,
}

// ── IDL parsing ───────────────────────────────────────────────────────────────

pub fn parse_idl(path: &str) -> Result<IdlJson> {
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read IDL file: {path}"))?;
    let idl: IdlJson =
        serde_json::from_str(&content).with_context(|| format!("Failed to parse IDL JSON from: {path}"))?;
    Ok(idl)
}

pub fn find_idl_in_workspace() -> Result<String> {
    let candidates = &["target/idl", "idl", "."];

    for dir in candidates {
        let dir_path = Path::new(dir);
        if dir_path.is_dir()
            && let Ok(entries) = fs::read_dir(dir_path)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json")
                    && let Ok(content) = fs::read_to_string(&path)
                    && serde_json::from_str::<IdlJson>(&content).is_ok()
                {
                    return Ok(path.to_string_lossy().to_string());
                }
            }
        }
    }

    anyhow::bail!("No Anchor IDL found. Specify a path or run from an Anchor workspace with a built IDL in target/idl/")
}

// ── State identification ──────────────────────────────────────────────────────

fn extract_field_type_name(ty: &serde_json::Value) -> String {
    match ty {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(obj) => {
            if let Some(defined) = obj.get("defined") {
                defined.as_str().unwrap_or("unknown").to_string()
            } else if let Some(vec_type) = obj.get("vec") {
                extract_field_type_name(vec_type)
            } else if let Some(opt_type) = obj.get("option") {
                extract_field_type_name(opt_type)
            } else {
                "complex".to_string()
            }
        }
        _ => "unknown".to_string(),
    }
}

fn identify_states(idl: &IdlJson) -> Vec<StateInfo> {
    let enum_types: HashMap<&str, &IdlTypeDef> =
        idl.types.iter().filter(|t| t.ty.kind == "enum").map(|t| (t.name.as_str(), t)).collect();

    let mut states = Vec::new();

    for account in &idl.accounts {
        if account.ty.kind != "struct" {
            continue;
        }

        let field_names: Vec<String> = account.ty.fields.iter().map(|f| f.name.clone()).collect();
        let has_init_flag = field_names.iter().any(|n| {
            let lower = n.to_lowercase();
            lower == "is_initialized" || lower == "initialized" || lower == "isinitialized"
        });
        let has_bump = field_names.iter().any(|n| n == "bump");
        let has_authority =
            field_names.iter().any(|n| n == "authority" || n == "admin" || n == "owner" || n == "governor");

        let mut has_status_enum = false;
        let mut status_field = None;
        let mut status_variants = Vec::new();

        for field in &account.ty.fields {
            let type_name = extract_field_type_name(&field.ty);
            if let Some(enum_def) = enum_types.get(type_name.as_str())
                && (field.name == "status" || field.name == "state" || field.name == "phase" || field.name == "mode")
            {
                has_status_enum = true;
                status_field = Some(field.name.clone());
                status_variants = enum_def.ty.variants.iter().map(|v| v.name.clone()).collect();
            }
        }

        states.push(StateInfo {
            name: account.name.clone(),
            field_names,
            has_init_flag,
            has_bump,
            has_authority,
            has_status_enum,
            status_field,
            status_variants,
        });
    }

    states
}

// ── Instruction categorization ────────────────────────────────────────────────

fn categorize_instructions(idl: &IdlJson, states: &[StateInfo]) -> Vec<InstructionInfo> {
    let state_names_lower: HashSet<String> = states.iter().map(|s| s.name.to_lowercase()).collect();
    let state_name_map: HashMap<String, &str> =
        states.iter().map(|s| (s.name.to_lowercase(), s.name.as_str())).collect();
    let mut instructions = Vec::new();

    for ix in &idl.instructions {
        let name_lower = ix.name.to_lowercase();
        let mut writable_states = Vec::new();
        let mut readable_states = Vec::new();
        let mut has_signer = false;
        let mut has_pda = false;
        let mut target_accounts = Vec::new();

        for acct in &ix.accounts {
            let acct_lower = acct.name.to_lowercase();
            let is_state = state_names_lower.contains(&acct_lower);
            let is_pda = acct.pda.is_some();
            let resolved_name =
                state_name_map.get(&acct_lower).map(|s| s.to_string()).unwrap_or_else(|| acct.name.clone());

            target_accounts.push(InstructionAccountInfo {
                name: resolved_name.clone(),
                is_mut: acct.is_mut,
                is_signer: acct.is_signer,
                is_pda,
            });

            if acct.is_mut && is_state {
                writable_states.push(resolved_name);
            } else if is_state {
                readable_states.push(resolved_name);
            }

            if acct.is_signer {
                has_signer = true;
            }
            if is_pda {
                has_pda = true;
            }
        }

        let role = classify_role(&name_lower, ix, &writable_states);

        instructions.push(InstructionInfo {
            name: ix.name.clone(),
            role,
            writable_states,
            readable_states,
            has_signer,
            has_pda,
            target_accounts,
        });
    }

    instructions
}

fn classify_role(name_lower: &str, _ix: &IdlInstruction, writable_states: &[String]) -> InstructionRole {
    let init_keywords = ["initialize", "init", "create", "new", "open", "setup", "deploy", "register", "mint"];
    let term_keywords = ["close", "delete", "destroy", "remove", "shutdown", "freeze", "terminate", "burn"];

    if init_keywords.iter().any(|kw| name_lower.starts_with(kw) || name_lower.contains(kw)) {
        return InstructionRole::Initializer;
    }

    if term_keywords.iter().any(|kw| name_lower.starts_with(kw) || name_lower.contains(kw)) {
        return InstructionRole::Terminator;
    }

    if !writable_states.is_empty() {
        return InstructionRole::Mutator;
    }

    InstructionRole::ReadOnly
}

// ── Transition graph ──────────────────────────────────────────────────────────

fn build_transition_graph(states: &[StateInfo], instructions: &[InstructionInfo]) -> Vec<StateGraph> {
    let mut graphs = Vec::new();

    for state in states {
        let mut edges = Vec::new();

        for ix in instructions {
            let touches_state = ix.writable_states.contains(&state.name) || ix.readable_states.contains(&state.name);

            if !touches_state {
                continue;
            }

            if state.has_status_enum && !state.status_variants.is_empty() {
                for (i, from_variant) in state.status_variants.iter().enumerate() {
                    let to_variant = if ix.role == InstructionRole::Initializer {
                        if i == 0 { &state.status_variants[0] } else { from_variant }
                    } else if ix.role == InstructionRole::Terminator {
                        state.status_variants.last().unwrap_or(from_variant)
                    } else {
                        from_variant
                    };

                    edges.push(TransitionEdge {
                        from_state: from_variant.clone(),
                        to_state: to_variant.clone(),
                        instruction: ix.name.clone(),
                    });
                }
            } else if state.has_init_flag {
                let from_initialized = "Initialized".to_string();
                let from_uninitialized = "Uninitialized".to_string();

                match ix.role {
                    InstructionRole::Initializer => {
                        edges.push(TransitionEdge {
                            from_state: from_uninitialized.clone(),
                            to_state: from_initialized.clone(),
                            instruction: ix.name.clone(),
                        });
                    }
                    InstructionRole::Terminator => {
                        edges.push(TransitionEdge {
                            from_state: from_initialized.clone(),
                            to_state: "Closed".to_string(),
                            instruction: ix.name.clone(),
                        });
                    }
                    _ => {
                        edges.push(TransitionEdge {
                            from_state: from_initialized.clone(),
                            to_state: from_initialized.clone(),
                            instruction: ix.name.clone(),
                        });
                    }
                }
            } else {
                let base = "Active".to_string();
                match ix.role {
                    InstructionRole::Initializer => {
                        edges.push(TransitionEdge {
                            from_state: "Uninitialized".to_string(),
                            to_state: base.clone(),
                            instruction: ix.name.clone(),
                        });
                    }
                    InstructionRole::Terminator => {
                        edges.push(TransitionEdge {
                            from_state: base.clone(),
                            to_state: "Closed".to_string(),
                            instruction: ix.name.clone(),
                        });
                    }
                    _ => {
                        edges.push(TransitionEdge {
                            from_state: base.clone(),
                            to_state: base.clone(),
                            instruction: ix.name.clone(),
                        });
                    }
                }
            }
        }

        let mut all_states = Vec::new();
        for edge in &edges {
            if !all_states.contains(&edge.from_state) {
                all_states.push(edge.from_state.clone());
            }
            if !all_states.contains(&edge.to_state) {
                all_states.push(edge.to_state.clone());
            }
        }

        graphs.push(StateGraph { account_name: state.name.clone(), states: all_states, edges });
    }

    graphs
}

// ── Analysis checks ───────────────────────────────────────────────────────────

fn check_reinitialization(states: &[StateInfo], instructions: &[InstructionInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let state_map: HashMap<&str, &StateInfo> = states.iter().map(|s| (s.name.as_str(), s)).collect();

    for ix in instructions.iter().filter(|i| i.role == InstructionRole::Initializer) {
        for state_name in &ix.writable_states {
            if let Some(state) = state_map.get(state_name.as_str()) {
                if !state.has_init_flag {
                    if state.has_status_enum && state.status_variants.len() < 2 {
                        continue;
                    }

                    let guard_suggestion = if state.has_bump {
                        format!(
                            "Add an `is_initialized: bool` field to `{}` and check it before writing. \
                             The bump field alone does not prevent reinitialization.",
                            state.name
                        )
                    } else {
                        format!(
                            "Add an `is_initialized: bool` field to `{}` and guard the initialize \
                             instruction with a requires!(!state.is_initialized). Alternatively, \
                             use Anchor's `#[account(init)]` constraint which enforces this automatically.",
                            state.name
                        )
                    };

                    let discriminator_warning = if state.has_bump {
                        " The presence of a bump field suggests PDA derivation, but without an explicit \
                         is_initialized flag or Anchor `init` constraint, the account discriminator check \
                         alone may be bypassed if a different program owns the account."
                    } else {
                        ""
                    };

                    findings.push(Finding {
                        id: format!("SAT-IDL-{:03}", findings.len() + 1),
                        title: format!("Reinitialization Risk: `{}` may overwrite existing `{}`", ix.name, state.name),
                        severity: Severity::Critical,
                        description: format!(
                            "The instruction `{}` is classified as an initializer for `{}`, but `{}` has no \
                             `is_initialized` guard field.{} If this instruction is called on an already-initialized \
                             account, it will overwrite the existing state — a critical vulnerability commonly \
                             exploited in reinitialization attacks.",
                            ix.name, state.name, state.name, discriminator_warning
                        ),
                        location: Some(format!("Instruction: {} → Account: {}", ix.name, state.name)),
                        suggestion: Some(guard_suggestion),
                    });
                } else if !ix.has_pda && !ix.has_signer {
                    findings.push(Finding {
                        id: format!("SAT-IDL-{:03}", findings.len() + 1),
                        title: format!(
                            "Weak Initialization Guard: `{}` initializes `{}` without signer or PDA constraint",
                            ix.name, state.name
                        ),
                        severity: Severity::High,
                        description: format!(
                            "The instruction `{}` initializes `{}` which has an `is_initialized` flag, \
                             but the instruction lacks both a signer requirement and a PDA derivation. \
                             Without authorization, initializations cannot be properly gated.",
                            ix.name, state.name
                        ),
                        location: Some(format!("Instruction: {} → Account: {}", ix.name, state.name)),
                        suggestion: Some(format!(
                            "Add `#[account(init, payer = authority, space = ...)]` to the `{}` account \
                             in the `#[derive(Accounts)]` struct, or restrict initialization to an \
                             admin signer with `#[account(signer)]`.",
                            state.name
                        )),
                    });
                }
            }
        }
    }

    findings
}

fn check_state_lockout(graphs: &[StateGraph], instructions: &[InstructionInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for graph in graphs {
        let mut outgoing: HashMap<&str, Vec<&str>> = HashMap::new();
        for state in &graph.states {
            outgoing.entry(state.as_str()).or_default();
        }
        for edge in &graph.edges {
            outgoing.entry(edge.from_state.as_str()).or_default().push(edge.instruction.as_str());
        }

        for (state, out_ixs) in &outgoing {
            if out_ixs.is_empty() && !state.contains("Closed") && !state.contains("Terminated") {
                let has_transition_in = graph.edges.iter().any(|e| e.to_state == *state);

                if has_transition_in {
                    findings.push(Finding {
                        id: format!("SAT-IDL-{:03}", findings.len() + 1),
                        title: format!(
                            "State Lockout: `{}` in `{}` has no outgoing transitions",
                            state, graph.account_name
                        ),
                        severity: Severity::Medium,
                        description: format!(
                            "The state `{}` in `{}` can be reached but has no instruction defined that \
                             transitions out of it. Once this state is entered, the account becomes \
                             permanently locked — funds may be stranded and governance may be paralyzed.",
                            state, graph.account_name
                        ),
                        location: Some(format!("Account: {} | State: {}", graph.account_name, state)),
                        suggestion: Some(format!(
                            "Add an instruction that transitions `{}` out of the `{}` state, \
                             or ensure this state is explicitly a terminal/closed state.",
                            graph.account_name, state
                        )),
                    });
                }
            }
        }

        let has_uninitialized = graph.states.iter().any(|s| s == "Uninitialized");
        if !has_uninitialized && !graph.states.is_empty() {
            let init_instrs: Vec<&str> = instructions
                .iter()
                .filter(|i| i.role == InstructionRole::Initializer && i.writable_states.contains(&graph.account_name))
                .map(|i| i.name.as_str())
                .collect();

            if init_instrs.is_empty() {
                findings.push(Finding {
                    id: format!("SAT-IDL-{:03}", findings.len() + 1),
                    title: format!("Missing Initializer: `{}` has no initialization path", graph.account_name),
                    severity: Severity::High,
                    description: format!(
                        "The state struct `{}` appears to have no explicit initializer instruction. \
                         This may indicate that initialization happens externally (e.g., via CPI or \
                         program-derived creation) which is harder to audit and may introduce subtle bugs.",
                        graph.account_name
                    ),
                    location: Some(format!("Account: {}", graph.account_name)),
                    suggestion: Some(
                        "Add an explicit initialization instruction or document the external initialization mechanism."
                            .to_string(),
                    ),
                });
            }
        }
    }

    findings
}

fn check_access_control(instructions: &[InstructionInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ix in instructions {
        if ix.role == InstructionRole::ReadOnly {
            continue;
        }

        if ix.writable_states.is_empty() {
            continue;
        }

        if !ix.has_signer {
            let severity = if ix.role == InstructionRole::Terminator { Severity::Critical } else { Severity::High };

            let role_label = match ix.role {
                InstructionRole::Initializer => "initializes",
                InstructionRole::Mutator => "modifies",
                InstructionRole::Terminator => "terminates",
                InstructionRole::ReadOnly => unreachable!(),
            };

            findings.push(Finding {
                id: format!("SAT-IDL-{:03}", findings.len() + 1),
                title: format!(
                    "Missing Access Control: `{}` {} state without signer authorization",
                    ix.name, role_label
                ),
                severity,
                description: format!(
                    "The instruction `{}` {} state accounts ({}) but has no signer requirement. \
                     Without a signer, any caller can invoke this instruction — potentially allowing \
                     unauthorized state modification, fund theft, {}.",
                    ix.name,
                    role_label,
                    ix.writable_states.join(", "),
                    if ix.role == InstructionRole::Terminator {
                        "or denial-of-service via premature account closure"
                    } else {
                        "or privilege escalation"
                    }
                ),
                location: Some(format!("Instruction: {}", ix.name)),
                suggestion: Some(format!(
                    "Add a signer requirement. In the `#[derive(Accounts)]` struct for `{}`, ensure \
                     at least one account has `#[account(signer)]` or `Signer` type, representing \
                     the authorized caller.",
                    ix.name
                )),
            });
        }

        let has_pda_target = ix.target_accounts.iter().any(|a| a.is_pda);
        if !ix.has_signer
            && !has_pda_target
            && ix.writable_states.len() == 1
            && (ix.role == InstructionRole::Mutator || ix.role == InstructionRole::Terminator)
        {
            findings.push(Finding {
                id: format!("SAT-IDL-{:03}", findings.len() + 1),
                title: format!(
                    "Unconstrained Writable: `{}` writes to `{}` without PDA or signer gate",
                    ix.name, ix.writable_states[0]
                ),
                severity: Severity::Medium,
                description: format!(
                    "The instruction `{}` writes to `{}` without requiring either a signer or PDA \
                     derivation. This state can potentially be modified by anyone who can construct \
                     a valid instruction call.",
                    ix.name, ix.writable_states[0]
                ),
                location: Some(format!("Instruction: {} → Account: {}", ix.name, ix.writable_states[0])),
                suggestion: Some(
                    "Consider requiring the state account to be a PDA derived from authorized seeds, \
                     or add a signer-based ownership check."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

fn check_discriminator_collisions(idl: &IdlJson) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: BTreeMap<Vec<u8>, Vec<&str>> = BTreeMap::new();

    for ix in &idl.instructions {
        let preimage = format!("global:{}", ix.name);
        let hash = Sha256::digest(preimage.as_bytes());
        let discriminator: Vec<u8> = hash[..8].to_vec();
        seen.entry(discriminator).or_default().push(&ix.name);
    }

    for (disc, names) in &seen {
        if names.len() > 1 {
            let hex_disc: String = disc.iter().map(|b| format!("{b:02x}")).collect();
            findings.push(Finding {
                id: format!("SAT-IDL-{:03}", findings.len() + 1),
                title: format!(
                    "Anchor Discriminator Collision: instructions {:?} share discriminator 0x{hex_disc}",
                    names
                ),
                severity: Severity::Critical,
                description: format!(
                    "The instructions {:?} produce the same 8-byte Anchor discriminator `0x{hex_disc}` \
                     (sha256(\"global:<instruction_name>\")[0..8]). At runtime, the first matching \
                     instruction handler in the dispatch table will execute — potentially for the wrong \
                     instruction. This is a protocol-level vulnerability.",
                    names
                ),
                location: Some(format!("IDL: {} ({} colliding instructions)", idl.name, names.len())),
                suggestion: Some(
                    "Rename one of the colliding instructions. Even a minor name change will produce \
                     a different discriminator hash."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

// ── Output rendering ──────────────────────────────────────────────────────────

fn render_state_model(states: &[StateInfo]) {
    ui::print_section_header("State Model");
    if states.is_empty() {
        ui::print_warning("No state structs identified in the IDL.");
        return;
    }
    ui::print_notice(&format!("Identified {} state type(s):", states.len()));
    println!();
    for state in states {
        println!("  {} {}", "•".blue(), state.name.bold());
        let mut tags = Vec::new();
        if state.has_init_flag {
            tags.push("init-flag".dimmed());
        }
        if state.has_bump {
            tags.push("bump".dimmed());
        }
        if state.has_authority {
            tags.push("authority".dimmed());
        }
        if state.has_status_enum
            && let Some(ref _status_field) = state.status_field
        {
            tags.push(format!("enum:{}", state.status_variants.join("|")).dimmed());
        }
        if !tags.is_empty() {
            println!("     {}", tags.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(" "));
        }
        let field_list: Vec<String> = state.field_names.iter().map(|f| f.dimmed().to_string()).collect();
        println!("     fields: {}", field_list.join(", "));
    }
    println!();
}

fn render_instruction_classification(instructions: &[InstructionInfo]) {
    ui::print_section_header("Instruction Classification");

    let init: Vec<_> = instructions.iter().filter(|i| i.role == InstructionRole::Initializer).collect();
    let mutes: Vec<_> = instructions.iter().filter(|i| i.role == InstructionRole::Mutator).collect();
    let terms: Vec<_> = instructions.iter().filter(|i| i.role == InstructionRole::Terminator).collect();
    let reads: Vec<_> = instructions.iter().filter(|i| i.role == InstructionRole::ReadOnly).collect();

    if !init.is_empty() {
        println!("{}", "  Initializers:".green().bold());
        for ix in &init {
            let targets = if ix.writable_states.is_empty() {
                "(no state writes)".dimmed().to_string()
            } else {
                ix.writable_states.join(", ")
            };
            let signer_mark = if ix.has_signer { " ✓signer".green() } else { " ✗no-signer".red() };
            println!("    {} {} → {}{}", "•".blue(), ix.name.bold(), targets, signer_mark);
        }
        println!();
    }

    if !mutes.is_empty() {
        println!("{}", "  Mutators:".yellow().bold());
        for ix in &mutes {
            let targets = ix.writable_states.join(", ");
            let signer_mark = if ix.has_signer { " ✓signer".green() } else { " ✗no-signer".red() };
            println!("    {} {} → {}{}", "•".blue(), ix.name.bold(), targets, signer_mark);
        }
        println!();
    }

    if !terms.is_empty() {
        println!("{}", "  Terminators:".red().bold());
        for ix in &terms {
            let targets = ix.writable_states.join(", ");
            let signer_mark = if ix.has_signer { " ✓signer".green() } else { " ✗no-signer".red() };
            println!("    {} {} → {}{}", "•".blue(), ix.name.bold(), targets, signer_mark);
        }
        println!();
    }

    if !reads.is_empty() {
        println!("{}", "  Read-Only:".cyan().bold());
        for ix in &reads {
            let targets = if ix.readable_states.is_empty() {
                "(no state reads)".dimmed().to_string()
            } else {
                ix.readable_states.join(", ")
            };
            println!("    {} {} → {}{}", "•".blue(), ix.name.bold(), targets, "".normal());
        }
        println!();
    }
}

fn render_transition_graph(graphs: &[StateGraph]) {
    ui::print_section_header("Transition Graph");

    if graphs.is_empty() || graphs.iter().all(|g| g.edges.is_empty()) {
        ui::print_notice("No transitions to display (no stateful instructions detected).");
        return;
    }

    for graph in graphs {
        if graph.edges.is_empty() {
            continue;
        }
        println!("{}", format!("  {}:", graph.account_name).bold());

        let mut by_from: HashMap<&str, Vec<&TransitionEdge>> = HashMap::new();
        for edge in &graph.edges {
            by_from.entry(edge.from_state.as_str()).or_default().push(edge);
        }

        for edges in by_from.values() {
            for edge in edges {
                let arrow = if edge.from_state == edge.to_state {
                    format!("  └─[{}]──▶ (self-loop)", edge.instruction).cyan()
                } else {
                    format!("  {} ──[{}]──▶ {}", edge.from_state.dimmed(), edge.instruction, edge.to_state.dimmed())
                        .normal()
                };
                println!("{arrow}");
            }
        }
        println!();
    }
}

fn render_findings(findings: &[Finding]) {
    ui::print_section_header("Findings");

    if findings.is_empty() {
        ui::print_success("No vulnerabilities detected in the IDL analysis.");
        println!();
        ui::print_notice("Note: IDL analysis is structural. Run `sat analyze src` for AST-level validation.");
        return;
    }

    let mut by_severity: BTreeMap<Severity, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_severity.entry(f.severity).or_default().push(f);
    }

    let severity_order = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Informational];

    let mut counter = 0;
    for sev in &severity_order {
        if let Some(group) = by_severity.get(sev) {
            for finding in group {
                counter += 1;
                let tag = ui::severity_tag(finding.severity);
                println!("{} {} {}", format!("#{counter}").dimmed(), tag, finding.title.bold());

                if let Some(ref location) = finding.location {
                    println!("  {} {location}", "📍".dimmed());
                }
                println!();
                println!("  {}", finding.description);

                if let Some(ref suggestion) = finding.suggestion {
                    println!();
                    println!("  {}", "Suggestion:".green().bold());
                    println!("  {suggestion}");
                }
                println!();
            }
        }
    }
}

fn render_summary(findings: &[Finding]) {
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.severity).or_default() += 1;
    }

    let parts: Vec<String> =
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Informational]
            .iter()
            .filter_map(|s| counts.get(s).map(|c| format!("{} {} {}", severity_tag(*s), c, s)))
            .collect();

    let total = findings.len();
    if total == 0 {
        ui::print_success("IDL analysis complete — 0 findings.");
    } else {
        println!(
            "{} {} {}: {}",
            "Summary:".bold(),
            total,
            if total == 1 { "finding" } else { "findings" },
            parts.join(" | ")
        );
    }
    println!();
}

fn severity_tag(severity: Severity) -> String {
    match severity {
        Severity::Critical => "🔴".to_string(),
        Severity::High => "🟠".to_string(),
        Severity::Medium => "🟡".to_string(),
        Severity::Low => "🔵".to_string(),
        Severity::Informational => "⚪".to_string(),
    }
}

// ── Main entry point ──────────────────────────────────────────────────────────

pub fn run(path: Option<&str>) -> Result<()> {
    ui::print_banner();

    let idl_path = match path {
        Some(p) => p.to_string(),
        None => find_idl_in_workspace()?,
    };

    ui::print_notice(&format!("Loading IDL: {idl_path}"));
    let idl = parse_idl(&idl_path)?;

    ui::print_notice(&format!(
        "Program: {} (IDL v{}, {} instructions, {} account types)",
        idl.name.bold(),
        idl.version,
        idl.instructions.len(),
        idl.accounts.len()
    ));

    if let Some(ref meta) = idl.metadata
        && let Some(ref addr) = meta.address
    {
        ui::print_notice(&format!("Program ID: {addr}"));
    }

    let states = identify_states(&idl);
    let instructions = categorize_instructions(&idl, &states);
    let graphs = build_transition_graph(&states, &instructions);

    let mut all_findings: Vec<Finding> = Vec::new();
    all_findings.extend(check_discriminator_collisions(&idl));
    all_findings.extend(check_reinitialization(&states, &instructions));
    all_findings.extend(check_access_control(&instructions));
    all_findings.extend(check_state_lockout(&graphs, &instructions));

    for (i, f) in all_findings.iter_mut().enumerate() {
        f.id = format!("SAT-{:03}", i + 1);
    }

    render_state_model(&states);
    render_instruction_classification(&instructions);
    render_transition_graph(&graphs);
    render_findings(&all_findings);
    render_summary(&all_findings);

    Ok(())
}

// ── Test helper functions (public API for integration tests) ───────────────────

#[allow(dead_code)]
pub fn identify_states_for_test(idl: &IdlJson) -> Vec<StateInfo> {
    identify_states(idl)
}

#[allow(dead_code)]
pub fn categorize_instructions_for_test(idl: &IdlJson, states: &[StateInfo]) -> Vec<InstructionInfo> {
    categorize_instructions(idl, states)
}

#[allow(dead_code)]
pub fn build_graph_for_test(states: &[StateInfo], instructions: &[InstructionInfo]) -> Vec<StateGraph> {
    build_transition_graph(states, instructions)
}

#[allow(dead_code)]
pub fn check_reinit_for_test(states: &[StateInfo], instructions: &[InstructionInfo]) -> Vec<Finding> {
    check_reinitialization(states, instructions)
}

#[allow(dead_code)]
pub fn check_access_for_test(instructions: &[InstructionInfo]) -> Vec<Finding> {
    check_access_control(instructions)
}

#[allow(dead_code)]
pub fn check_lockout_for_test(graphs: &[StateGraph], instructions: &[InstructionInfo]) -> Vec<Finding> {
    check_state_lockout(graphs, instructions)
}

#[allow(dead_code)]
pub fn check_discriminators_for_test(idl: &IdlJson) -> Vec<Finding> {
    check_discriminator_collisions(idl)
}
