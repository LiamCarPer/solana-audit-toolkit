use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::cpi;
use crate::idl::{self, IdlJson};
use crate::sarif;
use crate::token2022;
use crate::types::{Finding, Severity};
use crate::ui;

use crate::{render, serialization, sysvar, tx_report};

// ── Analysis data structures ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AccountsStruct {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
    pub fields: Vec<AccountField>,
}

#[derive(Debug, Clone)]
pub struct AccountField {
    pub name: String,
    pub ty_name: String,
    pub line: usize,
    pub has_signer: bool,
    pub has_mut: bool,
    pub has_init: bool,
    pub has_owner: bool,
    pub has_seeds: bool,
    pub has_one_values: Vec<String>,
    pub owner_value: Option<String>,
    pub is_account_info: bool,
    pub is_unchecked_account: bool,
    pub is_signer_type: bool,
}

#[derive(Debug, Clone)]
pub struct SourceInstruction {
    pub name: String,
    pub program_name: String,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AnalysisContext {
    pub(crate) accounts_structs: Vec<AccountsStruct>,
    pub(crate) instructions: Vec<SourceInstruction>,
    pub(crate) file_count: usize,
    #[allow(dead_code)]
    idl: Option<IdlJson>,
}

// ── Source discovery ──────────────────────────────────────────────────────────

fn discover_source_files(path: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
    {
        files.push(entry.path().to_path_buf());
    }
    files
}

fn find_default_source_path() -> PathBuf {
    for candidate in &["programs", "src", "."] {
        let p = PathBuf::from(candidate);
        if p.is_dir() {
            let has_rs = WalkDir::new(&p)
                .into_iter()
                .filter_map(|e| e.ok())
                .any(|e| e.path().extension().is_some_and(|ext| ext == "rs"));
            if has_rs {
                return p;
            }
        }
    }
    PathBuf::from(".")
}

// ── AST parsing ───────────────────────────────────────────────────────────────

fn parse_rust_file(path: &PathBuf) -> Result<syn::File> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read source file: {}", path.display()))?;
    syn::parse_file(&content).with_context(|| format!("Failed to parse Rust source: {}", path.display()))
}

fn extract_accounts_structs(file: &syn::File, file_path: &Path) -> Vec<AccountsStruct> {
    let mut structs = Vec::new();

    for item in &file.items {
        if let syn::Item::Struct(item_struct) = item {
            let has_accounts_derive = item_struct.attrs.iter().any(|attr| {
                let path = attr.path();
                if let Some(ident) = path.get_ident()
                    && ident == "derive"
                    && let Ok(nested) =
                        attr.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
                {
                    return nested.iter().any(|meta| meta.path().is_ident("Accounts"));
                }
                false
            });

            if !has_accounts_derive {
                continue;
            }

            let mut fields = Vec::new();

            for field in &item_struct.fields {
                let field_name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                let ty_name = type_to_string(&field.ty);

                let mut has_signer = false;
                let mut has_mut = false;
                let mut has_init = false;
                let mut has_owner = false;
                let mut has_seeds = false;
                let mut has_one_values = Vec::new();
                let mut owner_value = None;

                for attr in &field.attrs {
                    if attr.path().is_ident("account") {
                        let parsed = parse_account_attr_v2(attr);
                        has_signer = parsed.flags.contains("signer");
                        has_mut = parsed.flags.contains("mut");
                        has_init = parsed.flags.contains("init");
                        if parsed.key_values.contains_key("seeds") {
                            has_seeds = true;
                        }
                        if let Some(val) = parsed.key_values.get("owner") {
                            has_owner = true;
                            owner_value = Some(val.clone());
                        }
                        if let Some(val) = parsed.key_values.get("has_one") {
                            has_one_values.push(val.clone());
                        }
                    }
                }

                let is_account_info = ty_name.contains("AccountInfo");
                let is_unchecked_account = ty_name.contains("UncheckedAccount");
                let is_signer_type = ty_name.starts_with("Signer");

                fields.push(AccountField {
                    name: field_name,
                    ty_name,
                    line: 0,
                    has_signer,
                    has_mut,
                    has_init,
                    has_owner,
                    has_seeds,
                    has_one_values,
                    owner_value,
                    is_account_info,
                    is_unchecked_account,
                    is_signer_type,
                });
            }

            structs.push(AccountsStruct {
                name: item_struct.ident.to_string(),
                file: file_path.to_path_buf(),
                line: 0,
                fields,
            });
        }
    }

    structs
}

fn extract_instruction_names(file: &syn::File, file_path: &Path) -> Vec<SourceInstruction> {
    let mut instructions = Vec::new();

    for item in &file.items {
        if let syn::Item::Mod(item_mod) = item {
            let has_program_attr = item_mod.attrs.iter().any(|a| a.path().is_ident("program"));
            if !has_program_attr {
                continue;
            }

            let program_name = item_mod.ident.to_string();

            if let Some((_, items)) = &item_mod.content {
                for mod_item in items {
                    if let syn::Item::Fn(func) = mod_item
                        && matches!(func.vis, syn::Visibility::Public(_))
                    {
                        instructions.push(SourceInstruction {
                            name: func.sig.ident.to_string(),
                            program_name: program_name.clone(),
                            file: file_path.to_path_buf(),
                            line: 0,
                        });
                    }
                }
            }
        }
    }

    instructions
}

// ── Attribute parsing ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct AccountAttr {
    flags: HashSet<String>,
    key_values: HashMap<String, String>,
}

fn parse_account_attr_v2(attr: &syn::Attribute) -> AccountAttr {
    let mut flags = HashSet::new();
    let mut key_values = HashMap::new();

    let _ = attr.parse_nested_meta(|meta| {
        let key = meta.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
        if key.is_empty() {
            return Ok(());
        }
        if meta.input.peek(syn::Token![=]) {
            let value: syn::Expr = meta.value()?.parse()?;
            let val_str = expr_to_string(&value);
            key_values.insert(key, val_str);
        } else {
            flags.insert(key);
        }
        Ok(())
    });

    AccountAttr { flags, key_values }
}

fn lit_to_string(lit: &syn::Lit) -> String {
    match lit {
        syn::Lit::Str(s) => s.value(),
        syn::Lit::ByteStr(b) => String::from_utf8_lossy(&b.value()).to_string(),
        syn::Lit::Byte(b) => (b.value() as char).to_string(),
        syn::Lit::Char(c) => c.value().to_string(),
        syn::Lit::Int(i) => i.base10_digits().to_string(),
        syn::Lit::Float(f) => f.base10_digits().to_string(),
        syn::Lit::Bool(b) => b.value().to_string(),
        _ => "{lit}".to_string(),
    }
}

fn expr_to_string(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(expr_path) => {
            expr_path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
        }
        syn::Expr::Lit(lit) => lit_to_string(&lit.lit),
        _ => format!("{expr:?}"),
    }
}

pub(crate) fn type_to_string(ty: &syn::Type) -> String {
    fn format_type(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(type_path) => {
                let path_str: Vec<String> = type_path
                    .path
                    .segments
                    .iter()
                    .map(|seg| {
                        let mut s = seg.ident.to_string();
                        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                            let args_str: Vec<String> = args.args.iter().map(format_generic_arg).collect();
                            s.push_str(&format!("<{}>", args_str.join(", ")));
                        }
                        s
                    })
                    .collect();
                path_str.join("::")
            }
            syn::Type::Reference(type_ref) => {
                let inner = format_type(&type_ref.elem);
                let lifetime =
                    type_ref.lifetime.as_ref().map(|l| format!("&{} ", l.ident)).unwrap_or_else(|| "&".to_string());
                format!("{lifetime}{inner}")
            }
            _ => format!("{ty:?}"),
        }
    }

    fn format_generic_arg(arg: &syn::GenericArgument) -> String {
        match arg {
            syn::GenericArgument::Type(ty) => format_type(ty),
            syn::GenericArgument::Lifetime(lt) => lt.ident.to_string(),
            _ => format!("{arg:?}"),
        }
    }

    format_type(ty)
}

// ── Analysis checks ───────────────────────────────────────────────────────────

fn check_missing_signer(accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let authority_names: HashSet<&str> = [
        "authority",
        "admin",
        "owner",
        "signer",
        "governor",
        "governance_authority",
        "vault_authority",
        "pool_admin",
        "creator",
        "manager",
        "operator",
        "upgrade_authority",
        "mint_authority",
        "freeze_authority",
    ]
    .iter()
    .copied()
    .collect();

    for accts in accounts {
        for field in &accts.fields {
            let name_lower = field.name.to_lowercase();
            let looks_like_authority = authority_names.contains(name_lower.as_str())
                || name_lower.ends_with("_authority")
                || name_lower.ends_with("_admin")
                || name_lower.ends_with("_owner");

            if looks_like_authority && !field.has_signer && !field.is_signer_type && !field.has_seeds {
                let (severity, title_suffix) = if field.has_mut {
                    (Severity::High, "authority field is mutable but not marked as signer")
                } else {
                    (Severity::Medium, "authority field is missing signer constraint")
                };

                findings.push(Finding {
                    id: String::new(),
                    title: format!("Missing Signer: `{}::{}` {}", accts.name, field.name, title_suffix),
                    severity,
                    description: format!(
                        "The field `{}` in `{}` appears to represent an authority but is not constrained \
                         with `#[account(signer)]` and is not of type `Signer<'info>`. Without signer \
                         verification, this account's signature is not enforced, allowing unauthorized \
                         callers to supply arbitrary public keys for this account.",
                        field.name, accts.name
                    ),
                    location: Some(format!("{}:{} ({}::{})", accts.file.display(), field.line, accts.name, field.name)),
                    suggestion: Some(format!(
                        "Add `#[account(signer)]` to the `{}` field or change its type to `Signer<'info>`.",
                        field.name
                    )),
                });
            }
        }
    }

    findings
}

fn check_missing_owner(accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for accts in accounts {
        for field in &accts.fields {
            if !field.is_account_info && !field.is_unchecked_account {
                continue;
            }

            if field.has_init || field.has_signer || field.has_seeds {
                continue;
            }

            // FP filter: skip non-mut AccountInfo/UncheckedAccount fields — these are
            // often read-only references (mint addresses, treasury, etc.) where the
            // program's logic or seeds constraint provides adequate security.
            if !field.has_mut {
                continue;
            }

            if !field.has_owner {
                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Missing Owner Constraint: `{}::{}` is {} without `#[account(owner = ...)]`",
                        accts.name,
                        field.name,
                        if field.is_unchecked_account { "UncheckedAccount" } else { "AccountInfo" }
                    ),
                    severity: Severity::High,
                    description: format!(
                        "The field `{}` in `{}` is typed as `{}` without an explicit `#[account(owner = ...)]` \
                         constraint. Any account owned by any program can be passed here, enabling account \
                         substitution attacks where a malicious actor provides an account owned by a program \
                         they control.",
                        field.name,
                        accts.name,
                        if field.is_unchecked_account { "UncheckedAccount" } else { "AccountInfo" }
                    ),
                    location: Some(format!("{}:{} ({}::{})", accts.file.display(), field.line, accts.name, field.name)),
                    suggestion: Some(format!(
                        "Add `#[account(owner = <PROGRAM_ID>)]` to restrict this account to the expected \
                         program owner, or use a typed `Account<'info, T>` wrapper instead of raw \
                         `{}`.",
                        if field.is_unchecked_account { "UncheckedAccount" } else { "AccountInfo" }
                    )),
                });
            }
        }
    }

    findings
}

fn check_missing_mut(accounts: &[AccountsStruct], idl: Option<&IdlJson>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let idl_writable_map: HashMap<String, HashSet<String>> = if let Some(idl) = idl {
        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        for ix in &idl.instructions {
            for acct in &ix.accounts {
                if acct.is_mut {
                    map.entry(ix.name.clone()).or_default().insert(acct.name.to_lowercase());
                }
            }
        }
        map
    } else {
        return findings;
    };

    for accts in accounts {
        for field in &accts.fields {
            let field_lower = field.name.to_lowercase();
            let mut is_writable = false;
            let mut writing_instructions = Vec::new();

            for (ix_name, writable_fields) in &idl_writable_map {
                if writable_fields.contains(&field_lower) {
                    is_writable = true;
                    writing_instructions.push(ix_name.clone());
                }
            }

            if is_writable && !field.has_mut && !field.has_init {
                if field.is_signer_type || field.is_account_info {
                    continue;
                }

                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Missing `mut` Constraint: `{}::{}` is written to but not declared `#[account(mut)]`",
                        accts.name, field.name
                    ),
                    severity: Severity::High,
                    description: format!(
                        "The field `{}` in `{}` appears to be written to by instruction(s) [{}] \
                         (from the IDL), but is not marked with `#[account(mut)]`. Anchor requires \
                         the `mut` constraint to deserialize the account for writing. Without it, \
                         writes will fail at runtime or the account will be deserialized read-only.",
                        field.name,
                        accts.name,
                        writing_instructions.join(", ")
                    ),
                    location: Some(format!("{}:{} ({}::{})", accts.file.display(), field.line, accts.name, field.name)),
                    suggestion: Some(format!(
                        "Add `#[account(mut)]` to the `{}` field in `{}`.",
                        field.name, accts.name
                    )),
                });
            }
        }
    }

    findings
}

fn check_discriminator_collisions(instructions: &[SourceInstruction]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ix in instructions {
        let preimage = format!("global:{}", ix.name);
        let hash = Sha256::digest(preimage.as_bytes());
        let discriminator: Vec<u8> = hash[..8].to_vec();

        let collisions: Vec<&SourceInstruction> = instructions
            .iter()
            .filter(|other| {
                other.program_name == ix.program_name && other.name != ix.name && {
                    let other_hash = Sha256::digest(format!("global:{}", other.name).as_bytes());
                    other_hash[..8].to_vec() == discriminator
                }
            })
            .collect();

        if !collisions.is_empty() {
            let hex_disc: String = discriminator.iter().map(|b| format!("{b:02x}")).collect();
            let mut names: Vec<&str> = vec![ix.name.as_str()];
            names.extend(collisions.iter().map(|c| c.name.as_str()));
            names.sort();
            names.dedup();

            let title = format!(
                "Anchor Discriminator Collision: instructions {:?} share discriminator 0x{hex_disc} in program `{}`",
                names, ix.program_name
            );

            if !findings.iter().any(|f: &Finding| f.title == title) {
                findings.push(Finding {
                    id: String::new(),
                    title,
                    severity: Severity::Critical,
                    description: format!(
                        "The instructions {:?} produce the same 8-byte Anchor discriminator `0x{hex_disc}` \
                         (sha256(\"global:<instruction_name>\")[0..8]) within program `{}`. At runtime, \
                         the first matching instruction handler in the dispatch table will execute — \
                         potentially for the wrong instruction.",
                        names, ix.program_name
                    ),
                    location: Some(format!("Source: #[program] module `{}`", ix.program_name)),
                    suggestion: Some(
                        "Rename one of the colliding instructions. Even a minor name change will produce \
                         a different discriminator hash."
                            .to_string(),
                    ),
                });
            }
        }
    }

    findings
}

fn check_missing_has_one(accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let authority_signer_names: HashSet<&str> =
        ["authority", "admin", "owner", "creator", "manager", "operator", "governor"].iter().copied().collect();

    for accts in accounts {
        // Collect all Account<T> fields that have `mut` and store has_one values
        let typed_mut_fields: Vec<&AccountField> = accts
            .fields
            .iter()
            .filter(|f| {
                !f.is_account_info
                    && !f.is_unchecked_account
                    && !f.is_signer_type
                    && f.ty_name.starts_with("Account<")
                    && f.has_mut
            })
            .collect();

        if typed_mut_fields.is_empty() {
            continue;
        }

        // Find Signer fields that look like authorities
        let authority_signers: Vec<&AccountField> = accts
            .fields
            .iter()
            .filter(|f| {
                (f.is_signer_type || f.has_signer)
                    && (authority_signer_names.contains(f.name.to_lowercase().as_str())
                        || f.name.to_lowercase().ends_with("_authority")
                        || f.name.to_lowercase().ends_with("_admin")
                        || f.name.to_lowercase().ends_with("_owner"))
            })
            .collect();

        for signer in &authority_signers {
            // Check if ANY Account<T> field has `has_one` referencing this signer
            let has_link = typed_mut_fields
                .iter()
                .any(|f| f.has_one_values.iter().any(|v| v.to_lowercase() == signer.name.to_lowercase()));

            if !has_link {
                // Find which Account<T> field likely stores this authority
                let likely_field = typed_mut_fields.first();

                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Missing `has_one` Constraint: signer `{}` in `{}` is not linked to any Account field",
                        signer.name, accts.name
                    ),
                    severity: Severity::High,
                    description: format!(
                        "The `Signer<'info>` field `{}` in `{}` appears to be an authority (based on its name), \
                         but no `Account<'info, T>` field in this struct has `has_one = {}` to verify that the \
                         stored authority matches the signer. A program that accepts a signer without linking \
                         it to the stored authority via `has_one` cannot guarantee that the caller owns the \
                         account they are modifying. This enables privilege escalation and account substitution attacks.",
                        signer.name, accts.name, signer.name
                    ),
                    location: Some(format!("{}:{} ({}::{})", accts.file.display(), signer.line, accts.name, signer.name)),
                    suggestion: Some(format!(
                        "Add `#[account(mut, has_one = {})]` to the Account field that stores the authority \
                         pubkey (likely `{}`). Or add `#[account(signer)]` if the field is meant to be a \
                         standalone signer without a stored authority.",
                        signer.name,
                        likely_field.map(|f| f.name.as_str()).unwrap_or("<account-field>")
                    )),
                });
            }
        }
    }

    findings
}

fn check_reinit_risk(accounts: &[AccountsStruct], instructions: &[SourceInstruction]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let init_instructions: Vec<&str> = instructions
        .iter()
        .filter(|ix| {
            let name = ix.name.to_lowercase();
            name.starts_with("initialize") || name.starts_with("init_") || name.starts_with("create_")
        })
        .map(|ix| ix.name.as_str())
        .collect();

    if init_instructions.is_empty() {
        return findings;
    }

    for accts in accounts {
        let accts_lower = accts.name.to_lowercase();
        let is_init_struct = accts_lower.contains("init") || accts_lower.contains("create");

        if !is_init_struct {
            continue;
        }

        for field in &accts.fields {
            if field.has_mut && !field.has_init && !field.has_signer && !field.is_signer_type {
                let accts_stripped = accts_lower.replace('_', "");
                let instruction_matches = init_instructions
                    .iter()
                    .any(|ix_name| accts_stripped.contains(&ix_name.to_lowercase().replace('_', "")));

                if !instruction_matches {
                    continue;
                }

                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Reinitialization Risk: `{}::{}` uses `mut` instead of `init`",
                        accts.name, field.name
                    ),
                    severity: Severity::High,
                    description: format!(
                        "The field `{}` in `{}` is marked with `#[account(mut)]` but NOT `#[account(init)]`, \
                         even though this accounts struct appears to be used for initialization. Without \
                         Anchor's `init` constraint, the program does not check whether the account \
                         already exists. An attacker can call the initialization instruction multiple \
                         times, overwriting existing account data and resetting state (e.g., changing \
                         the admin to their own pubkey). This is the vulnerability class behind the \
                         Cashio $50M hack.",
                        field.name, accts.name
                    ),
                    location: Some(format!("{}:{} ({}::{})", accts.file.display(), field.line, accts.name, field.name)),
                    suggestion: Some(format!(
                        "Change `#[account(mut)]` to `#[account(init, payer = {}, space = 8 + ...)]` on \
                         the `{}` field, or add an explicit `is_initialized` check before any state writes.",
                        accts
                            .fields
                            .iter()
                            .find(|f| f.is_signer_type || f.has_signer)
                            .map(|f| f.name.as_str())
                            .unwrap_or("<signer>"),
                        field.name
                    )),
                });
            }
        }
    }

    findings
}

fn check_unsafe_arithmetic(parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (file, path_str) in parsed_files {
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
                            let fn_name = func.sig.ident.to_string();
                            let body = &func.block;
                            find_unsafe_ops_in_block(body, &fn_name, path_str, &mut findings);
                        }
                    }
                }
            }
        }
    }

    findings
}

fn find_unsafe_ops_in_block(block: &syn::Block, fn_name: &str, file: &str, findings: &mut Vec<Finding>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                find_unsafe_ops_in_expr(expr, fn_name, file, findings);
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    find_unsafe_ops_in_expr(&init.expr, fn_name, file, findings);
                }
            }
            _ => {}
        }
    }
}

fn find_unsafe_ops_in_expr(expr: &syn::Expr, fn_name: &str, file: &str, findings: &mut Vec<Finding>) {
    match expr {
        syn::Expr::Binary(binary) => {
            let is_sub_assign = matches!(binary.op, syn::BinOp::SubAssign(_));
            let is_add_assign = matches!(binary.op, syn::BinOp::AddAssign(_));
            let is_sub = matches!(binary.op, syn::BinOp::Sub(_));
            let is_add = matches!(binary.op, syn::BinOp::Add(_));
            let is_mul = matches!(binary.op, syn::BinOp::Mul(_));
            let is_mul_assign = matches!(binary.op, syn::BinOp::MulAssign(_));

            let lhs_str = expr_to_string_v2(&binary.left);
            let rhs_str = expr_to_string_v2(&binary.right);

            if is_sub_assign || is_add_assign || is_sub || is_add {
                let op_str = if is_sub_assign || is_sub { "-" } else { "+" };
                let op_form = if is_sub_assign || is_add_assign { "=" } else { "" };
                let is_assign = is_sub_assign || is_add_assign;

                findings.push(Finding {
                    id: String::new(),
                    title: format!("Unsafe Arithmetic: `{op_str}{op_form}` in `{fn_name}` — use checked_*() instead",),
                    severity: Severity::High,
                    description: format!(
                        "The expression `{lhs_str}` uses `{op_str}{op_form}` on a field in `{fn_name}`. \
                         In release mode (optimized builds), Rust arithmetic wraps \
                         on overflow instead of panicking. Use `checked_sub()`, \
                         `checked_add()`, or `overflow-checks = true` instead.",
                    ),
                    location: Some(format!("{file}:0")),
                    suggestion: Some(if is_assign {
                        "Replace with `.checked_sub(amount).ok_or(Error::Underflow)?` or \
                             `.checked_add(amount).ok_or(Error::Overflow)?`."
                            .to_string()
                    } else {
                        "Use `checked_sub()` or `checked_add()` instead of the raw operator.".to_string()
                    }),
                });
            }

            if (is_mul || is_mul_assign) && !lhs_str.is_empty() && !rhs_str.is_empty() {
                findings.push(Finding {
                    id: String::new(),
                    title: format!("Unsafe Multiplication: possible overflow in `{}`", fn_name),
                    severity: Severity::Medium,
                    description: format!(
                        "The expression `{}` in `{}` may overflow if both operands are large. \
                         Use `checked_mul()` and chain with `checked_div()`.",
                        lhs_str, fn_name
                    ),
                    location: Some(format!("{}:{}", file, 0)),
                    suggestion: Some(
                        "Use `.checked_mul(other)?.checked_div(10000)?` for fee calculations, \
                         or upcast to u128 for intermediate results."
                            .to_string(),
                    ),
                });
            }
        }
        syn::Expr::If(if_expr) => {
            find_unsafe_ops_in_expr(&if_expr.cond, fn_name, file, findings);
            find_unsafe_ops_in_block(&if_expr.then_branch, fn_name, file, findings);
            if let Some((_, else_expr)) = &if_expr.else_branch {
                find_unsafe_ops_in_expr(else_expr, fn_name, file, findings);
            }
        }
        syn::Expr::Block(block_expr) => {
            find_unsafe_ops_in_block(&block_expr.block, fn_name, file, findings);
        }
        syn::Expr::ForLoop(for_loop) => {
            find_unsafe_ops_in_block(&for_loop.body, fn_name, file, findings);
        }
        syn::Expr::While(while_loop) => {
            find_unsafe_ops_in_block(&while_loop.body, fn_name, file, findings);
        }
        syn::Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                if let Some((_, guard_expr)) = &arm.guard {
                    find_unsafe_ops_in_expr(guard_expr, fn_name, file, findings);
                }
                find_unsafe_ops_in_expr(&arm.body, fn_name, file, findings);
            }
        }
        syn::Expr::Call(call) => {
            for arg in &call.args {
                find_unsafe_ops_in_expr(arg, fn_name, file, findings);
            }
        }
        _ => {}
    }
}

fn expr_to_string_v2(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(expr_path) => {
            expr_path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
        }
        syn::Expr::Field(field) => {
            let base = expr_to_string_v2(&field.base);
            let member = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            format!("{}.{}", base, member)
        }
        syn::Expr::Lit(lit) => lit_to_string(&lit.lit),
        syn::Expr::Paren(paren) => format!("({})", expr_to_string_v2(&paren.expr)),
        syn::Expr::Binary(binary) => {
            format!("{} {:?} {}", expr_to_string_v2(&binary.left), binary.op, expr_to_string_v2(&binary.right))
        }
        syn::Expr::Unary(unary) => {
            format!("{:?}{}", unary.op, expr_to_string_v2(&unary.expr))
        }
        syn::Expr::MethodCall(method) => {
            format!("{}.{}()", expr_to_string_v2(&method.receiver), method.method)
        }
        syn::Expr::Cast(cast) => {
            format!("{} as {}", expr_to_string_v2(&cast.expr), type_to_string(&cast.ty))
        }
        _ => format!("{expr:?}"),
    }
}

pub fn run(path: Option<&str>, format: &str, tx_report: Option<&str>) -> Result<()> {
    ui::print_banner();

    if format != "text" && format != "sarif" {
        ui::print_warning(&format!("Unknown format '{}', defaulting to text.", format));
    }

    let src_path = path.map(PathBuf::from).unwrap_or_else(find_default_source_path);
    ui::print_notice(&format!("Source path: {}", src_path.display()));

    if let Some(report) = tx_report {
        ui::print_notice(&format!("Transaction report: {report}"));
    }

    let source_files = discover_source_files(&src_path.to_string_lossy());
    if source_files.is_empty() {
        ui::print_warning("No Rust source files found. Is this an Anchor workspace?");
        return Ok(());
    }

    ui::print_notice(&format!("Scanning {} source file(s)...", source_files.len()));

    let mut all_accounts = Vec::new();
    let mut all_instructions = Vec::new();
    let mut parsed_files: Vec<(syn::File, String)> = Vec::new();
    let mut file_count = 0;

    for file_path in &source_files {
        let path_str = file_path.to_string_lossy().to_string();
        let parsed = match parse_rust_file(file_path) {
            Ok(f) => f,
            Err(e) => {
                ui::print_warning(&format!("Skipping {}: {e}", file_path.display()));
                continue;
            }
        };

        file_count += 1;
        all_accounts.extend(extract_accounts_structs(&parsed, file_path));
        all_instructions.extend(extract_instruction_names(&parsed, file_path));
        parsed_files.push((parsed, path_str));
    }

    let idl = idl::find_idl_in_workspace().ok().and_then(|p| idl::parse_idl(&p).ok());

    let mut all_findings: Vec<Finding> = Vec::new();

    let ix_name_strings: Vec<String> = all_instructions.iter().map(|i| i.name.clone()).collect();
    all_findings.extend(check_missing_signer(&all_accounts));
    all_findings.extend(check_missing_owner(&all_accounts));
    all_findings.extend(check_missing_mut(&all_accounts, idl.as_ref()));
    all_findings.extend(check_discriminator_collisions(&all_instructions));
    all_findings.extend(check_missing_has_one(&all_accounts));
    all_findings.extend(check_reinit_risk(&all_accounts, &all_instructions));
    all_findings.extend(check_unsafe_arithmetic(&parsed_files));
    all_findings.extend(cpi::analyze_cpi_depth(&parsed_files, &ix_name_strings));
    all_findings.extend(sysvar::check_sysvar_misuse(&parsed_files, &all_accounts));
    all_findings.extend(serialization::check_serialization_mismatch(&parsed_files));
    all_findings.extend(token2022::analyze(&src_path, &parsed_files, &all_accounts));

    if let Some(report_path) = tx_report {
        all_findings.extend(tx_report::check_tx_report_correlation(&all_accounts, report_path));
    }

    for (i, f) in all_findings.iter_mut().enumerate() {
        f.id = format!("SAT-{:03}", i + 1);
    }

    let ctx = AnalysisContext { accounts_structs: all_accounts, instructions: all_instructions, file_count, idl };

    if format == "sarif" {
        let output_path = "sat-results.sarif";
        sarif::export_sarif(&all_findings, "program", output_path)?;
        ui::print_success(&format!("Exported {} finding(s) to {output_path}", all_findings.len()));
        return Ok(());
    }

    render::render_accounts_summary(&ctx);
    render::render_instructions_summary(&ctx);
    render::render_findings(&all_findings);
    render::render_summary(&all_findings);

    Ok(())
}

// ── Test helpers ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn analyze_string_for_test(source: &str) -> (Vec<AccountsStruct>, Vec<SourceInstruction>, Vec<Finding>) {
    let parsed = syn::parse_file(source).expect("test source should parse");
    let path = PathBuf::from("test.rs");
    let accounts = extract_accounts_structs(&parsed, &path);
    let instructions = extract_instruction_names(&parsed, &path);
    let mut findings = Vec::new();
    findings.extend(check_missing_signer(&accounts));
    findings.extend(check_missing_owner(&accounts));
    findings.extend(check_discriminator_collisions(&instructions));
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = format!("SAT-{:03}", i + 1);
    }
    (accounts, instructions, findings)
}
