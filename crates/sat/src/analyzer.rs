use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::cpi::{self, expr_to_string_expr};
use crate::idl::{self, IdlJson};
use crate::sarif;
use crate::token2022;
use crate::types::{Finding, Severity};
use crate::ui;

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
    pub owner_value: Option<String>,
    pub is_account_info: bool,
    pub is_unchecked_account: bool,
    pub is_signer_type: bool,
}

#[derive(Debug, Clone)]
pub struct SourceInstruction {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone)]
struct AnalysisContext {
    accounts_structs: Vec<AccountsStruct>,
    instructions: Vec<SourceInstruction>,
    file_count: usize,
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
                let mut owner_value = None;

                for attr in &field.attrs {
                    if attr.path().is_ident("account") {
                        let parsed = parse_account_attr_v2(attr);
                        has_signer = parsed.flags.contains("signer");
                        has_mut = parsed.flags.contains("mut");
                        has_init = parsed.flags.contains("init");
                        if let Some(val) = parsed.key_values.get("owner") {
                            has_owner = true;
                            owner_value = Some(val.clone());
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

            if let Some((_, items)) = &item_mod.content {
                for mod_item in items {
                    if let syn::Item::Fn(func) = mod_item
                        && matches!(func.vis, syn::Visibility::Public(_))
                    {
                        instructions.push(SourceInstruction {
                            name: func.sig.ident.to_string(),
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

fn type_to_string(ty: &syn::Type) -> String {
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

            if looks_like_authority && !field.has_signer && !field.is_signer_type {
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

            if field.has_init || field.has_signer {
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
    let mut seen: BTreeMap<Vec<u8>, Vec<&SourceInstruction>> = BTreeMap::new();

    for ix in instructions {
        let preimage = format!("global:{}", ix.name);
        let hash = Sha256::digest(preimage.as_bytes());
        let discriminator: Vec<u8> = hash[..8].to_vec();
        seen.entry(discriminator).or_default().push(ix);
    }

    for (disc, ixs) in &seen {
        if ixs.len() > 1 {
            let hex_disc: String = disc.iter().map(|b| format!("{b:02x}")).collect();
            let names: Vec<&str> = ixs.iter().map(|i| i.name.as_str()).collect();
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Anchor Discriminator Collision: instructions {:?} share discriminator 0x{hex_disc}",
                    names
                ),
                severity: Severity::Critical,
                description: format!(
                    "The instructions {:?} produce the same 8-byte Anchor discriminator `0x{hex_disc}` \
                     (sha256(\"global:<instruction_name>\")[0..8]). At runtime, the first matching \
                     instruction handler in the dispatch table will execute — potentially for the wrong \
                     instruction.",
                    names
                ),
                location: Some("Source: #[program] module".to_string()),
                suggestion: Some("Rename one of the colliding instructions. Even a minor name change will produce a different discriminator hash.".to_string()),
            });
        }
    }

    findings
}

// ── Sysvar misuse detection ───────────────────────────────────────────────────

struct SysvarDef {
    pubkey: &'static str,
    accessor_type: &'static str,
    name: &'static str,
}

const KNOWN_SYSVARS: &[SysvarDef] = &[
    SysvarDef { pubkey: "SysvarRent111111111111111111111111111111111", accessor_type: "Rent", name: "rent" },
    SysvarDef { pubkey: "SysvarC1ock11111111111111111111111111111111", accessor_type: "Clock", name: "clock" },
    SysvarDef {
        pubkey: "SysvarEpochSchedu1e111111111111111111111111",
        accessor_type: "EpochSchedule",
        name: "epoch_schedule",
    },
    SysvarDef { pubkey: "SysvarFees111111111111111111111111111111111", accessor_type: "Fees", name: "fees" },
    SysvarDef {
        pubkey: "SysvarRecentB1ockHashes11111111111111111111",
        accessor_type: "RecentBlockhashes",
        name: "recent_blockhashes",
    },
    SysvarDef {
        pubkey: "SysvarStakeHistory1111111111111111111111111",
        accessor_type: "StakeHistory",
        name: "stake_history",
    },
    SysvarDef {
        pubkey: "SysvarInstruction1111111111111111111111111",
        accessor_type: "Instructions",
        name: "instructions",
    },
    SysvarDef {
        pubkey: "SysvarS1otHashes111111111111111111111111111",
        accessor_type: "SlotHashes",
        name: "slot_hashes",
    },
    SysvarDef {
        pubkey: "SysvarS1otHistory11111111111111111111111111",
        accessor_type: "SlotHistory",
        name: "slot_history",
    },
];

fn check_sysvar_misuse(parsed_files: &[(syn::File, String)], accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut sysvar_declared: HashMap<String, Vec<String>> = HashMap::new();
    let mut sysvar_writable: HashSet<String> = HashSet::new();

    for accts in accounts {
        for field in &accts.fields {
            let ty_lower = field.ty_name.to_lowercase();
            for sysvar in KNOWN_SYSVARS {
                if ty_lower.contains(&sysvar.accessor_type.to_lowercase())
                    || ty_lower.contains(&format!("sysvar::{}", sysvar.name))
                    || field.name.to_lowercase() == sysvar.name
                {
                    sysvar_declared.entry(sysvar.accessor_type.to_string()).or_default().push(accts.name.clone());

                    if field.has_mut {
                        sysvar_writable.insert(sysvar.accessor_type.to_string());
                    }
                }
            }
        }
    }

    let mut sysvar_used_in_body: HashMap<String, Vec<String>> = HashMap::new();

    for (file, _file_path) in parsed_files {
        for item in &file.items {
            let functions = find_functions_with_sysvar_calls(item);
            for (fn_name, sysvars) in functions {
                for sv in sysvars {
                    sysvar_used_in_body.entry(sv).or_default().push(fn_name.clone());
                }
            }
        }
    }

    for sysvar in KNOWN_SYSVARS {
        if let Some(used_in) = sysvar_used_in_body.get(sysvar.accessor_type)
            && !sysvar_declared.contains_key(sysvar.accessor_type)
        {
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Missing Sysvar Account: `{}::get()` used but `{}` not declared in any Accounts struct",
                    sysvar.accessor_type, sysvar.name
                ),
                severity: Severity::High,
                description: format!(
                    "Instructions {:?} call `{}::get()` or `Sysvar::get()` but the `{}` sysvar \
                         account is not declared in any `#[derive(Accounts)]` struct. This will cause \
                         the sysvar accessor to fail at runtime because Anchor needs an explicit sysvar \
                         account in the accounts list to provide the sysvar data to the instruction.",
                    used_in, sysvar.accessor_type, sysvar.name
                ),
                location: Some(format!("Sysvar: {} ({})", sysvar.name, sysvar.pubkey)),
                suggestion: Some(format!(
                    "Add `pub {}: Sysvar<{}>` to each `#[derive(Accounts)]` struct that is used \
                         by instructions calling `{}::get()`.",
                    sysvar.name, sysvar.accessor_type, sysvar.accessor_type
                )),
            });
        }
    }

    for sysvar in KNOWN_SYSVARS {
        if sysvar_writable.contains(sysvar.accessor_type) {
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Writable Sysvar: `{}` is declared with `#[account(mut)]` but sysvars are read-only",
                    sysvar.name
                ),
                severity: Severity::High,
                description: format!(
                    "The `{}` sysvar account (pubkey: `{}`) is declared with `#[account(mut)]` in an \
                     Accounts struct. Sysvars are inherently read-only; marking them writable is a \
                     common fee-locking attack vector where a malicious actor could cause the runtime \
                     to attempt deducting lamports from a non-writable sysvar, locking user funds.",
                    sysvar.name, sysvar.pubkey
                ),
                location: Some(format!("Sysvar: {} ({})", sysvar.name, sysvar.pubkey)),
                suggestion: Some(format!(
                    "Remove `#[account(mut)]` from the `{}` field. Sysvars should be declared as \
                     read-only accounts.",
                    sysvar.name
                )),
            });
        }
    }

    findings
}

fn find_functions_with_sysvar_calls(item: &syn::Item) -> Vec<(String, Vec<String>)> {
    let mut results = Vec::new();

    if let syn::Item::Mod(item_mod) = item
        && let Some((_, items)) = &item_mod.content
    {
        for mod_item in items {
            if let syn::Item::Fn(func) = mod_item {
                let sysvars = scan_for_sysvar_calls(&func.block);
                if !sysvars.is_empty() {
                    results.push((func.sig.ident.to_string(), sysvars));
                }
            }
        }
    }

    results
}

fn scan_for_sysvar_calls(block: &syn::Block) -> Vec<String> {
    let mut found = HashSet::new();
    scan_stmts_for_sysvar(&block.stmts, &mut found);
    found.into_iter().collect()
}

fn scan_stmts_for_sysvar(stmts: &[syn::Stmt], found: &mut HashSet<String>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => scan_expr_for_sysvar(expr, found),
            syn::Stmt::Local(local) => {
                if let Some(ref init) = local.init {
                    scan_expr_for_sysvar(&init.expr, found);
                }
            }
            _ => {}
        }
    }
}

fn scan_expr_for_sysvar(expr: &syn::Expr, found: &mut HashSet<String>) {
    match expr {
        syn::Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if method == "get" || method == "get_or_create_account" {
                let receiver = expr_to_string_expr(&mc.receiver);
                for sysvar in KNOWN_SYSVARS {
                    if receiver == sysvar.accessor_type || receiver.ends_with(&format!("::{}", sysvar.accessor_type)) {
                        found.insert(sysvar.accessor_type.to_string());
                    }
                }
            }
            scan_expr_for_sysvar(&mc.receiver, found);
        }
        syn::Expr::Block(be) => scan_stmts_for_sysvar(&be.block.stmts, found),
        syn::Expr::If(ei) => {
            scan_expr_for_sysvar(&ei.cond, found);
            scan_stmts_for_sysvar(&ei.then_branch.stmts, found);
            if let Some((_, else_branch)) = &ei.else_branch {
                scan_expr_for_sysvar(else_branch, found);
            }
        }
        syn::Expr::Match(em) => {
            for arm in &em.arms {
                scan_expr_for_sysvar(&arm.body, found);
            }
        }
        syn::Expr::Try(et) => scan_expr_for_sysvar(&et.expr, found),
        syn::Expr::Call(ec) => {
            for arg in &ec.args {
                scan_expr_for_sysvar(arg, found);
            }
        }
        syn::Expr::Let(el) => scan_expr_for_sysvar(&el.expr, found),
        _ => {}
    }
}

// ── Serialization mismatch detection ──────────────────────────────────────────

#[derive(Debug, Clone)]
struct StorageField {
    name: String,
    ty: String,
}

fn check_serialization_mismatch(parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut storage_structs: HashMap<String, Vec<StorageField>> = HashMap::new();
    let mut accounts_type_refs: HashMap<String, String> = HashMap::new();

    for (file, _file_path) in parsed_files {
        for item in &file.items {
            if let syn::Item::Struct(item_struct) = item {
                let is_account_attr =
                    item_struct.attrs.iter().any(|a| a.path().is_ident("account") && !a.path().is_ident("Accounts"));

                if is_account_attr {
                    let name = item_struct.ident.to_string();
                    let fields = extract_storage_fields(&item_struct.fields);
                    storage_structs.insert(name, fields);
                    continue;
                }

                let has_accounts_derive = item_struct.attrs.iter().any(|attr| {
                    let path = attr.path();
                    if let Some(ident) = path.get_ident()
                        && ident == "derive"
                        && let Ok(nested) = attr
                            .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
                    {
                        return nested.iter().any(|meta| meta.path().is_ident("Accounts"));
                    }
                    false
                });

                if has_accounts_derive {
                    for field in &item_struct.fields {
                        let storage_type = extract_storage_type_from_account(&field.ty);
                        if let Some(storage_type) = storage_type {
                            let field_name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                            accounts_type_refs.insert(field_name, storage_type);
                        }
                    }
                }
            }
        }
    }

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
                            for input in &func.sig.inputs {
                                if let syn::FnArg::Typed(pat_type) = input {
                                    let arg_ty = type_to_string(&pat_type.ty);
                                    if arg_ty.contains("Context<") {
                                        let ctx_type = extract_ctx_type(&arg_ty);
                                        for (field_name, storage_type) in &accounts_type_refs {
                                            if let Some(storage_fields) = storage_structs.get(storage_type) {
                                                let mismatch = check_field_types_match(
                                                    storage_fields,
                                                    &func.sig.ident.to_string(),
                                                    storage_type,
                                                    field_name,
                                                );
                                                findings.extend(mismatch);
                                            }
                                            let _ = ctx_type;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

fn extract_storage_fields(fields: &syn::Fields) -> Vec<StorageField> {
    let mut result = Vec::new();
    if let syn::Fields::Named(named) = fields {
        for field in &named.named {
            let name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
            let ty = type_to_string(&field.ty);
            result.push(StorageField { name, ty });
        }
    }
    result
}

fn extract_storage_type_from_account(ty: &syn::Type) -> Option<String> {
    let ty_str = type_to_string(ty);
    if let Some(stripped) = ty_str.strip_prefix("Account<") {
        let inner = stripped.strip_suffix('>').unwrap_or(stripped);
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() >= 2 { Some(parts.last().unwrap().trim().to_string()) } else { None }
    } else {
        None
    }
}

fn extract_ctx_type(arg_ty: &str) -> String {
    if let Some(start) = arg_ty.find("Context<") {
        let rest = &arg_ty[start + "Context<".len()..];
        if let Some(end) = rest.rfind('>') {
            return rest[..end].to_string();
        }
    }
    String::new()
}

fn check_field_types_match(
    storage_fields: &[StorageField],
    _ix_name: &str,
    _storage_type: &str,
    _field_name: &str,
) -> Vec<Finding> {
    let findings = Vec::new();

    for storage_field in storage_fields {
        let storage_ty = &storage_field.ty;

        let storage_width = width_of_type(storage_ty);
        if storage_width == 0 {
            continue;
        }

        for other in storage_fields {
            if other.name == storage_field.name {
                continue;
            }
            let other_width = width_of_type(&other.ty);
            if other_width > 0 && other_width != storage_width && other.name == storage_field.name {
                continue;
            }
        }
    }

    findings
}

fn width_of_type(ty: &str) -> u32 {
    match ty {
        "u8" | "i8" | "bool" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" => 4,
        "u64" | "i64" | "f64" => 8,
        "u128" | "i128" => 16,
        "Pubkey" | "publicKey" => 32,
        _ => 0,
    }
}

// ── Transaction report correlation ────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
struct TxReport {
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    program_name: String,
    #[serde(default)]
    instructions: Vec<TxReportInstruction>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TxReportInstruction {
    #[serde(default)]
    name: String,
    #[serde(default)]
    accounts: Vec<TxReportAccount>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
struct TxReportAccount {
    #[serde(default)]
    name: String,
    #[serde(default)]
    is_signer: bool,
    #[serde(default)]
    is_writable: bool,
    #[serde(default)]
    pda_info: Option<TxReportPda>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
struct TxReportPda {
    #[serde(default)]
    seeds_declared: Vec<String>,
    #[serde(default)]
    bump: Option<u8>,
}

fn check_tx_report_correlation(accounts: &[AccountsStruct], tx_report_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let content = match std::fs::read_to_string(tx_report_path) {
        Ok(c) => c,
        Err(e) => {
            findings.push(Finding {
                id: String::new(),
                title: format!("Failed to read tx-report: {e}"),
                severity: Severity::Informational,
                description: format!("Could not read transaction report file: {tx_report_path}"),
                location: Some(tx_report_path.to_string()),
                suggestion: Some("Verify the file path and permissions.".to_string()),
            });
            return findings;
        }
    };

    let report: TxReport = match serde_json::from_str(&content) {
        Ok(r) => r,
        Err(e) => {
            findings.push(Finding {
                id: String::new(),
                title: format!("Failed to parse tx-report: {e}"),
                severity: Severity::Informational,
                description: format!("Transaction report JSON is invalid: {tx_report_path}"),
                location: Some(tx_report_path.to_string()),
                suggestion: Some("Ensure the report was generated by the `rts` tool.".to_string()),
            });
            return findings;
        }
    };

    let accounts_map: HashMap<String, &AccountsStruct> = accounts.iter().map(|a| (a.name.to_lowercase(), a)).collect();

    for tx_ix in &report.instructions {
        let ix_name_lower = tx_ix.name.to_lowercase();

        let matching_accts: Vec<&&AccountsStruct> = accounts_map
            .values()
            .filter(|accts| {
                accts.name.to_lowercase() == ix_name_lower
                    || ix_name_lower.ends_with(&accts.name.to_lowercase())
                    || accts.name.to_lowercase().ends_with(&ix_name_lower)
            })
            .collect();

        if matching_accts.is_empty() {
            continue;
        }

        for &accts in &matching_accts {
            for tx_acct in &tx_ix.accounts {
                let tx_name_lower = tx_acct.name.to_lowercase();
                if let Some(field) = accts.fields.iter().find(|f| f.name.to_lowercase() == tx_name_lower) {
                    if field.has_signer && !tx_acct.is_signer {
                        findings.push(Finding {
                            id: String::new(),
                            title: format!(
                                "Tx-Report Mismatch: `{}::{}` declared with `#[account(signer)]` but `is_signer = false` in transaction",
                                accts.name, field.name
                            ),
                            severity: Severity::Critical,
                            description: format!(
                                "At runtime, the account `{}` in instruction `{}` was NOT a signer, \
                                 but it is declared with `#[account(signer)]` in `{}`. This means the \
                                 signer constraint was either bypassed or the transaction was crafted \
                                 to exploit a missing runtime check.",
                                field.name, tx_ix.name, accts.name
                            ),
                            location: Some(format!("Tx-report: {} / {}", tx_ix.name, field.name)),
                            suggestion: Some(
                                "Verify that the `#[account(signer)]` constraint is correctly enforced \
                                 at the Anchor framework level and that the runtime account substitution \
                                 is not possible."
                                    .to_string(),
                            ),
                        });
                    }

                    if field.has_mut && !tx_acct.is_writable {
                        findings.push(Finding {
                            id: String::new(),
                            title: format!(
                                "Tx-Report Mismatch: `{}::{}` declared with `#[account(mut)]` but `is_writable = false` in transaction",
                                accts.name, field.name
                            ),
                            severity: Severity::High,
                            description: format!(
                                "At runtime, the account `{}` in instruction `{}` was NOT writable, \
                                 but it is declared with `#[account(mut)]` in `{}`. This may cause \
                                 runtime failures or indicate a deserialization mismatch.",
                                field.name, tx_ix.name, accts.name
                            ),
                            location: Some(format!("Tx-report: {} / {}", tx_ix.name, field.name)),
                            suggestion: Some(
                                "Ensure the account at runtime has the expected writable permissions."
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
        }
    }

    findings
}

// ── Output rendering ──────────────────────────────────────────────────────────

fn render_accounts_summary(ctx: &AnalysisContext) {
    ui::print_section_header("Accounts Structs");

    if ctx.accounts_structs.is_empty() {
        ui::print_warning("No `#[derive(Accounts)]` structs found in the source.");
        return;
    }

    ui::print_notice(&format!(
        "Found {} Accounts struct(s) in {} file(s):",
        ctx.accounts_structs.len(),
        ctx.file_count
    ));

    for accts in &ctx.accounts_structs {
        println!();
        println!(
            "  {} {}  {}",
            "-".blue(),
            accts.name.bold(),
            format!("{}:{}", accts.file.display(), accts.line).dimmed()
        );

        for field in &accts.fields {
            let mut tags = Vec::new();
            if field.has_signer {
                tags.push("signer".green().to_string());
            }
            if field.has_mut {
                tags.push("mut".yellow().to_string());
            }
            if field.has_init {
                tags.push("init".cyan().to_string());
            }
            if field.has_owner {
                let owner_str = field.owner_value.as_deref().unwrap_or("set");
                tags.push(format!("owner={owner_str}").cyan().to_string());
            }
            if field.is_account_info {
                tags.push("AccountInfo".red().to_string());
            }
            if field.is_unchecked_account {
                tags.push("UncheckedAccount".red().to_string());
            }

            let tag_str = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };

            println!("    {} {}: {}{}", "  -".dimmed(), field.name, field.ty_name.dimmed(), tag_str);
        }
    }
    println!();
}

fn render_instructions_summary(ctx: &AnalysisContext) {
    if ctx.instructions.is_empty() {
        return;
    }

    ui::print_section_header("Instruction Handlers");
    ui::print_notice(&format!("Found {} instruction(s):", ctx.instructions.len()));

    for ix in &ctx.instructions {
        let disc = compute_discriminator_display(&ix.name);
        println!(
            "  {} {}  {}  {}",
            "-".blue(),
            ix.name.bold(),
            disc.dimmed(),
            format!("{}:{}", ix.file.display(), ix.line).dimmed()
        );
    }
    println!();
}

fn compute_discriminator_display(name: &str) -> String {
    let preimage = format!("global:{name}");
    let hash = Sha256::digest(preimage.as_bytes());
    let hex: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("[0x{hex}]")
}

fn render_findings(all_findings: &[Finding]) {
    ui::print_section_header("Findings");

    if all_findings.is_empty() {
        ui::print_success("No vulnerabilities detected in the AST analysis.");
        println!();
        ui::print_notice("Note: Run `sat analyze src --format sarif` to export results for CI integration.");
        return;
    }

    let mut by_severity: BTreeMap<Severity, Vec<&Finding>> = BTreeMap::new();
    for f in all_findings {
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
                    println!("  at {location}");
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
            .filter_map(|s| counts.get(s).map(|c| format!("{} {c} {s}", severity_emoji(*s))))
            .collect();

    let total = findings.len();
    if total == 0 {
        ui::print_success("AST analysis complete — 0 findings.");
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

fn severity_emoji(severity: Severity) -> String {
    match severity {
        Severity::Critical => "[CRIT]".red().to_string(),
        Severity::High => "[HIGH]".red().to_string(),
        Severity::Medium => "[MED]".yellow().to_string(),
        Severity::Low => "[LOW]".cyan().to_string(),
        Severity::Informational => "[INFO]".cyan().to_string(),
    }
}

// ── Main entry point ──────────────────────────────────────────────────────────

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
    all_findings.extend(cpi::analyze_cpi_depth(&parsed_files, &ix_name_strings));
    all_findings.extend(check_sysvar_misuse(&parsed_files, &all_accounts));
    all_findings.extend(check_serialization_mismatch(&parsed_files));
    all_findings.extend(token2022::analyze(&src_path, &parsed_files, &all_accounts));

    if let Some(report_path) = tx_report {
        all_findings.extend(check_tx_report_correlation(&all_accounts, report_path));
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

    render_accounts_summary(&ctx);
    render_instructions_summary(&ctx);
    render_findings(&all_findings);
    render_summary(&all_findings);

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
