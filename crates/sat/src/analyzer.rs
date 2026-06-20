use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::idl::{self, IdlJson};
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
            "◼".blue(),
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

            println!("    {} {}: {}{}", "├╴".dimmed(), field.name, field.ty_name.dimmed(), tag_str);
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
            "•".blue(),
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
        Severity::Critical => "🔴".to_string(),
        Severity::High => "🟠".to_string(),
        Severity::Medium => "🟡".to_string(),
        Severity::Low => "🔵".to_string(),
        Severity::Informational => "⚪".to_string(),
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
    let mut file_count = 0;

    for file_path in &source_files {
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
    }

    let idl = idl::find_idl_in_workspace().ok().and_then(|p| idl::parse_idl(&p).ok());

    let mut all_findings: Vec<Finding> = Vec::new();

    all_findings.extend(check_missing_signer(&all_accounts));
    all_findings.extend(check_missing_owner(&all_accounts));
    all_findings.extend(check_missing_mut(&all_accounts, idl.as_ref()));
    all_findings.extend(check_discriminator_collisions(&all_instructions));

    for (i, f) in all_findings.iter_mut().enumerate() {
        f.id = format!("SAT-{:03}", i + 1);
    }

    let ctx = AnalysisContext { accounts_structs: all_accounts, instructions: all_instructions, file_count, idl };

    if format == "sarif" {
        render_sarif(&ctx, &all_findings)?;
        return Ok(());
    }

    render_accounts_summary(&ctx);
    render_instructions_summary(&ctx);
    render_findings(&all_findings);
    render_summary(&all_findings);

    Ok(())
}

// ── SARIF output (Phase 4 will expand) ────────────────────────────────────────

fn render_sarif(_ctx: &AnalysisContext, _findings: &[Finding]) -> Result<()> {
    ui::print_warning("SARIF output will be implemented in Phase 4.");
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
