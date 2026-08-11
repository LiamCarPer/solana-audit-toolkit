use std::fs;
use std::path::Path;

use crate::analyzer::AccountsStruct;
use crate::types::{Finding, Severity};
use quote::quote;

pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

// ── Detection ─────────────────────────────────────────────────────────────────

pub fn detect_token2022_dependency(workspace_root: &Path) -> bool {
    let toml_path = workspace_root.join("Cargo.toml");

    if let Ok(content) = fs::read_to_string(&toml_path)
        && (content.contains("spl-token-2022") || content.contains("token-2022"))
    {
        return true;
    }

    let crates_dir = workspace_root.join("crates");
    if crates_dir.is_dir()
        && let Ok(entries) = fs::read_dir(&crates_dir)
    {
        for entry in entries.flatten() {
            let cargo_path = entry.path().join("Cargo.toml");
            if let Ok(content) = fs::read_to_string(&cargo_path)
                && (content.contains("spl-token-2022") || content.contains("token-2022"))
            {
                return true;
            }
        }
    }

    false
}

pub fn detect_token2022_in_source(
    parsed_files: &[(syn::File, String)],
) -> (bool, Vec<Finding>, Vec<(String, String, String)>) {
    let mut found_program_id = false;
    let mut found_token2022_usage = false;
    let mut program_id_locations = Vec::new();
    let mut interface_account_locations = Vec::new();
    let mut token2022_transfer_instructions = Vec::new();
    let mut findings = Vec::new();

    for (file, file_path) in parsed_files {
        let source = fs::read_to_string(file_path).unwrap_or_default();
        if source.contains(TOKEN_2022_PROGRAM_ID) {
            found_program_id = true;
            program_id_locations.push(file_path.clone());
        }

        // Raw-source marker scan: catches Token-2022 references outside fn
        // bodies (file-level `use` statements, trait imports, type aliases,
        // macro invocations, etc.). The `TokenzQd...` program ID literal does
        // not contain `token_2022`, so program-ID-only files are not
        // misclassified as usage here; `spl_token_2022_interface` legitimately
        // contains the `token_2022` substring and is a real usage signal.
        let source_lower = source.to_lowercase();
        if source_lower.contains("spl_token_2022") || source_lower.contains("token_2022") {
            found_token2022_usage = true;
        }

        // Recursive fn-body scan: walk every `Item::Fn` wherever it lives
        // (file scope, modules, impl blocks, trait bodies) regardless of
        // visibility. The previous scan only visited `pub` fns directly
        // inside module items, missing `impl`-block methods entirely.
        scan_file_items(
            &file.items,
            file_path,
            &mut found_token2022_usage,
            &mut interface_account_locations,
            &mut token2022_transfer_instructions,
        );
    }

    if found_program_id {
        findings.push(Finding {
            id: String::new(),
            title: format!(
                "Token-2022 Usage Detected: program ID referenced in {} source file(s)",
                program_id_locations.len()
            ),
            severity: Severity::Informational,
            description: format!(
                "The Token-2022 program ID `{}` was found in source files: {:?}. \
                 Token-2022 introduces token extensions (transfer fees, permanent delegate, \
                 interest-bearing, etc.) that must be accounted for in program logic.",
                TOKEN_2022_PROGRAM_ID,
                program_id_locations.iter().map(|p| p.as_str()).collect::<Vec<_>>()
            ),
            location: Some(format!("Token-2022 program: {}", TOKEN_2022_PROGRAM_ID)),
            suggestion: Some(
                "Ensure the program correctly handles all relevant Token-2022 extensions for \
                 the mints it interacts with. Run `sat analyze src` with --tx-report for \
                 runtime validation."
                    .to_string(),
            ),
        });
    }

    (found_program_id || found_token2022_usage, findings, token2022_transfer_instructions)
}

/// Recursively visit every function body reachable from file-level items:
/// free fns, module members (including nested modules), `impl` blocks, and
/// trait default methods. Visibility is irrelevant for usage detection.
fn scan_file_items(
    items: &[syn::Item],
    file_path: &str,
    found_token2022_usage: &mut bool,
    interface_account_locations: &mut Vec<String>,
    token2022_transfer_instructions: &mut Vec<(String, String, String)>,
) {
    for item in items {
        match item {
            syn::Item::Fn(func) => scan_fn_body(
                &func.block,
                &func.sig.ident.to_string(),
                file_path,
                found_token2022_usage,
                interface_account_locations,
                token2022_transfer_instructions,
            ),
            syn::Item::Mod(item_mod) => {
                if let Some((_, items)) = &item_mod.content {
                    scan_file_items(
                        items,
                        file_path,
                        found_token2022_usage,
                        interface_account_locations,
                        token2022_transfer_instructions,
                    );
                }
            }
            syn::Item::Impl(item_impl) => scan_impl_items(
                &item_impl.items,
                file_path,
                found_token2022_usage,
                interface_account_locations,
                token2022_transfer_instructions,
            ),
            syn::Item::Trait(item_trait) => scan_trait_items(
                &item_trait.items,
                file_path,
                found_token2022_usage,
                interface_account_locations,
                token2022_transfer_instructions,
            ),
            _ => {}
        }
    }
}

/// Visit every function body inside an `impl` block (e.g. `impl Processor`).
fn scan_impl_items(
    items: &[syn::ImplItem],
    file_path: &str,
    found_token2022_usage: &mut bool,
    interface_account_locations: &mut Vec<String>,
    token2022_transfer_instructions: &mut Vec<(String, String, String)>,
) {
    for item in items {
        if let syn::ImplItem::Fn(func) = item {
            scan_fn_body(
                &func.block,
                &func.sig.ident.to_string(),
                file_path,
                found_token2022_usage,
                interface_account_locations,
                token2022_transfer_instructions,
            );
        }
    }
}

/// Visit every function body inside a trait definition (default methods).
fn scan_trait_items(
    items: &[syn::TraitItem],
    file_path: &str,
    found_token2022_usage: &mut bool,
    interface_account_locations: &mut Vec<String>,
    token2022_transfer_instructions: &mut Vec<(String, String, String)>,
) {
    for item in items {
        if let syn::TraitItem::Fn(func) = item
            && let Some(block) = &func.default
        {
            scan_fn_body(
                block,
                &func.sig.ident.to_string(),
                file_path,
                found_token2022_usage,
                interface_account_locations,
                token2022_transfer_instructions,
            );
        }
    }
}

/// Scan a single function body for Token-2022 usage markers and
/// interface-account references.
fn scan_fn_body(
    block: &syn::Block,
    func_name: &str,
    file_path: &str,
    found_token2022_usage: &mut bool,
    interface_account_locations: &mut Vec<String>,
    token2022_transfer_instructions: &mut Vec<(String, String, String)>,
) {
    let body_source = quote!(#block).to_string();
    let has_token2022_transfer = body_source.to_lowercase().contains("token_2022")
        || body_source.contains("TokenzQd")
        || body_source.to_lowercase().contains("spl_token_2022");

    if has_token2022_transfer {
        *found_token2022_usage = true;
        token2022_transfer_instructions.push((func_name.to_string(), body_source.clone(), file_path.to_string()));
    }

    let has_interface_account = {
        let lower = body_source.to_lowercase();
        lower.contains("interfaceaccount<") && (lower.contains("tokenaccount") || lower.contains("mint"))
    };

    if has_interface_account {
        *found_token2022_usage = true;
        interface_account_locations.push(format!("{file_path}:{func_name}"));
    }
}

// ── Account type detection ────────────────────────────────────────────────────

pub fn detect_interface_account(accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for accts in accounts {
        for field in &accts.fields {
            let ty_lower = field.ty_name.to_lowercase();

            if ty_lower.contains("interfaceaccount<")
                && (ty_lower.contains("tokenaccount") || ty_lower.contains("mint"))
            {
                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Token-2022 InterfaceAccount: `{}::{}` uses `{}`",
                        accts.name, field.name, field.ty_name
                    ),
                    severity: Severity::Informational,
                    description: format!(
                        "The field `{}` in `{}` is typed as `{}`, which indicates \
                         Token-2022 compatible account handling. Tokens with extensions \
                         (transfer fees, permanent delegate, etc.) may behave differently \
                         than standard SPL tokens passed through this account interface.",
                        field.name, accts.name, field.ty_name
                    ),
                    location: Some(format!("{}:{} ({}::{})", accts.file.display(), field.line, accts.name, field.name)),
                    suggestion: Some(
                        "Verify that the program handles all Token-2022 extensions for \
                         the tokens it accepts. Use `spl-token-2022` crate for complete \
                         extension support."
                            .to_string(),
                    ),
                });
            }
        }
    }

    findings
}

// ── Transfer fee bypass check ─────────────────────────────────────────────────

pub fn check_transfer_fee_bypass(token2022_transfers: &[(String, String, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let fee_keywords = [
        "transfer_fee",
        "transfer_fee_amount",
        "calculate_fee",
        "fee_basis_points",
        "max_fee",
        "deduct_fee",
        "fee_amount",
        "amount_after_fee",
        "effective_fee",
        "withheld_amount",
        "harvest_withheld_tokens",
        "check_fee",
    ];

    for (ix_name, body, file_path) in token2022_transfers {
        let has_fee_handling = fee_keywords.iter().any(|kw| body.to_lowercase().contains(kw));

        if !has_fee_handling {
            findings.push(Finding {
                id: String::new(),
                title: format!(
                    "Potential Transfer Fee Bypass: `{ix_name}` transfers Token-2022 tokens without fee handling"
                ),
                severity: Severity::High,
                description: format!(
                    "The instruction `{ix_name}` appears to transfer Token-2022 tokens but \
                     does not contain any transfer fee calculation logic (no references \
                     to `transfer_fee`, `calculate_fee`, `fee_basis_points`, `amount_after_fee`, \
                     etc.). Token-2022 mints can have transfer fees configured, and the actual \
                     amount received by the recipient will be less than the amount transferred. \
                     Without fee handling, internal accounting may silently drift from on-chain \
                     balances, allowing fund extraction or protocol insolvency."
                ),
                location: Some(format!("{file_path} ({ix_name})")),
                suggestion: Some(
                    "1. Use `spl-token-2022::extension::transfer_fee::TransferFeeConfig` to read \
                     the fee configuration.\n2. Calculate the fee: `fee = amount * fee_basis_points / 10000`.\
                     \n3. Store the post-fee amount or the actual received amount in internal state.\
                     \n4. Consider using `TransferChecked` with the expected post-fee amount."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

// ── Permanent delegate abuse check ────────────────────────────────────────────

pub fn check_permanent_delegate(parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let perm_delegate_keywords = [
        "permanent_delegate",
        "PermanentDelegate",
        "permanentDelegate",
        "approve_permanent_delegate",
        "set_permanent_delegate",
    ];

    for (_file, file_path) in parsed_files {
        let source = fs::read_to_string(file_path).unwrap_or_default();
        let source_lower = source.to_lowercase();

        let found_keywords: Vec<&&str> =
            perm_delegate_keywords.iter().filter(|kw| source_lower.contains(&kw.to_lowercase())).collect();

        if !found_keywords.is_empty() {
            findings.push(Finding {
                id: String::new(),
                title: format!("Permanent Delegate Extension Detected in {}", file_path),
                severity: Severity::Medium,
                description: format!(
                    "The source file `{}` references permanent delegate keywords: {:?}. \
                     The Permanent Delegate extension allows a designated address to \
                     transfer or burn tokens from ANY holder without their consent. \
                     If this extension is enabled on a mint used by this program, \
                     the permanent delegate could drain user deposits or manipulate \
                     protocol state. Programs should verify that mints they interact \
                     with do NOT have a permanent delegate enabled, or explicitly \
                     account for the delegate's authority.",
                    file_path, found_keywords
                ),
                location: Some(file_path.to_string()),
                suggestion: Some(
                    "1. Verify that mints this program interacts with do not have a \
                     permanent delegate enabled.\n2. If permanent delegates are expected, \
                     add access control checks to validate the delegate's actions.\
                     \n3. Consider adding a `require!(!has_permanent_delegate)` guard \
                     in initialization to reject unsafe mints."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

// ── Interest-bearing token check ──────────────────────────────────────────────

pub fn check_interest_bearing(parsed_files: &[(syn::File, String)], accounts: &[AccountsStruct]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let interest_keywords = [
        "interest_bearing",
        "InterestBearing",
        "interestBearing",
        "interest_rate",
        "update_rate",
        "amount_to_ui_amount",
        "ui_amount_to_amount",
    ];

    let mut has_interface_account = false;
    for accts in accounts {
        for field in &accts.fields {
            if field.ty_name.to_lowercase().contains("interfaceaccount") {
                has_interface_account = true;
                break;
            }
        }
    }

    for (_file, file_path) in parsed_files {
        let source = fs::read_to_string(file_path).unwrap_or_default();
        let source_lower = source.to_lowercase();

        let found_keywords: Vec<&&str> =
            interest_keywords.iter().filter(|kw| source_lower.contains(&kw.to_lowercase())).collect();

        if !found_keywords.is_empty() && has_interface_account {
            findings.push(Finding {
                id: String::new(),
                title: format!("Interest-Bearing Token Integration Detected in {}", file_path),
                severity: Severity::Low,
                description: format!(
                    "The source file `{}` references interest-bearing token keywords: {:?}. \
                     Interest-bearing tokens have a dynamically changing balance that increases \
                     over time via the `amount_to_ui_amount`/`ui_amount_to_amount` conversion. \
                     Programs storing raw token amounts in state will drift from the actual \
                     on-chain amount if interest accrues between interactions. \
                     This is flagged at LOW severity because interest-bearing tokens are \
                     a legitimate design choice; ensure your program accounts for the \
                     dynamic balance.",
                    file_path, found_keywords
                ),
                location: Some(file_path.to_string()),
                suggestion: Some(
                    "1. Never store raw token amounts from interest-bearing mints as fixed state; \
                     use `amount_to_ui_amount` to normalize.\n2. When transferring, use \
                     TransferChecked with the ui_amount.\n3. For vaults, track shares \
                     rather than absolute token amounts."
                        .to_string(),
                ),
            });
        }

        if has_interface_account && found_keywords.is_empty() {
            let has_token_amount_storage = source_lower.contains("amount")
                || source_lower.contains("token_amount")
                || source_lower.contains("balance");

            if has_token_amount_storage {
                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Potential Interest-Bearing Token Issue: `{}` stores token amounts \
                         with InterfaceAccount but has no interest-bearing handling",
                        file_path
                    ),
                    severity: Severity::Medium,
                    description: format!(
                        "The source file `{}` uses `InterfaceAccount` (Token-2022 compatible) and \
                         stores token amounts in state, but does not contain interest-bearing \
                         token handling logic. If a mint with the interest-bearing extension \
                         is passed to this program, the stored amounts will drift from actual \
                         balances as interest accrues.",
                        file_path
                    ),
                    location: Some(file_path.to_string()),
                    suggestion: Some(
                        "Add interest-bearing calculations or document that interest-bearing \
                         mints are not supported. Use `amount_to_ui_amount` from \
                         `spl-token-2022::extension::interest_bearing_mint` to normalize amounts."
                            .to_string(),
                    ),
                });
            }
        }
    }

    findings
}

// ── Main entry point ──────────────────────────────────────────────────────────

pub fn analyze(
    workspace_root: &Path,
    parsed_files: &[(syn::File, String)],
    accounts: &[AccountsStruct],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let has_dependency = detect_token2022_dependency(workspace_root);
    let (has_program_id, mut source_findings, token2022_transfers) = detect_token2022_in_source(parsed_files);
    let mut interface_findings = detect_interface_account(accounts);

    findings.append(&mut source_findings);
    findings.append(&mut interface_findings);

    if has_dependency && !has_program_id {
        findings.push(Finding {
            id: String::new(),
            title: "Token-2022 Dependency Without Program ID Usage".to_string(),
            severity: Severity::Informational,
            description: "The workspace depends on `spl-token-2022` but the Token-2022 \
                          program ID was not found in any source file. This may indicate \
                          unused dependency or lazily-loaded program ID."
                .to_string(),
            location: Some("Cargo.toml".to_string()),
            suggestion: Some(
                "Verify that the Token-2022 dependency is used or remove it \
                             from Cargo.toml."
                    .to_string(),
            ),
        });
    }

    if has_program_id || has_dependency {
        findings.extend(check_transfer_fee_bypass(&token2022_transfers));
        findings.extend(check_permanent_delegate(parsed_files));
        findings.extend(check_interest_bearing(parsed_files, accounts));
    } else {
        findings.push(Finding {
            id: String::new(),
            title: "No Token-2022 Usage Detected".to_string(),
            severity: Severity::Informational,
            description: "No Token-2022 usage was detected in this workspace. \
                          If the program handles Token-2022 tokens, verify that \
                          the program ID or dependency is correctly referenced."
                .to_string(),
            location: Some("Workspace root".to_string()),
            suggestion: Some("Token-2022 analysis was skipped.".to_string()),
        });
    }

    findings
}
