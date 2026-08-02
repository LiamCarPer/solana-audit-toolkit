//! PDA seed cross-check between IDL seed declarations and
//! `#[account(seeds = ...)]` constraints.
//!
//! For every IDL instruction account declared as a PDA (`pda: Some(...)`
//! with non-empty seeds), the check locates the matching
//! `#[derive(Accounts)]` struct and field and compares the seeds declared
//! in the `#[account(...)]` attribute against the IDL-declared seeds.
//!
//! # Seed normalization
//!
//! Both sides are normalized into [`SeedValue`] (raw bytes or an account
//! identifier) or marked unverifiable:
//!
//! | Side | Input                                                        | Result        |
//! |------|--------------------------------------------------------------|---------------|
//! | code | `b"literal"` (`syn::Lit::ByteStr`)                           | `Bytes`       |
//! | code | single-segment path, e.g. `authority`                        | `Name`        |
//! | code | method call, e.g. `authority.key()` / `amount.as_ref()`      | `Name` of the receiver |
//! | code | anything else (references, casts, macros, multi-segment paths like `state.owner`, ...) | unverifiable |
//! | idl  | `kind == "const"` with `value: Some(bytes)`                  | `Bytes`       |
//! | idl  | `kind == "account"` with `account: Some(name)`               | `Name`        |
//! | idl  | `kind == "arg"`, path-based seeds, or unknown kinds          | unverifiable  |
//!
//! Unverifiable seeds are skipped and never produce a finding.
//!
//! # Matching
//!
//! * Instruction → accounts struct: case-insensitive equality, or the
//!   instruction name ending with the struct name (or vice versa) — the
//!   same heuristic as `tx_report::check_tx_report_correlation`. An exact
//!   name match is preferred over a suffix match.
//! * IDL account → struct field: case-insensitive exact match.
//!
//! # Findings
//!
//! * HIGH — the IDL declares a PDA derived from at least one verifiable
//!   seed, but the matched field has no `seeds` constraint at all.
//! * HIGH — the seed counts differ, reported only when every seed on both
//!   sides is verifiable (an unverifiable seed could hide a real count
//!   difference, so the comparison is skipped).
//! * MEDIUM — the counts match, but the normalized seed at a given
//!   (0-based) index differs; reported per differing index.
//!
//! The `bump` flag / `bump = ...` value is recorded but does not count as
//! a seed: with a plain `bump` flag Anchor appends the bump implicitly (it
//! is not an IDL seed), and with `bump = <pda>` the IDL carries an extra
//! `kind == "bump"` seed, which is unverifiable and disables the count
//! check for that field.

use std::collections::HashMap;

use crate::analyzer::{AccountField, AccountsStruct};
use crate::idl::{IdlAccountItem, IdlJson, IdlSeed};
use crate::types::{Finding, Severity};

/// A normalized seed value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SeedValue {
    /// Raw bytes of a byte-string literal (e.g. `b"state"` / IDL `"value"`).
    Bytes(Vec<u8>),
    /// Identifier name of an account (e.g. `authority` / IDL `"account"`).
    Name(String),
}

/// Normalization result of a single seed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NormalizedSeed {
    Verifiable(SeedValue),
    Unverifiable,
}

/// What the `#[account(...)]` attribute declares about seeds.
#[derive(Debug, Clone, Default)]
enum SeedsInfo {
    /// No `seeds = ...` key present at all.
    #[default]
    Missing,
    /// `seeds = [...]` present; the array elements (possibly unverifiable).
    Parsed(Vec<NormalizedSeed>),
    /// `seeds` present but not an array literal — cannot be verified.
    Unverifiable,
}

/// Seeds information extracted from one struct field.
#[derive(Debug, Clone, Default)]
struct CodeSeedInfo {
    seeds: SeedsInfo,
    /// Whether a `bump` flag or `bump = ...` key is present. Recorded but
    /// not counted as a seed (see module docs).
    #[allow(dead_code)]
    has_bump: bool,
}

const SUGGESTION: &str = "Align the `#[account(seeds = ...)]` constraint with the IDL-declared seeds, \
or keep the IDL as the single source of truth so Anchor generates an identical derivation.";

pub fn check_pda_seed_mismatch(
    accounts: &[AccountsStruct],
    idl: Option<&IdlJson>,
    parsed_files: &[(syn::File, String)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(idl) = idl else { return findings };

    // `AccountField` only records *whether* seeds are present, not the seed
    // expressions, so re-parse the `#[account(...)]` attributes from the raw
    // sources: struct name → field name → seed info.
    let mut seeds_by_struct: HashMap<String, HashMap<String, CodeSeedInfo>> = HashMap::new();
    for (file, _path) in parsed_files {
        for (struct_name, fields) in extract_seeds_from_file(file) {
            seeds_by_struct.entry(struct_name).or_default().extend(fields);
        }
    }

    for ix in &idl.instructions {
        let ix_lower = ix.name.to_lowercase();

        // Instruction name → accounts struct, same heuristic as tx_report:
        // case-insensitive equality, or one name ending with the other.
        let matches: Vec<&AccountsStruct> = accounts
            .iter()
            .filter(|accts| {
                let struct_lower = accts.name.to_lowercase();
                struct_lower == ix_lower || ix_lower.ends_with(&struct_lower) || struct_lower.ends_with(&ix_lower)
            })
            .collect();
        // Prefer an exact case-insensitive name match over a suffix match.
        let Some(accts) =
            matches.iter().find(|a| a.name.to_lowercase() == ix_lower).copied().or_else(|| matches.first().copied())
        else {
            continue;
        };

        for acct_item in &ix.accounts {
            let Some(pda) = &acct_item.pda else { continue };
            if pda.seeds.is_empty() {
                continue;
            }

            // IDL account → struct field: case-insensitive exact match.
            let Some(field) = accts.fields.iter().find(|f| f.name.to_lowercase() == acct_item.name.to_lowercase())
            else {
                continue;
            };

            // Code-side seeds for this field. If the struct does not appear
            // in the parsed sources at all, treat it as unverifiable rather
            // than reporting a missing constraint we could not confirm.
            let code_seeds = match seeds_by_struct.get(&accts.name) {
                Some(fields) => fields.get(&field.name).map(|info| &info.seeds).unwrap_or(&SeedsInfo::Unverifiable),
                None => &SeedsInfo::Unverifiable,
            };

            let idl_seeds: Vec<NormalizedSeed> = pda.seeds.iter().map(normalize_idl_seed).collect();
            let idl_has_verifiable = idl_seeds.iter().any(|s| matches!(s, NormalizedSeed::Verifiable(_)));

            match code_seeds {
                // The field is verifiably missing a seeds constraint.
                SeedsInfo::Missing => {
                    if idl_has_verifiable {
                        findings.push(find_missing_seeds(&ix.name, acct_item, accts, field, pda.seeds.len()));
                    }
                }
                // `seeds = <non-array>`: cannot verify — never flag.
                SeedsInfo::Unverifiable => {}
                SeedsInfo::Parsed(code) => {
                    let code_all_verifiable = code.iter().all(|s| matches!(s, NormalizedSeed::Verifiable(_)));
                    let idl_all_verifiable = idl_seeds.iter().all(|s| matches!(s, NormalizedSeed::Verifiable(_)));
                    // An unverifiable seed on either side could hide a real
                    // count difference, so only compare fully verifiable sets.
                    if !code_all_verifiable || !idl_all_verifiable {
                        continue;
                    }
                    if code.len() != idl_seeds.len() {
                        findings.push(find_count_mismatch(
                            &ix.name,
                            acct_item,
                            accts,
                            field,
                            idl_seeds.len(),
                            code.len(),
                        ));
                        continue;
                    }
                    // Positional comparison: Anchor emits IDL seeds in the
                    // same order as the code array.
                    for (index, (idl_seed, code_seed)) in idl_seeds.iter().zip(code.iter()).enumerate() {
                        if let (NormalizedSeed::Verifiable(idl_v), NormalizedSeed::Verifiable(code_v)) =
                            (idl_seed, code_seed)
                            && idl_v != code_v
                        {
                            findings
                                .push(find_seed_diff(&ix.name, acct_item, accts, field, index, idl_seed, code_seed));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ── Seed extraction (code side) ───────────────────────────────────────────────

/// Walk a parsed source file and return, per `#[derive(Accounts)]` struct
/// and field, the `#[account(...)]` seeds information.
fn extract_seeds_from_file(file: &syn::File) -> HashMap<String, HashMap<String, CodeSeedInfo>> {
    let mut structs = HashMap::new();

    for item in &file.items {
        let syn::Item::Struct(item_struct) = item else { continue };
        if !has_accounts_derive(item_struct) {
            continue;
        }

        let mut fields = HashMap::new();
        for field in &item_struct.fields {
            let Some(ident) = &field.ident else { continue };
            let mut info = CodeSeedInfo::default();

            for attr in &field.attrs {
                if !attr.path().is_ident("account") {
                    continue;
                }
                let _ = attr.parse_nested_meta(|meta| {
                    let key = meta.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
                    if key == "seeds" && meta.input.peek(syn::Token![=]) {
                        if let Ok(value) = meta.value().and_then(|v| v.parse::<syn::Expr>()) {
                            match value {
                                syn::Expr::Array(array) => {
                                    info.seeds =
                                        SeedsInfo::Parsed(array.elems.iter().map(normalize_code_seed).collect());
                                }
                                _ => info.seeds = SeedsInfo::Unverifiable,
                            }
                        } else {
                            info.seeds = SeedsInfo::Unverifiable;
                        }
                    } else if key == "bump" {
                        info.has_bump = true;
                    }
                    Ok(())
                });
            }

            fields.insert(ident.to_string(), info);
        }
        structs.insert(item_struct.ident.to_string(), fields);
    }

    structs
}

/// Replicates the `#[derive(Accounts)]` detection in
/// `analyzer::extract_accounts_structs`.
fn has_accounts_derive(item_struct: &syn::ItemStruct) -> bool {
    item_struct.attrs.iter().any(|attr| {
        let path = attr.path();
        if let Some(ident) = path.get_ident()
            && ident == "derive"
            && let Ok(nested) =
                attr.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        {
            return nested.iter().any(|meta| meta.path().is_ident("Accounts"));
        }
        false
    })
}

// ── Normalization ─────────────────────────────────────────────────────────────

/// Normalize one code-side seed expression. Anything other than a byte
/// string, a single-segment path, or a method call on such a path is
/// unverifiable and never flagged.
fn normalize_code_seed(expr: &syn::Expr) -> NormalizedSeed {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            // b"literal" → raw bytes (matches IDL `kind: "const"`).
            syn::Lit::ByteStr(bytes) => NormalizedSeed::Verifiable(SeedValue::Bytes(bytes.value())),
            _ => NormalizedSeed::Unverifiable,
        },
        // Single-segment path, e.g. `authority`. Multi-segment paths such as
        // `state.owner` are unverifiable.
        syn::Expr::Path(path) => match path.path.get_ident() {
            Some(ident) => NormalizedSeed::Verifiable(SeedValue::Name(ident.to_string())),
            None => NormalizedSeed::Unverifiable,
        },
        // Method call on an account name, e.g. `authority.key()` or
        // `authority.key().as_ref()` → receiver identifier.
        syn::Expr::MethodCall(call) => normalize_method_receiver(&call.receiver),
        _ => NormalizedSeed::Unverifiable,
    }
}

fn normalize_method_receiver(receiver: &syn::Expr) -> NormalizedSeed {
    match receiver {
        syn::Expr::Path(path) => match path.path.get_ident() {
            Some(ident) => NormalizedSeed::Verifiable(SeedValue::Name(ident.to_string())),
            None => NormalizedSeed::Unverifiable,
        },
        // Chained calls: `authority.key().as_ref()` → `authority`.
        syn::Expr::MethodCall(call) => normalize_method_receiver(&call.receiver),
        _ => NormalizedSeed::Unverifiable,
    }
}

/// Normalize one IDL seed. `kind: "arg"`, path-based seeds, and unknown
/// kinds are unverifiable and never flagged.
fn normalize_idl_seed(seed: &IdlSeed) -> NormalizedSeed {
    match seed.kind.as_str() {
        "const" => match &seed.value {
            Some(bytes) => NormalizedSeed::Verifiable(SeedValue::Bytes(bytes.clone())),
            None => NormalizedSeed::Unverifiable,
        },
        "account" => match &seed.account {
            Some(name) => NormalizedSeed::Verifiable(SeedValue::Name(name.clone())),
            None => NormalizedSeed::Unverifiable,
        },
        _ => NormalizedSeed::Unverifiable,
    }
}

/// Human-readable form of a seed for the diff-finding title.
fn seed_form(seed: &NormalizedSeed) -> String {
    match seed {
        NormalizedSeed::Verifiable(SeedValue::Bytes(bytes)) => format!("b\"{}\"", String::from_utf8_lossy(bytes)),
        NormalizedSeed::Verifiable(SeedValue::Name(name)) => name.clone(),
        NormalizedSeed::Unverifiable => "?".to_string(),
    }
}

fn plural_seeds(n: usize) -> &'static str {
    if n == 1 { "seed" } else { "seeds" }
}

// ── Finding builders ──────────────────────────────────────────────────────────

fn location_for(accts: &AccountsStruct, field: &AccountField, ix: &str, acct: &str) -> String {
    format!("{}:{} ({ix}, {acct})", accts.file.display(), field.line)
}

/// HIGH: IDL declares a PDA from seeds, but the code field has no
/// `seeds` constraint at all.
fn find_missing_seeds(
    ix: &str,
    acct: &IdlAccountItem,
    accts: &AccountsStruct,
    field: &AccountField,
    n: usize,
) -> Finding {
    Finding {
        id: String::new(),
        title: format!(
            "PDA Seed Mismatch: `{ix}` derives `{}` from seeds per IDL but `{}::{}` has no `seeds` constraint",
            acct.name, accts.name, field.name
        ),
        severity: Severity::High,
        description: format!(
            "The IDL declares `{}` in `{ix}` as a PDA derived from {n} {}, but `{}::{}` has no `seeds` \
             constraint. Deriving with a different seed set (or none) yields a different address than the \
             program expects; an attacker could supply their own account at that different address, bypassing \
             PDA checks.",
            acct.name,
            plural_seeds(n),
            accts.name,
            field.name
        ),
        location: Some(location_for(accts, field, ix, &acct.name)),
        suggestion: Some(SUGGESTION.to_string()),
    }
}

/// HIGH: the number of seeds declared on each side differs.
fn find_count_mismatch(
    ix: &str,
    acct: &IdlAccountItem,
    accts: &AccountsStruct,
    field: &AccountField,
    n: usize,
    m: usize,
) -> Finding {
    Finding {
        id: String::new(),
        title: format!(
            "PDA Seed Mismatch: `{ix}` declares {n} {} for `{}` but `{}::{}` declares {m} {}",
            plural_seeds(n),
            acct.name,
            accts.name,
            field.name,
            plural_seeds(m)
        ),
        severity: Severity::High,
        description: format!(
            "`{ix}` declares {n} {} for `{}` in the IDL, but `{}::{}` declares {m} {}. A mismatch in the \
             number of seeds changes the derived address; an attacker could supply their own account at that \
             different address, bypassing PDA checks.",
            plural_seeds(n),
            acct.name,
            accts.name,
            field.name,
            plural_seeds(m)
        ),
        location: Some(location_for(accts, field, ix, &acct.name)),
        suggestion: Some(SUGGESTION.to_string()),
    }
}

/// MEDIUM: same seed count, but the normalized seed at a 0-based index
/// differs between the IDL and the code.
fn find_seed_diff(
    ix: &str,
    acct: &IdlAccountItem,
    accts: &AccountsStruct,
    field: &AccountField,
    index: usize,
    idl_seed: &NormalizedSeed,
    code_seed: &NormalizedSeed,
) -> Finding {
    Finding {
        id: String::new(),
        title: format!(
            "PDA Seed Mismatch: seed {index} of `{}` in `{ix}` differs between IDL ({}) and code ({})",
            acct.name,
            seed_form(idl_seed),
            seed_form(code_seed)
        ),
        severity: Severity::Medium,
        description: format!(
            "The seed at index {index} of `{}` in `{ix}` differs between the IDL ({}) and the code ({}). \
             Deriving the PDA with the wrong seed yields a different address than the program expects; an \
             attacker could supply their own account at that different address, bypassing PDA checks.",
            acct.name,
            seed_form(idl_seed),
            seed_form(code_seed)
        ),
        location: Some(location_for(accts, field, ix, &acct.name)),
        suggestion: Some(SUGGESTION.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_expr(src: &str) -> syn::Expr {
        syn::parse_str(src).expect("test expression should parse")
    }

    #[test]
    fn normalizes_code_seeds() {
        // Byte-string literal → bytes.
        assert_eq!(
            normalize_code_seed(&parse_expr(r#"b"state""#)),
            NormalizedSeed::Verifiable(SeedValue::Bytes(b"state".to_vec()))
        );
        // Single-segment path → name.
        assert_eq!(
            normalize_code_seed(&parse_expr("authority")),
            NormalizedSeed::Verifiable(SeedValue::Name("authority".to_string()))
        );
        // Method call on a path → receiver name.
        assert_eq!(
            normalize_code_seed(&parse_expr("authority.key()")),
            NormalizedSeed::Verifiable(SeedValue::Name("authority".to_string()))
        );
        // Chained method calls → receiver name.
        assert_eq!(
            normalize_code_seed(&parse_expr("authority.key().as_ref()")),
            NormalizedSeed::Verifiable(SeedValue::Name("authority".to_string()))
        );
        // Multi-segment path → unverifiable.
        assert_eq!(normalize_code_seed(&parse_expr("state.owner")), NormalizedSeed::Unverifiable);
        // Reference → unverifiable.
        assert_eq!(normalize_code_seed(&parse_expr("&authority")), NormalizedSeed::Unverifiable);
        // String literal (not byte string) → unverifiable.
        assert_eq!(normalize_code_seed(&parse_expr(r#""state""#)), NormalizedSeed::Unverifiable);
    }

    #[test]
    fn normalizes_idl_seeds() {
        // kind "const" with bytes → bytes.
        let seed = IdlSeed { kind: "const".into(), value: Some(b"state".to_vec()), path: None, account: None };
        assert_eq!(normalize_idl_seed(&seed), NormalizedSeed::Verifiable(SeedValue::Bytes(b"state".to_vec())));
        // kind "const" without a value → unverifiable.
        let seed = IdlSeed { kind: "const".into(), value: None, path: None, account: None };
        assert_eq!(normalize_idl_seed(&seed), NormalizedSeed::Unverifiable);
        // kind "account" with a name → name.
        let seed = IdlSeed { kind: "account".into(), value: None, path: None, account: Some("authority".into()) };
        assert_eq!(normalize_idl_seed(&seed), NormalizedSeed::Verifiable(SeedValue::Name("authority".into())));
        // kind "arg" → unverifiable.
        let seed = IdlSeed { kind: "arg".into(), value: None, path: Some("amount".into()), account: None };
        assert_eq!(normalize_idl_seed(&seed), NormalizedSeed::Unverifiable);
        // Unknown kind → unverifiable.
        let seed = IdlSeed { kind: "bump".into(), value: None, path: None, account: None };
        assert_eq!(normalize_idl_seed(&seed), NormalizedSeed::Unverifiable);
    }
}
