use crate::analyzer::type_to_string;
use crate::types::{Finding, Severity};
use std::collections::HashMap;

// ── Serialization mismatch detection ──────────────────────────────────────────

#[derive(Debug, Clone)]
struct StorageField {
    name: String,
    ty: String,
}

pub(crate) fn check_serialization_mismatch(parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut storage_structs: HashMap<String, Vec<StorageField>> = HashMap::new();
    let mut arg_structs: HashMap<String, Vec<StorageField>> = HashMap::new();
    let mut accounts_type_refs: Vec<(String, String)> = Vec::new();

    for (file, _file_path) in parsed_files {
        for item in &file.items {
            if let syn::Item::Struct(item_struct) = item {
                let is_account_attr =
                    item_struct.attrs.iter().any(|a| a.path().is_ident("account") && !a.path().is_ident("Accounts"));

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

                if is_account_attr {
                    let name = item_struct.ident.to_string();
                    let fields = extract_storage_fields(&item_struct.fields);
                    storage_structs.insert(name, fields);
                    continue;
                }

                if has_accounts_derive {
                    for field in &item_struct.fields {
                        let storage_type = extract_storage_type_from_account(&field.ty);
                        if let Some(storage_type) = storage_type {
                            let field_name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                            accounts_type_refs.push((field_name, storage_type));
                        }
                    }
                    continue;
                }

                let name = item_struct.ident.to_string();
                let fields = extract_storage_fields(&item_struct.fields);
                arg_structs.insert(name, fields);
            }
        }
    }

    for (file, file_path) in parsed_files {
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
                                    if !arg_ty.contains("Context<") {
                                        let clean_ty = arg_ty.trim().to_string();
                                        if let Some(arg_fields) = arg_structs.get(&clean_ty) {
                                            for (_acct_field_name, storage_type) in &accounts_type_refs {
                                                if let Some(storage_fields) = storage_structs.get(storage_type) {
                                                    let mismatches = compare_fields(
                                                        storage_fields,
                                                        arg_fields,
                                                        storage_type,
                                                        &func.sig.ident.to_string(),
                                                        file_path,
                                                    );
                                                    findings.extend(mismatches);
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
        }
    }

    findings
}

fn compare_fields(
    storage_fields: &[StorageField],
    arg_fields: &[StorageField],
    storage_name: &str,
    ix_name: &str,
    file_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let arg_map: HashMap<&str, &StorageField> = arg_fields.iter().map(|f| (f.name.as_str(), f)).collect();

    for sf in storage_fields {
        if let Some(af) = arg_map.get(sf.name.as_str()) {
            let storage_width = width_of_type(&sf.ty);
            let arg_width = width_of_type(&af.ty);

            if storage_width > 0 && arg_width > 0 && storage_width != arg_width {
                let (narrower, wider, wider_name, _narrower_name) = if storage_width > arg_width {
                    (arg_width, storage_width, "storage", "args")
                } else {
                    (storage_width, arg_width, "args", "storage")
                };

                findings.push(Finding {
                    id: String::new(),
                    title: format!(
                        "Serialization Mismatch: field `{}` is {}({}B) in {} but {}({}B) in args — possible data truncation",
                        sf.name,
                        if wider == storage_width { &sf.ty } else { &af.ty },
                        wider,
                        wider_name,
                        if wider == storage_width { &af.ty } else { &sf.ty },
                        narrower,
                    ),
                    severity: Severity::High,
                    description: format!(
                        "The field `{}` has type `{}` ({}-byte) in `#[account]` struct `{}` but type `{}` \
                         ({}-byte) in instruction argument struct. When the instruction deserializes this \
                         field, only {} bytes are written to the on-chain struct. The remaining {} bytes \
                         retain whatever data was previously in the account, leading to silent data \
                         corruption or truncation.",
                        sf.name,
                        sf.ty, storage_width, storage_name,
                        af.ty, arg_width,
                        narrower, wider - narrower,
                    ),
                    location: Some(format!("{file_path} ({ix_name}, {storage_name})")),
                    suggestion: Some(format!(
                        "Change the instruction arg field `{}` from `{}` to `{}` to match the storage type, \
                         or vice versa. Ensure all serialized representations use the same byte width.",
                        sf.name, af.ty, sf.ty
                    )),
                });
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
