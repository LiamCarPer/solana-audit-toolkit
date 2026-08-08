//! IDL-driven account layout generation for the fuzzer harness.
//!
//! Renders a self-contained `pub mod accounts { ... }` block for the generated
//! fuzzer crate: `struct`/`enum` definitions mirroring the IDL account and
//! type definitions, arbitrary-value fillers, the Anchor account
//! discriminator (`sha256("account:<name>")[..8]`), and `build_*` functions
//! that produce borsh-serialized account data (discriminator prefix + fields)
//! so program handlers can deserialize seeded accounts instead of failing on
//! 1024 zero bytes.

use crate::idl::{IdlEnumVariant, IdlField, IdlJson};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Renders a `pub mod accounts { ... }` block for the generated fuzzer:
/// struct/enum definitions mirroring the IDL account types, arbitrary-value
/// fillers, Anchor discriminators, and `build_*` functions producing the
/// borsh-serialized account data (discriminator prefix + fields).
pub fn render_account_factories(idl: &IdlJson) -> String {
    let body = render_module_body(idl);

    let mut out = String::from("pub mod accounts {\n");
    if body.contains("BorshSerialize") {
        out.push_str("    use borsh::{BorshDeserialize, BorshSerialize};\n");
    }
    if body.contains("impl Rng") {
        out.push_str("    use rand::Rng;\n");
    }
    if body.contains("random_string(rng)") {
        out.push_str(RANDOM_STRING_FN);
    }
    if body.contains("Pubkey") {
        out.push_str("    use solana_program::pubkey::Pubkey;\n");
    }
    out.push_str(DISCRIMINATOR_FN);
    out.push_str(&body);
    out.push_str("}\n");
    out
}

/// Generated `discriminator` helper: Anchor account discriminator
/// `sha256("account:<name>")[..8]`, computed at fuzzer runtime via
/// `solana_program::hash::hash` (SHA-256).
const DISCRIMINATOR_FN: &str = r#"    pub fn discriminator(name: &str) -> [u8; 8] {
        let preimage = format!("account:{name}");
        let hash = solana_program::hash::hash(preimage.as_bytes());
        let bytes = hash.to_bytes();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&bytes[..8]);
        disc
    }
"#;

/// Generated helper producing small random strings (len 0..=8) for `string`
/// fields, using the rand 0.8 API.
const RANDOM_STRING_FN: &str = r#"    fn random_string(rng: &mut impl Rng) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..rng.gen_range(0..=8))
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect()
    }
"#;

/// What an IDL type definition looks like: either a struct with fields or an
/// enum with variants. Only these shapes can be emitted as Rust items.
/// Enums are unit types in the generated code, so no payload is needed.
enum DefKind<'a> {
    Struct(&'a [IdlField]),
    Enum,
}

/// A successfully mapped IDL type.
struct FieldType {
    /// Rust type text, e.g. `u64`, `Option<Pubkey>`, `Vec<u64>`.
    rust: String,
    /// Expression producing an arbitrary value of `rust`.
    filler: String,
    /// Comment to emit above the field, if any.
    comment: Option<String>,
    /// True when recursion truncation happened inside this type.
    recursive: bool,
}

enum Resolved {
    Supported(FieldType),
    /// The offending IDL type serialized to JSON text; triggers the
    /// placeholder fallback for the whole account factory.
    Unsupported(String),
}

/// Renders everything inside `pub mod accounts`, except the header `use`
/// lines and the `discriminator` helper (added by `render_account_factories`).
fn render_module_body(idl: &IdlJson) -> String {
    let mut defs: HashMap<&str, DefKind<'_>> = HashMap::new();
    for account in &idl.accounts {
        insert_def(&mut defs, &account.name, &account.ty.kind, &account.ty.fields);
    }
    for ty in &idl.types {
        insert_def(&mut defs, &ty.name, &ty.ty.kind, &ty.ty.fields);
    }

    let mut body = String::new();
    // Sanitized Rust names already emitted; guards against duplicate items
    // when an account and a type def share a name.
    let mut emitted: HashSet<String> = HashSet::new();

    for account in &idl.accounts {
        let rust_name = sanitize_type_name(&account.name);
        if !emitted.insert(rust_name.clone()) {
            continue;
        }
        if account.ty.kind != "struct" {
            let fallback = format!(
                "    // unsupported account layout (type kind \"{}\"): placeholder data — wire manually\n    pub fn build_{}(_rng: &mut impl Rng) -> Vec<u8> {{\n        vec![0; 64]\n    }}\n",
                account.ty.kind,
                to_snake_case(&rust_name)
            );
            body.push_str(&fallback);
        } else {
            match render_account_factory(&rust_name, &account.name, &account.ty.fields, &defs) {
                Ok(factory) => body.push_str(&factory),
                Err(json) => {
                    let fallback = format!(
                        "    // unsupported field type {json}: placeholder data — wire manually\n    pub fn build_{}(_rng: &mut impl Rng) -> Vec<u8> {{\n        vec![0; 64]\n    }}\n",
                        to_snake_case(&rust_name)
                    );
                    body.push_str(&fallback);
                }
            }
        }
        body.push('\n');
    }

    for ty in &idl.types {
        let rust_name = sanitize_type_name(&ty.name);
        if !emitted.insert(rust_name.clone()) {
            continue;
        }
        match ty.ty.kind.as_str() {
            "struct" => match render_struct(&rust_name, &ty.ty.fields, &defs, std::slice::from_ref(&ty.name)) {
                Ok(rendered) => body.push_str(&rendered),
                Err(json) => {
                    let skipped = format!("    // type {rust_name} skipped: unsupported field type {json}\n");
                    body.push_str(&skipped);
                }
            },
            "enum" => body.push_str(&render_enum(&rust_name, &ty.ty.variants)),
            _ => continue,
        }
        body.push('\n');
    }

    body
}

fn insert_def<'a>(defs: &mut HashMap<&'a str, DefKind<'a>>, name: &'a str, kind: &str, fields: &'a [IdlField]) {
    if defs.contains_key(name) {
        return;
    }
    match kind {
        "struct" => {
            defs.insert(name, DefKind::Struct(fields));
        }
        "enum" => {
            defs.insert(name, DefKind::Enum);
        }
        _ => {}
    }
}

/// Struct definition + `make_*` filler + `build_*` factory for one account.
fn render_account_factory(
    rust_name: &str,
    idl_name: &str,
    fields: &[IdlField],
    defs: &HashMap<&str, DefKind<'_>>,
) -> Result<String, String> {
    let chain = vec![idl_name.to_string()];
    let mut out = render_struct(rust_name, fields, defs, &chain)?;
    out.push_str(&render_build(rust_name, idl_name));
    Ok(out)
}

/// Struct definition + `make_*` filler. `chain` holds the raw IDL names of
/// the definitions currently being expanded, for the recursion guard.
fn render_struct(
    rust_name: &str,
    fields: &[IdlField],
    defs: &HashMap<&str, DefKind<'_>>,
    chain: &[String],
) -> Result<String, String> {
    let snake = to_snake_case(rust_name);
    let mut struct_fields = String::new();
    let mut filler_fields = String::new();
    for field in fields {
        let field_name = sanitize_field_name(&field.name);
        match resolve_type(&field.ty, defs, chain) {
            Resolved::Unsupported(json) => return Err(json),
            Resolved::Supported(ft) => {
                if let Some(comment) = &ft.comment {
                    let comment_line = format!("        // {comment}\n");
                    struct_fields.push_str(&comment_line);
                }
                let field_line = format!("        pub {field_name}: {},\n", ft.rust);
                struct_fields.push_str(&field_line);
                let filler_line = format!("            {field_name}: {},\n", ft.filler);
                filler_fields.push_str(&filler_line);
            }
        }
    }
    Ok(format!(
        "    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]\n    pub struct {rust_name} {{\n{struct_fields}    }}\n\n    pub fn make_{snake}(rng: &mut impl Rng) -> {rust_name} {{\n        {rust_name} {{\n{filler_fields}        }}\n    }}\n"
    ))
}

/// `build_*` factory: Anchor discriminator prefix + borsh-serialized fields.
fn render_build(rust_name: &str, idl_name: &str) -> String {
    let snake = to_snake_case(rust_name);
    format!(
        "    pub fn build_{snake}(rng: &mut impl Rng) -> Vec<u8> {{\n        let mut data = discriminator(\"{idl_name}\").to_vec();\n        data.extend(borsh::to_vec(&make_{snake}(rng)).expect(\"serialize\"));\n        data\n    }}\n"
    )
}

/// Enum definition + `make_*` filler picking a variant.
fn render_enum(rust_name: &str, variants: &[IdlEnumVariant]) -> String {
    let snake = to_snake_case(rust_name);
    let mut variant_lines = String::new();
    let mut rust_variants = Vec::with_capacity(variants.len());
    for variant in variants {
        let variant_name = sanitize_type_name(&variant.name);
        rust_variants.push(variant_name.clone());
        if variant.fields.as_ref().is_some_and(|fields| !fields.is_empty()) {
            variant_lines.push_str("        // variant fields omitted (unit variant for fuzzing)\n");
        }
        let line = format!("        {variant_name},\n");
        variant_lines.push_str(&line);
    }
    let mut out = format!(
        "    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]\n    pub enum {rust_name} {{\n{variant_lines}    }}\n\n"
    );
    out.push_str(&render_enum_filler(&snake, rust_name, &rust_variants));
    out
}

/// Enum fillers pick a variant uniformly at random via `rng.gen_range(0..n)`;
/// single-variant enums return their only variant and empty enums are
/// unreachable (they have no values).
fn render_enum_filler(snake: &str, rust_name: &str, variants: &[String]) -> String {
    match variants.len() {
        0 => format!(
            "    pub fn make_{snake}(rng: &mut impl Rng) -> {rust_name} {{\n        let _ = rng;\n        unreachable!(\"{rust_name} has no variants\")\n    }}\n"
        ),
        1 => format!(
            "    pub fn make_{snake}(rng: &mut impl Rng) -> {rust_name} {{\n        let _ = rng;\n        {rust_name}::{}\n    }}\n",
            variants[0]
        ),
        n => {
            let mut arms = String::new();
            for (i, variant) in variants.iter().enumerate() {
                if i + 1 < n {
                    let arm = format!("            {i} => {rust_name}::{variant},\n");
                    arms.push_str(&arm);
                } else {
                    let arm = format!("            _ => {rust_name}::{variant},\n");
                    arms.push_str(&arm);
                }
            }
            format!(
                "    pub fn make_{snake}(rng: &mut impl Rng) -> {rust_name} {{\n        match rng.gen_range(0..{n}) {{\n{arms}        }}\n    }}\n"
            )
        }
    }
}

/// Maps an IDL type to a Rust type + filler expression, resolving `defined`
/// references against `defs`. `chain` holds the raw IDL names of definitions
/// currently being expanded (starting with the definition being generated).
///
/// Recursion guard: a `defined` reference is substituted with `u64` (plus a
/// comment) when its name is already on the expansion chain (direct or
/// transitive cycle) or when the chain has reached depth 3. Truncation and
/// unsupported types propagate up through containers and references so the
/// emitted module always compiles.
fn resolve_type(ty: &Value, defs: &HashMap<&str, DefKind<'_>>, chain: &[String]) -> Resolved {
    if let Some(prim) = ty.as_str() {
        return match prim {
            "u8" | "u16" | "u32" | "u64" | "u128" | "i8" | "i16" | "i32" | "i64" | "i128" => {
                supported(prim, "rng.gen()", None)
            }
            // f64 does not implement BorshSerialize; approximate as u64.
            "f64" => supported("u64", "rng.gen()", Some("f64 approximated as u64 for fuzzing")),
            "bool" => supported("bool", "rng.gen()", None),
            "string" => supported("String", "random_string(rng)", None),
            "publicKey" => supported("Pubkey", "Pubkey::new_unique()", None),
            _ => Resolved::Unsupported(format!("{ty}")),
        };
    }
    if let Some(obj) = ty.as_object()
        && obj.len() == 1
    {
        if let Some(inner) = obj.get("vec") {
            return wrap(
                inner,
                defs,
                chain,
                |ft| format!("Vec<{}>", ft.rust),
                |ft| format!("(0..rng.gen_range(0..=3)).map(|_| {{ {} }}).collect()", ft.filler),
            );
        }
        if let Some(inner) = obj.get("option") {
            return wrap(
                inner,
                defs,
                chain,
                |ft| format!("Option<{}>", ft.rust),
                |ft| format!("if rng.gen() {{ Some({{ {} }}) }} else {{ None }}", ft.filler),
            );
        }
        if let Some(arr) = obj.get("array") {
            if let (Some(inner), Some(n)) = (arr.get(0), arr.get(1).and_then(Value::as_u64)) {
                return wrap(
                    inner,
                    defs,
                    chain,
                    |ft| format!("[{}; {n}]", ft.rust),
                    |ft| format!("std::array::from_fn(|_| {{ {} }})", ft.filler),
                );
            }
            return Resolved::Unsupported(format!("{ty}"));
        }
        if let Some(name) = obj.get("defined").and_then(Value::as_str) {
            return resolve_defined(name, ty, defs, chain);
        }
    }
    Resolved::Unsupported(format!("{ty}"))
}

fn resolve_defined(name: &str, ty: &Value, defs: &HashMap<&str, DefKind<'_>>, chain: &[String]) -> Resolved {
    let name_owned = name.to_string();
    if chain.contains(&name_owned) || chain.len() >= 3 {
        return truncated();
    }
    match defs.get(name) {
        None => Resolved::Unsupported(format!("{ty}")),
        Some(DefKind::Enum) => supported(name, &format!("make_{}(rng)", to_snake_case(name)), None),
        Some(DefKind::Struct(fields)) => {
            // Expand the referenced struct's fields to detect cycles or
            // unsupported types before accepting the reference.
            let mut next_chain = chain.to_vec();
            next_chain.push(name_owned);
            let mut recursive = false;
            for field in *fields {
                match resolve_type(&field.ty, defs, &next_chain) {
                    Resolved::Unsupported(json) => return Resolved::Unsupported(json),
                    Resolved::Supported(ft) => recursive |= ft.recursive,
                }
            }
            if recursive { truncated() } else { supported(name, &format!("make_{}(rng)", to_snake_case(name)), None) }
        }
    }
}

/// Wraps a resolved inner type in a container, propagating comments and
/// recursion markers.
fn wrap(
    inner: &Value,
    defs: &HashMap<&str, DefKind<'_>>,
    chain: &[String],
    rust: impl FnOnce(&FieldType) -> String,
    filler: impl FnOnce(&FieldType) -> String,
) -> Resolved {
    match resolve_type(inner, defs, chain) {
        Resolved::Supported(ft) => Resolved::Supported(FieldType {
            rust: rust(&ft),
            filler: filler(&ft),
            comment: ft.comment,
            recursive: ft.recursive,
        }),
        unsupported @ Resolved::Unsupported(_) => unsupported,
    }
}

fn supported(rust: &str, filler: &str, comment: Option<&str>) -> Resolved {
    Resolved::Supported(FieldType {
        rust: rust.to_string(),
        filler: filler.to_string(),
        comment: comment.map(str::to_string),
        recursive: false,
    })
}

fn truncated() -> Resolved {
    Resolved::Supported(FieldType {
        rust: "u64".to_string(),
        filler: "rng.gen()".to_string(),
        comment: Some("recursive defined type truncated for fuzzing".to_string()),
        recursive: true,
    })
}

/// Rust keywords that would break generated fields or types; suffixed with `_`.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
    "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while",
];

/// camelCase/PascalCase IDL names → snake_case Rust idents
/// (`totalDeposits` → `total_deposits`). Non-alphanumeric characters become
/// `_`; surrounding underscores are trimmed.
fn to_snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() {
            let breaks = i > 0 && (chars[i - 1].is_ascii_lowercase() || chars[i - 1].is_ascii_digit());
            if breaks {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() { "field".to_string() } else { trimmed.to_string() }
}

/// IDL type/variant names → valid PascalCase Rust type idents.
fn sanitize_type_name(name: &str) -> String {
    let mut ident: String = name.chars().filter(|ch| ch.is_ascii_alphanumeric()).collect();
    if ident.is_empty() {
        ident.push_str("Type");
    } else if ident.chars().next().is_some_and(|ch| ch.is_ascii_lowercase()) {
        let first = ident.remove(0).to_ascii_uppercase();
        ident.insert(0, first);
    } else if ident.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        ident.insert(0, 'T');
    }
    if RUST_KEYWORDS.contains(&ident.as_str()) {
        ident.push('_');
    }
    ident
}

/// IDL field names → snake_case Rust idents; keywords get a `_` suffix
/// (e.g. an IDL field named `type` becomes `type_`).
fn sanitize_field_name(name: &str) -> String {
    let mut ident = to_snake_case(name);
    if ident.starts_with(|ch: char| ch.is_ascii_digit()) {
        ident.insert(0, '_');
    }
    if RUST_KEYWORDS.contains(&ident.as_str()) {
        ident.push('_');
    }
    ident
}

/// Anchor account discriminator: `sha256("account:<name>")[..8]`. This is the
/// same computation the generated `discriminator` fn performs at fuzzer
/// runtime with `solana_program::hash::hash`; kept here so tests can verify
/// the bytes with the `sha2` crate directly.
#[cfg(test)]
fn account_discriminator(name: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let digest = Sha256::digest(format!("account:{name}").as_bytes());
    out.copy_from_slice(&digest[..8]);
    out
}

#[cfg(test)]
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idl::parse_idl;
    use serde_json::json;

    fn fixture(name: &str) -> IdlJson {
        let path = format!("tests/fixtures/{name}.json");
        parse_idl(&path).unwrap_or_else(|err| panic!("parse {path}: {err}"))
    }

    fn expect_supported(ty: Value, defs: &HashMap<&str, DefKind<'_>>, rust: &str, filler: &str) {
        let chain = Vec::<String>::new();
        match resolve_type(&ty, defs, &chain) {
            Resolved::Unsupported(json) => panic!("expected supported type, got unsupported: {json}"),
            Resolved::Supported(ft) => {
                assert_eq!(ft.rust, rust, "rust type mismatch");
                assert_eq!(ft.filler, filler, "filler mismatch");
            }
        }
    }

    fn expect_unsupported(ty: Value, defs: &HashMap<&str, DefKind<'_>>) {
        let chain = Vec::<String>::new();
        assert!(
            matches!(resolve_type(&ty, defs, &chain), Resolved::Unsupported(_)),
            "expected unsupported type for {ty}"
        );
    }

    #[test]
    fn type_mapping_table() {
        let empty_defs = HashMap::<&str, DefKind<'_>>::new();
        for prim in ["u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128"] {
            expect_supported(json!(prim), &empty_defs, prim, "rng.gen()");
        }
        expect_supported(json!("bool"), &empty_defs, "bool", "rng.gen()");
        expect_supported(json!("string"), &empty_defs, "String", "random_string(rng)");
        expect_supported(json!("publicKey"), &empty_defs, "Pubkey", "Pubkey::new_unique()");

        // f64 does not implement BorshSerialize → approximated as u64.
        let chain = Vec::<String>::new();
        match resolve_type(&json!("f64"), &empty_defs, &chain) {
            Resolved::Supported(ft) => {
                assert_eq!(ft.rust, "u64");
                assert_eq!(ft.comment.as_deref(), Some("f64 approximated as u64 for fuzzing"));
            }
            Resolved::Unsupported(json) => panic!("f64 must be supported: {json}"),
        }

        expect_supported(
            json!({"vec": "u8"}),
            &empty_defs,
            "Vec<u8>",
            "(0..rng.gen_range(0..=3)).map(|_| { rng.gen() }).collect()",
        );
        expect_supported(
            json!({"option": "bool"}),
            &empty_defs,
            "Option<bool>",
            "if rng.gen() { Some({ rng.gen() }) } else { None }",
        );
        expect_supported(
            json!({"array": ["u64", 4]}),
            &empty_defs,
            "[u64; 4]",
            "std::array::from_fn(|_| { rng.gen() })",
        );
        expect_supported(
            json!({"vec": {"option": "publicKey"}}),
            &empty_defs,
            "Vec<Option<Pubkey>>",
            "(0..rng.gen_range(0..=3)).map(|_| { if rng.gen() { Some({ Pubkey::new_unique() }) } else { None } }).collect()",
        );

        // `defined` resolves against the defs map and is unsupported when absent.
        let defs = HashMap::from([("PoolStatus", DefKind::Enum)]);
        expect_supported(json!({"defined": "PoolStatus"}), &defs, "PoolStatus", "make_pool_status(rng)");
        expect_unsupported(json!({"defined": "Missing"}), &defs);

        // Unknown primitives, malformed containers and non-object shapes.
        expect_unsupported(json!("bytes"), &empty_defs);
        expect_unsupported(json!("stringzz"), &empty_defs);
        expect_unsupported(json!({"unknown": "x"}), &empty_defs);
        expect_unsupported(json!({"array": ["u64"]}), &empty_defs);
        expect_unsupported(json!({"vec": 42}), &empty_defs);
        expect_unsupported(json!(42), &empty_defs);
    }

    #[test]
    fn discriminator_matches_anchor_sha256_prefix() {
        let expected: [u8; 8] = {
            let digest = Sha256::digest(b"account:VaultState");
            let mut out = [0u8; 8];
            out.copy_from_slice(&digest[..8]);
            out
        };
        assert_eq!(account_discriminator("VaultState"), expected);

        // The generated module performs the same computation at runtime.
        let rendered = render_account_factories(&fixture("vault"));
        assert!(rendered.contains("solana_program::hash::hash"), "{rendered}");
        assert!(rendered.contains(r#"format!("account:{name}")"#), "{rendered}");
    }

    #[test]
    fn renders_vault_fixture_factories() {
        let out = render_account_factories(&fixture("vault"));
        for needle in [
            "pub mod accounts",
            "struct VaultState",
            "struct UserDeposit",
            "make_vault_state",
            "build_vault_state",
            "make_user_deposit",
            "build_user_deposit",
            "discriminator",
            "borsh::to_vec",
            "pub total_deposits: u64",
            "pub deposited_at: i64",
            "pub is_initialized: bool",
            "Pubkey::new_unique()",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in output:\n{out}");
        }
        let wrapped = format!("pub mod accounts {{\n{out}\n}}");
        syn::parse_file(&wrapped).expect("generated module must parse as Rust");
    }

    #[test]
    fn unsupported_defined_type_falls_back_to_placeholder() {
        let idl: IdlJson = serde_json::from_value(json!({
            "version": "0.1.0",
            "name": "demo",
            "instructions": [],
            "accounts": [{
                "name": "BrokenState",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "ok", "type": "u64"},
                        {"name": "bad", "type": {"defined": "Missing"}}
                    ]
                }
            }],
            "types": []
        }))
        .expect("inline idl");
        let out = render_account_factories(&idl);
        assert!(out.contains("unsupported field type"), "{out}");
        assert!(out.contains("placeholder data"), "{out}");
        assert!(out.contains("build_broken_state"), "{out}");
        assert!(out.contains("vec![0; 64]"), "{out}");
        assert!(!out.contains("make_broken_state"), "unsupported account must not emit a filler: {out}");
        let wrapped = format!("pub mod accounts {{\n{out}\n}}");
        syn::parse_file(&wrapped).expect("fallback module must parse as Rust");
    }

    #[test]
    fn renders_staking_enum_from_fixture() {
        let out = render_account_factories(&fixture("staking"));
        assert!(out.contains("enum PoolStatus"), "{out}");
        for variant in ["Active", "Paused", "Closed"] {
            assert!(out.contains(variant), "missing variant {variant}: {out}");
        }
        assert!(out.contains("make_pool_status"), "{out}");
        assert!(out.contains("rng.gen_range(0..3)"), "{out}");
        assert!(out.contains("pub status: PoolStatus"), "{out}");
        assert!(out.contains("build_pool_state"), "{out}");
        let wrapped = format!("pub mod accounts {{\n{out}\n}}");
        syn::parse_file(&wrapped).expect("staking module must parse as Rust");
    }

    #[test]
    fn recursive_defined_types_are_truncated() {
        let idl: IdlJson = serde_json::from_value(json!({
            "version": "0.1.0",
            "name": "tree",
            "instructions": [],
            "accounts": [{
                "name": "TreeNode",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "value", "type": "u64"},
                        {"name": "next", "type": {"option": {"defined": "TreeNode"}}},
                        {"name": "children", "type": {"vec": {"defined": "TreeNode"}}}
                    ]
                }
            }],
            "types": []
        }))
        .expect("inline idl");
        let out = render_account_factories(&idl);
        assert!(out.contains("recursive defined type truncated for fuzzing"), "{out}");
        assert!(out.contains("pub next: Option<u64>"), "{out}");
        assert!(out.contains("pub children: Vec<u64>"), "{out}");
        let wrapped = format!("pub mod accounts {{\n{out}\n}}");
        syn::parse_file(&wrapped).expect("recursive module must parse as Rust");
    }

    #[test]
    fn mutually_recursive_defined_types_are_truncated() {
        let idl: IdlJson = serde_json::from_value(json!({
            "version": "0.1.0",
            "name": "mutual",
            "instructions": [],
            "accounts": [],
            "types": [
                {
                    "name": "TypeA",
                    "type": {
                        "kind": "struct",
                        "fields": [{"name": "b", "type": {"defined": "TypeB"}}]
                    }
                },
                {
                    "name": "TypeB",
                    "type": {
                        "kind": "struct",
                        "fields": [{"name": "a", "type": {"defined": "TypeA"}}]
                    }
                }
            ]
        }))
        .expect("inline idl");
        let out = render_account_factories(&idl);
        assert!(out.contains("recursive defined type truncated for fuzzing"), "{out}");
        assert!(out.contains("pub b: u64"), "{out}");
        assert!(out.contains("pub a: u64"), "{out}");
        assert!(out.contains("make_type_a"), "{out}");
        assert!(out.contains("make_type_b"), "{out}");
        let wrapped = format!("pub mod accounts {{\n{out}\n}}");
        syn::parse_file(&wrapped).expect("mutual recursion module must parse as Rust");
    }
}
