//! IDL-driven PDA seed materialization and signer bookkeeping for the
//! generated fuzzer harness.
//!
//! [`render_pda_setup`] emits `pub const MAX_SIGNERS`, the address book
//! (`account_address`) and per-(instruction, PDA-account) helpers
//! (`seeds_<ix>_<acct>` / `pda_<ix>_<acct>`). [`render_signer_info`] emits
//! `signer_count_<ix>` per instruction. The rendered text is embedded into the
//! generated fuzzer's `lib.rs`, which defines `fuzz_account_pubkey`,
//! `well_known_account` and `program_id`.
//!
//! Signer ordinal convention: an account's ordinal is its position among the
//! instruction's `is_signer` accounts (0 = first signer = payer). The harness
//! passes `signer_pubkeys` with `signer_pubkeys[0] == *payer`.

use crate::idl::{IdlInstruction, IdlJson, IdlSeed};

use std::collections::{BTreeMap, HashSet};

/// Comment attached to seeds that cannot be materialized from the IDL (arg
/// seeds reference fuzzed args, which the harness cannot predict).
const UNVERIFIABLE_SEED_COMMENT: &str = "// \"arg\"/unverifiable seed — placeholder (fuzzed args cannot be matched)";

/// Rust keywords; a sanitized ident that collides with one gets a `_` suffix.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
    "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while",
];

/// Well-known programs/sysvars → canonical pubkey expressions, with every
/// spelling seen in Anchor IDLs (snake_case and camelCase).
const WELL_KNOWN: &[(&str, &[&str])] = &[
    ("solana_program::system_program::ID", &["system_program", "systemProgram"]),
    ("spl_token::ID", &["token_program", "tokenProgram"]),
    ("spl_token_2022::ID", &["token_2022_program", "token2022_program", "token_2022Program", "token2022Program"]),
    ("solana_program::sysvar::rent::ID", &["rent"]),
    ("solana_program::sysvar::clock::ID", &["clock"]),
    ("solana_program::sysvar::instructions::ID", &["instructions"]),
];

/// Renders the address-book + PDA helpers for the generated fuzzer:
/// `account_address`, `seeds_<ix>_<acct>`, `pda_<ix>_<acct>`, and
/// `pub const MAX_SIGNERS`.
pub fn render_pda_setup(idl: &IdlJson) -> String {
    let mut out = String::new();
    out.push_str("// ── PDA seeds & address book (generated from the IDL) ─────────────────────────\n");
    out.push_str("// Signer ordinal = position among the instruction's `is_signer` accounts; 0 = payer.\n");
    out.push_str("// `signer_pubkeys[0]` is the payer; additional signer keypairs follow in IDL order.\n\n");
    out.push_str(&format!("pub const MAX_SIGNERS: usize = {};\n\n", max_signer_count(idl)));
    out.push_str(&render_address_book(idl));
    out.push('\n');
    out.push_str(&render_seeds_fns(idl));
    out
}

/// Renders `pub fn signer_count_<ix>() -> usize` for every instruction.
pub fn render_signer_info(idl: &IdlJson) -> String {
    let mut out = String::new();
    out.push_str("// ── Signer bookkeeping (generated from the IDL) ───────────────────────────────\n");
    out.push_str("// signer_count_<ix> = number of `is_signer` accounts for that instruction; always at\n");
    out.push_str("// least 1, because the payer signs every transaction.\n\n");
    let mut used = HashSet::new();
    for ix in &idl.instructions {
        let base = format!("signer_count_{}", sanitize_ident(&ix.name));
        let (ident, note) = unique_ident(&base, &mut used);
        out.push_str(&format!("{note}pub fn {ident}() -> usize {{\n    {}\n}}\n\n", signer_count(ix).max(1)));
    }
    out
}

/// `account_address` + `seeds_<ix>_<acct>` / `pda_<ix>_<acct>` helpers.
fn render_address_book(idl: &IdlJson) -> String {
    let ordinals = signer_ordinals(idl);
    let names = distinct_account_names(idl);

    let mut out = String::new();
    out.push_str("/// Resolves an IDL account name to its pubkey for the current fuzz iteration.\n");
    out.push_str("/// Well-known programs/sysvars resolve to canonical pubkeys; IDL signers resolve to\n");
    out.push_str("/// `signer_pubkeys[<ordinal>]` (ordinal 0 = payer); everything else falls back to\n");
    out.push_str("/// `fuzz_account_pubkey` (the deterministic sat-fuzz PDA).\n");
    out.push_str("#[allow(unused_variables)] // `payer` is contract-mandated; signer_pubkeys[0] covers the payer\n");
    out.push_str("pub fn account_address(name: &str, payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Pubkey {\n");
    out.push_str("    match name {\n");

    // Well-known arms, merged with any IDL spellings that normalize to them.
    let mut extra_spellings = vec![Vec::<String>::new(); WELL_KNOWN.len()];
    for name in &names {
        if let Some(idx) = well_known_index(name)
            && !WELL_KNOWN[idx].1.contains(&name.as_str())
        {
            extra_spellings[idx].push(name.clone());
        }
    }
    for (idx, (expr, spellings)) in WELL_KNOWN.iter().enumerate() {
        let mut all: Vec<String> = spellings.iter().map(|s| (*s).to_string()).collect();
        all.extend(extra_spellings[idx].iter().cloned());
        all.sort();
        all.dedup();
        let alts = all.iter().map(|s| format!("\"{}\"", escape_str(s))).collect::<Vec<_>>().join(" | ");
        out.push_str(&format!("        {alts} => {expr},\n"));
    }

    // Remaining distinct names: signers → signer_pubkeys[ordinal], else the
    // deterministic sat-fuzz PDA (the fallback arm below also covers them).
    for name in names.iter().filter(|n| well_known_index(n).is_none()) {
        if let Some((ordinal, first_ix, consistent)) = ordinals.get(name) {
            if *consistent {
                out.push_str(&format!("        \"{}\" => signer_pubkeys[{ordinal}],\n", escape_str(name)));
            } else {
                out.push_str(&format!(
                    "        // NOTE: \"{name}\" is a signer at different ordinals across instructions (first seen in `{first_ix}`); using {ordinal}.\n        \"{}\" => signer_pubkeys[{ordinal}],\n",
                    escape_str(name)
                ));
            }
        } else {
            out.push_str(&format!(
                "        \"{}\" => fuzz_account_pubkey(\"{}\"),\n",
                escape_str(name),
                escape_str(name)
            ));
        }
    }
    out.push_str("        _ => fuzz_account_pubkey(name),\n");
    out.push_str("    }\n}\n");
    out
}

/// Per-(instruction, PDA-account) seed and PDA helpers.
fn render_seeds_fns(idl: &IdlJson) -> String {
    let mut out = String::new();
    let mut used = HashSet::new();
    for ix in &idl.instructions {
        let mut section = String::new();
        let mut any_pda = false;
        for acct in &ix.accounts {
            let Some(pda) = &acct.pda else { continue };
            if pda.seeds.is_empty() {
                continue;
            }
            any_pda = true;
            let base = format!("seeds_{}_{}", sanitize_ident(&ix.name), sanitize_ident(&acct.name));
            let (seeds_ident, note) = unique_ident(&base, &mut used);
            let pda_ident = seeds_ident.replacen("seeds_", "pda_", 1);

            let has_account_seed = pda.seeds.iter().any(|s| s.kind == "account" && seed_account_name(s).is_some());
            let allow = if has_account_seed {
                ""
            } else {
                "    #[allow(unused_variables)] // const-only seeds — payer/signer_pubkeys not referenced\n"
            };
            let seed_exprs = pda.seeds.iter().map(render_seed_expr).collect::<Vec<_>>().join("\n");

            section.push_str(&format!(
                "{note}{allow}pub fn {seeds_ident}(payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Vec<Vec<u8>> {{\n    vec![\n{seed_exprs}\n    ]\n}}\n\n"
            ));
            section.push_str(&format!(
                "pub fn {pda_ident}(payer: &Pubkey, program_id: &Pubkey, signer_pubkeys: &[Pubkey]) -> (Pubkey, u8) {{\n    let seeds: Vec<&[u8]> = {seeds_ident}(payer, signer_pubkeys).iter().map(|s| s.as_slice()).collect();\n    Pubkey::find_program_address(&seeds, program_id)\n}}\n\n"
            ));
        }
        if any_pda {
            out.push_str(&format!("// {}\n", ix.name));
            out.push_str(&section);
        }
    }
    out
}

/// One seed expression for `seeds_<ix>_<acct>`: `b"..."`/byte literals for
/// const seeds, `account_address(...)` for account-derived seeds, and a fixed
/// placeholder for arg/unknown seeds.
fn render_seed_expr(seed: &IdlSeed) -> String {
    match seed.kind.as_str() {
        "const" => match seed.value.as_deref() {
            Some(bytes)
                if !bytes.is_empty() && bytes.iter().all(|b| b.is_ascii_graphic() && *b != b'"' && *b != b'\\') =>
            {
                let text = String::from_utf8_lossy(bytes);
                format!("        b\"{text}\".to_vec(),")
            }
            Some(bytes) if !bytes.is_empty() => {
                let literals = bytes.iter().map(|b| format!("{b}u8")).collect::<Vec<_>>().join(", ");
                format!("        vec![{literals}],")
            }
            _ => format!("        vec![0u8; 32], {UNVERIFIABLE_SEED_COMMENT}"),
        },
        "account" => match seed_account_name(seed) {
            Some(name) => format!(
                "        account_address(\"{}\", payer, signer_pubkeys).to_bytes().to_vec(),",
                escape_str(&name)
            ),
            None => format!("        vec![0u8; 32], {UNVERIFIABLE_SEED_COMMENT}"),
        },
        _ => format!("        vec![0u8; 32], {UNVERIFIABLE_SEED_COMMENT}"),
    }
}

/// The account name a `kind == "account"` seed refers to: the explicit
/// `account` field when present, else the first path segment (Anchor IDLs
/// usually carry `path`, e.g. `"user"` or `"authority.key"`).
fn seed_account_name(seed: &IdlSeed) -> Option<String> {
    if let Some(name) = seed.account.as_deref().filter(|s| !s.is_empty()) {
        return Some(name.to_string());
    }
    seed.path.as_deref().map(|p| p.split('.').next().unwrap_or("").to_string()).filter(|s| !s.is_empty())
}

/// Number of `is_signer` accounts in an instruction.
fn signer_count(ix: &IdlInstruction) -> usize {
    ix.accounts.iter().filter(|a| a.is_signer).count()
}

/// Max `is_signer` count over all instructions, at least 1 (the payer).
fn max_signer_count(idl: &IdlJson) -> usize {
    idl.instructions.iter().map(signer_count).max().unwrap_or(0).max(1)
}

/// Signer ordinal per distinct signer name: (ordinal, first instruction,
/// consistent-across-instructions). Ordinal = position among `is_signer`
/// accounts, 0 = payer.
fn signer_ordinals(idl: &IdlJson) -> BTreeMap<String, (usize, String, bool)> {
    let mut out: BTreeMap<String, (usize, String, bool)> = BTreeMap::new();
    for ix in &idl.instructions {
        let mut ordinal = 0usize;
        for acct in &ix.accounts {
            if acct.is_signer {
                match out.get_mut(&acct.name) {
                    Some((prev, _, consistent)) => {
                        if *prev != ordinal {
                            *consistent = false;
                        }
                    }
                    None => {
                        out.insert(acct.name.clone(), (ordinal, ix.name.clone(), true));
                    }
                }
                ordinal += 1;
            }
        }
    }
    out
}

/// All distinct account names across instructions, in first-appearance order.
fn distinct_account_names(idl: &IdlJson) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ix in &idl.instructions {
        for acct in &ix.accounts {
            if seen.insert(acct.name.clone()) {
                out.push(acct.name.clone());
            }
        }
    }
    out
}

/// Index into `WELL_KNOWN` if `name` is a known program/sysvar spelling
/// (case-insensitive, ignoring non-alphanumerics).
fn well_known_index(name: &str) -> Option<usize> {
    let norm = normalize(name);
    WELL_KNOWN.iter().position(|(_, spellings)| spellings.iter().any(|s| normalize(s) == norm))
}

fn normalize(name: &str) -> String {
    name.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

/// Makes an IDL name a valid Rust identifier: non-alphanumerics → `_`,
/// leading digit → `_` prefix, Rust keyword → `_` suffix, empty → `_`.
fn sanitize_ident(name: &str) -> String {
    let mut out: String = name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if out.is_empty() {
        out.push('_');
    } else if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if RUST_KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

/// Returns `base` if unused, else `base_2`, `base_3`, ... A NOTE comment is
/// returned on collision so the generated code explains the suffix.
fn unique_ident(base: &str, used: &mut HashSet<String>) -> (String, String) {
    if used.insert(base.to_string()) {
        return (base.to_string(), String::new());
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}_{n}");
        if used.insert(candidate.clone()) {
            let note = format!(
                "// NOTE: sanitized name \"{base}\" collides with an earlier instruction; suffixed with _{n} for uniqueness.\n"
            );
            return (candidate, note);
        }
        n += 1;
    }
}

/// Escapes a string for embedding in a generated Rust string literal.
fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idl::{IdlAccountItem, IdlInstruction, IdlJson, IdlPda, IdlSeed, parse_idl};

    fn fixture(name: &str) -> IdlJson {
        let path = format!("tests/fixtures/{name}.json");
        parse_idl(&path).unwrap_or_else(|err| panic!("parse {path}: {err}"))
    }

    fn seed(kind: &str, value: Option<Vec<u8>>, path: Option<&str>, account: Option<&str>) -> IdlSeed {
        IdlSeed { kind: kind.to_string(), value, path: path.map(str::to_string), account: account.map(str::to_string) }
    }

    fn account(name: &str, is_signer: bool, pda: Option<IdlPda>) -> IdlAccountItem {
        IdlAccountItem { name: name.to_string(), is_mut: true, is_signer, pda, desc: None }
    }

    fn instruction(name: &str, accounts: Vec<IdlAccountItem>) -> IdlInstruction {
        IdlInstruction { name: name.to_string(), accounts, args: vec![], discriminator: None }
    }

    fn idl(instructions: Vec<IdlInstruction>) -> IdlJson {
        IdlJson {
            version: "0.1.0".to_string(),
            name: "test".to_string(),
            instructions,
            accounts: vec![],
            types: vec![],
            metadata: None,
        }
    }

    /// The generated code is embedded into the fuzzer's lib.rs; wrap it in a
    /// module and require it to parse as valid Rust.
    fn assert_parses(code: &str) {
        let wrapped = format!("mod generated {{\n{code}\n}}");
        syn::parse_file(&wrapped)
            .unwrap_or_else(|err| panic!("generated code does not parse: {err}\n--- code ---\n{code}"));
    }

    /// Extracts the full text of `pub fn <name>(...) { ... }`.
    fn extract_fn(code: &str, name: &str) -> String {
        let start = code.find(&format!("pub fn {name}(")).unwrap_or_else(|| panic!("fn {name} not found"));
        let rest = &code[start..];
        let mut depth = 0i32;
        for (i, ch) in rest.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return rest[..=i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces in fn {name}")
    }

    #[test]
    fn vault_fixture_pda_setup_renders_and_parses() {
        let out = render_pda_setup(&fixture("vault"));
        for needle in [
            "pub const MAX_SIGNERS: usize = 1;",
            "pub fn account_address(name: &str, payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Pubkey",
            "pub fn seeds_initializeVault_vaultState(payer: &Pubkey, signer_pubkeys: &[Pubkey]) -> Vec<Vec<u8>>",
            "pub fn pda_initializeVault_vaultState(",
            "pub fn seeds_deposit_userDeposit(",
            "find_program_address",
            "b\"vault\".to_vec()",
        ] {
            assert!(out.contains(needle), "missing `{needle}` in:\n{out}");
        }
        // account-kind seed carrying only `path` (fixture style) resolves via account_address.
        let deposit_seeds = extract_fn(&out, "seeds_deposit_userDeposit");
        assert!(
            deposit_seeds.contains("account_address(\"user\", payer, signer_pubkeys).to_bytes().to_vec()"),
            "{deposit_seeds}"
        );
        // camelCase well-known name resolves to the canonical system program.
        let book = extract_fn(&out, "account_address");
        assert!(
            book.contains("\"systemProgram\" | \"system_program\" => solana_program::system_program::ID,"),
            "{book}"
        );
        assert!(book.contains("_ => fuzz_account_pubkey(name),"), "{book}");
        assert_parses(&out);
    }

    #[test]
    fn staking_fixture_signer_info_renders_and_parses() {
        let idl = fixture("staking");
        let info = render_signer_info(&idl);
        for name in [
            "signer_count_initializePool",
            "signer_count_stake",
            "signer_count_unstake",
            "signer_count_claimRewards",
            "signer_count_closePool",
        ] {
            assert!(info.contains(&format!("pub fn {name}() -> usize {{")), "missing {name} in:\n{info}");
        }
        assert_parses(&info);

        let setup = render_pda_setup(&idl);
        assert!(setup.contains("pub const MAX_SIGNERS: usize = 1;"), "MAX_SIGNERS must be >= 1:\n{setup}");
        assert!(setup.contains("pub fn seeds_initializePool_poolState("), "{setup}");
        assert!(setup.contains("pub fn seeds_stake_userStake("), "{setup}");
        assert_parses(&setup);
    }

    #[test]
    fn const_and_account_seeds_materialize_bytes() {
        let idl = idl(vec![instruction(
            "init",
            vec![
                account(
                    "state",
                    false,
                    Some(IdlPda {
                        seeds: vec![
                            seed("const", Some(b"state".to_vec()), None, None),
                            seed("account", None, None, Some("authority")),
                        ],
                    }),
                ),
                account("authority", true, None),
            ],
        )]);
        let out = render_pda_setup(&idl);
        let seeds = extract_fn(&out, "seeds_init_state");
        assert!(seeds.contains("b\"state\".to_vec()"), "const seed should be readable ASCII bytes:\n{seeds}");
        assert!(seeds.contains("account_address(\"authority\", payer, signer_pubkeys).to_bytes().to_vec()"), "{seeds}");
        assert_parses(&out);
    }

    #[test]
    fn arg_seed_renders_placeholder() {
        let idl = idl(vec![instruction(
            "mint",
            vec![account("mintState", false, Some(IdlPda { seeds: vec![seed("arg", None, None, None)] }))],
        )]);
        let out = render_pda_setup(&idl);
        assert!(out.contains(UNVERIFIABLE_SEED_COMMENT), "placeholder comment missing:\n{out}");
        assert!(out.contains("vec![0u8; 32],"), "placeholder seed expression missing:\n{out}");
        assert_parses(&out);
    }

    #[test]
    fn signer_count_and_max_signers() {
        let idl =
            idl(vec![instruction("transfer", vec![account("authority", true, None), account("delegate", true, None)])]);
        let info = render_signer_info(&idl);
        assert!(info.contains("pub fn signer_count_transfer() -> usize {\n    2\n}"), "{info}");
        assert_parses(&info);

        let setup = render_pda_setup(&idl);
        assert!(setup.contains("pub const MAX_SIGNERS: usize = 2;"), "{setup}");
        let book = extract_fn(&setup, "account_address");
        assert!(book.contains("\"authority\" => signer_pubkeys[0],"), "{book}");
        assert!(book.contains("\"delegate\" => signer_pubkeys[1],"), "{book}");
        assert_parses(&setup);
    }

    #[test]
    fn sanitized_names_produce_valid_rust_idents() {
        let idl = idl(vec![instruction(
            "init-vault",
            vec![account(
                "my-account",
                false,
                Some(IdlPda { seeds: vec![seed("const", Some(b"v".to_vec()), None, None)] }),
            )],
        )]);
        let out = render_pda_setup(&idl);
        assert!(out.contains("pub fn seeds_init_vault_my_account("), "{out}");
        assert!(out.contains("pub fn pda_init_vault_my_account("), "{out}");
        assert_parses(&out);

        let info = render_signer_info(&idl);
        assert!(info.contains("pub fn signer_count_init_vault()"), "{info}");
        assert_parses(&info);
    }

    #[test]
    fn sanitized_name_collisions_get_suffixed() {
        let pda_a = Some(IdlPda { seeds: vec![seed("const", Some(b"a".to_vec()), None, None)] });
        let pda_b = Some(IdlPda { seeds: vec![seed("const", Some(b"b".to_vec()), None, None)] });
        let idl = idl(vec![
            instruction("foo-bar", vec![account("state", false, pda_a)]),
            instruction("foo_bar", vec![account("state", false, pda_b)]),
        ]);
        let out = render_pda_setup(&idl);
        assert!(out.contains("pub fn seeds_foo_bar_state("), "first occurrence keeps the base name:\n{out}");
        assert!(out.contains("pub fn seeds_foo_bar_state_2("), "collision should be suffixed:\n{out}");
        assert!(out.contains("pub fn pda_foo_bar_state_2("), "pda helper must follow the suffixed name:\n{out}");
        assert!(out.contains("NOTE"), "collision should be noted in a comment:\n{out}");
        assert_parses(&out);
    }
}
