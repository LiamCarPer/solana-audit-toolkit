//! Frontend tests: parse each frontend fixture with
//! `sat::native::analyze_source_for_test` and assert on the pinned model
//! (`NativeProgram` / `NativeInstruction` / `ResolvedAccount`).

use sat::native::model::{AccountKind, NativeInstruction, NativeProgram, ResolvedAccount};

fn fixture_source(name: &str) -> String {
    let path = format!("tests/fixtures_native/frontend/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

fn analyze_fixture(name: &str) -> NativeProgram {
    sat::native::analyze_source_for_test(&fixture_source(name))
}

fn account<'a>(ix: &'a NativeInstruction, name: &str) -> &'a ResolvedAccount {
    ix.accounts
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("account `{name}` not resolved (have: {:?})", account_names(ix)))
}

fn account_names(ix: &NativeInstruction) -> Vec<&str> {
    ix.accounts.iter().map(|a| a.name.as_str()).collect()
}

fn entrypoint_line_of(source: &str) -> usize {
    source.lines().position(|l| l.contains("entrypoint!(")).map(|i| i + 1).unwrap_or(0)
}

// ── Strategy 1: positional iterator ─────────────────────────────────────────

#[test]
fn fixture_positional_resolves_iterator_accounts_and_guards() {
    let source = fixture_source("fixture_positional.rs");
    let p = analyze_fixture("fixture_positional.rs");

    assert_eq!(p.program_id, None, "no declare_id in this fixture");
    assert_eq!(p.entrypoint_file, "test.rs");
    assert_eq!(p.entrypoint_line, entrypoint_line_of(&source));
    assert_eq!(p.instructions.len(), 1, "no dispatch match -> single fallback instruction");

    let ix = &p.instructions[0];
    assert_eq!(ix.name, "process_instruction");
    assert_eq!(ix.handler, "process_instruction");
    assert_eq!(ix.discriminator, None);
    assert_eq!(ix.file, "test.rs");

    assert_eq!(account_names(ix), ["state", "authority", "payer", "vault", "system_program"]);
    for (i, a) in ix.accounts.iter().enumerate() {
        assert_eq!(a.index, i, "positional order must match next_account_info call order");
    }

    let authority = account(ix, "authority");
    assert!(authority.is_signer_checked, "authority has an is_signer guard");
    assert!(!authority.owner_checked);

    let state = account(ix, "state");
    assert!(state.owner_checked, "state.owner == program_id guard");
    assert!(!state.is_signer_checked);

    let vault = account(ix, "vault");
    assert!(vault.key_checked, "vault.key == pda guard");
    assert!(vault.is_pda, "vault key is compared against find_program_address result");
    assert_eq!(vault.seeds, vec!["b\"vault\"".to_string(), "authority.key.as_ref()".to_string()]);

    let system_program = account(ix, "system_program");
    assert_eq!(system_program.kind, AccountKind::SystemProgram);
    assert!(system_program.key_checked);

    assert_eq!(account(ix, "payer").kind, AccountKind::Unchecked);
    assert!(!account(ix, "payer").written);
}

// ── Strategy 2: subscript ───────────────────────────────────────────────────

#[test]
fn fixture_subscript_resolves_indexed_accounts_and_writes() {
    let p = analyze_fixture("fixture_subscript.rs");
    assert_eq!(p.instructions.len(), 1);
    let ix = &p.instructions[0];

    assert_eq!(account_names(ix), ["state", "authority", "payer", "token_account"]);
    for (i, a) in ix.accounts.iter().enumerate() {
        assert_eq!(a.index, i);
    }

    assert!(account(ix, "authority").is_signer_checked);
    assert!(account(ix, "payer").written, "&mut accounts[2] binding");
    assert!(account(ix, "state").written, "state.data.borrow_mut()");
    assert_eq!(account(ix, "token_account").kind, AccountKind::TokenAccount);
}

// ── Strategy 3: struct try_from ─────────────────────────────────────────────

#[test]
fn fixture_struct_tryfrom_resolves_fields_in_declaration_order() {
    let p = analyze_fixture("fixture_struct_tryfrom.rs");
    assert_eq!(p.instructions.len(), 1);
    let ix = &p.instructions[0];

    assert_eq!(account_names(ix), ["state", "authority", "token_account", "vault"]);
    for (i, a) in ix.accounts.iter().enumerate() {
        assert_eq!(a.index, i, "one index per field in declaration order");
    }

    assert!(account(ix, "authority").is_signer_checked, "accs.authority.is_signer guard");
    assert!(account(ix, "state").owner_checked, "accs.state.owner guard");
    assert_eq!(account(ix, "token_account").kind, AccountKind::TokenAccount);
    assert_eq!(account(ix, "vault").kind, AccountKind::Unchecked);
}

// ── Strategy 4: helper call graph ──────────────────────────────────────────

#[test]
fn fixture_helpers_propagate_checks_from_single_account_helpers() {
    let p = analyze_fixture("fixture_helpers.rs");
    assert_eq!(p.instructions.len(), 1);
    let ix = &p.instructions[0];

    assert_eq!(account_names(ix), ["state", "authority", "admin"]);
    assert!(account(ix, "authority").is_signer_checked, "check_signer(&authority) helper body");
    assert!(account(ix, "state").owner_checked, "check_owner(&state, program_id) helper");
    assert!(!account(ix, "admin").is_signer_checked);
}

// ── Dispatch: byte-slice match ──────────────────────────────────────────────

#[test]
fn fixture_dispatch_match8_recovers_handlers_and_discriminators() {
    let p = analyze_fixture("fixture_dispatch_match8.rs");
    assert_eq!(p.instructions.len(), 3);

    let deposit = &p.instructions[0];
    assert_eq!(deposit.name, "process_deposit");
    assert_eq!(deposit.handler, "process_deposit");
    assert_eq!(deposit.discriminator, None, "binding pattern [a..h] carries no literal bytes");
    assert_eq!(account_names(deposit), ["state", "authority"]);
    assert!(account(deposit, "authority").is_signer_checked);

    let withdraw = &p.instructions[1];
    assert_eq!(withdraw.name, "process_withdraw");
    assert_eq!(withdraw.handler, "process_withdraw");
    assert_eq!(withdraw.discriminator, Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(account_names(withdraw), ["vault", "authority"]);

    let unknown = &p.instructions[2];
    assert_eq!(unknown.name, "instruction_0x0909090909090909", "hex fallback name");
    assert_eq!(unknown.handler, "", "no handler call in the arm body");
    assert_eq!(unknown.discriminator, Some(vec![9; 8]));
    assert!(unknown.accounts.is_empty());
}

// ── Dispatch: enum match ────────────────────────────────────────────────────

#[test]
fn fixture_dispatch_enum_recovers_variants_and_tags() {
    let p = analyze_fixture("fixture_dispatch_enum.rs");
    assert_eq!(p.instructions.len(), 3);

    let initialize = &p.instructions[0];
    assert_eq!(initialize.name, "Initialize");
    assert_eq!(initialize.handler, "process_initialize");
    assert_eq!(initialize.discriminator, Some(vec![0]), "tag recovered from Instruction::unpack");
    assert_eq!(account_names(initialize), ["state", "authority"]);
    assert!(account(initialize, "authority").is_signer_checked);

    let deposit = &p.instructions[1];
    assert_eq!(deposit.name, "Deposit");
    assert_eq!(deposit.handler, "process_deposit");
    assert_eq!(deposit.discriminator, Some(vec![1]));
    assert_eq!(account_names(deposit), ["state", "authority", "token_account"]);
    assert_eq!(account(deposit, "token_account").kind, AccountKind::TokenAccount);

    let withdraw = &p.instructions[2];
    assert_eq!(withdraw.name, "Withdraw");
    assert_eq!(withdraw.handler, "process_withdraw");
    assert_eq!(withdraw.discriminator, Some(vec![2]));
    assert_eq!(account_names(withdraw), ["state", "authority", "vault"]);
}

// ── Dispatch: u8 tag fallback ───────────────────────────────────────────────

#[test]
fn fixture_dispatch_tag_falls_back_to_instruction_0x_names() {
    let p = analyze_fixture("fixture_dispatch_tag.rs");
    assert_eq!(p.instructions.len(), 2);

    let close = &p.instructions[0];
    assert_eq!(close.name, "instruction_0x00");
    assert_eq!(close.handler, "process_close");
    assert_eq!(close.discriminator, Some(vec![0]));
    assert_eq!(account_names(close), ["state", "authority"]);

    let update = &p.instructions[1];
    assert_eq!(update.name, "instruction_0x01");
    assert_eq!(update.handler, "process_update");
    assert_eq!(update.discriminator, Some(vec![1]));
    assert_eq!(account_names(update), ["state", "authority", "vault"]);
    assert!(account(update, "vault").key_checked);
    assert!(account(update, "state").key_checked);
}

// ── Dispatch: borsh try_from_slice inside impl-method processor ─────────────

#[test]
fn fixture_try_from_slice_follows_delegation_and_shank_accounts() {
    let p = analyze_fixture("fixture_try_from_slice.rs");
    assert_eq!(p.instructions.len(), 3);

    let initialize = &p.instructions[0];
    assert_eq!(initialize.name, "Initialize");
    assert_eq!(initialize.discriminator, Some(vec![0]), "borsh tag = declaration order");
    assert_eq!(initialize.handler, "process_initialize", "Self:: method handler recovered");
    assert_eq!(account_names(initialize), ["payer", "state"], "shank names win over handler bindings");
    assert!(account(initialize, "payer").is_signer_checked, "handler signer guard survives shank merge");

    let deposit = &p.instructions[1];
    assert_eq!(deposit.name, "Deposit");
    assert_eq!(deposit.discriminator, Some(vec![1]));
    assert_eq!(account_names(deposit), ["state", "authority", "token_account"]);
    assert_eq!(account(deposit, "authority").kind, AccountKind::Signer, "shank signer flag maps to kind");

    let withdraw = &p.instructions[2];
    assert_eq!(withdraw.name, "Withdraw");
    assert_eq!(withdraw.discriminator, Some(vec![2]));
    assert_eq!(account_names(withdraw), ["state", "authority"], "no shank attrs -> handler positional");
}

// ── Dispatch: split_at account destructuring ────────────────────────────────

#[test]
fn fixture_split_at_tracks_both_slice_halves_positionally() {
    let p = analyze_fixture("fixture_split_at.rs");
    assert_eq!(p.instructions.len(), 1);
    let ix = &p.instructions[0];

    assert_eq!(account_names(ix), ["state", "authority", "vault", "account_3"]);
    for (i, a) in ix.accounts.iter().enumerate() {
        assert_eq!(a.index, i, "split_at continuation must keep positional order");
    }
    assert!(account(ix, "authority").is_signer_checked, "guard inside the destructured head");
}

// ── Dispatch: framework-macro token recovery (solitaire! class) ─────────────

#[test]
fn fixture_macro_dispatch_recovers_solitaire_rows() {
    let source = fixture_source("fixture_macro_dispatch.rs");
    let p = analyze_fixture("fixture_macro_dispatch.rs");

    assert_eq!(p.instructions.len(), 8, "one instruction per solitaire! row");
    let line = source.lines().position(|l| l.contains("solitaire! {")).map(|i| i + 1).unwrap();
    assert_eq!(p.entrypoint_line, line, "entrypoint line is the macro invocation line");

    for (i, ix) in p.instructions.iter().enumerate() {
        assert_eq!(ix.discriminator, Some(vec![i as u8]), "borsh order = declaration order");
        assert!(ix.accounts.is_empty(), "framework-peeled accounts stay unresolved");
    }
    assert_eq!(p.instructions[0].name, "Initialize");
    assert_eq!(p.instructions[0].handler, "initialize");
    assert_eq!(p.instructions[3].name, "SetFees");
    assert_eq!(p.instructions[3].handler, "set_fees");
    assert_eq!(p.instructions[7].name, "VerifySignatures");
    assert_eq!(p.instructions[7].handler, "verify_signatures");
}

// ── Mango-style composite ───────────────────────────────────────────────────

#[test]
fn fixture_mango_style_builds_full_program() {
    let p = analyze_fixture("fixture_mango_style.rs");

    assert_eq!(
        p.program_id.as_deref(),
        Some("MangoCzJ36AjZyKwVj3VnYU4GTonjftVETpppHvdwSQe"),
        "declare_id literal captured"
    );
    assert_eq!(p.entrypoint_file, "test.rs");
    assert_eq!(p.instructions.len(), 1);

    let ix = &p.instructions[0];
    assert_eq!(ix.name, "process_instruction");
    assert_eq!(account_names(ix), ["state", "authority", "token_account"]);

    let state = account(ix, "state");
    assert!(state.owner_checked, "accs.state.owner != program_id guard");
    assert!(state.written, "State::load_mut(&accs.state)");
    assert!(!state.is_pda);

    let authority = account(ix, "authority");
    assert!(authority.is_signer_checked, "validate(&accs.authority) helper");
    assert!(!authority.written);

    assert_eq!(account(ix, "token_account").kind, AccountKind::TokenAccount);
}

// ── Robustness: garbage input and non-native sources ────────────────────────

#[test]
fn unparseable_input_does_not_panic() {
    // `analyze_source_for_test` documents: parse failures yield a default
    // (empty) NativeProgram with no entrypoint — never a panic.
    for src in ["", "fn broken(", "entrypoint!(", "pub fn process_instruction("] {
        let p = sat::native::analyze_source_for_test(src);
        assert!(p.entrypoint_file.is_empty(), "no entrypoint for {src:?}");
        assert!(p.instructions.is_empty());
        assert!(p.program_id.is_none());
    }
}

#[test]
fn non_native_source_yields_empty_program_and_no_findings() {
    let src = r#"
        #[program]
        pub mod anchor_program {
            use super::*;
            pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
                Ok(())
            }
        }
    "#;
    let p = sat::native::analyze_source_for_test(src);
    assert!(p.entrypoint_file.is_empty(), "Anchor-style file has no native marker");
    assert!(p.instructions.is_empty());

    let parsed = syn::parse_file(src).expect("test source should parse");
    assert!(sat::native::analyze(&[(parsed, "test.rs".to_string())]).is_empty());
}

#[test]
fn native_analysis_runs_wired_rule_slices() {
    // Rules are wired into rules::run since integration: a native program with
    // an unguarded authority must produce findings through the full pipeline.
    let src = std::fs::read_to_string("tests/fixtures_native/auth/vuln.rs").expect("auth vuln fixture");
    let parsed = syn::parse_file(&src).expect("test source should parse");
    let findings = sat::native::analyze(&[(parsed, "test.rs".to_string())]);
    assert!(
        findings.iter().any(|f| f.title.starts_with("Unverified Signer Account:")),
        "wired pipeline should surface SAT019 on the auth vuln fixture"
    );
}

#[test]
fn default_model_shapes() {
    let p = NativeProgram::default();
    assert_eq!(p.entrypoint_file, "");
    assert_eq!(p.entrypoint_line, 0);
    assert!(p.instructions.is_empty());
    assert!(p.program_id.is_none());

    let r = ResolvedAccount::default();
    assert_eq!(r.name, "");
    assert_eq!(r.index, 0);
    assert_eq!(r.kind, AccountKind::Unchecked);
    assert!(!r.is_signer_checked && !r.owner_checked && !r.key_checked && !r.written && !r.is_pda);
    assert!(r.seeds.is_empty());
}
