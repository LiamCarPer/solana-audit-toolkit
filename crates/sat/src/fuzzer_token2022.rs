//! Token-2022 account factories for the generated fuzzer harness.
//!
//! [`render_token_2022_factories`] renders the `token2022_accounts` module
//! that gets embedded into the generated fuzzer's `lib.rs`. The returned
//! string MUST start with the marker line `// Generated token-2022 account
//! factories` — the harness integration agent asserts on that marker, so it
//! stays the first line of the rendered module.
//!
//! The rendered module targets the spl-token-2022 API pinned by the generated
//! fuzzer's `Cargo.toml` (default `"7"` → 7.0.0, or the version mirrored from
//! the target program). All type names, field names, field order and layouts
//! were verified against docs.rs and the published crate sources before
//! writing the templates below; the version caveats are re-stated inside the
//! generated module itself.

/// The rendered `token2022_accounts` module.
const GENERATED_TOKEN_2022_ACCOUNT_FACTORIES: &str = r#"// Generated token-2022 account factories
//
// Version caveats (verified on docs.rs, 2026-08):
// - This module targets the spl-token-2022 API pinned by the generated
//   fuzzer's Cargo.toml: default "7" (=> 7.0.0, pod-based API), or the
//   version mirrored from the target program's Cargo.toml.
// - docs.rs/latest is spl-token-2022 11.x: its extension structs use
//   spl-token-2022-interface types (`MaybeNull<Address>`, `U64`, `I64`,
//   `I16`) — this module does NOT match that API.
// - In 6.x/7.x the extension structs (TransferFeeConfig, InterestBearingConfig,
//   PermanentDelegate, TransferFee) are spl-pod types: authority fields are
//   `OptionalNonZeroPubkey`, numeric fields are `PodU64`/`PodU16`/`PodI64`/
//   `PodI16` (little-endian). The generated fuzzer has no `spl-pod`/`bytemuck`
//   dependency and spl-token-2022 does not re-export those types, so the TLV
//   entries below are serialized field-by-field in the verified repr(C)
//   layout, byte-identical to the Pod bytes the processor unpacks.
// - `pack_extension` and `ExtensionType::get_account_len` (the API from the
//   original task sketch, with COption<Pubkey>/u64/i64/i16 fields) are
//   pre-3.0 helpers; they are absent from every 2.x+ release spot-checked
//   (2.0.2, 3.0.5, 4.0.1, 5.0.2, 6.0.0, 7.0.0). 3.x+ computes lengths via
//   `ExtensionType::try_calculate_account_len::<Mint>(&[...])` and appends
//   TLV entries as done here.
// - VERIFY: if the mirrored target pins a major outside 6.x/7.x (8.x-10.x
//   were not checked; 11.x is different), re-verify the field types and the
//   packing layout above before relying on this module.
pub mod token2022_accounts {
    use solana_program::program_option::COption;
    use solana_program_test::ProgramTest;
    use solana_sdk::{account::Account, pubkey::Pubkey};
    use spl_token_2022::extension::interest_bearing_mint::InterestBearingConfig;
    use spl_token_2022::extension::permanent_delegate::PermanentDelegate;
    use spl_token_2022::extension::transfer_fee::{TransferFee, TransferFeeConfig};
    use spl_token_2022::extension::{AccountType, ExtensionType};
    use spl_token_2022::state::{Account as TokenAccount, AccountState, Mint};
    use std::mem::size_of;

    pub fn token_2022_program_id() -> Pubkey {
        spl_token_2022::ID
    }

    /// Appends one TLV entry ([type u16 LE][length u16 LE][value]) at
    /// `offset` inside the extension region of a token-2022 account, mirroring
    /// the format written by `StateWithExtensionsMut::init_extension`.
    fn write_tlv_entry(
        data: &mut [u8],
        offset: &mut usize,
        extension_type: ExtensionType,
        value: &[u8],
    ) {
        let entry_len = u16::try_from(value.len()).expect("extension value fits in u16");
        data[*offset..*offset + 2].copy_from_slice(&(extension_type as u16).to_le_bytes());
        data[*offset + 2..*offset + 4].copy_from_slice(&entry_len.to_le_bytes());
        data[*offset + 4..*offset + 4 + value.len()].copy_from_slice(value);
        *offset += 4 + value.len();
    }

    /// Seeds a Token-2022 mint WITH extensions (transfer fee, interest
    /// bearing, permanent delegate), owned by `spl_token_2022::ID`.
    ///
    /// Account layout (verified against the token-2022 processor):
    /// `[0, Mint::LEN)` packed base `Mint`, `[Mint::LEN, Account::LEN)` zero
    /// padding, `[Account::LEN]` account type byte (`AccountType::Mint`),
    /// then the TLV entries. The total length comes from
    /// `ExtensionType::try_calculate_account_len::<Mint>` — never hardcoded.
    ///
    /// Compatibility rule: an interest-bearing mint CANNOT have a mint
    /// authority (InitializeMint rejects it), so `mint_authority` is
    /// `COption::None` while the InterestBearingConfig extension is attached.
    /// Transfer fee + permanent delegate alone would allow keeping
    /// `COption::Some(*owner)`; if you remove the interest-bearing extension,
    /// restore it.
    pub fn seed_fuzz_mint(program_test: &mut ProgramTest, mint: &Pubkey, owner: &Pubkey) {
        let base = Mint {
            // Interest-bearing mints cannot have a mint authority
            // (InitializeMint rejects it) — see the compatibility rule above.
            mint_authority: COption::None,
            supply: 10_000_000_000_000_000,
            decimals: 9,
            is_initialized: true,
            freeze_authority: COption::None,
        };
        let extension_types = [
            ExtensionType::TransferFeeConfig,
            ExtensionType::InterestBearingConfig,
            ExtensionType::PermanentDelegate,
        ];
        // 7.x length API; the pre-3.0 name was `ExtensionType::get_account_len`.
        let len = ExtensionType::try_calculate_account_len::<Mint>(&extension_types)
            .expect("token-2022 mint extension length");
        let mut data = vec![0u8; len];
        Mint::pack(base, &mut data[..Mint::LEN]).expect("pack token-2022 mint base state");
        // Account type byte at `Account::LEN` (the base account length), then
        // the TLV entries.
        data[TokenAccount::LEN] = AccountType::Mint as u8;
        let mut tlv_offset = TokenAccount::LEN + 1;

        // --- TransferFeeConfig (transfer fees) ---
        // Charges 100 basis points (1%), capped at 1_000_000 tokens, on every
        // transfer from epoch 0 on. `owner` can change the fee and withdraw
        // withheld fees. To remove: drop the entry from `extension_types`
        // above and delete this block. To extend: tune the basis points /
        // maximum fee (10_000 bp = 100%).
        let transfer_fee = |epoch: u64, maximum_fee: u64, basis_points: u16| -> Vec<u8> {
            let mut bytes = Vec::with_capacity(size_of::<TransferFee>());
            bytes.extend_from_slice(&epoch.to_le_bytes()); // TransferFee::epoch
            bytes.extend_from_slice(&maximum_fee.to_le_bytes()); // TransferFee::maximum_fee
            bytes.extend_from_slice(&basis_points.to_le_bytes()); // TransferFee::transfer_fee_basis_points
            bytes
        };
        let fee = transfer_fee(0, 1_000_000, 100);
        assert_eq!(fee.len(), size_of::<TransferFee>(), "TransferFee layout");
        let mut value = Vec::with_capacity(size_of::<TransferFeeConfig>());
        value.extend_from_slice(&owner.to_bytes()); // transfer_fee_config_authority
        value.extend_from_slice(&owner.to_bytes()); // withdraw_withheld_authority
        value.extend_from_slice(&0u64.to_le_bytes()); // withheld_amount
        value.extend_from_slice(&fee); // older_transfer_fee
        value.extend_from_slice(&fee); // newer_transfer_fee
        assert_eq!(
            value.len(),
            size_of::<TransferFeeConfig>(),
            "TransferFeeConfig layout"
        );
        write_tlv_entry(&mut data, &mut tlv_offset, ExtensionType::TransferFeeConfig, &value);

        // --- InterestBearingConfig (interest accrual) ---
        // Accrues 100 basis points (1%) per year, compounded continuously,
        // with `owner` as the rate authority. MUST stay paired with
        // `mint_authority: COption::None` (see the compatibility rule above).
        // To remove: drop it from `extension_types` and restore
        // `mint_authority: COption::Some(*owner)`.
        let mut value = Vec::with_capacity(size_of::<InterestBearingConfig>());
        value.extend_from_slice(&owner.to_bytes()); // rate_authority
        value.extend_from_slice(&0i64.to_le_bytes()); // initialization_timestamp
        value.extend_from_slice(&0i16.to_le_bytes()); // pre_update_average_rate
        value.extend_from_slice(&0i64.to_le_bytes()); // last_update_timestamp
        value.extend_from_slice(&100i16.to_le_bytes()); // current_rate
        assert_eq!(
            value.len(),
            size_of::<InterestBearingConfig>(),
            "InterestBearingConfig layout"
        );
        write_tlv_entry(
            &mut data,
            &mut tlv_offset,
            ExtensionType::InterestBearingConfig,
            &value,
        );

        // --- PermanentDelegate ---
        // `owner` may transfer or burn any holder's tokens; the delegate is
        // permanent once the mint is created. To remove: drop it from
        // `extension_types` above and delete this block.
        let mut value = Vec::with_capacity(size_of::<PermanentDelegate>());
        value.extend_from_slice(&owner.to_bytes()); // delegate
        assert_eq!(
            value.len(),
            size_of::<PermanentDelegate>(),
            "PermanentDelegate layout"
        );
        write_tlv_entry(&mut data, &mut tlv_offset, ExtensionType::PermanentDelegate, &value);

        assert_eq!(tlv_offset, data.len(), "TLV entries must exactly fill the mint");

        program_test.add_account(
            *mint,
            Account {
                lamports: 1_000_000_000,
                data,
                owner: spl_token_2022::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    /// Seeds a plain Token-2022 token account (no extensions), owned by
    /// `spl_token_2022::ID`.
    ///
    /// Note: on the transfer-fee mint above, the token-2022 transfer processor
    /// additionally requires the `TransferFeeAmount` extension on BOTH the
    /// source and destination accounts; without it, transfers fail
    /// (ExtensionNotFound / InvalidState) before any fee is collected. If the
    /// target program initializes accounts itself, its own flow creates that
    /// extension. To seed fee-capable accounts directly, append a
    /// TransferFeeAmount TLV entry (ExtensionType::TransferFeeAmount, 8
    /// bytes: withheld_amount) via `write_tlv_entry` after packing the base
    /// state.
    pub fn seed_token_account(
        program_test: &mut ProgramTest,
        address: &Pubkey,
        mint: &Pubkey,
        owner: &Pubkey,
        amount: u64,
    ) {
        let account = TokenAccount {
            mint: *mint,
            owner: *owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        };
        let mut data = vec![0u8; TokenAccount::LEN];
        TokenAccount::pack(account, &mut data).expect("pack token-2022 account base state");
        program_test.add_account(
            *address,
            Account {
                lamports: 1_000_000_000,
                data,
                owner: spl_token_2022::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }
}
"#;

/// Renders the `token2022_accounts` module embedded into the generated
/// fuzzer's `lib.rs`.
///
/// The returned string starts with the marker line
/// `// Generated token-2022 account factories` (contract: the harness
/// integration agent asserts on it) and is a complete, parseable Rust module.
pub fn render_token_2022_factories() -> String {
    GENERATED_TOKEN_2022_ACCOUNT_FACTORIES.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts a `pub fn` and its body from the rendered module, ending at
    /// the function's closing brace (4-space indent).
    fn fn_body<'a>(out: &'a str, name: &str) -> &'a str {
        let start =
            out.find(&format!("pub fn {name}")).unwrap_or_else(|| panic!("missing fn {name} in generated module"));
        let rest = &out[start..];
        let end = rest.find("\n    }\n").unwrap_or_else(|| panic!("unterminated fn {name} in generated module"));
        &rest[..end]
    }

    #[test]
    fn output_starts_with_marker() {
        let out = render_token_2022_factories();
        assert!(
            out.starts_with("// Generated token-2022 account factories"),
            "rendered module must start with the marker line:\n{out}"
        );
    }

    #[test]
    fn output_parses_as_rust() {
        let out = render_token_2022_factories();
        syn::parse_file(&out)
            .unwrap_or_else(|err| panic!("rendered token-2022 module does not parse: {err}\n---\n{out}"));
    }

    #[test]
    fn mint_uses_extension_packing() {
        let out = render_token_2022_factories();
        for needle in [
            "pack_extension",
            "TransferFeeConfig",
            "InterestBearingConfig",
            "PermanentDelegate",
            "ExtensionType::get_account_len",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in generated module");
        }
    }

    #[test]
    fn mint_authority_none_for_interest_bearing() {
        let out = render_token_2022_factories();
        assert!(out.contains("mint_authority: COption::None"), "interest-bearing mint must drop the mint authority");
        assert!(out.contains("cannot have a mint authority"), "missing the interest-bearing compatibility comment");
    }

    #[test]
    fn token_account_owned_by_token_2022() {
        let out = render_token_2022_factories();
        let body = fn_body(&out, "seed_token_account");
        assert!(body.contains("spl_token_2022::ID"), "token account must be owned by token-2022");
        assert!(body.contains("TokenAccount::LEN"), "token account must use TokenAccount::LEN");
    }

    #[test]
    fn fixture_parses() {
        let idl = crate::idl::parse_idl("tests/fixtures/token2022_fuzz.json").expect("token2022_fuzz fixture parses");
        assert_eq!(idl.name, "token2022_fuzz");
        assert_eq!(idl.instructions.len(), 1, "fixture must have one instruction");
        let ix = &idl.instructions[0];
        assert_eq!(ix.name, "transfer");
        assert_eq!(ix.accounts.len(), 5, "transfer must declare 5 accounts");
        assert_eq!(ix.args.len(), 1);
        assert_eq!(ix.args[0].name, "amount");
        assert_eq!(ix.args[0].ty, "u64");
    }
}
