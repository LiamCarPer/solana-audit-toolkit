//! Pinned frontend model for the native (non-Anchor) Solana backend.
//!
//! These types are the binding contract between the frontend slice and the
//! rule slices (SAT019–SAT030). Field names and types are pinned by
//! `docs/NATIVE_BACKEND.md` section 5 — do not rename fields or change types
//! without updating the spec and re-checking all downstream agents.

/// The kind of account a [`ResolvedAccount`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccountKind {
    /// No specific role inferred (plain `AccountInfo` / unknown type).
    #[default]
    Unchecked,
    /// Signer-ness guaranteed by construction (`Signer`-typed field).
    Signer,
    /// A program state account (typed `Account<'info, X>` or name heuristic).
    State,
    /// A token account (`Account<'info, TokenAccount>` / name heuristic).
    TokenAccount,
    /// A mint (`Account<'info, Mint>` / name heuristic).
    Mint,
    /// A program account (`Program<'info, X>` or `*_program` name).
    Program,
    /// A sysvar account (`Sysvar<'info, X>` / `clock`-style names).
    Sysvar,
    /// The system program (`Program<'info, System>` / `system_program` name).
    SystemProgram,
}

/// A single native program built from the parsed workspace sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeProgram {
    /// From `declare_id!("...")` literal if present.
    pub program_id: Option<String>,
    pub entrypoint_file: String,
    pub entrypoint_line: usize,
    pub instructions: Vec<NativeInstruction>,
}

/// One dispatched instruction (or the single fallback instruction when the
/// entrypoint does no dispatch).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeInstruction {
    /// Dispatch name; fallback `instruction_0x<disc>`.
    pub name: String,
    /// 8-byte prefix, from match-arm byte arrays.
    pub discriminator: Option<Vec<u8>>,
    /// Function name.
    pub handler: String,
    pub file: String,
    pub line: usize,
    /// Positional order = AccountMeta order.
    pub accounts: Vec<ResolvedAccount>,
}

/// One account of an instruction, resolved by the frontend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedAccount {
    /// Variable name; fallback `account_{index}`.
    pub name: String,
    /// Position in the instruction's account list.
    pub index: usize,
    pub kind: AccountKind,
    /// `is_signer` guard reachable in call path.
    pub is_signer_checked: bool,
    /// Owner equality guard reachable.
    pub owner_checked: bool,
    /// Key-equality guard reachable.
    pub key_checked: bool,
    /// Borrowed mutably / deserialized mut.
    pub written: bool,
    /// `find_program_address` seed expressions (source text).
    pub seeds: Vec<String>,
    pub is_pda: bool,
}
