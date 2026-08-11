//! Clean native program: SAT032 — Sysvar-Introspection Misuse must stay
//! silent.
//!
//! The introspection reads use the CHECKED variant (`load_instruction_at_checked`,
//! which validates the account is the real instructions sysvar before parsing),
//! and the only sysvar accessor is the `Clock::get()`-style accessor, which is
//! never part of the unchecked introspection family. Zero SAT032 findings.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program`/`solitaire` crates.
use solana_program::{
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

#[derive(FromAccounts)]
pub struct VerifySignatures<'b> {
    /// Guardian set of the signatures
    pub guardian_set: GuardianSet<'b, { AccountState::Initialized }>,

    /// Signature Account
    pub signature_set: Mut<Signer<SignatureSet<'b, { AccountState::MaybeInitialized }>>>,

    /// Instruction reflection account (special sysvar)
    pub instruction_acc: Info<'b>,
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match &instruction_data[0..8] {
        [0x07, ..] => verify_signatures(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn verify_signatures(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let mut accs = VerifySignatures::try_from_slice(accounts)?;

    // Post-fix shape: the _checked variant validates the sysvar address
    // (check_id) before parsing; a plain &AccountInfo argument is the
    // checked form and must not trigger SAT032.
    let secp_ix = solana_program::sysvar::instructions::load_instruction_at_checked(
        0usize,
        &accs.instruction_acc,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Clock::get()-style accessors never trigger SAT032.
    let clock = solana_program::clock::Clock::get()?;
    let _now = clock.unix_timestamp;

    if secp_ix.program_id != solana_program::secp256k1_program::id() {
        return Err(ProgramError::InvalidAccountData);
    }

    accs.signature_set.hash = secp_ix.data[0..32].try_into().unwrap();
    Ok(())
}
