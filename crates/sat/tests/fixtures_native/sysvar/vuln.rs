//! Vulnerable native program: SAT032 — Sysvar-Introspection Misuse (the
//! Wormhole bridge class, Feb 2022, ~$320M).
//!
//! `verify_signatures` trusts a caller-supplied account
//! (`accs.instruction_acc`, the "Instruction reflection account" slot) as the
//! instructions sysvar and feeds its raw bytes to the UNCHECKED
//! introspection helpers `load_current_index` and `load_instruction_at`.
//! The unchecked helpers parse whatever bytes they are given with no sysvar
//! address check; the `_checked` variants validate the account first. An
//! attacker can fabricate the account, so the introspection results are
//! attacker-controlled (the exact `verify_signature.rs` pre-exploit shape at
//! wormhole commit 79ab522).
//!
//! Expect: two HIGH SAT032 findings — one per unchecked call site
//! (`load_current_index`, `load_instruction_at`).
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

    // SAT032: unchecked introspection over caller-supplied account data.
    // The attacker supplies the account for `instruction_acc`, so the
    // "current instruction index" below is attacker-controlled.
    let current_instruction = solana_program::sysvar::instructions::load_current_index(
        &accs.instruction_acc.try_borrow_mut_data()?,
    );
    if current_instruction == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // SAT032: same class, the instruction-at-index read.
    let secp_ix_index = (current_instruction - 1) as u8;
    let secp_ix = solana_program::sysvar::instructions::load_instruction_at(
        secp_ix_index as usize,
        &accs.instruction_acc.try_borrow_mut_data()?,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    if secp_ix.program_id != solana_program::secp256k1_program::id() {
        return Err(ProgramError::InvalidAccountData);
    }

    // ... the attacker's fabricated instruction list is trusted from here on.
    accs.signature_set.hash = secp_ix.data[0..32].try_into().unwrap();
    Ok(())
}
