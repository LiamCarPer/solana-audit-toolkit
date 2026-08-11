//! Genuine Token-2022 transfer WITHOUT any transfer-fee handling: a raw
//! `spl_token_2022_interface::instruction::transfer_checked` CPI with no fee
//! calculation anywhere in the function. The transfer-fee bypass finding MUST
//! still fire.

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke_signed,
    program_error::ProgramError, pubkey::Pubkey,
};

pub fn transfer_tokens_unhandled(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
    decimals: u8,
) -> ProgramResult {
    let [token_program, source, mint, destination, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let ix = spl_token_2022_interface::instruction::transfer_checked(
        token_program.key,
        source.key,
        mint.key,
        destination.key,
        authority.key,
        &[],
        amount,
        decimals,
    )?;

    invoke_signed(
        &ix,
        &[
            source.clone(),
            mint.clone(),
            destination.clone(),
            authority.clone(),
        ],
        &[],
    )?;

    Ok(())
}
