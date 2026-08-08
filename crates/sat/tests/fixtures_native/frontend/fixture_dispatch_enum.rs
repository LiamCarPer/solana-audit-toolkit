//! Enum dispatch: `match instruction { Instruction::Deposit { .. } => ... }`
//! with an instruction enum whose `unpack` maps u8 tags to variants.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub enum Instruction {
    Initialize,
    Deposit { amount: u64 },
    Withdraw { amount: u64 },
}

impl Instruction {
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let tag = input[0];
        Ok(match tag {
            0 => Instruction::Initialize,
            1 => Instruction::Deposit { amount: 0 },
            2 => Instruction::Withdraw { amount: 0 },
            _ => return Err(ProgramError::InvalidInstructionData),
        })
    }
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = Instruction::unpack(instruction_data)?;
    match instruction {
        Instruction::Initialize => process_initialize(accounts),
        Instruction::Deposit { amount: _ } => process_deposit(accounts),
        Instruction::Withdraw { amount } => process_withdraw(accounts),
    }
}

fn process_initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    Ok(())
}

fn process_deposit(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let token_account = next_account_info(accounts_iter)?;

    Ok(())
}

fn process_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let state = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;

    Ok(())
}
