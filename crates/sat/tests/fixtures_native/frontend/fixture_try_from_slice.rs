//! Borsh enum-unpack dispatch inside an impl-method processor (SDI shape):
//! the entrypoint delegates to `Processor::process`, which deserializes the
//! instruction via `try_from_slice` (borsh derive — tags are declaration
//! order) and matches on the enum. Shank-style `#[account(N, ...)]`
//! attributes on variants declare the positional account table; handlers
//! still resolve guards positionally.
//!
//! Note: this fixture only needs to parse with `syn` — it does not need to
//! compile against real `solana_program` crates.
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub struct InitializeArgs;
pub struct DepositArgs;
pub struct WithdrawArgs;

pub enum InterceptorInstruction {
    #[account(0, signer, name = "payer")]
    #[account(1, name = "state")]
    Initialize(InitializeArgs),
    #[account(0, writable, name = "state")]
    #[account(1, signer, name = "authority")]
    #[account(2, name = "token_account")]
    Deposit(DepositArgs),
    Withdraw(WithdrawArgs),
}

pub struct Processor;

impl Processor {
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
        let instruction = InterceptorInstruction::try_from_slice(input)?;
        match instruction {
            InterceptorInstruction::Initialize(args) => {
                Self::process_initialize(program_id, accounts, args)?;
            }
            InterceptorInstruction::Deposit(args) => {
                Self::process_deposit(program_id, accounts, args)?;
            }
            InterceptorInstruction::Withdraw(args) => {
                Self::process_withdraw(program_id, accounts, args)?;
            }
        }
        Ok(())
    }

    fn process_initialize(_program_id: &Pubkey, accounts: &[AccountInfo], _args: InitializeArgs) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let payer = next_account_info(account_info_iter)?;
        let state = next_account_info(account_info_iter)?;
        if !payer.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        Ok(())
    }

    fn process_deposit(_program_id: &Pubkey, accounts: &[AccountInfo], _args: DepositArgs) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let state = next_account_info(account_info_iter)?;
        let authority = next_account_info(account_info_iter)?;
        let token_account = next_account_info(account_info_iter)?;
        Ok(())
    }

    fn process_withdraw(_program_id: &Pubkey, accounts: &[AccountInfo], _args: WithdrawArgs) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let state = next_account_info(account_info_iter)?;
        let authority = next_account_info(account_info_iter)?;
        Ok(())
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    if let Err(error) = Processor::process(program_id, accounts, instruction_data) { Err(error) } else { Ok(()) }
}
