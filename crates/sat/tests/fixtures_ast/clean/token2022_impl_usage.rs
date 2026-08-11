//! Minimal mirror of the Stake Deposit Interceptor processor shape:
//! Token-2022 usage confined to `impl`-block methods plus a file-level
//! `use` statement. Neither the `use` statement nor the `impl` methods are
//! `pub fn` directly inside a module, so the old scan missed all of it.

use spl_token_2022_interface::{
    extension::{BaseStateWithExtensions, StateWithExtensions},
    state::{Account, AccountState},
};

pub struct Processor;

impl Processor {
    pub fn process_deposit_stake(token_program_info: &AccountInfo) -> Result<(), ProgramError> {
        spl_token_2022_interface::check_spl_token_program_account(token_program_info.key)?;
        Ok(())
    }

    fn unpack_pool_mint(pool_mint_info: &AccountInfo) -> Result<(), ProgramError> {
        let _mint = spl_token_2022_interface::state::Mint::unpack(&pool_mint_info.data.borrow())?;
        Ok(())
    }
}
