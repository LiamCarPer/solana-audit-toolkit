//! Control fixture: uses only the standard SPL token interface. The
//! analyzer MUST keep emitting the "No Token-2022 Usage Detected" negative.

use spl_token_interface::state::Account;

pub struct Processor;

impl Processor {
    pub fn process(account: &Account) -> Result<(), ProgramError> {
        let _ = account;
        Ok(())
    }
}
