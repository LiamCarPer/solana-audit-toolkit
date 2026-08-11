//! Token-2022 usage appears ONLY in the file-level import; no function body
//! references it. Exercises the raw-source marker scan.

use spl_token_2022_interface::extension::transfer_fee::TransferFeeConfig;

pub mod handler {
    pub fn process(_input: &[u8]) -> Result<(), ProgramError> {
        Ok(())
    }
}
