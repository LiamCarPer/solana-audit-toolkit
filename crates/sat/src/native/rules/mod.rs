//! Native rule slices (SAT019–SAT030).
//!
//! Each submodule exports `pub fn check(program: &NativeProgram, parsed:
//! &[(syn::File, String)]) -> Vec<Finding>` and owns its fixtures + tests:
//! - `auth`      — SAT019 Unverified Signer Account / SAT020 Unverified Owner Account / SAT021 Unchecked Authority Key
//! - `pda_cei`   — SAT022 Seed Derivation Mismatch / SAT023 State Write After CPI
//! - `lifecycle` — SAT024 Account Reinit After Close / SAT025 Unchecked Deserialization / SAT026 Unsafe Arithmetic / SAT027 Writable Builtin Account
//! - `cpi`       — SAT028 Token CPI Unverified Authority / SAT029 Self-Invocation / SAT030 Cross-Instruction State Reuse

pub mod auth;
pub mod cpi;
pub mod lifecycle;
pub mod pda_cei;

use crate::native::model::NativeProgram;
use crate::types::Finding;

pub fn run(program: &NativeProgram, parsed: &[(syn::File, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(auth::check(program, parsed));
    findings.extend(pda_cei::check(program, parsed));
    findings.extend(lifecycle::check(program, parsed));
    findings.extend(cpi::check(program, parsed));
    findings
}
