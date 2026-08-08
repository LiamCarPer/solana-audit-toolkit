//! Native (non-Anchor) Solana program backend.
//!
//! The frontend slice owns the pinned model (`model.rs`), paradigm detection
//! and account/dispatch resolution (`frontend.rs`); the rule slices own the
//! SAT019–SAT030 checks (`rules/`); the integration slice wires the module
//! into the CLI pipeline.
//!
//! `analyze` runs iff any parsed file carries a native marker
//! (`entrypoint!` or a canonical `process_instruction`); Anchor files in the
//! same workspace are handled by the existing backend.

pub mod frontend;
pub mod model;
pub mod rules;

use crate::native::model::NativeProgram;
use crate::types::Finding;

pub mod expectations;

/// Run the native backend over a workspace of parsed files. Empty when no
/// file has a native marker, or when the rule slices produce no findings.
pub fn analyze(parsed_files: &[(syn::File, String)]) -> Vec<Finding> {
    let has_native_marker = parsed_files.iter().any(|(file, _)| frontend::has_native_marker(file));
    if !has_native_marker {
        return Vec::new();
    }
    let program = frontend::build_program(parsed_files);
    rules::run(&program, parsed_files)
}

/// Parse a single source string and return the built program (used by tests).
///
/// Parse failures (unparseable or empty input) do not panic: they yield a
/// default (empty) [`NativeProgram`] with no entrypoint.
///
/// The binary target builds this module privately and never calls it, so
/// dead-code analysis flags it there; the integration tests in
/// `tests/native_frontend.rs` are the consumers.
#[allow(dead_code)]
pub fn analyze_source_for_test(source: &str) -> NativeProgram {
    let Ok(parsed) = syn::parse_file(source) else {
        return NativeProgram::default();
    };
    frontend::build_program(&[(parsed, "test.rs".to_string())])
}

/// Parse a single source string and return both the built program and the
/// parsed file pair (used by rule-slice tests that need raw syntax trees).
#[allow(dead_code)]
pub fn analyze_source_and_files_for_test(source: &str) -> (NativeProgram, Vec<(syn::File, String)>) {
    let Ok(parsed) = syn::parse_file(source) else {
        return (NativeProgram::default(), Vec::new());
    };
    let files = vec![(parsed.clone(), "test.rs".to_string())];
    (frontend::build_program(&files), files)
}
