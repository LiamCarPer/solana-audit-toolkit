use anyhow::{Result, bail};

use crate::analyzer::collect;
use crate::sarif::classify_finding_rule;
use crate::ui;

/// Entry point for `sat poc <finding-id>`: resolve a finding from a prior
/// `sat analyze src` run against the same source tree, classify it to a rule,
/// and generate a runnable ProgramTest PoC crate in `out_dir`.
pub fn run(finding_id: &str, path: Option<&str>, out_dir: &str) -> Result<()> {
    ui::print_banner();
    ui::print_section_header("PoC Generation");

    let output = collect(path, None, None)?;

    let finding = output.findings.iter().find(|f| f.id == finding_id).ok_or_else(|| {
        anyhow::anyhow!("finding {finding_id} not found — re-run `sat analyze src` against the same source path first")
    })?;

    let rule = classify_finding_rule(finding);
    ui::print_success(&format!("Resolved {finding_id} ({rule}): {}", finding.title));
    println!("severity : {}", finding.severity);
    println!("location : {}", finding.location.as_deref().unwrap_or("(none)"));
    println!("output   : {out_dir}/");

    bail!("PoC generation is not implemented yet for rule {rule}");
}
