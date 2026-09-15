//! Baseline snapshots — gate CI on **new** findings only.
//!
//! Adopting a scanner on an existing codebase is noisy: a `--fail-on high`
//! gate would fail on day one for findings that predate adoption. A baseline
//! snapshots the accepted finding set; later runs report and gate only on
//! findings that are *not* in the baseline.
//!
//! ```text
//! # accept the current state once
//! sat analyze src programs/vault/src --baseline .sat-baseline.json --update-baseline
//! # CI: fail only on regressions introduced after the baseline
//! sat analyze src programs/vault/src --baseline .sat-baseline.json --fail-on high
//! ```
//!
//! Finding identity is the same deduplicated signature `sat watch` uses
//! (`rule_id`, `title`, line-normalized `location`, `severity`), so line drift
//! within a file does not register as a new finding.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::types::Finding;
use crate::watch::{FindingSignature, signature_from_finding};

/// A persisted snapshot of accepted findings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
    pub generated: String,
    pub signatures: Vec<FindingSignature>,
}

impl Baseline {
    /// Snapshot the given findings (locations normalized against `src_path`).
    pub fn from_findings(findings: &[Finding], src_path: &str) -> Self {
        let signatures = findings.iter().map(|f| signature_from_finding(f, src_path)).collect();
        Baseline { generated: chrono::Utc::now().to_rfc3339(), signatures }
    }

    /// Load a baseline file.
    pub fn load(path: &str) -> Result<Baseline> {
        let text = std::fs::read_to_string(path).with_context(|| format!("failed to read baseline {path}"))?;
        serde_json::from_str(&text).with_context(|| format!("invalid baseline JSON in {path}"))
    }

    /// Write the baseline to `path` (pretty JSON).
    pub fn write(&self, path: &str) -> Result<()> {
        if let Some(parent) = Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create baseline dir {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self).context("failed to serialize baseline")?;
        std::fs::write(path, json).with_context(|| format!("failed to write baseline {path}"))?;
        Ok(())
    }

    pub fn signature_set(&self) -> HashSet<FindingSignature> {
        self.signatures.iter().cloned().collect()
    }
}

/// Drop findings already present in the baseline; returns the count removed.
pub fn retain_new(findings: &mut Vec<Finding>, baseline: &Baseline, src_path: &str) -> usize {
    let known = baseline.signature_set();
    let before = findings.len();
    findings.retain(|f| !known.contains(&signature_from_finding(f, src_path)));
    before - findings.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn finding(title: &str, loc: &str) -> Finding {
        Finding {
            id: String::new(),
            title: title.to_string(),
            severity: Severity::High,
            description: String::new(),
            location: Some(loc.to_string()),
            suggestion: None,
        }
    }

    #[test]
    fn retains_only_new_findings() {
        let src = "programs/vault/src";
        let old = vec![
            finding("Unverified Signer Account: `a`", "programs/vault/src/lib.rs:10"),
            finding("Unsafe Arithmetic: `+=`", "programs/vault/src/lib.rs:20"),
        ];
        let baseline = Baseline::from_findings(&old, src);

        let mut current = vec![
            finding("Unverified Signer Account: `a`", "programs/vault/src/lib.rs:10"),
            finding("Unsafe Arithmetic: `+=`", "programs/vault/src/lib.rs:20"),
            finding("Unverified Owner Account: `b`", "programs/vault/src/lib.rs:30"),
        ];
        let removed = retain_new(&mut current, &baseline, src);
        assert_eq!(removed, 2);
        assert_eq!(current.len(), 1);
        assert!(current[0].title.contains("Owner"));
    }

    #[test]
    fn line_drift_is_not_new() {
        let src = "src";
        let baseline = Baseline::from_findings(&[finding("X", "src/lib.rs:10")], src);
        let mut current = vec![finding("X", "src/lib.rs:99")];
        assert_eq!(retain_new(&mut current, &baseline, src), 1);
        assert!(current.is_empty());
    }
}
