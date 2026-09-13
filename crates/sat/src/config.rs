//! Project configuration (`sat.toml`).
//!
//! Lets a workspace tune the analysis without recompiling: gate CI on a
//! severity threshold, disable rules, override severities, and exclude path
//! prefixes. Discovered from `./sat.toml` (or an explicit `--config PATH`).
//!
//! ```toml
//! # sat.toml
//! fail_on = "high"                     # none|info|low|medium|high|critical
//! exclude = ["tests/", "migrations/"]  # findings whose location contains any
//! disabled_rules = ["SAT026"]          # rule ids to drop
//!
//! [severity_overrides]
//! SAT012 = "low"                       # remap a rule's severity
//! ```

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::sarif::classify_finding_rule;
use crate::types::{Finding, Severity};

/// Parsed `sat.toml`. All fields optional so an empty/partial file is valid.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Severity threshold for a non-zero exit (`--fail-on` CLI flag wins).
    pub fail_on: Option<String>,
    /// Path fragments; findings whose `location` contains any are dropped.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Rule ids (e.g. `SAT026`) whose findings are dropped.
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Rule id → severity name override.
    #[serde(default)]
    pub severity_overrides: HashMap<String, String>,
}

impl Config {
    /// Load an explicit config, or auto-discover `./sat.toml` (missing → default).
    pub fn load(explicit: Option<&str>) -> Result<Config> {
        if let Some(path) = explicit {
            let text = std::fs::read_to_string(path).with_context(|| format!("failed to read config {path}"))?;
            return toml::from_str(&text).with_context(|| format!("invalid config {path}"));
        }
        let default = Path::new("sat.toml");
        if default.exists() {
            let text = std::fs::read_to_string(default).context("failed to read sat.toml")?;
            return toml::from_str(&text).context("invalid sat.toml");
        }
        Ok(Config::default())
    }

    /// Apply the config to a finding set in place: drop disabled rules and
    /// excluded paths, then remap severities.
    pub fn apply(&self, findings: &mut Vec<Finding>) {
        if !self.disabled_rules.is_empty() {
            findings.retain(|f| !self.disabled_rules.iter().any(|r| r == &classify_finding_rule(f)));
        }
        if !self.exclude.is_empty() {
            findings.retain(|f| {
                let loc = f.location.clone().unwrap_or_default();
                !self.exclude.iter().any(|pat| loc.contains(pat.as_str()))
            });
        }
        if !self.severity_overrides.is_empty() {
            for f in findings.iter_mut() {
                let rule = classify_finding_rule(f);
                if let Some(name) = self.severity_overrides.get(&rule)
                    && let Some(sev) = Severity::parse(name)
                {
                    f.severity = sev;
                }
            }
        }
    }

    /// The effective fail-on threshold: explicit CLI flag wins over config.
    pub fn fail_on(&self, cli: Option<&str>) -> Option<Severity> {
        cli.or(self.fail_on.as_deref()).and_then(Severity::parse)
    }
}

/// Whether any finding meets/exceeds the threshold (i.e. should fail CI).
/// `Severity` is ordered Critical < High < Medium < Low < Informational, so a
/// finding fails when its severity is `<= threshold`.
pub fn fails(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|f| f.severity <= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(title: &str, sev: Severity, loc: &str) -> Finding {
        Finding {
            id: String::new(),
            title: title.to_string(),
            severity: sev,
            description: String::new(),
            location: Some(loc.to_string()),
            suggestion: None,
        }
    }

    #[test]
    fn disables_rules_and_excludes_paths() {
        let cfg = Config {
            disabled_rules: vec!["SAT012".to_string()],
            exclude: vec!["tests/".to_string()],
            ..Default::default()
        };
        let mut findings = vec![
            finding("Unsafe Arithmetic: `+=`", Severity::High, "src/lib.rs:1"),
            finding("Unverified Signer Account:", Severity::High, "tests/foo.rs:2"),
            finding("Unverified Owner Account:", Severity::High, "src/bar.rs:3"),
        ];
        cfg.apply(&mut findings);
        // SAT012 disabled; tests/ excluded; the owner finding survives.
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Owner"));
    }

    #[test]
    fn remaps_severity() {
        let mut overrides = HashMap::new();
        overrides.insert("SAT012".to_string(), "low".to_string());
        let cfg = Config { severity_overrides: overrides, ..Default::default() };
        let mut findings = vec![finding("Unsafe Arithmetic: `+=`", Severity::High, "src/lib.rs:1")];
        cfg.apply(&mut findings);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn fail_threshold_respects_ordering() {
        let high = vec![finding("Unverified Signer Account:", Severity::High, "a.rs")];
        assert!(fails(&high, Severity::High), "fail-on high catches high");
        assert!(!fails(&high, Severity::Critical), "fail-on critical does not catch high");
        assert!(fails(&high, Severity::Medium), "fail-on medium catches high (more severe)");
        let crit = vec![finding("x", Severity::Critical, "a.rs")];
        assert!(fails(&crit, Severity::High), "fail-on high catches critical");
        let low = vec![finding("x", Severity::Low, "a.rs")];
        assert!(!fails(&low, Severity::High), "fail-on high ignores low");
    }
}
