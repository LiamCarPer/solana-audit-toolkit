//! Machine-readable JSON finding export (`sat analyze src --format json`).
//!
//! Stable shape for CI gating, dashboards, and SAT↔RTS correlation:
//!
//! ```json
//! {
//!   "program": "vault",
//!   "source": "programs/vault/src",
//!   "summary": { "total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0 },
//!   "findings": [
//!     { "id": "", "rule": "SAT001", "title": "...", "severity": "high",
//!       "confidence": "high", "location": "...", "description": "...", "suggestion": "..." }
//!   ]
//! }
//! ```

use serde_json::{Value, json};

use crate::sarif::classify_finding_rule;
use crate::types::{Finding, Severity};

/// Count findings at each severity.
fn counts(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c.0 += 1,
            Severity::High => c.1 += 1,
            Severity::Medium => c.2 += 1,
            Severity::Low => c.3 += 1,
            Severity::Informational => c.4 += 1,
        }
    }
    c
}

/// Render the JSON report (pretty-printed, trailing newline).
pub fn render_json(findings: &[Finding], program: &str, source: &str) -> String {
    let (crit, high, med, low, info) = counts(findings);

    let items: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "rule": classify_finding_rule(f),
                "title": f.title,
                "severity": f.severity.as_str(),
                "confidence": f.confidence().to_string().to_ascii_lowercase(),
                "location": f.location,
                "description": f.description,
                "suggestion": f.suggestion,
            })
        })
        .collect();

    let report = json!({
        "program": program,
        "source": source,
        "summary": {
            "total": findings.len(),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "informational": info,
        },
        "findings": items,
    });

    let mut out = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(title: &str, sev: Severity) -> Finding {
        Finding {
            id: String::new(),
            title: title.to_string(),
            severity: sev,
            description: "desc".to_string(),
            location: Some("src/lib.rs:1".to_string()),
            suggestion: None,
        }
    }

    #[test]
    fn json_has_summary_and_rule() {
        let findings = vec![finding("Unverified Signer Account:", Severity::High)];
        let s = render_json(&findings, "vault", "programs/vault/src");
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["summary"]["total"], 1);
        assert_eq!(v["summary"]["high"], 1);
        assert_eq!(v["findings"][0]["rule"], "SAT019");
        assert_eq!(v["findings"][0]["severity"], "high");
    }
}
