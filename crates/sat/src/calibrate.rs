//! FP-calibration harness (`sat calibrate`).
//!
//! Runs the full analysis pipeline over a corpus of live top-TVL programs and
//! produces the "benchmark that never lies": a per-rule precision report with
//! severity-adjustment suggestions, plus an exportable suppression set that
//! `sat analyze --fp-suppressions` consumes.
//!
//! Labeling model (mirrors `docs/BENCHMARK.md` semantics):
//! - `TP` — the finding matches a real exploitable (or exploitable-shaped)
//!   issue in the target.
//! - `FP` — the finding is neutralized elsewhere / not reachable / wrong.
//! - `HARDENING` — the observation is correct but not exploitable.
//! - `UNLABELED` — not yet reviewed (excluded from precision).
//!
//! Precision per rule = TP / (TP + FP) over labeled findings only.
//!
//! Workflow:
//! 1. `sat calibrate corpus.json` — scans every repo (the corpus config is
//!    the same `WatchConfig` shape as `sat watch`), writes labeled state to
//!    `<report dir>/.sat-calib/<name>.json` (first pass auto-suggests labels
//!    from rule-class priors; everything security-relevant starts UNLABELED),
//!    renders `precision.md` and exports `.sat-calib/suppressions.json`.
//! 2. Review the state files by hand: flip `"UNLABELED"` labels to
//!    `"TP"`/`"FP"`/`"HARDENING"` in the JSON.
//! 3. Re-run `sat calibrate corpus.json` — precision recomputes from your
//!    labels and the suppression export updates.
//!
//! The CLI wiring for this module is exactly:
//!
//! ```text
//! // crates/sat/src/lib.rs
//! pub mod calibrate;
//! // crates/sat/src/main.rs
//! mod calibrate;
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::analyzer;
use crate::types::{Finding, Severity};
use crate::ui;
use crate::watch::{FindingSignature, WatchConfig, WatchRepo, ensure_repo, signature_from_finding};

/// Where calibration state lives, relative to the report's directory.
const STATE_DIR: &str = ".sat-calib";

/// A reviewer label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CalibrationLabel {
    Tp,
    Fp,
    Hardening,
    Unlabeled,
}

/// One finding with its reviewer label.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LabeledFinding {
    #[serde(flatten)]
    pub signature: FindingSignature,
    pub label: CalibrationLabel,
}

/// Persistent per-repo calibration state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoState {
    pub name: String,
    pub scanned_at: String,
    pub findings: Vec<LabeledFinding>,
}

/// The suppression file format consumed by `sat analyze --fp-suppressions`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressionFile {
    pub suppressions: Vec<FindingSignature>,
}

/// Rule-class priors: informational markers and known-noise shapes start as
/// HARDENING; everything security-relevant starts UNLABELED and waits for a
/// human review.
fn suggest_label(finding: &Finding, rule_id: &str) -> CalibrationLabel {
    if finding.severity == Severity::Informational {
        return CalibrationLabel::Hardening;
    }
    if rule_id == "SAT013" && finding.title.contains("No Token-2022") {
        return CalibrationLabel::Hardening;
    }
    CalibrationLabel::Unlabeled
}

/// Scans one repo, returns (name, findings) and merges prior labels from the
/// state file (signatures that vanished are dropped).
fn scan_repo(repo: &WatchRepo, base_dir: &Path, out_dir: &Path) -> Result<(String, Vec<LabeledFinding>)> {
    let repo_root = ensure_repo(repo, base_dir, out_dir)?;
    let src = if repo.src_path.is_empty() { repo_root.clone() } else { repo_root.join(&repo.src_path) };

    let output = analyzer::collect(Some(&src.to_string_lossy()), None, None)
        .with_context(|| format!("analysis failed for repo {}", repo.name))?;

    let state_path = out_dir.join(format!("{}.json", repo.name));
    let prior = load_state(&state_path);

    let mut findings: Vec<LabeledFinding> = output
        .findings
        .iter()
        .map(|f| {
            let signature = signature_from_finding(f, &src.to_string_lossy());
            let label = prior
                .findings
                .iter()
                .find(|p| p.signature == signature)
                .map(|p| p.label)
                .unwrap_or_else(|| suggest_label(f, &signature.rule_id));
            LabeledFinding { signature, label }
        })
        .collect();
    findings.sort_by(|a, b| {
        (&a.signature.rule_id, &a.signature.location).cmp(&(&b.signature.rule_id, &b.signature.location))
    });
    findings.dedup_by(|a, b| a.signature == b.signature);

    Ok((repo.name.clone(), findings))
}

fn load_state(path: &Path) -> RepoState {
    let Ok(content) = fs::read_to_string(path) else {
        return RepoState { name: String::new(), scanned_at: String::new(), findings: Vec::new() };
    };
    serde_json::from_str(&content).unwrap_or_else(|_| RepoState {
        name: String::new(),
        scanned_at: String::new(),
        findings: Vec::new(),
    })
}

/// Aggregates per-rule label counts across all repos.
fn aggregate(states: &[RepoState]) -> BTreeMap<String, LabelCounts> {
    let mut out: BTreeMap<String, LabelCounts> = BTreeMap::new();
    for state in states {
        for finding in &state.findings {
            let counts = out.entry(finding.signature.rule_id.clone()).or_default();
            match finding.label {
                CalibrationLabel::Tp => counts.tp += 1,
                CalibrationLabel::Fp => counts.fp += 1,
                CalibrationLabel::Hardening => counts.hardening += 1,
                CalibrationLabel::Unlabeled => counts.unlabeled += 1,
            }
        }
    }
    out
}

#[derive(Debug, Default, Clone, Copy)]
struct LabelCounts {
    tp: usize,
    fp: usize,
    hardening: usize,
    unlabeled: usize,
}

impl LabelCounts {
    fn precision(&self) -> Option<f64> {
        let labeled = self.tp + self.fp;
        if labeled == 0 {
            return None;
        }
        Some(self.tp as f64 / labeled as f64)
    }

    fn suggestion(&self) -> &'static str {
        match self.precision() {
            None => "unlabeled — review required",
            Some(p) if p < 0.3 => "DOWNGrade or suppress — high FP rate",
            Some(p) if p < 0.5 => "review — borderline precision",
            Some(_) => "ok",
        }
    }
}

/// The precision report: per-rule precision table + per-repo inventory +
/// severity-adjustment suggestions.
pub fn render_report(states: &[RepoState], corpus: &[WatchRepo]) -> String {
    let by_rule = aggregate(states);
    let total: usize = states.iter().map(|s| s.findings.len()).sum();

    let mut md = String::new();
    md.push_str("# Calibration Report\n\n");
    md.push_str(&format!("| Repos | {} |\n", corpus.len()));
    md.push_str(&format!("| Findings | {total} |\n"));
    md.push_str(&format!("| Generated | {} |\n\n", chrono::Local::now().format("%Y-%m-%d")));

    md.push_str("## Per-rule precision\n\n");
    md.push_str("| Rule | TP | FP | HARDENING | UNLABELED | Precision | Suggestion |\n| --- | ---: | ---: | ---: | ---: | ---: | --- |\n");
    for (rule, counts) in &by_rule {
        let precision = counts.precision().map(|p| format!("{:.0}%", p * 100.0)).unwrap_or_else(|| "—".to_string());
        md.push_str(&format!(
            "| {rule} | {} | {} | {} | {} | {precision} | {} |\n",
            counts.tp,
            counts.fp,
            counts.hardening,
            counts.unlabeled,
            counts.suggestion()
        ));
    }

    md.push_str("\n## Per-repo inventory\n\n");
    md.push_str("| Repo | Findings |\n| --- | ---: |\n");
    for state in states {
        md.push_str(&format!("| {} | {} |\n", state.name, state.findings.len()));
    }

    md.push_str("\n## Semantics\n\n");
    md.push_str(
        "Precision = TP / (TP + FP) over **labeled** findings only; HARDENING is excluded from the \
                 denominator (a correct observation that is not exploitable). Unlabeled findings do not affect \
                 precision. Edit `.sat-calib/<repo>.json` to flip labels, then re-run `sat calibrate`.\n",
    );
    md
}

/// Runs the full calibration pass: scan the corpus, merge labels, render the
/// report, and export the FP suppression set.
pub fn run(config_path: &str, out_path: Option<&str>) -> Result<()> {
    ui::print_banner();
    ui::print_section_header("FP Calibration");

    let config_content =
        fs::read_to_string(config_path).with_context(|| format!("failed to read corpus config {config_path}"))?;
    let config: WatchConfig = serde_json::from_str(&config_content)
        .with_context(|| format!("invalid corpus config JSON in {config_path}"))?;

    // State lives next to the report (`.sat-calib/` in the report's directory)
    // so tests and multi-project invocations stay hermetic.
    let report_path = Path::new(out_path.unwrap_or("precision.md"));
    let state_dir = report_path.parent().unwrap_or(Path::new(".")).join(STATE_DIR);
    fs::create_dir_all(&state_dir).with_context(|| format!("failed to create state dir {}", state_dir.display()))?;

    let mut states = Vec::new();
    for repo in &config.repos {
        match scan_repo(repo, Path::new("."), &state_dir) {
            Ok((name, findings)) => {
                let state = RepoState { name: name.clone(), scanned_at: chrono::Utc::now().to_rfc3339(), findings };
                let json = serde_json::to_string_pretty(&state).context("failed to serialize calibration state")?;
                fs::write(state_dir.join(format!("{name}.json")), json)
                    .with_context(|| format!("failed to write state for {name}"))?;
                states.push(state);
                println!("== {name}: {} finding(s) ==", states.last().map(|s| s.findings.len()).unwrap_or(0));
            }
            Err(err) => {
                ui::print_warning(&format!("repo {} skipped: {err:#}", repo.name));
            }
        }
    }

    let report = render_report(&states, &config.repos);
    fs::write(report_path, report)
        .with_context(|| format!("failed to write precision report {}", report_path.display()))?;

    // Export confirmed-FP signatures as the suppression set.
    let suppressions: Vec<FindingSignature> = states
        .iter()
        .flat_map(|s| s.findings.iter().filter(|f| f.label == CalibrationLabel::Fp).map(|f| f.signature.clone()))
        .collect();
    let suppression_file = SuppressionFile { suppressions };
    let supp_path = state_dir.join("suppressions.json");
    fs::write(&supp_path, serde_json::to_string_pretty(&suppression_file).context("failed to serialize suppressions")?)
        .with_context(|| format!("failed to write {}", supp_path.display()))?;

    ui::print_success(&format!("Precision report written to {}", report_path.display()));
    if suppression_file.suppressions.is_empty() {
        ui::print_notice(&format!(
            "{} has no confirmed FPs yet — label some findings as FP and re-run.",
            supp_path.display()
        ));
    } else {
        ui::print_success(&format!(
            "{} confirmed FP suppression(s) exported to {}",
            suppression_file.suppressions.len(),
            supp_path.display()
        ));
    }
    ui::print_notice("Next: review .sat-calib/<repo>.json labels, then re-run sat calibrate.");
    Ok(())
}

/// Filters findings against a suppression file (confirmed FP signatures).
/// Matching is exact on `(rule_id, title, normalized location, severity)`.
pub fn apply_suppressions(findings: &mut Vec<Finding>, suppressions_path: &str, src_path: &str) -> Result<()> {
    let content = fs::read_to_string(suppressions_path)
        .with_context(|| format!("failed to read suppressions file {suppressions_path}"))?;
    let file: SuppressionFile =
        serde_json::from_str(&content).with_context(|| format!("invalid suppressions JSON in {suppressions_path}"))?;
    let suppressed: Vec<FindingSignature> = file.suppressions;
    if suppressed.is_empty() {
        return Ok(());
    }

    let before = findings.len();
    findings.retain(|f| {
        let signature = signature_from_finding(f, src_path);
        !suppressed.contains(&signature)
    });
    if findings.len() != before {
        ui::print_notice(&format!("{} finding(s) suppressed by {suppressions_path}", before - findings.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use crate::watch::signature_from_finding;
    use tempfile::tempdir;

    fn finding(id: &str, title: &str, severity: Severity, location: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: title.to_string(),
            severity,
            description: "test".to_string(),
            location: Some(location.to_string()),
            suggestion: None,
        }
    }

    #[test]
    fn suggest_label_priors_mark_informational_as_hardening() {
        let f = finding("x", "No Token-2022 Usage Detected", Severity::Informational, "Workspace root");
        assert_eq!(suggest_label(&f, "SAT013"), CalibrationLabel::Hardening);
        let high = finding("x", "Missing Signer: `a`", Severity::High, "l.rs:1");
        assert_eq!(suggest_label(&high, "SAT001"), CalibrationLabel::Unlabeled);
    }

    #[test]
    fn precision_math_excludes_unlabeled_and_hardening() {
        let counts = LabelCounts { tp: 2, fp: 3, hardening: 50, unlabeled: 100 };
        assert_eq!(counts.precision(), Some(0.4));
        assert!(counts.suggestion().contains("review"));

        let empty = LabelCounts { unlabeled: 7, ..LabelCounts::default() };
        assert_eq!(empty.precision(), None);
        assert!(empty.suggestion().contains("unlabeled"));
    }

    #[test]
    fn apply_suppressions_filters_exact_signatures() {
        let src = "C:\\repo\\program\\src";
        let f = finding("SAT-001", "Missing Signer: `a`", Severity::High, "C:\\repo\\program\\src\\lib.rs:10 (a)");
        let mut findings = vec![f.clone()];

        let sig = signature_from_finding(&f, src);
        let file = SuppressionFile { suppressions: vec![sig] };
        let dir = tempdir().unwrap();
        let path = dir.path().join("supp.json");
        fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();

        apply_suppressions(&mut findings, path.to_str().unwrap(), src).unwrap();
        assert!(findings.is_empty(), "matching signature must be suppressed");

        // A different location survives.
        let other = finding("SAT-002", "Missing Signer: `b`", Severity::High, "C:\\repo\\program\\src\\lib.rs:20 (b)");
        let mut findings = vec![other.clone()];
        apply_suppressions(&mut findings, path.to_str().unwrap(), src).unwrap();
        assert_eq!(findings.len(), 1, "non-matching finding must survive");
    }
}
