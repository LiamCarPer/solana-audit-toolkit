//! Release delta scanner (`sat watch`).
//!
//! Watches target program repositories, runs the full static analysis on
//! each one, and diffs the finding set against the previous scan so newly
//! introduced (or removed) findings are surfaced at release time — the
//! first-hours hunting window where bounty money is made.
//!
//! State per repo is a JSON file under the output directory
//! (`<out_dir>/<name>.json`) carrying a deduplicated signature set. A finding
//! signature is `(rule_id, title, line-normalized location, severity)`, so
//! scans of different commits are comparable. Findings whose only difference
//! is line drift within the same file are NOT treated as new.
//!
//! Local repos (no `url`) are scanned in place relative to the current
//! working directory. Remote repos are shallow-cloned under
//! `<out_dir>/repos/<name>` and checked out at the configured branch or
//! pinned revision.
//!
//! The CLI wiring for this module is exactly:
//!
//! ```text
//! // crates/sat/src/lib.rs
//! pub mod watch;
//! // crates/sat/src/main.rs
//! mod watch;
//! ```

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::analyzer;
use crate::sarif::classify_finding_rule;
use crate::types::Finding;
use crate::ui;

/// Per-repo watch configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WatchConfig {
    pub repos: Vec<WatchRepo>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WatchRepo {
    /// Display name; also the state file name and the clone directory name.
    pub name: String,
    /// Relative source path under the repo root to analyze ("" = whole repo).
    #[serde(default)]
    pub src_path: String,
    /// Remote URL; when set the repo is shallow-cloned under `<out>/repos/<name>`.
    pub url: Option<String>,
    /// Absolute local path override for local repos (when the repo directory
    /// is not `<cwd>/<name>`).
    pub local_path: Option<String>,
    /// Branch to check out (default `master`; used only for remote repos).
    #[serde(default = "default_branch")]
    pub branch: String,
    /// Pinned revision (commit hash); checked out after clone when set.
    pub rev: Option<String>,
}

fn default_branch() -> String {
    "master".to_string()
}

/// A comparable finding identity. Locations are normalized (source-path
/// prefix stripped, backslashes → forward slashes) so the same finding at a
/// different line still matches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct FindingSignature {
    pub rule_id: String,
    pub title: String,
    pub location: String,
    pub severity: String,
}

/// Persistent per-repo scan state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ScanState {
    scanned_at: String,
    signatures: Vec<FindingSignature>,
}

/// The result of comparing one scan against the previous state.
#[derive(Debug, Default)]
pub struct WatchDiff {
    pub added: Vec<FindingSignature>,
    pub removed: Vec<FindingSignature>,
}

impl WatchDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Builds a comparable signature from a finding, normalizing its location.
pub fn signature_from_finding(finding: &Finding, src_path: &str) -> FindingSignature {
    FindingSignature {
        rule_id: classify_finding_rule(finding),
        title: finding.title.clone(),
        location: normalize_location(finding.location.as_deref(), src_path),
        severity: finding.severity.to_string(),
    }
}

/// Strips the analyzed source prefix from a location and normalizes path
/// separators: `C:\repo\program\src\lib.rs:10 (set)` + src `C:\repo\program\src`
/// → `lib.rs:10 (set)`.
fn normalize_location(location: Option<&str>, src_path: &str) -> String {
    let Some(raw) = location else { return String::new() };
    let normalized_src = src_path.replace('\\', "/").trim_end_matches('/').to_string();
    let mut normalized = raw.replace('\\', "/");
    if !normalized_src.is_empty() && normalized.starts_with(&normalized_src) {
        normalized = normalized[normalized_src.len()..].trim_start_matches('/').to_string();
    }
    normalized
}

/// Scans one repo and diffs it against the previous scan state.
///
/// `base_dir` is the directory the repo paths are resolved against (used for
/// local repos); the clone/state directories live under `out_dir`.
pub fn scan_repo(repo: &WatchRepo, base_dir: &Path, out_dir: &Path) -> Result<WatchDiff> {
    let repo_root = ensure_repo(repo, base_dir, out_dir)?;
    let src = if repo.src_path.is_empty() { repo_root.clone() } else { repo_root.join(&repo.src_path) };

    let output = analyzer::collect(Some(&src.to_string_lossy()), None, None)
        .with_context(|| format!("analysis failed for repo {}", repo.name))?;

    let mut signatures: Vec<FindingSignature> =
        output.findings.iter().map(|f| signature_from_finding(f, &src.to_string_lossy())).collect();
    signatures.sort_by(|a, b| (&a.rule_id, &a.location).cmp(&(&b.rule_id, &b.location)));
    signatures.dedup();

    let state_path = out_dir.join(format!("{}.json", repo.name));
    let previous = load_state(&state_path);

    let new_set: BTreeSet<FindingSignature> = signatures.iter().cloned().collect();
    let old_set: BTreeSet<FindingSignature> = previous.signatures.iter().cloned().collect();

    let diff = WatchDiff {
        added: new_set.difference(&old_set).cloned().collect(),
        removed: old_set.difference(&new_set).cloned().collect(),
    };

    let state = ScanState { scanned_at: chrono::Utc::now().to_rfc3339(), signatures };
    fs::create_dir_all(out_dir).with_context(|| format!("failed to create watch state dir {}", out_dir.display()))?;
    let json = serde_json::to_string_pretty(&state).context("failed to serialize watch state")?;
    fs::write(&state_path, json).with_context(|| format!("failed to write watch state {}", state_path.display()))?;

    Ok(diff)
}

/// Loads the previous scan state (missing or unreadable = first scan).
fn load_state(path: &Path) -> ScanState {
    let Ok(content) = fs::read_to_string(path) else {
        return ScanState { scanned_at: String::new(), signatures: Vec::new() };
    };
    serde_json::from_str(&content).unwrap_or_else(|_| ScanState { scanned_at: String::new(), signatures: Vec::new() })
}

/// Resolves the repo root: clones a remote repo when a url is configured,
/// otherwise uses the local path (absolute override or `<base_dir>/<name>`).
/// Shared with the calibration harness (`calibrate`).
pub(crate) fn ensure_repo(repo: &WatchRepo, base_dir: &Path, out_dir: &Path) -> Result<PathBuf> {
    if let Some(url) = &repo.url {
        let repos_dir = out_dir.join("repos");
        let clone_dir = repos_dir.join(&repo.name);
        if !clone_dir.join(".git").exists() {
            fs::create_dir_all(&repos_dir)
                .with_context(|| format!("failed to create clone dir {}", repos_dir.display()))?;
            run_git(&["clone", "--quiet", "--depth", "1", url, &clone_dir.to_string_lossy()])
                .with_context(|| format!("git clone failed for repo {}", repo.name))?;
        }
        if let Some(rev) = &repo.rev {
            run_git_in(&clone_dir, &["fetch", "--quiet", "--depth", "1", "origin", rev])?;
            run_git_in(&clone_dir, &["checkout", "--quiet", rev])?;
        } else {
            run_git_in(&clone_dir, &["checkout", "--quiet", &repo.branch])?;
        }
        return Ok(clone_dir);
    }
    if let Some(local) = &repo.local_path {
        return Ok(PathBuf::from(local));
    }
    Ok(base_dir.join(&repo.name))
}

fn run_git(args: &[&str]) -> Result<()> {
    run_git_in(Path::new("."), args)
}

fn run_git_in(dir: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("failed to spawn git in {}", dir.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "git {} failed in {}: {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Runs every configured repo through [`scan_repo`], printing a concise
/// per-repo delta report. A failing repo is reported as a warning and does
/// not abort the other scans.
pub fn run(config_path: &str, out_dir: &str) -> Result<()> {
    let config_content =
        fs::read_to_string(config_path).with_context(|| format!("failed to read watch config {config_path}"))?;
    let config: WatchConfig =
        serde_json::from_str(&config_content).with_context(|| format!("invalid watch config JSON in {config_path}"))?;

    ui::print_section_header("Release Delta Scanner");
    let out = PathBuf::from(out_dir);
    fs::create_dir_all(&out).with_context(|| format!("failed to create out dir {out_dir}"))?;

    for repo in &config.repos {
        match scan_repo(repo, Path::new("."), &out) {
            Ok(diff) => {
                if diff.is_empty() {
                    println!("== {}: no changes ==", repo.name);
                    continue;
                }
                println!("== {}: +{} added, -{} removed ==", repo.name, diff.added.len(), diff.removed.len());
                for signature in &diff.added {
                    if signature.severity == "CRITICAL" || signature.severity == "HIGH" {
                        println!(
                            "NEW [{sev}] {rule} {title} @ {location}",
                            sev = signature.severity,
                            rule = signature.rule_id,
                            title = signature.title,
                            location = signature.location
                        );
                    }
                }
                for signature in &diff.removed {
                    println!(
                        "GONE [{sev}] {rule} {title}",
                        sev = signature.severity,
                        rule = signature.rule_id,
                        title = signature.title
                    );
                }
            }
            Err(err) => {
                ui::print_warning(&format!("repo {} skipped: {err:#}", repo.name));
            }
        }
    }

    Ok(())
}

/// Whether a finding set changed between two signature lists (helper for tests).
#[allow(dead_code)] // exercised from tests/watch_diff.rs; the bin target never calls it
pub fn diff_signatures(previous: &[FindingSignature], current: &[FindingSignature]) -> WatchDiff {
    let old_set: HashSet<&FindingSignature> = previous.iter().collect();
    let new_set: HashSet<&FindingSignature> = current.iter().collect();
    WatchDiff {
        added: current.iter().filter(|s| !old_set.contains(s)).cloned().collect(),
        removed: previous.iter().filter(|s| !new_set.contains(s)).cloned().collect(),
    }
}
