//! `sat hunt` — bounty-oriented lead brief.
//!
//! Turns a raw finding dump into a **ranked, money-oriented shortlist**: each
//! lead is annotated with the payout class it enables, the real-world precedent
//! (from `docs/EXPLOIT_CORPUS.md`), and the first manual-verification step.
//! This is the triage accelerator for a hunt cycle — not an autopilot: every
//! lead still requires manual confirmation before submission.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::json;

use crate::analyzer;
use crate::sarif::classify_finding_rule;
use crate::types::{Confidence, Finding, Severity};
use crate::ui;

/// A payout class a rule maps to: what an exploitable instance is worth and the
/// precedent that argues for its severity. `weight` is the class's bounty
/// value (3 = theft/unauthenticated-fund-movement, 1 = hardening/noise).
struct PayoutClass {
    class: &'static str,
    impact: &'static str,
    precedent: &'static str,
    weight: u8,
}

/// Rule → payout class. Derived from `docs/EXPLOIT_CORPUS.md`.
fn payout_class(rule: &str) -> Option<PayoutClass> {
    let (class, impact, precedent, weight) = match rule {
        // Unauthenticated privileged action / unauthorized fund movement.
        "SAT001" | "SAT019" => ("Authorization bypass", "Privileged action without a signer", "Amulet class", 3),
        "SAT028" | "SAT017" => ("Token-CPI authority", "Unauthorized token transfer/mint/burn", "class", 3),
        "SAT021" => ("Impersonation", "Authority key never pinned", "Amulet class", 2),
        // Account confusion / substitution.
        "SAT002" | "SAT020" => ("Account confusion", "Substitute an attacker-owned account", "Wormhole / Cashio", 3),
        "SAT025" | "SAT018" => ("Type confusion", "Parse attacker bytes as trusted state", "class", 2),
        "SAT004" => ("Type confusion", "Discriminator collision across instructions", "class", 2),
        // PDA / seed substitution.
        "SAT022" | "SAT015" => ("Account substitution", "PDA seed mismatch enables swap", "class", 3),
        // Reentrancy / CEI.
        "SAT023" | "SAT014" => ("Reentrancy / CEI", "Stale state used across a CPI", "Wormhole ($320M)", 3),
        // Reinitialization / account takeover.
        "SAT005" | "SAT016" | "SAT024" => ("Account takeover", "Revive/re-init a closed account", "class", 2),
        // Arithmetic / precision.
        "SAT026" | "SAT012" => ("Arithmetic / precision", "Overflow, underflow, or rounding error", "class", 2),
        // Validation-chain classes.
        "SAT031" => ("Fake account chain", "Self-consistent fake accounts accepted", "Cashio ($48M)", 3),
        "SAT032" => ("Authority takeover", "Caller chooses authority at state creation", "class", 3),
        "SAT033" => ("Fake mint", "Token mint never anchored to a real mint", "Cashio ($48M)", 3),
        "SAT038" => ("Missing validation", "Attacker value reaches a privileged sink", "class", 2),
        // Oracle / price.
        "SAT034" | "SAT035" | "SAT036" | "SAT041" => {
            ("Oracle manipulation", "Stale/manipulable price drives a value decision", "Mango ($114M)", 2)
        }
        // Accounting / token extensions.
        "SAT039" => ("Accounting drift", "Internal balance desyncs from on-chain", "class", 2),
        "SAT013" => ("Token-2022 extension", "Unhandled transfer-fee/delegate/interest", "class", 2),
        "SAT037" => ("Instruction introspection", "Unchecked sysvar introspection", "Wormhole ($320M)", 3),
        // Lower-yield lints / hardening.
        "SAT027" => ("Account tampering", "Writable builtin account", "class", 1),
        "SAT010" => ("Serialization mismatch", "Field width mismatch in serialized state", "class", 1),
        "SAT011" => ("Runtime mismatch", "Declared vs observed account mismatch", "class", 1),
        "SAT006" | "SAT007" => ("Access control", "State lockout / missing access guard", "class", 2),
        "SAT008" => ("CPI depth", "CPI beyond depth 4", "class", 1),
        "SAT009" => ("Sysvar misuse", "Sysvar used without declaring the account", "class", 1),
        "SAT003" => ("State not mut", "Account written without `mut`", "class", 1),
        _ => return None,
    };
    Some(PayoutClass { class, impact, precedent, weight })
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::High => 3,
        Confidence::Medium => 2,
        Confidence::Low => 1,
    }
}

/// A ranked bounty lead.
struct Lead<'a> {
    finding: &'a Finding,
    rule: String,
    class: PayoutClass,
    score: u32,
}

impl<'a> Lead<'a> {
    fn new(finding: &'a Finding) -> Self {
        let rule = classify_finding_rule(finding);
        let class = payout_class(&rule).unwrap_or(PayoutClass {
            class: "Unclassified",
            impact: "—",
            precedent: "—",
            weight: 1,
        });
        // Money-first, evidence-aware: payout class × severity × the tool's own
        // confidence in the pattern. Multiplicative so a low-confidence lead can
        // never outrank a high-confidence lead of a comparable class.
        let score = u32::from(class.weight)
            * u32::from(severity_rank(finding.severity))
            * u32::from(confidence_rank(finding.confidence()));
        Lead { finding, rule, class, score }
    }

    fn is_primary(&self) -> bool {
        self.finding.confidence() != Confidence::Low
    }
}

/// Build the ranked lead list (highest-value first).
fn build_leads(findings: &[Finding]) -> Vec<Lead<'_>> {
    let mut leads: Vec<Lead<'_>> = findings.iter().map(Lead::new).collect();
    leads.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.finding.severity.cmp(&a.finding.severity))
            .then_with(|| a.finding.title.cmp(&b.finding.title))
    });
    leads
}

/// Derive a readable program name from the source path (`.../programs/vault/src`
/// → `vault`; falls back to the last non-`src` path segment).
fn program_name(source: &str) -> String {
    let path = std::path::Path::new(source);
    let last = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if !last.is_empty() && last != "src" {
        return last.to_string();
    }
    path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()).unwrap_or("program").to_string()
}

/// Render the markdown hunt brief.
pub fn render_brief(findings: &[Finding], program: &str, source: &str) -> String {
    let leads = build_leads(findings);
    let primary: Vec<&Lead<'_>> = leads.iter().filter(|l| l.is_primary()).collect();
    let low: Vec<&Lead<'_>> = leads.iter().filter(|l| !l.is_primary()).collect();
    let generated = chrono::Local::now().format("%Y-%m-%d %H:%M");

    let mut md = String::new();
    md.push_str(&format!("# Hunt Brief — {program}\n\n"));
    md.push_str(&format!("- **Source:** `{source}`\n"));
    md.push_str(&format!("- **Generated:** {generated}\n"));
    md.push_str(&format!(
        "- **Findings:** {} ({} primary leads, {} low-confidence)\n\n",
        findings.len(),
        primary.len(),
        low.len()
    ));

    if leads.is_empty() {
        md.push_str("No findings. This is not an assertion of security — see the limitations below.\n\n");
        md.push_str(LIMITATIONS);
        return md;
    }

    if primary.is_empty() {
        md.push_str(
            "**No primary (medium/high-confidence) leads.** All findings are low-confidence \
                     heuristic patterns — on well-audited code these are usually already-mitigated \
                     or `CHECK:`-documented. Treat the low-confidence surface below as a coverage \
                     map, not a lead list.\n\n",
        );
    } else {
        md.push_str("## Top leads\n\n");
        md.push_str("| # | Score | Sev | Conf | Rule | Class | Impact | Precedent | Location |\n");
        md.push_str("| --- | ---: | --- | --- | --- | --- | --- | --- | --- |\n");
        for (i, lead) in primary.iter().take(30).enumerate() {
            let loc = lead.finding.location.clone().unwrap_or_else(|| "—".to_string());
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | `{}` |\n",
                i + 1,
                lead.score,
                lead.finding.severity,
                lead.finding.confidence(),
                lead.rule,
                lead.class.class,
                lead.class.impact,
                lead.class.precedent,
                loc
            ));
        }
        md.push('\n');

        md.push_str("## Verification queue\n\n");
        for (i, lead) in primary.iter().take(15).enumerate() {
            md.push_str(&format!(
                "{}. **{}** — {} ({}, {} confidence)\n",
                i + 1,
                lead.finding.title,
                lead.class.impact,
                lead.rule,
                lead.finding.confidence()
            ));
            if let Some(loc) = &lead.finding.location {
                md.push_str(&format!("   - Location: `{loc}`\n"));
            }
            let accounts = lead.finding.affected_accounts();
            if !accounts.is_empty() {
                md.push_str(&format!("   - Affected: {}\n", accounts.join(", ")));
            }
            if let Some(step) = lead.finding.manual_verification_steps().first() {
                md.push_str(&format!("   - First check: {step}\n"));
            }
        }
        md.push('\n');
    }

    // Low-confidence surface: rolled up by class so it stays a coverage map.
    if !low.is_empty() {
        md.push_str("## Low-confidence surface (coverage map)\n\n");
        md.push_str("| Class | Count | Precedent |\n| --- | ---: | --- |\n");
        let mut by_class: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
        for lead in &low {
            by_class.entry(lead.class.class).or_insert((0, lead.class.precedent)).0 += 1;
        }
        let mut rows: Vec<_> = by_class.into_iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1.0));
        for (class, (count, precedent)) in rows {
            md.push_str(&format!("| {class} | {count} | {precedent} |\n"));
        }
        md.push('\n');
    }

    md.push_str(LIMITATIONS);
    md
}

const LIMITATIONS: &str = "## Honest limitations\n\n\
Leads are heuristic: `sat` flags code patterns, not proven exploits. Every lead \
requires manual confirmation of reachability and impact, and a working PoC, \
before submission. Out of scope for this static backend: protocol-economic \
invariants (rounding direction, liquidation math), oracle manipulation economics, \
cross-transaction atomicity, and governance logic. `Score` ranks expected bounty \
value (payout class × severity × confidence), not likelihood.\n";

/// Render the lead list as JSON.
pub fn render_json(findings: &[Finding], program: &str, source: &str) -> String {
    let leads = build_leads(findings);
    let items: Vec<_> = leads
        .iter()
        .map(|l| {
            json!({
                "rank": 0, // filled below
                "score": l.score,
                "rule": l.rule,
                "class": l.class.class,
                "impact": l.class.impact,
                "precedent": l.class.precedent,
                "severity": l.finding.severity.as_str(),
                "confidence": l.finding.confidence().to_string().to_ascii_lowercase(),
                "title": l.finding.title,
                "location": l.finding.location,
            })
        })
        .enumerate()
        .map(|(i, mut v)| {
            v["rank"] = json!(i + 1);
            v
        })
        .collect();
    let report = json!({
        "program": program,
        "source": source,
        "total_findings": findings.len(),
        "leads": items,
    });
    let mut out = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    out.push('\n');
    out
}

/// `sat hunt [PATH] --out <file> --format md|json`: write a ranked hunt brief.
pub fn run(src_path: Option<&str>, out_path: Option<&str>, format: &str) -> Result<()> {
    let output = analyzer::collect(src_path, None, None)?;
    if output.parsed_files.is_empty() {
        anyhow::bail!("No Rust source files found under the given path.");
    }

    let source = src_path.unwrap_or(".").to_string();
    let program = program_name(&source);

    let body = if format.eq_ignore_ascii_case("json") {
        render_json(&output.findings, &program, &source)
    } else {
        render_brief(&output.findings, &program, &source)
    };

    let default_name = if format.eq_ignore_ascii_case("json") { "hunt-brief.json" } else { "hunt-brief.md" };
    let path = out_path.unwrap_or(default_name);
    std::fs::write(path, body).with_context(|| format!("failed to write hunt brief to {path}"))?;

    let leads = build_leads(&output.findings).len();
    ui::print_success(&format!("Hunt brief written to {path} ({leads} leads, {} findings).", output.findings.len()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(title: &str, sev: Severity, loc: &str) -> Finding {
        Finding {
            id: String::new(),
            title: title.to_string(),
            severity: sev,
            description: "desc".to_string(),
            location: Some(loc.to_string()),
            suggestion: None,
        }
    }

    #[test]
    fn ranks_high_value_classes_first() {
        // A SAT031 (Cashio, class weight 3) must outrank a SAT003 (weight 1)
        // even though SAT003 is the more confident pattern.
        let findings = vec![
            finding("Missing `mut` on account", Severity::High, "a.rs:1"),
            finding("Self-Referential Validation: `x`", Severity::High, "b.rs:2"),
        ];
        let leads = build_leads(&findings);
        assert_eq!(leads[0].rule, "SAT031", "highest payout class must rank first");
        assert_eq!(leads[0].class.precedent, "Cashio ($48M)");
    }

    #[test]
    fn brief_contains_top_leads_and_precedent() {
        // A High-confidence SAT001 is a primary lead (drives the Top leads table).
        let findings = vec![finding("Missing Signer: `authority`", Severity::High, "programs/x/src/lib.rs:9")];
        let md = render_brief(&findings, "x", "programs/x/src");
        assert!(md.contains("# Hunt Brief"), "header missing");
        assert!(md.contains("## Top leads"), "lead table missing");
        assert!(md.contains("## Verification queue"), "verification queue missing");
        assert!(md.contains("Honest limitations"), "limitations missing");
        assert!(md.contains("Authorization bypass"), "SAT001 class missing");
    }
}
