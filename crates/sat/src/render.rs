use crate::analyzer::AnalysisContext;
use crate::types::{Confidence, Finding, Severity};
use crate::ui;
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ── Output rendering ──────────────────────────────────────────────────────────

pub(crate) fn render_accounts_summary(ctx: &AnalysisContext) {
    ui::print_section_header("Accounts Structs");

    if ctx.accounts_structs.is_empty() {
        ui::print_warning("No `#[derive(Accounts)]` structs found in the source.");
        return;
    }

    ui::print_notice(&format!(
        "Found {} Accounts struct(s) in {} file(s):",
        ctx.accounts_structs.len(),
        ctx.file_count
    ));

    for accts in &ctx.accounts_structs {
        println!();
        println!(
            "  {} {}  {}",
            "-".blue(),
            accts.name.bold(),
            format!("{}:{}", accts.file.display(), accts.line).dimmed()
        );

        for field in &accts.fields {
            let mut tags = Vec::new();
            if field.has_signer {
                tags.push("signer".green().to_string());
            }
            if field.has_mut {
                tags.push("mut".yellow().to_string());
            }
            if field.has_init {
                tags.push("init".cyan().to_string());
            }
            if field.has_owner {
                let owner_str = field.owner_value.as_deref().unwrap_or("set");
                tags.push(format!("owner={owner_str}").cyan().to_string());
            }
            if field.is_account_info {
                tags.push("AccountInfo".red().to_string());
            }
            if field.is_unchecked_account {
                tags.push("UncheckedAccount".red().to_string());
            }

            let tag_str = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };

            println!("    {} {}: {}{}", "  -".dimmed(), field.name, field.ty_name.dimmed(), tag_str);
        }
    }
    println!();
}

pub(crate) fn render_instructions_summary(ctx: &AnalysisContext) {
    if ctx.instructions.is_empty() {
        return;
    }

    ui::print_section_header("Instruction Handlers");
    ui::print_notice(&format!("Found {} instruction(s):", ctx.instructions.len()));

    for ix in &ctx.instructions {
        let disc = compute_discriminator_display(&ix.name);
        println!(
            "  {} {}  {}  {}",
            "-".blue(),
            ix.name.bold(),
            disc.dimmed(),
            format!("{}:{}", ix.file.display(), ix.line).dimmed()
        );
    }
    println!();
}

fn compute_discriminator_display(name: &str) -> String {
    let preimage = format!("global:{name}");
    let hash = Sha256::digest(preimage.as_bytes());
    let hex: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("[0x{hex}]")
}

pub(crate) fn render_findings(all_findings: &[Finding]) {
    ui::print_section_header("Findings");

    if all_findings.is_empty() {
        ui::print_success("No vulnerabilities detected in the AST analysis.");
        println!();
        ui::print_notice("Note: Run `sat analyze src --format sarif` to export results for CI integration.");
        return;
    }

    let mut by_severity: BTreeMap<Severity, Vec<&Finding>> = BTreeMap::new();
    for f in all_findings {
        by_severity.entry(f.severity).or_default().push(f);
    }

    let severity_order = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Informational];

    let mut counter = 0;
    for sev in &severity_order {
        if let Some(group) = by_severity.get(sev) {
            for finding in group {
                counter += 1;
                let tag = ui::severity_tag(finding.severity);
                println!("{} {} {}", format!("#{counter}").dimmed(), tag, finding.title.bold());

                if let Some(ref location) = finding.location {
                    println!("  at {location}");
                }
                println!("  confidence: {}", finding.confidence());

                let affected_accounts = finding.affected_accounts();
                if !affected_accounts.is_empty() {
                    println!("  affected: {}", affected_accounts.join(", "));
                }
                println!();
                println!("  {}", finding.description);

                if let Some(ref suggestion) = finding.suggestion {
                    println!();
                    println!("  {}", "Suggestion:".green().bold());
                    println!("  {suggestion}");
                }

                let verification_steps = finding.manual_verification_steps();
                if !verification_steps.is_empty() {
                    println!();
                    println!("  {}", "Manual verification:".cyan().bold());
                    for step in verification_steps {
                        println!("  - {step}");
                    }
                }
                println!();
            }
        }
    }
}

pub(crate) fn render_triage_findings(all_findings: &[Finding]) {
    ui::print_section_header("Triage Queue");

    let actionable: Vec<&Finding> = all_findings
        .iter()
        .filter(|finding| {
            matches!(finding.severity, Severity::Critical | Severity::High)
                || (finding.severity == Severity::Medium && finding.confidence() != Confidence::Low)
        })
        .collect();

    if actionable.is_empty() {
        ui::print_success("No high-priority triage items found.");
        println!();
        return;
    }

    for (index, finding) in actionable.iter().enumerate() {
        println!(
            "{} {} {} ({})",
            format!("#{}", index + 1).dimmed(),
            ui::severity_tag(finding.severity),
            finding.title.bold(),
            finding.confidence()
        );

        if let Some(location) = &finding.location {
            println!("  at {location}");
        }

        let accounts = finding.affected_accounts();
        if !accounts.is_empty() {
            println!("  affected: {}", accounts.join(", "));
        }

        if let Some(step) = finding.manual_verification_steps().first() {
            println!("  first check: {step}");
        }
        println!();
    }
}

pub(crate) fn render_summary(findings: &[Finding]) {
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.severity).or_default() += 1;
    }

    let parts: Vec<String> =
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Informational]
            .iter()
            .filter_map(|s| counts.get(s).map(|c| format!("{} {c} {s}", severity_emoji(*s))))
            .collect();

    let total = findings.len();
    if total == 0 {
        ui::print_success("AST analysis complete — 0 findings.");
    } else {
        println!(
            "{} {} {}: {}",
            "Summary:".bold(),
            total,
            if total == 1 { "finding" } else { "findings" },
            parts.join(" | ")
        );
    }
    println!();
}

pub(crate) fn severity_emoji(severity: Severity) -> String {
    match severity {
        Severity::Critical => "[CRIT]".red().to_string(),
        Severity::High => "[HIGH]".red().to_string(),
        Severity::Medium => "[MED]".yellow().to_string(),
        Severity::Low => "[LOW]".cyan().to_string(),
        Severity::Informational => "[INFO]".cyan().to_string(),
    }
}
