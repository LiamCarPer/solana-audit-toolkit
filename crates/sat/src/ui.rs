#![allow(dead_code)]

use crate::types::Severity;
use colored::*;

pub fn print_banner() {
    println!("{}", "╔══════════════════════════════════════════════════╗".blue());
    println!("{}", "║       Solana Audit Toolkit (sat) v0.1.0         ║".blue().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".blue());
}

pub fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical | Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low | Severity::Informational => Color::Cyan,
    }
}

pub fn severity_tag(severity: Severity) -> String {
    let label = format!("{}", severity);
    let color = severity_color(severity);
    format!("[{}]", label).color(color).bold().to_string()
}

pub fn print_finding(finding: &crate::types::Finding) {
    let tag = severity_tag(finding.severity);
    println!("{} {}", tag, finding.title.bold());

    if let Some(ref location) = finding.location {
        println!("  {} {location}", "📍".dimmed());
    }

    println!();
    println!("{}", finding.description);

    if let Some(ref suggestion) = finding.suggestion {
        println!();
        println!("{}", "Suggestion:".green().bold());
        println!("  {suggestion}");
    }
    println!();
}

pub fn print_section_header(title: &str) {
    println!();
    println!("{}", "┌".blue());
    println!("{} {}", "├─".blue(), title.bold());
}

pub fn print_notice(msg: &str) {
    println!("{} {msg}", "ℹ ".cyan());
}

pub fn print_success(msg: &str) {
    println!("{} {msg}", "✓ ".green());
}

pub fn print_warning(msg: &str) {
    println!("{} {msg}", "⚠ ".yellow());
}

pub fn print_error(msg: &str) {
    println!("{} {msg}", "✗ ".red());
}
