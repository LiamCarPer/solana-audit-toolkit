use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use crate::types::Severity;

const OUTPUT_DIR: &str = "audit-findings";

#[derive(Debug, Serialize)]
struct FindingMetadata {
    id: String,
    title: String,
    severity: String,
    date: String,
    tags: Vec<String>,
}

struct FindingInput {
    title: String,
    severity: Severity,
    description: String,
    exploit: String,
    remediation: String,
    tags: Vec<String>,
}

pub fn new_finding() -> Result<()> {
    crate::ui::print_banner();
    println!();
    println!("{}", "Audit Finding Reporter".bold().green());
    println!("{}", "─────────────────────".dimmed());
    println!();
    println!("  Create a structured markdown audit finding for your portfolio.");
    println!("  Press Ctrl+C at any prompt to cancel.");
    println!();

    let title = prompt_required("Finding title")?;
    let severity = prompt_severity()?;
    println!();
    println!("  {}", "Description".bold());
    println!("  {}", "Enter the full description of the vulnerability. End with a blank line.".dimmed());
    let description = prompt_multiline()?;

    println!();
    println!("  {}", "Exploit Scenario".bold());
    println!("  {}", "Describe how an attacker would exploit this vulnerability. End with a blank line.".dimmed());
    let exploit = prompt_multiline()?;

    println!();
    println!("  {}", "Remediation".bold());
    println!("  {}", "Describe how to fix this vulnerability. End with a blank line.".dimmed());
    let remediation = prompt_multiline()?;

    println!();
    println!("  {}", "Tags (comma-separated)".bold());
    println!("  {}", "e.g., access-control, reinitialization, anchor".dimmed());
    let tags = prompt_string("Tags", Some(""))?;
    let tags: Vec<String> = tags.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();

    let next_id = get_next_finding_id()?;
    let slug = slugify(&title);
    let filename = format!("{next_id}-{slug}.md");
    let output_path = ensure_output_dir()?.join(&filename);

    let date = chrono::Local::now().format("%Y-%m-%d").to_string();

    let metadata =
        FindingMetadata { id: next_id.clone(), title: title.clone(), severity: severity.to_string(), date, tags };

    let markdown = render_finding(
        &metadata,
        &FindingInput { title, severity, description, exploit, remediation, tags: metadata.tags.clone() },
    );

    fs::write(&output_path, &markdown)
        .with_context(|| format!("Failed to write finding to {}", output_path.display()))?;

    println!();
    println!("{} Created finding {} → {}", "OK".green(), next_id.bold(), output_path.display().to_string().dimmed());

    Ok(())
}

fn ensure_output_dir() -> Result<PathBuf> {
    let dir = PathBuf::from(OUTPUT_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("Failed to create directory: {}", dir.display()))?;
    Ok(dir)
}

fn get_next_finding_id() -> Result<String> {
    let dir = PathBuf::from(OUTPUT_DIR);
    if !dir.is_dir() {
        return Ok("SAT-001".to_string());
    }

    let mut max_num: u32 = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(rest) = name_str.strip_prefix("SAT-")
                && let Some(num_str) = rest.split('-').next()
                && let Ok(num) = num_str.parse::<u32>()
                && num > max_num
            {
                max_num = num;
            }
        }
    }

    Ok(format!("SAT-{:03}", max_num + 1))
}

fn slugify(title: &str) -> String {
    let mut slug = String::new();
    for c in title.to_lowercase().chars() {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if (c == ' ' || c == '_' || c == '-') && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug = slug.trim_matches('-').to_string();
    if slug.len() > 80 {
        slug = slug[..80].to_string();
        if let Some(last_dash) = slug.rfind('-') {
            slug = slug[..last_dash].to_string();
        }
    }
    slug
}

fn render_finding(meta: &FindingMetadata, input: &FindingInput) -> String {
    let yaml = serde_yaml::to_string(meta).unwrap_or_default();
    let mut md = String::new();

    md.push_str("---\n");
    md.push_str(&yaml);
    md.push_str("---\n\n");

    md.push_str(&format!("# {}: {}\n\n", meta.id, input.title));
    md.push_str(&format!("**Severity:** {}\n\n", input.severity));
    md.push_str("## Description\n\n");
    md.push_str(&input.description);
    md.push_str("\n\n");

    md.push_str("## Exploit Scenario\n\n");
    md.push_str(&input.exploit);
    md.push_str("\n\n");

    md.push_str("## Remediation\n\n");
    md.push_str(&input.remediation);
    md.push_str("\n\n");

    if !input.tags.is_empty() {
        md.push_str("## Tags\n\n");
        for tag in &input.tags {
            md.push_str(&format!("- `{tag}`\n"));
        }
        md.push('\n');
    }

    md
}

fn prompt_required(label: &str) -> Result<String> {
    loop {
        print!("  {}: ", label.bold());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
        println!("  {} Title is required.", "ERR".red());
    }
}

fn prompt_string(label: &str, default: Option<&str>) -> Result<String> {
    let prompt = if let Some(d) = default {
        format!("  {} [{}]: ", label.bold(), d.dimmed())
    } else {
        format!("  {}: ", label.bold())
    };
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() { Ok(default.unwrap_or("").to_string()) } else { Ok(trimmed) }
}

fn prompt_severity() -> Result<Severity> {
    println!("  {}:", "Severity".bold());
    println!("    1. Critical");
    println!("    2. High");
    println!("    3. Medium");
    println!("    4. Low");
    println!("    5. Informational");

    loop {
        print!("  {} [1-5]: ", "Select".bold());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim() {
            "1" => return Ok(Severity::Critical),
            "2" => return Ok(Severity::High),
            "3" => return Ok(Severity::Medium),
            "4" => return Ok(Severity::Low),
            "5" => return Ok(Severity::Informational),
            _ => println!("  {} Please enter a number 1-5.", "ERR".red()),
        }
    }
}

fn prompt_multiline() -> Result<String> {
    let mut lines = Vec::new();

    loop {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').to_string();

        if trimmed.is_empty() {
            if lines.is_empty() {
                continue;
            } else {
                break;
            }
        }

        lines.push(trimmed);
    }

    Ok(lines.join("\n"))
}
