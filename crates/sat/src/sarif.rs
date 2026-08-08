use std::fs;

use anyhow::Result;
use serde::Serialize;

use crate::types::{Finding, Severity};

#[derive(Debug, Serialize)]
#[allow(private_interfaces)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifRule {
    pub id: String,
    pub short_description: SarifMessage,
    pub full_description: SarifMessage,
    pub default_configuration: SarifDefaultConfig,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifDefaultConfig {
    pub level: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifResult {
    pub rule_id: String,
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifRegion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
}

const RULES: &[(&str, &str, &str)] = &[
    ("SAT001", "Missing Signer Constraint", "An authority field lacks #[account(signer)] or Signer<'info> type."),
    ("SAT002", "Missing Owner Constraint", "AccountInfo/UncheckedAccount field lacks #[account(owner = ...)]."),
    ("SAT003", "Missing Mut Constraint", "Account written to in IDL but not marked #[account(mut)]."),
    ("SAT004", "Discriminator Collision", "Two instruction names hash to the same 8-byte Anchor discriminator."),
    ("SAT005", "Reinitialization Risk", "Initializer instruction may overwrite existing state."),
    ("SAT006", "State Lockout", "State has no instruction to transition out."),
    ("SAT007", "Missing Access Control", "State-modifying instruction has no signer requirement."),
    ("SAT008", "CPI Depth Overflow", "CPI call chain exceeds the Solana limit of 4."),
    ("SAT009", "Sysvar Misuse", "Missing sysvar account declaration or writable sysvar."),
    ("SAT010", "Serialization Mismatch", "Field type mismatch between storage and instruction args."),
    ("SAT011", "Tx-Report Mismatch", "Runtime transaction data differs from declared constraints."),
    ("SAT012", "Unsafe Arithmetic", "Arithmetic on security-sensitive values lacks checked operations."),
    ("SAT013", "Token-2022 Risk", "Token-2022 usage requires extension-specific accounting checks."),
    ("SAT014", "CEI Violation", "State write occurs after an external call (CPI), enabling reentrancy attacks."),
    (
        "SAT015",
        "PDA Seed Mismatch",
        "Runtime PDA seeds diverge from IDL-declared seeds, enabling account substitution.",
    ),
    ("SAT016", "Init-if-Needed Risk", "Authority-bearing account uses init_if_needed without an initialization guard."),
    ("SAT017", "Token-CPI Authority", "Token transfer/set_authority CPI uses an authority not constrained as signer."),
    ("SAT018", "Manual Deserialization", "Account data deserialized without owner or discriminator validation."),
];

/// Extracts the artifact URI and line number from a `Finding::location` string.
///
/// Locations use a `path:line` shape, optionally followed by a parenthetical
/// context. The *last* `:<digits>` sequence is used so Windows drive letters
/// (`C:\...`) are never mistaken for a line separator. Locations without a
/// line number (e.g. `Sysvar: rent (...)`) fall back to the whole string as
/// the URI with no line.
fn location_to_uri_and_line(loc: &str) -> (String, Option<u32>) {
    let bytes = loc.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] != b':' {
            continue;
        }
        let digits_start = i + 1;
        let mut digits_end = digits_start;
        while digits_end < bytes.len() && bytes[digits_end].is_ascii_digit() {
            digits_end += 1;
        }
        let has_digits = digits_end > digits_start;
        let followed_by_boundary = digits_end == bytes.len() || bytes[digits_end] == b' ' || bytes[digits_end] == b'(';
        if has_digits && followed_by_boundary {
            let line = loc[digits_start..digits_end].parse().ok();
            return (loc[..i].to_string(), line);
        }
    }
    (loc.to_string(), None)
}

pub fn export_sarif(findings: &[Finding], _program_name: &str, output_path: &str) -> Result<()> {
    let rules: Vec<SarifRule> = RULES
        .iter()
        .map(|(id, short, full)| SarifRule {
            id: id.to_string(),
            short_description: SarifMessage { text: short.to_string() },
            full_description: SarifMessage { text: full.to_string() },
            default_configuration: SarifDefaultConfig { level: "warning".to_string() },
        })
        .collect();

    let mut results = Vec::new();

    for finding in findings {
        let rule_id = classify_finding_rule(finding);
        let rule_index = RULES.iter().position(|(id, _, _)| *id == rule_id).unwrap_or(0);

        let (uri, start_line) =
            finding.location.as_deref().map(location_to_uri_and_line).unwrap_or_else(|| ("unknown".to_string(), None));

        results.push(SarifResult {
            rule_id,
            rule_index,
            level: severity_to_sarif_level(finding.severity),
            message: SarifMessage {
                text: format!(
                    "{}: {} Confidence: {}. Manual verification: {}",
                    finding.title,
                    finding.description,
                    finding.confidence(),
                    finding.manual_verification_steps().join(" ")
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation { uri },
                    region: SarifRegion { start_line, start_column: Some(1) },
                },
            }],
        });
    }

    let log = SarifLog {
        version: "2.1.0".to_string(),
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            .to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sat".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/LiamCarPer/solana-audit-toolkit".to_string(),
                    rules,
                },
            },
            results,
        }],
    };

    let json = serde_json::to_string_pretty(&log)?;
    fs::write(output_path, json)?;

    Ok(())
}

fn classify_finding_rule(finding: &Finding) -> String {
    // Ordering is load-bearing: these titles also contain substrings matched by
    // older arms below (e.g. "Reinitialization Risk" would hit SAT005, and
    // "Token Transfer CPI" titles mention Token-2022 ops), so they must be
    // classified before the broader arms.
    if finding.title.contains("init_if_needed") {
        "SAT016".to_string()
    } else if finding.title.contains("Token Transfer CPI") {
        "SAT017".to_string()
    } else if finding.title.contains("Manual Deserialization") {
        "SAT018".to_string()
    } else if finding.title.contains("Missing Signer") {
        "SAT001".to_string()
    } else if finding.title.contains("Missing Owner") {
        "SAT002".to_string()
    } else if finding.title.contains("Missing `mut`") {
        "SAT003".to_string()
    } else if finding.title.contains("Discriminator Collision") {
        "SAT004".to_string()
    } else if finding.title.contains("Reinitialization") {
        "SAT005".to_string()
    } else if finding.title.contains("Lockout") || finding.title.contains("No outgoing") {
        "SAT006".to_string()
    } else if finding.title.contains("Missing Access") {
        "SAT007".to_string()
    } else if finding.title.contains("CPI Depth") {
        "SAT008".to_string()
    } else if finding.title.contains("Sysvar") {
        "SAT009".to_string()
    } else if finding.title.contains("CEI Violation") {
        "SAT014".to_string()
    } else if finding.title.contains("PDA Seed") || finding.title.contains("Seed Mismatch") {
        "SAT015".to_string()
    } else if finding.title.contains("Serialization Mismatch") || finding.title.contains("Mismatch") {
        "SAT010".to_string()
    } else if finding.title.contains("Tx-Report") || finding.title.contains("Transaction") {
        "SAT011".to_string()
    } else if finding.title.contains("Unsafe Arithmetic") || finding.title.contains("Unsafe Multiplication") {
        "SAT012".to_string()
    } else if finding.title.contains("Token-2022")
        || finding.title.contains("Transfer Fee")
        || finding.title.contains("Permanent Delegate")
        || finding.title.contains("Interest-Bearing")
    {
        "SAT013".to_string()
    } else {
        "SAT001".to_string()
    }
}

fn severity_to_sarif_level(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low | Severity::Informational => "note".to_string(),
    }
}
