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
];

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

        let uri =
            finding
                .location
                .as_ref()
                .and_then(|loc| {
                    if loc.contains(':') { loc.split(':').next().map(|s| s.to_string()) } else { Some(loc.clone()) }
                })
                .unwrap_or_else(|| "unknown".to_string());

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
                    region: SarifRegion { start_line: Some(1), start_column: Some(1) },
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
    if finding.title.contains("Missing Signer") {
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
