#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Informational => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub location: Option<String>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "High"),
            Confidence::Medium => write!(f, "Medium"),
            Confidence::Low => write!(f, "Low"),
        }
    }
}

impl Finding {
    pub fn confidence(&self) -> Confidence {
        let title = self.title.to_lowercase();

        if title.contains("tx-report mismatch")
            || title.contains("discriminator collision")
            || title.contains("writable sysvar")
            || title.contains("missing owner constraint")
            || title.contains("missing signer")
        {
            return Confidence::High;
        }

        if title.contains("unsafe arithmetic")
            || title.contains("unsafe multiplication")
            || title.contains("missing `has_one`")
            || title.contains("missing `mut`")
            || title.contains("serialization mismatch")
            || title.contains("reinitialization risk")
            || title.contains("token-2022")
            || title.contains("transfer fee")
            || title.contains("permanent delegate")
            || title.contains("interest-bearing")
        {
            return Confidence::Medium;
        }

        Confidence::Low
    }

    pub fn affected_accounts(&self) -> Vec<String> {
        let mut accounts = Vec::new();

        for token in self.title.split('`').skip(1).step_by(2) {
            if token.contains("::") || token.contains("Account") || token.contains("State") {
                push_unique(&mut accounts, token.to_string());
            }
        }

        if let Some(location) = &self.location {
            for prefix in ["Account: ", "Sysvar: ", "Instruction: "] {
                if let Some(rest) = location.split(prefix).nth(1) {
                    let value = rest.split(['|', '/', '(']).next().unwrap_or(rest).trim();
                    if !value.is_empty() {
                        push_unique(&mut accounts, value.to_string());
                    }
                }
            }
        }

        accounts
    }

    pub fn manual_verification_steps(&self) -> Vec<&'static str> {
        let title = self.title.to_lowercase();

        if title.contains("missing signer") {
            return vec![
                "Confirm the account authorizes privileged state changes or fund movement.",
                "Check whether the handler has an equivalent manual `is_signer` or key equality guard.",
                "Attempt a transaction with this account supplied as a non-signer.",
            ];
        }

        if title.contains("missing owner") {
            return vec![
                "Confirm the raw account is deserialized or trusted by program logic.",
                "Try substituting an account owned by an attacker-controlled program.",
                "Verify whether a manual owner check exists before reads or writes.",
            ];
        }

        if title.contains("missing `has_one`") {
            return vec![
                "Locate the stored authority field in the mutable account data.",
                "Check whether the handler manually compares it with the signer key.",
                "Try pairing a valid signer with another user's state account.",
            ];
        }

        if title.contains("reinitialization") {
            return vec![
                "Confirm whether Anchor `init` or `init_if_needed` is used on the state account.",
                "Check for an explicit initialized/discriminator guard before state writes.",
                "Attempt calling the initializer twice against the same state account.",
            ];
        }

        if title.contains("unsafe arithmetic") || title.contains("unsafe multiplication") {
            return vec![
                "Check whether overflow checks are enabled in the release profile.",
                "Trace attacker-controlled operands and account balance fields.",
                "Build a boundary-value PoC for underflow, overflow, or precision loss.",
            ];
        }

        if title.contains("token-2022") || title.contains("transfer fee") {
            return vec![
                "Identify which Token-2022 extensions can be enabled for accepted mints.",
                "Compare internal accounting with actual token balance deltas after transfer.",
                "Test with transfer-fee, permanent-delegate, and interest-bearing mints.",
            ];
        }

        vec![
            "Map the flagged account or instruction to the handler logic.",
            "Check whether equivalent manual validation exists outside Anchor attributes.",
            "Create the smallest transaction or unit test that proves exploitability.",
        ]
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}
