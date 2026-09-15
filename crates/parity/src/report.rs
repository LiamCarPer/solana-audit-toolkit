//! Rendering of comparison reports (markdown + JSON) for humans and the AI.

use crate::engine::ComparisonReport;
use crate::scenario::Scenario;

/// Human/AI-readable markdown report.
pub fn render_markdown(report: &ComparisonReport, scenario: &Scenario) -> String {
    let generated = chrono::Local::now().format("%Y-%m-%d %H:%M");
    let mut md = String::new();

    let status = if report.is_clean() { "CLEAN (parity)" } else { "DIVERGED" };
    md.push_str(&format!("# Parity Report — {}\n\n", report.scenario));
    md.push_str(&format!("- **Status:** {status}\n"));
    md.push_str(&format!("- **Expected model:** `{}`\n", report.expected_model));
    md.push_str(&format!("- **Actual model:** `{}`\n", report.actual_model));
    md.push_str(&format!("- **Operations:** {}\n", scenario.ops.len()));
    md.push_str(&format!("- **Agreed rejections:** {}\n", report.agreed_errors));
    md.push_str(&format!("- **Generated:** {generated}\n\n"));

    if report.is_clean() {
        md.push_str(
            "No divergence and no invariant violation. On this scenario set the candidate \
                     behaves identically to the reference. Widen the scenarios (edge amounts, \
                     rounding boundaries, sequences) — parity on narrow input is not proof of safety.\n",
        );
        return md;
    }

    // Minimal repro first: it is the actionable artifact.
    let repro = report.minimal_repro(scenario);
    md.push_str("## Minimal repro\n\n");
    md.push_str(&format!("{} operation(s) reproduce the divergence:\n\n", repro.ops.len()));
    md.push_str("```json\n");
    md.push_str(&repro.to_json());
    md.push_str("\n```\n\n");

    if !report.divergences.is_empty() {
        md.push_str("## Divergences\n\n");
        md.push_str("| Op# | Field | Expected | Actual | Operation |\n| ---: | --- | ---: | ---: | --- |\n");
        for d in &report.divergences {
            md.push_str(&format!(
                "| {} | {} | {} | {} | `{}` |\n",
                d.op_index,
                d.field,
                d.expected,
                d.actual,
                op_label(&d.op)
            ));
        }
        md.push('\n');
    }

    if !report.violations.is_empty() {
        md.push_str("## Invariant violations\n\n");
        md.push_str("| Op# | Model | Invariant | Detail |\n| ---: | --- | --- | --- |\n");
        for v in &report.violations {
            md.push_str(&format!("| {} | {} | {} | {} |\n", v.op_index, v.model, v.invariant, v.detail));
        }
        md.push('\n');
    }

    md.push_str("## Next actions (AI)\n\n");
    md.push_str("1. Reduce the divergence to the smallest input (the minimal repro above).\n");
    md.push_str("2. Decide which side is wrong: is the reference model wrong, or the candidate?\n");
    md.push_str(
        "3. Trace the candidate's source for the divergent field (rounding direction, \
                 fee accrual, index update) and confirm it is reachable.\n",
    );
    md.push_str("4. Build a PoC transaction against a fork and quantify the value extractable.\n");

    md
}

fn op_label(op: &crate::scenario::Op) -> String {
    use crate::scenario::Op;
    match op {
        Op::Deposit { user, amount } => format!("deposit({user}, {amount})"),
        Op::Withdraw { user, amount } => format!("withdraw({user}, {amount})"),
        Op::Borrow { user, amount } => format!("borrow({user}, {amount})"),
        Op::Repay { user, amount } => format!("repay({user}, {amount})"),
        Op::Accrue { seconds } => format!("accrue({seconds}s)"),
        Op::SetPrice { price } => format!("set_price({price})"),
    }
}

/// Structured JSON report.
pub fn render_json(report: &ComparisonReport, scenario: &Scenario) -> String {
    let value = serde_json::json!({
        "scenario": report.scenario,
        "status": if report.is_clean() { "clean" } else { "diverged" },
        "expected_model": report.expected_model,
        "actual_model": report.actual_model,
        "first_divergence_op": report.first_divergence_op,
        "divergences": report.divergences,
        "violations": report.violations,
        "agreed_errors": report.agreed_errors,
        "minimal_repro": report.minimal_repro(scenario),
    });
    let mut out = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string());
    out.push('\n');
    out
}
