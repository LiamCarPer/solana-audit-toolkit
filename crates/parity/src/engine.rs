//! Differential engine: run one scenario against two models, check invariants
//! after every op, and report where the observable state diverges.
//!
//! This is the core primitive: the "expected" model is the AI's source-derived
//! reference; the "actual" side is a candidate implementation (another
//! protocol, or a `program-test` adapter). The engine does the mechanical work
//! (run, normalize, diff, minimise the repro); the AI interprets divergences.

use serde::Serialize;

use crate::invariants;
use crate::model::ProgramModel;
use crate::scenario::{Invariant, Observables, Op, Scenario, Trace};

/// One field divergence at an operation step.
#[derive(Debug, Clone, Serialize)]
pub struct Divergence {
    /// 0-based index of the operation that produced the divergence.
    pub op_index: usize,
    /// The operation (for the repro).
    pub op: Op,
    /// Observable field that differs.
    pub field: String,
    pub expected: String,
    pub actual: String,
}

/// An invariant violation observed in one model.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub op_index: usize,
    pub model: String,
    pub invariant: String,
    pub detail: String,
}

/// The full result of comparing two models over a scenario.
#[derive(Debug, Clone, Serialize)]
pub struct ComparisonReport {
    pub scenario: String,
    pub expected_model: String,
    pub actual_model: String,
    /// Index of the first divergence (minimal repro prefix length).
    pub first_divergence_op: Option<usize>,
    pub divergences: Vec<Divergence>,
    pub violations: Vec<Violation>,
    /// Operations that ended in the same error on both sides (parity on revert).
    pub agreed_errors: usize,
}

impl ComparisonReport {
    pub fn diverged(&self) -> bool {
        !self.divergences.is_empty()
    }

    pub fn violated(&self) -> bool {
        !self.violations.is_empty()
    }

    pub fn is_clean(&self) -> bool {
        !self.diverged() && !self.violated()
    }

    /// The minimal repro: the scenario prefix up to and including the first
    /// divergence (or violation), so an engineer can reproduce with the least
    /// input.
    pub fn minimal_repro(&self, scenario: &Scenario) -> Scenario {
        let cut = self
            .first_divergence_op
            .or_else(|| self.violations.first().map(|v| v.op_index))
            .map(|i| i + 1)
            .unwrap_or(scenario.ops.len());
        let mut repro = scenario.clone();
        repro.ops = scenario.ops[..cut.min(scenario.ops.len())].to_vec();
        repro.name = format!("{}-minimal", scenario.name);
        repro
    }
}

/// Steps that both sides rejected identically (same `Err`) are legitimate
/// parity, not divergence.
fn same_error(e: &Result<(), String>, a: &Result<(), String>) -> bool {
    matches!((e, a), (Err(x), Err(y)) if x == y)
}

/// Run `scenario` against two models and diff after every operation.
pub fn compare(
    scenario: &Scenario,
    expected: &mut dyn ProgramModel,
    actual: &mut dyn ProgramModel,
) -> ComparisonReport {
    let invariants =
        if scenario.invariants.is_empty() { invariants::default_set() } else { scenario.invariants.clone() };

    let mut divergences = Vec::new();
    let mut violations = Vec::new();
    let mut agreed_errors = 0usize;
    let mut first_divergence_op = None;

    let mut prev_expected = expected.observe();
    let mut prev_actual = actual.observe();

    for (i, op) in scenario.ops.iter().enumerate() {
        let er = expected.apply(op);
        let ar = actual.apply(op);

        if same_error(&er, &ar) {
            agreed_errors += 1;
            continue;
        }

        let obs_e = expected.observe();
        let obs_a = actual.observe();

        // Invariant checks run on whichever side actually applied the op.
        if er.is_ok() {
            record_violations(&invariants, &obs_e, expected.name(), i, &mut violations);
        }
        if ar.is_ok() {
            record_violations(&invariants, &obs_a, actual.name(), i, &mut violations);
        }

        // Error-shape divergence (one rejects, the other accepts).
        if er.is_err() || ar.is_err() {
            divergences.push(Divergence {
                op_index: i,
                op: op.clone(),
                field: "result".to_string(),
                expected: format!("{er:?}"),
                actual: format!("{ar:?}"),
            });
            first_divergence_op.get_or_insert(i);
        }

        for (field, e, a) in obs_e.differences(&obs_a) {
            // Only report fields that actually changed on at least one side,
            // to avoid re-reporting a persistent difference every step.
            let changed = field_changed(field, &prev_expected, &obs_e) || field_changed(field, &prev_actual, &obs_a);
            if changed {
                divergences.push(Divergence {
                    op_index: i,
                    op: op.clone(),
                    field: field.to_string(),
                    expected: e,
                    actual: a,
                });
                first_divergence_op.get_or_insert(i);
            }
        }

        prev_expected = obs_e;
        prev_actual = obs_a;
    }

    ComparisonReport {
        scenario: scenario.name.clone(),
        expected_model: expected.name().to_string(),
        actual_model: actual.name().to_string(),
        first_divergence_op,
        divergences,
        violations,
        agreed_errors,
    }
}

fn record_violations(
    invariants: &[Invariant],
    obs: &Observables,
    model: &str,
    op_index: usize,
    out: &mut Vec<Violation>,
) {
    for inv in invariants {
        if let Err(detail) = invariants::check(inv, obs) {
            out.push(Violation { op_index, model: model.to_string(), invariant: inv.name().to_string(), detail });
        }
    }
}

fn field_changed(field: &str, before: &Observables, after: &Observables) -> bool {
    match field {
        "total_deposits" => before.total_deposits != after.total_deposits,
        "total_borrows" => before.total_borrows != after.total_borrows,
        "total_shares" => before.total_shares != after.total_shares,
        "vault_balance" => before.vault_balance != after.vault_balance,
        "user_shares" => before.user_shares != after.user_shares,
        "user_balance" => before.user_balance != after.user_balance,
        "price" => before.price != after.price,
        _ => true,
    }
}

/// Compare a scenario against a **recorded real-program trace**.
///
/// The expected side is the reference model; the actual side is the trace
/// emitted by a generated `solana-program-test` harness. This is how P2 turns
/// the engine from a model-vs-model check into a check against a live program.
pub fn compare_with_trace(scenario: &Scenario, expected: &mut dyn ProgramModel, trace: &Trace) -> ComparisonReport {
    let invariants =
        if scenario.invariants.is_empty() { invariants::default_set() } else { scenario.invariants.clone() };

    let mut divergences = Vec::new();
    let mut violations = Vec::new();
    let mut agreed_errors = 0usize;
    let mut first_divergence_op = None;

    let mut prev_expected = expected.observe();
    let mut prev_actual = trace.steps.first().map(|s| s.observables.clone()).unwrap_or_default();

    for (i, op) in scenario.ops.iter().enumerate() {
        let er = expected.apply(op);
        let obs_e = expected.observe();

        let Some(step) = trace.steps.iter().find(|s| s.op_index == i) else {
            divergences.push(Divergence {
                op_index: i,
                op: op.clone(),
                field: "trace".to_string(),
                expected: format!("{er:?}"),
                actual: "no step recorded".to_string(),
            });
            first_divergence_op.get_or_insert(i);
            break;
        };
        let ar: Result<(), String> = match &step.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        };
        let obs_a = step.observables.clone();

        if same_error(&er, &ar) {
            agreed_errors += 1;
            prev_expected = obs_e;
            prev_actual = obs_a;
            continue;
        }

        if er.is_ok() {
            record_violations(&invariants, &obs_e, expected.name(), i, &mut violations);
        }
        if ar.is_ok() {
            record_violations(&invariants, &obs_a, &trace.model, i, &mut violations);
        }
        if er.is_err() || ar.is_err() {
            divergences.push(Divergence {
                op_index: i,
                op: op.clone(),
                field: "result".to_string(),
                expected: format!("{er:?}"),
                actual: format!("{ar:?}"),
            });
            first_divergence_op.get_or_insert(i);
        }

        for (field, e, a) in obs_e.differences(&obs_a) {
            if field_changed(field, &prev_expected, &obs_e) || field_changed(field, &prev_actual, &obs_a) {
                divergences.push(Divergence {
                    op_index: i,
                    op: op.clone(),
                    field: field.to_string(),
                    expected: e,
                    actual: a,
                });
                first_divergence_op.get_or_insert(i);
            }
        }

        prev_expected = obs_e;
        prev_actual = obs_a;
    }

    ComparisonReport {
        scenario: scenario.name.clone(),
        expected_model: expected.name().to_string(),
        actual_model: trace.model.clone(),
        first_divergence_op,
        divergences,
        violations,
        agreed_errors,
    }
}
