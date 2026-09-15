//! End-to-end differential tests: the engine must catch an injected accounting
//! bug (the class that survives audits) and stay silent on true parity.

use parity::model::Rounding;
use parity::scenario::{AccountSpec, Config, Invariant, Op, Role, Scenario};
use parity::{LendingModel, ProgramModel, compare};

fn lending_scenario(ops: Vec<Op>) -> Scenario {
    Scenario {
        name: "test".to_string(),
        description: String::new(),
        config: Config { price: 1, rate_bps_per_second: 1 },
        accounts: vec![AccountSpec { role: Role::User, name: "user".to_string(), initial: 1_000_000 }],
        ops,
        invariants: vec![Invariant::Solvency, Invariant::ShareConservation, Invariant::VaultBacking],
    }
}

/// Interest accrual breaks 1:1 share parity, so a non-exact withdrawal exposes
/// the rounding direction. A candidate that rounds shares DOWN on withdraw
/// takes more value than it burns — the engine must flag it.
#[test]
fn rounding_down_on_withdraw_is_detected() {
    let scenario = lending_scenario(vec![
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Borrow { user: "user".to_string(), amount: 500 },
        Op::Accrue { seconds: 1_000 },
        Op::Withdraw { user: "user".to_string(), amount: 333 },
    ]);

    let mut expected = LendingModel::reference(&scenario).named("reference");
    let mut actual = LendingModel::with_rounding(&scenario, Rounding::Down, Rounding::Down).named("candidate");

    let report = compare(&scenario, &mut expected, &mut actual);

    assert!(report.diverged(), "rounding-down candidate must diverge");
    assert_eq!(report.first_divergence_op, Some(4), "divergence begins at the withdraw");
    assert!(
        report.divergences.iter().any(|d| d.field == "total_shares" || d.field == "user_shares"),
        "share accounting must be the divergent field: {:?}",
        report.divergences
    );
}

/// Two identical references are exact parity.
#[test]
fn reference_matches_itself_clean() {
    let scenario = lending_scenario(vec![
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Borrow { user: "user".to_string(), amount: 500 },
        Op::Accrue { seconds: 1_000 },
        Op::Withdraw { user: "user".to_string(), amount: 333 },
    ]);

    let mut a = LendingModel::reference(&scenario).named("a");
    let mut b = LendingModel::reference(&scenario).named("b");
    let report = compare(&scenario, &mut a, &mut b);

    assert!(report.is_clean(), "identical references must be clean: {:?}", report.divergences);
}

/// The minimal repro is the scenario prefix up to and including the first
/// divergence, so the engineer sees the least input that reproduces.
#[test]
fn minimal_repro_is_prefix() {
    let scenario = lending_scenario(vec![
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Borrow { user: "user".to_string(), amount: 500 },
        Op::Accrue { seconds: 1_000 },
        Op::Withdraw { user: "user".to_string(), amount: 333 },
        // Anything after the divergence must not be in the repro.
        Op::Deposit { user: "user".to_string(), amount: 1 },
    ]);

    let mut expected = LendingModel::reference(&scenario).named("reference");
    let mut actual = LendingModel::with_rounding(&scenario, Rounding::Down, Rounding::Down).named("candidate");
    let report = compare(&scenario, &mut expected, &mut actual);

    let repro = report.minimal_repro(&scenario);
    assert_eq!(repro.ops.len(), 5, "repro must stop at the diverging op (index 4)");
}

/// When both sides reject the same op identically, that is parity — not a
/// divergence.
#[test]
fn agreed_rejection_is_parity() {
    let scenario = lending_scenario(vec![
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        // Both models reject: withdrawing more than was deposited.
        Op::Withdraw { user: "user".to_string(), amount: 10_000_000 },
    ]);

    let mut expected = LendingModel::reference(&scenario).named("reference");
    let mut actual = LendingModel::with_rounding(&scenario, Rounding::Down, Rounding::Down).named("candidate");
    let report = compare(&scenario, &mut expected, &mut actual);

    assert!(report.is_clean(), "identical rejections are parity: {:?}", report.divergences);
    assert_eq!(report.agreed_errors, 1);
}

// ── P2: differential against a recorded real-program trace ───────────────────

use parity::scenario::{Trace, TraceStep};

fn scenario_ops() -> Vec<Op> {
    vec![
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Deposit { user: "user".to_string(), amount: 1_000 },
        Op::Borrow { user: "user".to_string(), amount: 500 },
        Op::Accrue { seconds: 1_000 },
        Op::Withdraw { user: "user".to_string(), amount: 333 },
    ]
}

/// Build a trace by executing the reference model (the "ideal" recorded run).
fn trace_from_reference(scenario: &Scenario, model: &str) -> Trace {
    let mut reference = LendingModel::reference(scenario);
    let mut steps = Vec::new();
    for (i, op) in scenario.ops.iter().enumerate() {
        let error = reference.apply(op).err();
        steps.push(TraceStep { op_index: i, observables: reference.observe(), error });
    }
    Trace { scenario: scenario.name.clone(), model: model.to_string(), steps }
}

/// A trace that matches the reference is parity (this is the correct program).
#[test]
fn trace_matching_reference_is_clean() {
    let scenario = lending_scenario(scenario_ops());
    let trace = trace_from_reference(&scenario, "lending-ok");
    let mut reference = LendingModel::reference(&scenario);
    let report = parity::compare_with_trace(&scenario, &mut reference, &trace);
    assert!(report.is_clean(), "correct program must be parity: {:?}", report.divergences);
}

/// A trace whose final withdraw burned fewer shares than the reference (the
/// real buggy program) must be flagged — this is the P2 end-to-end shape.
#[test]
fn trace_with_rounding_bug_is_detected() {
    let scenario = lending_scenario(scenario_ops());
    let mut trace = trace_from_reference(&scenario, "lending-bug");
    // Mutate the last step to the floor-rounded share count a buggy program
    // would record (fewer shares burned => more shares retained).
    let last = trace.steps.last_mut().unwrap();
    last.observables.total_shares += 1;
    last.observables.user_shares += 1;

    let mut reference = LendingModel::reference(&scenario);
    let report = parity::compare_with_trace(&scenario, &mut reference, &trace);

    assert!(report.diverged(), "a divergent real-program trace must be flagged");
    assert_eq!(report.first_divergence_op, Some(4));
    assert_eq!(report.actual_model, "lending-bug");
}
