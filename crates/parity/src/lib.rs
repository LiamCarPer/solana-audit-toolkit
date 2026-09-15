//! `parity` — a differential/behavioral engine for Solana protocol hunts.
//!
//! Static pattern tools find textbook bugs; audited code has none left. What
//! survives audits is *behavior*: rounding asymmetries, fee/index accounting
//! drift, sequence-dependent state. `parity` finds those by running the *same*
//! normalized scenario against two implementations of a primitive (a
//! source-derived reference model, a sibling protocol, or a `program-test`
//! adapter) and reporting where their observable state diverges.
//!
//! Division of labour: the tool does the mechanical work (scenario execution,
//! normalization, diffing, minimal-repro minimisation, reporting); the AI does
//! the protocol-logic reasoning (authoring the reference model and adapters,
//! interpreting divergences, building the PoC).
//!
//! See `docs/PARITY.md` for the design and roadmap.

pub mod engine;
pub mod invariants;
pub mod model;
pub mod report;
pub mod scenario;

pub use engine::{ComparisonReport, Divergence, Violation, compare, compare_with_trace};
pub use model::{LendingModel, ProgramModel, Rounding};
pub use scenario::{Config, Invariant, Observables, Op, Role, Scenario, Trace, TraceStep};
