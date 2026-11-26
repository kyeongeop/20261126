//! Multi-target hardening release gate.
//!
//! Checks PIE, NX, RELRO, BIND_NOW and symbol evidence for executables,
//! shared libraries and static archives. Indeterminate results are reported
//! as `unknown`; a required target only passes when every applicable required
//! check is explicitly `pass`.

pub mod archive;
pub mod artifact;
pub mod checks;
pub mod classify;
pub mod cli;
pub mod codes;
pub mod elf;
pub mod gate;
pub mod html;
pub mod manifest;
pub mod model;
pub mod report;
pub mod scan;
pub mod symbols;

pub use artifact::{inspect_bytes, inspect_path, InspectedArtifact};
pub use checks::{build_checks, CHECK_ORDER};
pub use gate::{evaluate_target, TargetEvaluation};
pub use manifest::{load_manifest, parse_manifest, Manifest, ManifestTarget};
pub use model::{Check, Status, SymbolRef, TargetType};
pub use report::{ArtifactReport, GateReport, GateSummary};
pub use scan::{build_from_manifest, evaluate_path, inspect_single, scan_directory};

/// Library-facing prelude for tests and embedders.
pub mod prelude {
    pub use crate::checks;
    pub use crate::codes;
    pub use crate::gate::evaluate_target;
    pub use crate::html::render_html;
    pub use crate::model::{Check, Status, TargetType};
    pub use crate::report::GateReport;
    pub use crate::scan::{build_from_manifest, evaluate_path, inspect_single, scan_directory};
}

/// Inspect and evaluate a single file as a required target.
pub fn check_file(path: impl AsRef<std::path::Path>) -> ArtifactReport {
    scan::report_from_path(path.as_ref(), true, Vec::new())
}

/// Evaluate a file, directory or `.json` manifest and build the full report.
pub fn run_gate(path: impl AsRef<std::path::Path>) -> Result<GateReport, String> {
    evaluate_path(path.as_ref())
}
