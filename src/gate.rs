//! Per-target rollup and release decision.

use crate::artifact::InspectedArtifact;
use crate::checks;
use crate::codes;
use crate::model::{Check, Status, TargetType};

#[derive(Debug, Clone)]
pub struct TargetEvaluation {
    pub checks: Vec<Check>,
    /// Compliance rollup: `pass`, `fail`, `unknown` or `not_gated`.
    pub status: String,
    /// True when this required target blocks the release.
    pub release_blocks: bool,
    pub blocking_check_ids: Vec<String>,
    pub reason_codes: Vec<String>,
}

pub fn evaluate_target(artifact: &InspectedArtifact) -> TargetEvaluation {
    let checks = checks::build_checks(artifact);

    // Unrecognized / unreadable target that the release considers required:
    // fail closed as `unknown` rather than silently passing.
    if artifact.target_type == TargetType::Other {
        if artifact.required {
            let code = artifact
                .error_code
                .clone()
                .unwrap_or_else(|| codes::E_ARTIFACT_KIND_MISMATCH.to_string());
            return TargetEvaluation {
                checks,
                status: codes::TARGET_UNKNOWN.to_string(),
                release_blocks: true,
                blocking_check_ids: vec!["identity".to_string()],
                reason_codes: vec![code],
            };
        }
        return TargetEvaluation {
            checks,
            status: codes::TARGET_NOT_GATED.to_string(),
            release_blocks: false,
            blocking_check_ids: Vec::new(),
            reason_codes: Vec::new(),
        };
    }

    let mut blocking_check_ids = Vec::new();
    let mut reason_codes = Vec::new();
    let mut saw_fail = false;
    let mut saw_unknown = false;

    for check in &checks {
        if check.is_blocking() {
            blocking_check_ids.push(check.id.clone());
            reason_codes.push(check.reason_code.clone());
            match check.status {
                Status::Fail => saw_fail = true,
                Status::Unknown => saw_unknown = true,
                _ => {}
            }
        }
    }

    // A fatal artifact parse error can also force unknown even if a specific
    // check happened to default to a non-blocking state.
    if let Some(code) = &artifact.error_code {
        if code == codes::E_ARTIFACT_PARSE || code == codes::E_ARTIFACT_EMPTY {
            saw_unknown = true;
            reason_codes.push(code.clone());
        }
    }

    let status = if saw_fail {
        codes::TARGET_FAIL
    } else if saw_unknown {
        codes::TARGET_UNKNOWN
    } else {
        codes::TARGET_PASS
    };

    let release_blocks = artifact.required && status != codes::TARGET_PASS;

    TargetEvaluation {
        checks,
        status: status.to_string(),
        release_blocks,
        blocking_check_ids,
        reason_codes,
    }
}
