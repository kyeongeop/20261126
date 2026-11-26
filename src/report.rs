//! Gate report model and stable JSON rendering.

use serde_json::{json, Value};

use crate::artifact::InspectedArtifact;
use crate::codes;
use crate::gate::TargetEvaluation;

pub const SCHEMA_VERSION: &str = "1.0";
pub const FEATURE_ID: &str = "multi-target-hardening-gate";
pub const FEATURE_NAME_ZH: &str = "多目标加固门禁";
pub const PLATFORM: &str = "release-artifact-management-platform";

#[derive(Debug, Clone)]
pub struct ArtifactReport {
    pub inspected: InspectedArtifact,
    pub evaluation: TargetEvaluation,
}

impl ArtifactReport {
    pub fn to_json(&self) -> Value {
        let artifact = &self.inspected;
        let evaluation = &self.evaluation;
        let check_json: Vec<Value> = evaluation
            .checks
            .iter()
            .map(|check| check.to_json())
            .collect();

        json!({
            "path": artifact.display_path,
            "file": artifact.display_path,
            "file_name": artifact.file_name,
            "absolute_path": artifact.path,
            "sha256": artifact.sha256,
            "sha256_hex": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "target_type": artifact.target_type.as_str(),
            "type": artifact.target_type.as_str(),
            "required": artifact.required,
            "gated": artifact.required,
            "status": evaluation.status,
            "verdict": evaluation.status,
            "release_blocks": evaluation.release_blocks,
            "blocks_release": evaluation.release_blocks,
            "gate": if evaluation.release_blocks { "blocked" } else { "clear" },
            "blocking_checks": evaluation.blocking_check_ids,
            "reason_codes": evaluation.reason_codes,
            "error_code": artifact.error_code,
            "error": artifact.error_message.as_ref().map(|message| json!({
                "code": artifact.error_code,
                "message": message,
            })),
            "classification_basis": artifact.basis,
            "required_symbols": artifact.required_symbols,
            "checks": check_json,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct GateSummary {
    pub decision: String,
    pub release_allowed: bool,
    pub exit_code: i32,
    pub total_targets: usize,
    pub required_targets: usize,
    pub passed: usize,
    pub failed: usize,
    pub unknown: usize,
    pub not_gated: usize,
    pub blocking_targets: Vec<String>,
}

impl GateSummary {
    pub fn to_json(&self) -> Value {
        json!({
            "decision": self.decision,
            "result": self.decision,
            "release_allowed": self.release_allowed,
            "allowed": self.release_allowed,
            "passed_gate": self.release_allowed,
            "exit_code": self.exit_code,
            "total_targets": self.total_targets,
            "required_targets": self.required_targets,
            "passed": self.passed,
            "failed": self.failed,
            "unknown": self.unknown,
            "not_gated": self.not_gated,
            "blocking_targets": self.blocking_targets,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GateReport {
    pub source_kind: String,
    pub source: String,
    pub release_name: Option<String>,
    pub release_version: Option<String>,
    pub generated_unix_secs: u64,
    pub artifacts: Vec<ArtifactReport>,
    pub ignored_files: Vec<String>,
    pub summary: GateSummary,
}

pub fn current_unix_secs() -> u64 {
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(seconds) = epoch.trim().parse::<u64>() {
            return seconds;
        }
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

impl GateReport {
    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "feature": FEATURE_ID,
            "feature_id": FEATURE_ID,
            "feature_name_zh": FEATURE_NAME_ZH,
            "title": FEATURE_NAME_ZH,
            "platform": PLATFORM,
            "generated_unix_secs": self.generated_unix_secs,
            "source": { "kind": self.source_kind, "location": self.source },
            "release": {
                "name": self.release_name,
                "version": self.release_version,
            },
            "gate": self.summary.to_json(),
            "summary": self.summary.to_json(),
            "targets": self.artifacts.iter().map(ArtifactReport::to_json).collect::<Vec<_>>(),
            "artifacts": self.artifacts.iter().map(ArtifactReport::to_json).collect::<Vec<_>>(),
            "files": self.artifacts.iter().map(ArtifactReport::to_json).collect::<Vec<_>>(),
            "ignored_files": self.ignored_files,
            "error_code_catalog": crate::codes::ALL_CODES,
        })
    }

    pub fn to_json_string_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.to_json()).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Compute the summary/decision for an ordered set of artifact reports.
pub fn summarize(artifacts: &[ArtifactReport]) -> GateSummary {
    let mut summary = GateSummary {
        total_targets: artifacts.len(),
        ..GateSummary::default()
    };

    for report in artifacts {
        let status = report.evaluation.status.as_str();
        match status {
            codes::TARGET_PASS => summary.passed += 1,
            codes::TARGET_FAIL => summary.failed += 1,
            codes::TARGET_UNKNOWN => summary.unknown += 1,
            _ => summary.not_gated += 1,
        }
        if report.inspected.required {
            summary.required_targets += 1;
        }
        if report.evaluation.release_blocks {
            summary
                .blocking_targets
                .push(report.inspected.display_path.clone());
        }
    }

    let blocked = !summary.blocking_targets.is_empty();
    if blocked {
        summary.decision = codes::DECISION_BLOCKED.to_string();
        summary.release_allowed = false;
        summary.exit_code = codes::EXIT_BLOCKED;
    } else {
        summary.decision = codes::DECISION_PASSED.to_string();
        summary.release_allowed = true;
        summary.exit_code = codes::EXIT_PASS;
    }
    summary
}
