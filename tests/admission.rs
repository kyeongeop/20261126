use release_signature_admission::{
    AdmissionEngine, AdmissionReport, AdmissionRequest, E_ALGORITHM_NOT_ALLOWED, E_DIGEST_MISMATCH,
    E_DUPLICATE_SIGNER, E_INVALID_ARTIFACT_DIGEST, E_INVALID_CONFIG, E_INVALID_REQUEST,
    E_INVALID_TIMESTAMP, E_NO_POLICY_MATCHED, E_POLICY_REVOKED, E_PUBLISHER_OUT_OF_SCOPE,
    E_SIGNATURE_OUTSIDE_VALIDITY, E_SIGNATURE_REVOKED,
};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn fixture(name: &str) -> String {
    fs::read_to_string(fixture_path(name)).expect("repository fixture must be readable")
}

fn engine() -> AdmissionEngine {
    AdmissionEngine::from_json_str(&fixture("policies.json")).expect("fixture policy is valid")
}

fn request_value() -> Value {
    serde_json::from_str(&fixture("request_allow.json")).expect("fixture request is valid JSON")
}

fn evaluate(engine: &AdmissionEngine, value: &Value) -> AdmissionReport {
    engine.evaluate(&AdmissionRequest::from_value(value).expect("request shape is valid"))
}

fn chain_ids(report: &AdmissionReport) -> Vec<&str> {
    report
        .policy_chain
        .iter()
        .map(|hit| hit.policy_id.as_str())
        .collect()
}

#[test]
fn preflight_returns_ordered_policy_chain_and_allows() {
    let request = AdmissionRequest::from_json_str(&fixture("request_allow.json")).unwrap();
    let report = engine().preflight(&request);

    assert!(report.is_allowed(), "{report:#?}");
    assert_eq!(chain_ids(&report), ["global-audit", "desktop-release"]);
    assert_eq!(report.policy_chain[0].priority, 5);
    assert_eq!(report.policy_chain[1].priority, 20);
    assert_eq!(
        report.policy_chain[1].accepted_publishers,
        ["acme.release", "acme.security"]
    );
    assert_eq!(report.to_json()["decision"], "allow");
}

#[test]
fn policy_conflict_uses_stricter_deny_result() {
    let mut request = request_value();
    request["signatures"].as_array_mut().unwrap().remove(0);
    let report = evaluate(&engine(), &request);

    assert!(!report.is_allowed());
    assert_eq!(chain_ids(&report), ["global-audit", "desktop-release"]);
    assert_eq!(report.policy_chain[0].decision.as_str(), "deny");
    assert_eq!(report.policy_chain[1].decision.as_str(), "allow");
    assert!(report
        .error_codes
        .contains(&release_signature_admission::E_INSUFFICIENT_SIGNATURES));
}

#[test]
fn revoked_signature_is_denied_even_when_other_policy_allows() {
    let mut request = request_value();
    request["signatures"][1]["status"] = json!("revoked");
    let report = evaluate(&engine(), &request);

    assert!(!report.is_allowed());
    assert_eq!(report.policy_chain[0].decision.as_str(), "allow");
    assert_eq!(report.policy_chain[1].decision.as_str(), "deny");
    assert!(report.error_codes.contains(&E_SIGNATURE_REVOKED));
}

#[test]
fn expired_signature_and_policy_window_are_enforced() {
    let mut request = request_value();
    request["signatures"][2]["valid_until"] = json!("2026-10-01T00:00:00Z");
    let report = evaluate(&engine(), &request);
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_SIGNATURE_OUTSIDE_VALIDITY));

    let mut config: Value = serde_json::from_str(&fixture("policies.json")).unwrap();
    config["policies"][1]["valid_until"] = json!("2026-06-01T00:00:00Z");
    let expired_engine = AdmissionEngine::from_value(&config).unwrap();
    let report = evaluate(&expired_engine, &request_value());
    assert!(!report.is_allowed());
    assert_eq!(
        report.error_codes,
        vec![release_signature_admission::E_POLICY_OUTSIDE_VALIDITY]
    );
}

#[test]
fn revoked_policy_and_publisher_scope_are_reported_in_chain() {
    let mut config: Value = serde_json::from_str(&fixture("policies.json")).unwrap();
    config["policies"][1]["status"] = json!("revoked");
    let revoked_engine = AdmissionEngine::from_value(&config).unwrap();
    let report = evaluate(&revoked_engine, &request_value());
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_POLICY_REVOKED));

    let mut request = request_value();
    request["signatures"][1]["publisher"] = json!("acme.legacy");
    let report = evaluate(&engine(), &request);
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_PUBLISHER_OUT_OF_SCOPE));
}

#[test]
fn artifact_digest_and_distinct_signer_are_enforced() {
    let mut request = request_value();
    request["signatures"][1]["artifact_sha256"] = json!("0".repeat(64));
    let report = evaluate(&engine(), &request);
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_DIGEST_MISMATCH));

    let mut request = request_value();
    request["signatures"][2]["key_id"] = json!("release-key-1");
    let report = evaluate(&engine(), &request);
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_DUPLICATE_SIGNER));
}

#[test]
fn algorithm_allowlist_is_enforced() {
    let mut request = request_value();
    request["signatures"][1]["algorithm"] = json!("ed25519");
    let report = evaluate(&engine(), &request);
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_ALGORITHM_NOT_ALLOWED));
}

#[test]
fn revocation_time_is_evaluated_against_publish_time() {
    let mut request = request_value();
    request["signatures"][1]["revoked_at"] = json!("2026-12-01T00:00:00Z");
    let report = evaluate(&engine(), &request);
    assert!(report.is_allowed(), "future revocation must not revoke yet");

    request["signatures"][1]["revoked_at"] = json!("2026-11-01T00:00:00Z");
    let report = evaluate(&engine(), &request);
    assert!(!report.is_allowed());
    assert!(report.error_codes.contains(&E_SIGNATURE_REVOKED));
}

#[test]
fn unmatched_product_line_is_denied_without_chain() {
    let mut request = request_value();
    request["product_line"] = json!("tablet-edge");
    let empty_engine = AdmissionEngine::from_value(&json!({ "policies": [] })).unwrap();
    let report = evaluate(&empty_engine, &request);

    assert!(!report.is_allowed());
    assert!(report.policy_chain.is_empty());
    assert_eq!(report.error_codes, vec![E_NO_POLICY_MATCHED]);
}

#[test]
fn parse_errors_keep_stable_codes() {
    assert_eq!(
        AdmissionEngine::from_json_str("{").unwrap_err().code(),
        E_INVALID_CONFIG
    );
    assert_eq!(
        AdmissionRequest::from_json_str("{").unwrap_err().code(),
        E_INVALID_REQUEST
    );

    let mut request = request_value();
    request["publish_at"] = json!("2026-02-30T00:00:00Z");
    let error = AdmissionRequest::from_value(&request).unwrap_err();
    assert_eq!(error.code(), E_INVALID_TIMESTAMP);

    let mut request = request_value();
    request["signatures"][0]["artifact_sha256"] = json!("not-a-digest");
    let error = AdmissionRequest::from_value(&request).unwrap_err();
    assert_eq!(error.code(), E_INVALID_ARTIFACT_DIGEST);
}

#[test]
fn top_level_preflight_entry_returns_the_same_chain() {
    let report = release_signature_admission::preflight(
        &fixture("policies.json"),
        &fixture("request_allow.json"),
    )
    .unwrap();
    assert!(report.is_allowed());
    assert_eq!(chain_ids(&report), ["global-audit", "desktop-release"]);
}
