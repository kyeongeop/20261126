use std::path::PathBuf;

use hardening_gate::checks::CHECK_ORDER;
use hardening_gate::codes;
use hardening_gate::html::render_html;
use hardening_gate::manifest::load_manifest;
use hardening_gate::model::Status;
use hardening_gate::scan::{build_from_manifest, inspect_single, report_from_path, scan_directory};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn fixture(relative: &str) -> PathBuf {
    fixtures().join(relative)
}

fn status_of(report: &hardening_gate::ArtifactReport, id: &str) -> Status {
    report
        .evaluation
        .checks
        .iter()
        .find(|check| check.id == id)
        .map(|check| check.status)
        .unwrap_or_else(|| panic!("missing check {id}"))
}

#[test]
fn check_order_is_the_stable_five() {
    assert_eq!(
        CHECK_ORDER,
        ["pie", "nx", "relro", "bind_now", "symbol_evidence"]
    );
}

#[test]
fn hardened_executable_passes_every_required_check() {
    let report = report_from_path(&fixture("bin/app_hardened"), true, vec![]);
    assert_eq!(report.inspected.target_type.as_str(), "executable");
    for id in CHECK_ORDER {
        assert_eq!(status_of(&report, id), Status::Pass, "{id} should pass");
    }
    assert_eq!(report.evaluation.status, codes::TARGET_PASS);
    assert!(!report.evaluation.release_blocks);
}

#[test]
fn weak_executable_fails_pie_nx_relro_bindnow() {
    let report = report_from_path(&fixture("bin/app_weak"), true, vec![]);
    assert_eq!(report.inspected.target_type.as_str(), "executable");
    assert_eq!(status_of(&report, "pie"), Status::Fail);
    assert_eq!(status_of(&report, "nx"), Status::Fail);
    assert_eq!(status_of(&report, "relro"), Status::Fail);
    assert_eq!(status_of(&report, "bind_now"), Status::Fail);
    assert_eq!(status_of(&report, "symbol_evidence"), Status::Pass);
    assert_eq!(report.evaluation.status, codes::TARGET_FAIL);
    assert!(report.evaluation.release_blocks);
    assert!(report
        .evaluation
        .blocking_check_ids
        .contains(&"pie".to_string()));
}

#[test]
fn shared_libraries_are_differentiated_from_executables() {
    let hard = report_from_path(&fixture("lib/libmgate_hard.so"), true, vec![]);
    assert_eq!(hard.inspected.target_type.as_str(), "shared_library");
    assert_eq!(status_of(&hard, "pie"), Status::Pass);
    assert_eq!(status_of(&hard, "bind_now"), Status::Pass);
    assert_eq!(hard.evaluation.status, codes::TARGET_PASS);

    let weak = report_from_path(&fixture("lib/libmgate_weak.so"), true, vec![]);
    assert_eq!(weak.inspected.target_type.as_str(), "shared_library");
    // A shared object is still ET_DYN/PIC, so the PIE/PIC check passes even
    // when RELRO/BIND_NOW/NX are weak.
    assert_eq!(status_of(&weak, "pie"), Status::Pass);
    assert_eq!(status_of(&weak, "nx"), Status::Fail);
    assert_eq!(status_of(&weak, "relro"), Status::Fail);
    assert_eq!(status_of(&weak, "bind_now"), Status::Fail);
    assert!(weak.evaluation.release_blocks);
}

#[test]
fn static_archive_uses_symbol_evidence_as_primary_gate() {
    let safe = report_from_path(&fixture("static/libmgate_safe.a"), true, vec![]);
    assert_eq!(safe.inspected.target_type.as_str(), "static_library");
    assert_eq!(status_of(&safe, "pie"), Status::NotApplicable);
    assert_eq!(status_of(&safe, "relro"), Status::NotApplicable);
    assert_eq!(status_of(&safe, "bind_now"), Status::NotApplicable);
    assert_eq!(status_of(&safe, "nx"), Status::Pass);
    assert_eq!(status_of(&safe, "symbol_evidence"), Status::Pass);
    assert_eq!(safe.evaluation.status, codes::TARGET_PASS);

    let symbol_check = safe
        .evaluation
        .checks
        .iter()
        .find(|c| c.id == "symbol_evidence")
        .unwrap();
    assert!(
        symbol_check
            .symbols
            .iter()
            .any(|s| s.name == "__stack_chk_fail"),
        "safe archive should cite __stack_chk_fail"
    );
}

#[test]
fn empty_archive_is_unknown_and_blocks_when_required() {
    let report = report_from_path(&fixture("static/libmgate_empty.a"), true, vec![]);
    assert_eq!(report.inspected.target_type.as_str(), "static_library");
    assert_eq!(status_of(&report, "symbol_evidence"), Status::Unknown);
    assert_eq!(report.evaluation.status, codes::TARGET_UNKNOWN);
    assert!(report.evaluation.release_blocks);
}

#[test]
fn truncated_elf_is_unknown_not_panic() {
    let report = inspect_single(&fixture("other/truncated.elf"), vec![]);
    assert_eq!(report.artifacts.len(), 1);
    let target = &report.artifacts[0];
    assert!(target.inspected.error_code.is_some());
    assert_eq!(target.evaluation.status, codes::TARGET_UNKNOWN);
    assert!(target.evaluation.release_blocks);
}

#[test]
fn missing_required_symbol_fails_symbol_check() {
    let report = report_from_path(
        &fixture("bin/app_hardened"),
        true,
        vec!["mgate_does_not_exist".to_string()],
    );
    assert_eq!(status_of(&report, "symbol_evidence"), Status::Fail);
    assert!(report.evaluation.release_blocks);
}

#[test]
fn good_manifest_passes_and_default_manifest_blocks() {
    let good = load_manifest(&fixtures().join("release-good.json")).unwrap();
    let good_report = build_from_manifest(&good, "release-good.json");
    assert!(good_report.summary.release_allowed);
    assert_eq!(good_report.summary.exit_code, codes::EXIT_PASS);
    assert_eq!(good_report.summary.passed, 3);

    let base = load_manifest(&fixtures().join("release.json")).unwrap();
    let blocked = build_from_manifest(&base, "release.json");
    assert!(!blocked.summary.release_allowed);
    assert_eq!(blocked.summary.exit_code, codes::EXIT_BLOCKED);
    assert_eq!(blocked.summary.failed, 2);
    assert!(blocked
        .summary
        .blocking_targets
        .iter()
        .any(|p| p == "bin/app_weak"));
    assert!(blocked
        .summary
        .blocking_targets
        .iter()
        .any(|p| p == "lib/libmgate_weak.so"));
}

#[test]
fn unknown_manifest_reports_three_unknowns_and_blocks() {
    let manifest = load_manifest(&fixtures().join("release-unknown.json")).unwrap();
    let report = build_from_manifest(&manifest, "release-unknown.json");
    assert_eq!(report.summary.unknown, 3);
    assert!(!report.summary.release_allowed);
    let json = report.to_json_string_pretty();
    assert!(json.contains("\"unknown\""));
    assert!(json.contains(codes::E_ARTIFACT_PARSE));
}

#[test]
fn directory_scan_finds_all_object_targets() {
    let report = scan_directory(&fixtures());
    let paths: Vec<&str> = report
        .artifacts
        .iter()
        .map(|a| a.inspected.display_path.as_str())
        .collect();
    assert_eq!(report.artifacts.len(), 8, "targets: {paths:?}");
    assert!(report
        .ignored_files
        .iter()
        .any(|p| p.ends_with("notes.txt")));
    assert!(paths.iter().any(|p| p.contains("app_hardened")));
    assert!(paths.iter().any(|p| p.contains("libmgate_safe.a")));
}

#[test]
fn html_page_lists_concrete_files_and_unknown_state() {
    let manifest = load_manifest(&fixtures().join("release.json")).unwrap();
    let report = build_from_manifest(&manifest, "release.json");
    let html = render_html(&report);
    for expected in [
        "bin/app_hardened",
        "bin/app_weak",
        "lib/libmgate_hard.so",
        "lib/libmgate_weak.so",
        "static/libmgate_safe.a",
        "多目标加固门禁",
        "BIND_NOW",
        "data-check=\"symbol_evidence\"",
    ] {
        assert!(html.contains(expected), "html missing {expected}");
    }

    let unknown_manifest = load_manifest(&fixtures().join("release-unknown.json")).unwrap();
    let unknown_html = render_html(&build_from_manifest(&unknown_manifest, "u"));
    assert!(unknown_html.contains("unknown"));
    assert!(unknown_html.contains("static/libmgate_empty.a"));
}

#[test]
fn json_schema_is_serializable_with_stable_statuses() {
    let report = report_from_path(&fixture("bin/app_hardened"), true, vec![]);
    let value = report.to_json();
    assert_eq!(value["target_type"], "executable");
    assert_eq!(value["status"], "pass");
    let ids: Vec<&str> = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, CHECK_ORDER);
    assert!(value["sha256"].as_str().unwrap().len() == 64);
}

#[test]
fn stable_error_code_values_are_pinned() {
    assert_eq!(codes::EXIT_PASS, 0);
    assert_eq!(codes::EXIT_RUNTIME_ERROR, 1);
    assert_eq!(codes::EXIT_BLOCKED, 2);
    assert_eq!(codes::EXIT_USAGE, 64);
    assert_eq!(codes::E_ARTIFACT_PARSE, "E_ARTIFACT_PARSE");
    assert_eq!(codes::E_MANIFEST_PARSE, "E_MANIFEST_PARSE");
    assert_eq!(codes::DECISION_BLOCKED, "blocked");
}

#[test]
fn extension_named_non_binary_degrades_to_unknown() {
    let artifact = hardening_gate::inspect_bytes(
        "libfake.so",
        b"/* GNU ld script, not an ELF object */",
        true,
        vec![],
    );
    assert_eq!(artifact.target_type.as_str(), "shared_library");
    assert_eq!(
        artifact.error_code.as_deref(),
        Some(codes::E_ARTIFACT_KIND_MISMATCH)
    );
    let evaluation = hardening_gate::evaluate_target(&artifact);
    assert_eq!(evaluation.status, codes::TARGET_UNKNOWN);
    assert!(evaluation.release_blocks);
}
