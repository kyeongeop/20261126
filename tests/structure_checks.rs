use std::process::Command;

use archive_structure_check::archive::parse_archive;
use archive_structure_check::check::check_archive;
use archive_structure_check::codes::{issue_catalog, IssueCode, Severity};
use archive_structure_check::error::ErrorCode;
use archive_structure_check::fixtures::FixtureStore;
use archive_structure_check::manifest::UploadManifest;
use archive_structure_check::model::{StructureReport, Verdict};
use archive_structure_check::report::{build_report, report_json};
use archive_structure_check::CheckOptions;

fn store() -> FixtureStore {
    FixtureStore::new(env!("CARGO_MANIFEST_DIR"), "fixtures").expect("fixture store")
}

fn load_report(manifest_name: &str) -> StructureReport {
    let store = store();
    let manifest = store.read_manifest(manifest_name).expect("manifest");
    let archive = parse_archive(
        &manifest.archive_path,
        &store.read_bytes(&manifest.archive_path).expect("archive"),
    )
    .expect("parse archive");
    let previous = manifest.previous_archive_path.as_ref().map(|path| {
        (
            path.clone(),
            parse_archive(path, &store.read_bytes(path).expect("previous archive"))
                .expect("parse previous"),
        )
    });
    let (previous_path, previous_archive) = match previous {
        Some((path, archive)) => (Some(path), Some(archive)),
        None => (None, None),
    };
    build_report(
        manifest_name,
        &manifest,
        &manifest.archive_path,
        archive,
        previous_path,
        previous_archive,
        &CheckOptions::default(),
    )
}

fn codes(report: &StructureReport) -> Vec<&'static str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

#[test]
fn clean_zip_is_accepted_and_has_object_metadata() {
    let report = load_report("upload.json");
    assert_eq!(report.verdict, Verdict::Accepted);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.archive.format, "zip");
    assert_eq!(report.members.len(), 14);
    let binary = report
        .members
        .iter()
        .find(|member| member.path == "bin/agent")
        .expect("bin/agent");
    let object = binary.object.as_ref().expect("ELF metadata");
    assert_eq!(object.format, "elf");
    assert_eq!(binary.mode_octal().as_deref(), Some("0755"));
}

#[test]
fn clean_tar_gz_with_valid_hardlink_is_accepted() {
    let report = load_report("upload-tar.json");
    assert_eq!(report.verdict, Verdict::Accepted);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.archive.format, "tar.gz");
    assert!(report
        .members
        .iter()
        .any(|member| member.kind.as_str() == "hard_link"));
}

#[test]
fn bad_zip_marks_each_member_and_blocks_release() {
    let report = load_report("upload-bad.json");
    assert_eq!(report.verdict, Verdict::Blocked);
    let found = codes(&report);
    for code in [
        "ARC2001", "ARC2002", "ARC2004", "ARC2005", "ARC2006", "ARC2008", "ARC2009", "ARC2010",
        "ARC2014", "ARC2015", "ARC2016", "ARC2018", "ARC2022", "ARC2025",
    ] {
        assert!(found.contains(&code), "missing {code}: {found:?}");
    }
    let duplicate = report
        .members
        .iter()
        .filter(|member| member.path == "bin/agent")
        .filter(|member| {
            member
                .issues
                .iter()
                .any(|issue| issue.code == IssueCode::DuplicatePath)
        })
        .count();
    assert_eq!(duplicate, 2);
    let absolute = report
        .findings
        .iter()
        .find(|finding| finding.code == IssueCode::AbsolutePath)
        .expect("absolute path finding");
    assert_eq!(absolute.member_name.as_deref(), Some("/etc/shadow"));
    assert!(absolute.member_index.is_some());
    let special = report
        .findings
        .iter()
        .find(|finding| finding.code == IssueCode::SpecialFile)
        .expect("special file finding");
    assert_eq!(special.member_path.as_deref(), Some("dev/null"));
}

#[test]
fn bad_tar_reports_hardlinks_and_special_files() {
    let report = load_report("upload-bad-tar.json");
    assert_eq!(report.verdict, Verdict::Blocked);
    let found = codes(&report);
    assert!(found.contains(&"ARC2012"), "{found:?}");
    assert!(found.contains(&"ARC2013"), "{found:?}");
    assert!(found.contains(&"ARC2025"), "{found:?}");
}

#[test]
fn fix_upload_compares_content_but_keeps_structure() {
    let report = load_report("reupload.json");
    assert_eq!(report.verdict, Verdict::Accepted);
    let comparison = report.comparison.as_ref().expect("comparison");
    assert!(comparison.same_structure);
    assert_eq!(comparison.added.len(), 0);
    assert_eq!(comparison.removed.len(), 0);
    assert_eq!(comparison.changed.len(), 1);
    assert!(comparison
        .findings
        .iter()
        .any(|finding| finding.code == IssueCode::ReuploadContentChanged));
}

#[test]
fn fix_upload_regression_exposes_new_member_issues() {
    let report = load_report("reupload-regression.json");
    assert_eq!(report.verdict, Verdict::Blocked);
    let comparison = report.comparison.as_ref().expect("comparison");
    assert!(!comparison.same_structure);
    assert!(comparison.added.len() >= 9);
    assert!(comparison
        .findings
        .iter()
        .any(|finding| finding.code == IssueCode::ReuploadMemberAdded));
    assert!(comparison
        .findings
        .iter()
        .any(|finding| finding.code == IssueCode::ReuploadNewIssue));
}

#[test]
fn declared_outer_hash_mismatch_blocks() {
    let store = store();
    let mut manifest = store.read_manifest("upload.json").expect("manifest");
    manifest.archive_sha256 = Some("0".repeat(64));
    let archive = parse_archive(
        &manifest.archive_path,
        &store.read_bytes(&manifest.archive_path).expect("archive"),
    )
    .expect("parse");
    let report = build_report(
        "upload.json",
        &manifest,
        &manifest.archive_path,
        archive,
        None,
        None,
        &CheckOptions::default(),
    );
    assert_eq!(report.verdict, Verdict::Blocked);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == IssueCode::ArchiveHashMismatch));
}

#[test]
fn fixture_reads_are_confined() {
    let store = store();
    assert_eq!(
        store.read_bytes("../README.md").unwrap_err().code,
        ErrorCode::PathOutsideFixtureRoot
    );
    assert_eq!(
        store.read_bytes("/etc/passwd").unwrap_err().code,
        ErrorCode::PathOutsideFixtureRoot
    );
    assert_eq!(
        store.read_manifest("../upload.json").unwrap_err().code,
        ErrorCode::PathOutsideFixtureRoot
    );
}

#[test]
fn stable_runtime_and_issue_codes_are_locked() {
    let runtime = [
        ErrorCode::InvalidArgument,
        ErrorCode::FixtureRootNotFound,
        ErrorCode::ManifestNotFound,
        ErrorCode::ManifestReadFailed,
        ErrorCode::ManifestJsonInvalid,
        ErrorCode::ManifestSchemaInvalid,
        ErrorCode::PathOutsideFixtureRoot,
        ErrorCode::ArchiveNotFound,
        ErrorCode::ArchiveReadFailed,
        ErrorCode::UnsupportedArchiveFormat,
        ErrorCode::ArchiveParseFailed,
        ErrorCode::ArchiveHashMismatch,
        ErrorCode::PreviousArchiveRequired,
        ErrorCode::OutputWriteFailed,
        ErrorCode::Internal,
    ];
    let values: Vec<_> = runtime.iter().map(|code| code.as_str()).collect();
    assert_eq!(
        values,
        [
            "ARC1001", "ARC1002", "ARC1003", "ARC1004", "ARC1005", "ARC1006", "ARC1007", "ARC1008",
            "ARC1009", "ARC1010", "ARC1011", "ARC1012", "ARC1013", "ARC1014", "ARC1015"
        ]
    );
    let catalog = issue_catalog();
    let entries = catalog.as_array().expect("catalog");
    let issue_values: Vec<&str> = entries
        .iter()
        .map(|entry| entry["code"].as_str().expect("code"))
        .collect();
    assert_eq!(
        issue_values,
        [
            "ARC2001", "ARC2002", "ARC2003", "ARC2004", "ARC2005", "ARC2006", "ARC2007", "ARC2008",
            "ARC2009", "ARC2010", "ARC2011", "ARC2012", "ARC2013", "ARC2014", "ARC2015", "ARC2016",
            "ARC2017", "ARC2018", "ARC2019", "ARC2020", "ARC2021", "ARC2022", "ARC2023", "ARC2024",
            "ARC2025", "ARC2026", "ARC2027", "ARC2028", "ARC2029", "ARC2030", "ARC2031", "ARC2032",
            "ARC3001", "ARC3002", "ARC3003", "ARC3004", "ARC3005", "ARC3006", "ARC3007", "ARC3008",
            "ARC3009"
        ]
    );
    assert!(entries.iter().any(|entry| {
        entry["code"] == "ARC2001" && entry["severity"] == Severity::Blocking.as_str()
    }));
    assert!(entries.iter().any(|entry| entry["code"] == "ARC3009"));
}

#[test]
fn cli_exit_codes_and_stdout_are_stable() {
    let clean = Command::new(env!("CARGO_BIN_EXE_archive-check"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "check",
            "--fixtures",
            "fixtures",
            "--manifest",
            "upload.json",
        ])
        .output()
        .expect("run cli");
    assert!(clean.status.success());
    let json: serde_json::Value = serde_json::from_slice(&clean.stdout).expect("json");
    assert_eq!(json["verdict"], "accepted");

    let blocked = Command::new(env!("CARGO_BIN_EXE_archive-check"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "check",
            "--fixtures",
            "fixtures",
            "--manifest",
            "upload-bad.json",
        ])
        .output()
        .expect("run cli");
    assert_eq!(blocked.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&blocked.stdout).expect("json");
    assert_eq!(json["verdict"], "blocked");

    let missing = Command::new(env!("CARGO_BIN_EXE_archive-check"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "check",
            "--fixtures",
            "fixtures",
            "--manifest",
            "missing.json",
        ])
        .output()
        .expect("run cli");
    assert_eq!(missing.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&missing.stderr).expect("error json");
    assert_eq!(json["error"]["code"], "ARC1003");
}

#[test]
fn parsed_members_can_be_checked_without_a_manifest() {
    let store = store();
    let archive = parse_archive(
        "archives/agent-2.4.1-bad.zip",
        &store
            .read_bytes("archives/agent-2.4.1-bad.zip")
            .expect("archive"),
    )
    .expect("parse");
    let outcome = check_archive(&archive, &CheckOptions::default());
    assert!(outcome.findings.iter().any(|finding| finding.is_blocking()));
    let json = report_json(&build_report(
        "scan",
        &UploadManifest::from_json_str(
            r#"{"release":{"name":"agent","version":"2.4.1"},"archive":"archives/agent-2.4.1-bad.zip"}"#,
        )
        .expect("manifest"),
        "archives/agent-2.4.1-bad.zip",
        archive,
        None,
        None,
        &CheckOptions::default(),
    ));
    assert_eq!(json["feature"], "archive-structure-check");
    assert_eq!(json["feature_name_zh"], "压缩包结构检查");
}
