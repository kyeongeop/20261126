use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hardening_gate::cli::run_with_args;
use hardening_gate::codes;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("mgate-test-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_blocks_bad_release_and_writes_page() {
    let dir = unique_dir("blocked");
    let json = dir.join("report.json");
    let html = dir.join("report.html");
    let code = run_with_args(vec![
        "--manifest",
        fixtures().join("release.json").to_str().unwrap(),
        "--json",
        json.to_str().unwrap(),
        "--html",
        html.to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(code, codes::EXIT_BLOCKED);

    let json_text = std::fs::read_to_string(&json).unwrap();
    assert!(json_text.contains("\"decision\": \"blocked\""));
    assert!(json_text.contains("bin/app_weak"));

    let html_text = std::fs::read_to_string(&html).unwrap();
    assert!(html_text.contains("bin/app_weak"));
    assert!(html_text.contains("lib/libmgate_weak.so"));
}

#[test]
fn cli_passes_good_release() {
    let code = run_with_args(vec![
        "--manifest",
        fixtures().join("release-good.json").to_str().unwrap(),
        "--no-write",
        "--quiet",
    ]);
    assert_eq!(code, codes::EXIT_PASS);
}

#[test]
fn cli_reports_missing_path_as_runtime_error() {
    let code = run_with_args(vec!["/no/such/mgate-artifact-xyz", "--no-write", "--quiet"]);
    assert_eq!(code, codes::EXIT_RUNTIME_ERROR);
}

#[test]
fn cli_usage_error_and_help() {
    assert_eq!(
        run_with_args(vec!["--definitely-unknown-flag"]),
        codes::EXIT_USAGE
    );
    assert_eq!(run_with_args(vec!["--help"]), codes::EXIT_PASS);
    assert_eq!(run_with_args(vec!["--version"]), codes::EXIT_PASS);
}
