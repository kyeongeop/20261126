//! 端到端测试：只读取仓库内 fixtures，验证面板 JSON 的风险语义与稳定错误码。

use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    let mut path = assert_cmd_cargo_target_dir().join("dlr");
    if !path.exists() {
        path.set_extension("exe");
    }
    path
}

/// 不引入额外测试依赖，通过环境变量推断 target 目录。
fn assert_cmd_cargo_target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir).join("debug");
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("target").join("debug")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_scan(artifact: &str, config: Option<&str>) -> serde_json::Value {
    let mut cmd = Command::new(bin_path());
    cmd.current_dir(repo_root())
        .arg("--repo-root")
        .arg(".")
        .arg("--artifact")
        .arg(artifact);
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    let output = cmd.output().expect("dlr 进程启动失败");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("stdout 必须是合法 JSON")
}

fn run_expect_error(args: &[&str]) -> String {
    let output = Command::new(bin_path())
        .current_dir(repo_root())
        .args(args)
        .output()
        .expect("dlr 进程启动失败");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let json_end = stderr
        .find("\n[")
        .unwrap_or(stderr.len());
    let body: serde_json::Value =
        serde_json::from_str(stderr[..json_end].trim()).expect("stderr 必须包含错误 JSON");
    body["error_code"].as_str().unwrap().to_string()
}

fn codes(report: &serde_json::Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn app_panel_covers_rpath_empty_escape_and_multilevel() {
    let report = run_scan("fixtures/bin/app", Some("fixtures/allowed_directories.json"));
    let all = codes(&report);

    assert!(all.contains(&"DLP2002".to_string()), "应识别旧 RPATH: {all:?}");
    assert!(all.contains(&"DLP2001".to_string()), "应识别空路径项: {all:?}");
    assert!(all.contains(&"DLP2004".to_string()), "应识别仓库逃逸: {all:?}");
    assert!(all.contains(&"DLP2003".to_string()), "应识别 CWD 回退: {all:?}");
    assert!(all.contains(&"DLP2006".to_string()), "应识别版本遮蔽: {all:?}");
    assert!(all.contains(&"DLP2010".to_string()), "应识别多级 RPATH 继承: {all:?}");

    let empty = report["artifacts"][0]["search_entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["empty"].as_bool().unwrap())
        .expect("必须保留空路径项");
    assert!(empty["expanded"].is_null());

    let escape = report["artifacts"][0]["search_entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["escapes_repo"].as_bool().unwrap())
        .expect("必须标记逃逸目录");
    assert_eq!(escape["origin"], "rpath");
}

#[test]
fn missing_dependency_is_reported_with_code() {
    let report = run_scan("fixtures/bin/app_missing", Some("fixtures/allowed_directories.json"));
    assert!(codes(&report).contains(&"DLP2007".to_string()));
    assert_eq!(report["summary"]["missing_dependencies"], 1);
    let edge = &report["edges"][0];
    assert!(edge["resolved"].is_null());
    assert!(edge["candidates"].as_array().unwrap().len() >= 1);
}

#[test]
fn runpath_keeps_unexpanded_variable() {
    let report = run_scan("fixtures/bin/app_runpath", Some("fixtures/allowed_directories.json"));
    assert!(codes(&report).contains(&"DLP2005".to_string()));
    let entry = &report["artifacts"][0]["search_entries"][0];
    assert_eq!(entry["origin"], "runpath");
    assert!(entry["unexpanded_variable"].as_bool().unwrap());
    assert!(
        entry["expanded"]
            .as_str()
            .unwrap()
            .contains("${PLATFORM}")
    );
}

#[test]
fn stripped_and_sectionless_elf_parse_dynamic_segment() {
    for artifact in [
        "fixtures/lib/libmiddle.stripped.so.1",
        "fixtures/lib/libmiddle.nosection.so.1",
    ] {
        let report = run_scan(artifact, Some("fixtures/allowed_directories.json"));
        let item = report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["path"] == artifact)
            .unwrap();
        assert_eq!(item["needed"][0], "libbase.so.1");
        assert_eq!(item["soname"], "libmiddle.so.1");
        assert_eq!(item["runpath_raw"], "$ORIGIN");
    }
}

#[test]
fn stable_error_codes_are_returned() {
    assert_eq!(
        run_expect_error(&["--repo-root", ".", "--artifact", "/etc/hostname"]),
        "DLP1002"
    );
    assert_eq!(
        run_expect_error(&["--repo-root", ".", "--artifact", "fixtures/bin/does-not-exist"]),
        "DLP1003"
    );
    assert_eq!(
        run_expect_error(&["--repo-root", ".", "--artifact", "README.md"]),
        "DLP1004"
    );
    assert_eq!(run_expect_error(&["--repo-root", "."]), "DLP1001");
}

#[test]
fn sha256_is_emitted_for_every_artifact() {
    let report = run_scan("fixtures/bin/app", Some("fixtures/allowed_directories.json"));
    for artifact in report["artifacts"].as_array().unwrap() {
        let hash = artifact["sha256"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn ld_library_path_layer_changes_search_order() {
    let report = run_scan("fixtures/bin/app_missing", Some("fixtures/config_with_ldpath.json"));
    let entries = &report["artifacts"][0]["search_entries"];
    let origins: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["origin"].as_str().unwrap())
        .collect();
    assert!(
        origins.contains(&"ld_library_path"),
        "配置的 LD_LIBRARY_PATH 层必须出现在搜索条目中: {origins:?}"
    );
    // app_missing 的 RUNPATH 指向 lib，而 LD_LIBRARY_PATH 指向 lib/sub：
    // 候选目录中必须能看到两个不同来源。
    let edge = &report["edges"][0];
    let candidate_origins: Vec<&str> = edge["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["origin"].as_str().unwrap())
        .collect();
    assert!(candidate_origins.contains(&"ld_library_path"));
    assert!(candidate_origins.contains(&"runpath"));
}

#[test]
fn default_config_flags_all_directories_as_disallowed() {
    // 不传 --config 时 allowed_directories 为空，所有实体目录都应触发 DLP2008。
    let report = run_scan("fixtures/bin/app_runpath", None);
    assert!(codes(&report).contains(&"DLP2008".to_string()));
}

#[test]
fn html_panel_is_self_contained() {
    let out_rel = format!("artifacts/dlr/test-panel-{}.html", std::process::id());
    std::fs::create_dir_all(repo_root().join("artifacts/dlr")).unwrap();
    let output = Command::new(bin_path())
        .current_dir(repo_root())
        .args([
            "--repo-root",
            ".",
            "--artifact",
            "fixtures/bin/app",
            "--config",
            "fixtures/allowed_directories.json",
            "--html-out",
        ])
        .arg(&out_rel)
        .output()
        .unwrap();
    assert!(output.status.success());
    let out = repo_root().join(&out_rel);
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(html.contains("动态库路径风险面板"));
    assert!(html.contains("DLP2004"));
    assert!(html.contains("优先搜索目录"));
    assert!(html.contains("依赖链解析"));
    assert!(html.contains("window.__PANEL_DATA__"));
    std::fs::remove_file(&out).ok();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert!(report["root_artifact"].is_string());
    assert!(report["summary"]["finding_count"].is_number());
}
