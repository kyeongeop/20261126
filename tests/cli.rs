use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn run(request: &str) -> std::process::Output {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    Command::new(env!("CARGO_BIN_EXE_signature-admission"))
        .current_dir(root)
        .arg("--config")
        .arg(root.join("tests/fixtures/policies.json"))
        .arg("--request")
        .arg(root.join("tests/fixtures").join(request))
        .output()
        .expect("CLI process starts")
}

#[test]
fn cli_prints_policy_chain_and_uses_admission_exit_codes() {
    let allowed = run("request_allow.json");
    assert_eq!(allowed.status.code(), Some(0));
    let output: Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(output["decision"], "allow");
    assert_eq!(output["policy_chain"][0]["policy_id"], "global-audit");
    assert_eq!(output["policy_chain"][1]["policy_id"], "desktop-release");

    let denied = run("request_deny.json");
    assert_eq!(denied.status.code(), Some(1));
    let output: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(output["decision"], "deny");
    assert!(output["error_codes"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(
            release_signature_admission::E_INSUFFICIENT_SIGNATURES
        )));
}
