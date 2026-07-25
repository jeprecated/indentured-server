use std::fs;
use std::process::Command;

use tempfile::TempDir;

fn run_indentured(local_fallback: bool, connection_enabled: Option<bool>) -> std::process::Output {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path();
    let config_dir = repo_root.join(".indentured-server");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(repo_root.join("hello.txt"), "hello").expect("write source");

    let mut connection_lines = String::new();
    if let Some(enabled) = connection_enabled {
        connection_lines.push_str(&format!("enabled = {enabled}\n"));
    }
    connection_lines.push_str(&format!("local_fallback = {local_fallback}\n"));

    let config = format!(
        r#"[sources]
include = ["hello.txt"]

[connection]
{connection_lines}
"#
    );
    fs::write(config_dir.join("config.toml"), config).expect("write config");

    // TCP port zero is not a connectable server endpoint, so failure is deterministic
    // without releasing an ephemeral-port reservation before the client starts.
    let endpoint = "http://127.0.0.1:0";

    let state = TempDir::new().expect("state dir");
    Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo_root)
        .env_remove("INDENTURED_SERVER_ENABLED")
        .env("XDG_STATE_HOME", state.path())
        .arg("--endpoint")
        .arg(endpoint)
        .arg("run")
        .arg("make")
        .output()
        .expect("run indentured")
}

#[test]
fn indentured_returns_fallback_code_when_local_fallback_enabled() {
    let output = run_indentured(true, None);

    assert_eq!(output.status.code(), Some(222));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("build request failed"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn indentured_returns_error_code_when_local_fallback_disabled() {
    let output = run_indentured(false, None);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("build request failed"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn indentured_skips_indentured_server_when_disabled_in_config() {
    let output = run_indentured(false, Some(false));

    assert_eq!(output.status.code(), Some(222));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[indentured-server] disabled"),
        "unexpected stderr: {stderr}"
    );
}
