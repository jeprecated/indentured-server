use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn start_stream_server(body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = None;
        let mut chunked = false;
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        assert!(request_line.starts_with("POST /v1/builds HTTP/1.1"));
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
                if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
        }
        if let Some(length) = content_length {
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
        } else if chunked {
            read_chunked(&mut reader);
        }
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        stream.write_all(response.as_bytes()).unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn read_chunked(reader: &mut BufReader<std::net::TcpStream>) {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let size = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
        if size == 0 {
            let mut trailer = String::new();
            reader.read_line(&mut trailer).unwrap();
            break;
        }
        let mut chunk = vec![0; size + 2];
        reader.read_exact(&mut chunk).unwrap();
    }
}

fn write_config(repo: &Path, endpoint: &str) {
    let dir = repo.join(".indentured-server");
    fs::create_dir(&dir).unwrap();
    fs::write(
        dir.join("config.toml"),
        format!(
            r#"[sources]
include = ["hello.txt"]
[connection]
endpoint = "{endpoint}"
[output]
stdout_max_lines = 1
stderr_max_lines = 1
"#
        ),
    )
    .unwrap();
    fs::write(repo.join("hello.txt"), "hello\n").unwrap();
}

fn run_dir(state: &Path) -> PathBuf {
    let root = state.join("indentured/runs");
    let entries: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    entries[0].clone()
}

#[test]
fn streamed_output_is_always_captured_in_xdg_run_directory() {
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let body = concat!(
        "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"started\"}\n",
        "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"phase_started\",\"phase\":\"run\"}\n",
        "{\"type\":\"stdout\",\"data\":\"one\\ntwo\\n\"}\n",
        "{\"type\":\"stderr\",\"data\":\"err-one\\nerr-two\\n\"}\n",
        "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"phase_finished\",\"phase\":\"run\",\"duration_ms\":42,\"exit_code\":0,\"timed_out\":false}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false,\"phases\":[{\"phase\":\"run\",\"duration_ms\":42,\"exit_code\":0,\"timed_out\":false}]}\n"
    )
    .to_string();
    let (endpoint, handle) = start_stream_server(body);
    write_config(repo.path(), &endpoint);
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("run")
        .arg("build")
        .output()
        .unwrap();
    handle.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run = run_dir(state.path());
    assert_eq!(
        fs::read_to_string(run.join("stdout.log")).unwrap(),
        "one\ntwo\n"
    );
    assert_eq!(
        fs::read_to_string(run.join("stderr.log")).unwrap(),
        "err-one\nerr-two\n"
    );
    assert_eq!(
        fs::metadata(&run).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(run.join("stdout.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["schema_version"], 2);
    assert_eq!(provenance["phases"][0]["phase"], "run");
    assert_eq!(provenance["phases"][0]["duration_ms"], 42);
    assert!(run.join("source-manifest.json").exists());
    assert!(
        fs::read_dir(&run).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".source-")),
        "temporary source archives must be removed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(run.to_str().unwrap()));
    assert!(stderr.contains("run phase started"));
    assert!(stderr.contains("run phase finished in 0.042s"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("one\n"));
}

#[test]
fn nonzero_remote_status_is_returned_with_evidence_preserved() {
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let body = concat!(
        "{\"type\":\"build\",\"id\":\"bld_fail\",\"status\":\"started\"}\n",
        "{\"type\":\"stderr\",\"data\":\"failed\\n\"}\n",
        "{\"type\":\"exit\",\"code\":7,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, handle) = start_stream_server(body);
    write_config(repo.path(), &endpoint);
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("run")
        .arg("build")
        .output()
        .unwrap();
    handle.join().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let run = run_dir(state.path());
    assert_eq!(
        fs::read_to_string(run.join("stderr.log")).unwrap(),
        "failed\n"
    );
    let provenance = fs::read_to_string(run.join("provenance.json")).unwrap();
    assert!(provenance.contains("\"remote_exit_code\": 7"));
    assert!(provenance.contains("\"status\": \"failed\""));
}

fn start_real_server(root: &Path) -> (String, Child) {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let endpoint = format!("http://127.0.0.1:{port}");
    let config = root.join("server.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = "12"
[service]
max_concurrent_builds = 1
[service.socket]
enabled = false
path = "{root}/control.sock"
mode = "0600"
[service.http]
enabled = true
listen_addr = "127.0.0.1:{port}"
[service.http.auth]
type = "bearer"
required = false
token_files = []
[service.http.tls]
enabled = false
[build]
workspace_root = "{root}/workspaces"
max_timeout_sec = 10
max_output_bytes = 1048576
[tasks.fail]
script = '''
# configured-script-secret-marker
printf failed > failure.txt
exit 7
'''
cwd = "."
timeout_sec = 5
workspace = "fresh"
[tasks.fail.environment]
PATH = "/usr/bin:/bin"
[tasks.fail.artifacts]
include = ["failure.txt"]
exclude = []
[tasks.timeout]
script = '''
printf timed-out > timeout.txt
while :; do :; done
'''
cwd = "."
timeout_sec = 1
workspace = "fresh"
[tasks.timeout.environment]
PATH = "/usr/bin:/bin"
[tasks.timeout.artifacts]
include = ["timeout.txt"]
exclude = []
[sources]
max_transfer_bytes = 134217728
max_uncompressed_bytes = 1342177280
max_files = 50000
max_depth = 64
[artifacts]
storage_root = "{root}/artifacts"
max_transfer_bytes = 536870912
max_uncompressed_bytes = 2147483648
max_files = 10000
max_depth = 64
restricted_patterns = []
[logging]
level = "info"
directory = "{root}/logs"
max_bytes = 1048576
max_files = 2
console = false
"#,
            root = root.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_indentured-server"))
        .arg("--config")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "real server did not listen");
        thread::sleep(Duration::from_millis(20));
    }
    (endpoint, child)
}

#[test]
fn configured_token_is_rejected_inside_source_result_base_and_result_alias() {
    let runtime_root = PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));

    let source_repo = tempfile::tempdir_in(&runtime_root).unwrap();
    let source_results = tempfile::tempdir_in(&runtime_root).unwrap();
    write_config(source_repo.path(), "http://127.0.0.1:9");
    let source_token = source_repo.path().join("token");
    fs::write(&source_token, "secret\n").unwrap();
    fs::set_permissions(&source_token, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(source_repo.path())
        .arg("--token-file")
        .arg(&source_token)
        .arg("run")
        .arg("--result-root")
        .arg(source_results.path())
        .arg("build")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("credential file must be outside"));

    let repo = TempDir::new().unwrap();
    write_config(repo.path(), "http://127.0.0.1:9");
    let result_base = tempfile::tempdir_in(&runtime_root).unwrap();
    let result_token = result_base.path().join("token");
    fs::write(&result_token, "secret\n").unwrap();
    fs::set_permissions(&result_token, fs::Permissions::from_mode(0o600)).unwrap();
    let aliases = tempfile::tempdir_in(&runtime_root).unwrap();
    let alias = aliases.path().join("result-alias");
    std::os::unix::fs::symlink(result_base.path(), &alias).unwrap();
    for explicit_base in [result_base.path(), alias.as_path()] {
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .arg("--token-file")
            .arg(&result_token)
            .arg("run")
            .arg("--result-root")
            .arg(explicit_base)
            .arg("build")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("credential file must be outside"));
    }
}

#[test]
fn real_server_returns_failure_and_timeout_artifacts_without_masking_status() {
    let server_root = TempDir::new().unwrap();
    let (endpoint, mut server) = start_real_server(server_root.path());
    for (task, expected_status, artifact, contents, timed_out) in [
        ("fail", 7, "failure.txt", "failed", false),
        ("timeout", 124, "timeout.txt", "timed-out", true),
    ] {
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        write_config(repo.path(), &endpoint);
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .arg("run")
            .arg(task)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let run = run_dir(state.path());
        let artifact_path = run.join("artifacts").join(artifact);
        assert!(
            artifact_path.exists(),
            "missing {} for {task}; stderr={}; run entries={:?}; provenance={}",
            artifact_path.display(),
            String::from_utf8_lossy(&output.stderr),
            fs::read_dir(&run)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            fs::read_to_string(run.join("provenance.json")).unwrap()
        );
        assert_eq!(fs::read_to_string(artifact_path).unwrap(), contents);
        let provenance = fs::read_to_string(run.join("provenance.json")).unwrap();
        assert!(provenance.contains(&format!("\"timed_out\": {timed_out}")));
        assert!(provenance.contains("\"status\": \"failed\""));
    }
    server.kill().unwrap();
    server.wait().unwrap();
    let diagnostics = fs::read_dir(server_root.path().join("logs"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap_or_default())
        .collect::<String>();
    assert!(!diagnostics.contains("configured-script-secret-marker"));
}

#[test]
fn malformed_daemon_config_does_not_echo_script_source() {
    let root = TempDir::new().unwrap();
    let marker = "malformed-daemon-script-secret";
    let config = root.path().join("malformed.toml");
    fs::write(
        &config,
        format!("schema_version = \"6\"\nscript = \"{marker}\" unexpected\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured-server"))
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(marker), "{stderr}");
    assert!(stderr.contains("failed to parse config"), "{stderr}");
}
