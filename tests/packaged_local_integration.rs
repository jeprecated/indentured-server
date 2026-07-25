#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const STDOUT_MARKER: &str = "packaged-local-stdout:uploaded-source";
const STDERR_MARKER: &str = "packaged-local-stderr:server-owned-task";

struct ChildGuard(Child);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn required_package_binary(variable: &str, name: &str, other: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(variable)
            .unwrap_or_else(|| panic!("{variable} must point to the Nix-packaged {name} binary")),
    );
    assert!(path.is_absolute(), "{variable} must be absolute");
    assert_eq!(
        path.file_name().and_then(|value| value.to_str()),
        Some(name)
    );
    let metadata = fs::metadata(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    assert!(metadata.is_file());
    assert_ne!(metadata.permissions().mode() & 0o111, 0);
    assert!(
        !path.with_file_name(other).exists(),
        "package output unexpectedly contains {other}"
    );
    path
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().unwrap().port()
}

fn render_server_config(root: &Path, port: u16) -> PathBuf {
    let config = root.join("server.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = "6"
[service]
max_concurrent_builds = 1
[service.socket]
enabled = false
path = "{root}/control/server.sock"
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
max_timeout_sec = 15
max_output_bytes = 1048576
[tasks.package_probe]
script = '''
IFS= read -r input < input.txt
printf '{stdout_marker}\n'
printf '{stderr_marker}\n' >&2
printf 'server-policy:%s\n' "$input" > out/result.txt
i=0
while [ "$i" -lt 1000000 ]; do i=$((i + 1)); done
exit 7
'''
cwd = "."
timeout_sec = 10
workspace = "fresh"
[tasks.package_probe.environment]
PATH = "/usr/bin:/bin"
LANG = "C"
[tasks.package_probe.artifacts]
include = ["out/**"]
exclude = ["out/.keep"]
[sources]
max_transfer_bytes = 1048576
max_uncompressed_bytes = 1048576
max_files = 100
max_depth = 16
[artifacts]
storage_root = "{root}/artifacts"
max_transfer_bytes = 1048576
max_uncompressed_bytes = 1048576
max_files = 100
max_depth = 16
restricted_patterns = []
[logging]
level = "info"
directory = "{root}/logs"
max_bytes = 1048576
max_files = 2
console = false
"#,
            root = toml_path(root),
            stdout_marker = STDOUT_MARKER,
            stderr_marker = STDERR_MARKER,
        ),
    )
    .unwrap();
    config
}

fn start_packaged_server(server_bin: &Path, root: &Path) -> (String, ChildGuard) {
    for _ in 0..5 {
        let port = reserve_port();
        let config = render_server_config(root, port);
        let child = Command::new(server_bin)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start packaged server");
        let mut guard = ChildGuard(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return (format!("http://127.0.0.1:{port}"), guard);
            }
            if guard.child_mut().try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "packaged server did not listen");
            thread::sleep(Duration::from_millis(20));
        }
    }
    panic!("packaged server did not bind after bounded retries");
}

fn write_client_config(source: &Path, endpoint: &str) {
    let directory = source.join(".indentured-server");
    fs::create_dir(&directory).unwrap();
    fs::write(
        directory.join("config.toml"),
        format!(
            r#"[sources]
include = ["input.txt", "out/.keep"]
exclude = []
[connection]
endpoint = "{endpoint}"
local_fallback = false
[output]
stdout_max_lines = 100
stderr_max_lines = 100
"#
        ),
    )
    .unwrap();
}

fn one_child(path: &Path) -> PathBuf {
    let entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected one child under {}",
        path.display()
    );
    entries[0].clone()
}

fn wait_bounded(child: &mut Child, deadline: Instant) -> std::process::ExitStatus {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("packaged client exceeded integration deadline");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "run through scripts/check-packaged-local-integration.sh with Nix package paths"]
fn packaged_local_flow() {
    let server_bin = required_package_binary(
        "INDENTURED_TEST_SERVER_BIN",
        "indentured-server",
        "indentured",
    );
    let client_bin = required_package_binary(
        "INDENTURED_TEST_CLIENT_BIN",
        "indentured",
        "indentured-server",
    );

    let root = TempDir::new().unwrap();
    let source = root.path().join("source");
    let server_root = root.path().join("server");
    let state = root.path().join("state");
    let result_base = root.path().join("results");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&server_root).unwrap();
    fs::create_dir(&state).unwrap();
    fs::write(source.join("input.txt"), "uploaded-source\n").unwrap();
    fs::create_dir(source.join("out")).unwrap();
    fs::write(source.join("out/.keep"), "").unwrap();
    let (endpoint, _server) = start_packaged_server(&server_bin, &server_root);
    write_client_config(&source, &endpoint);

    let mut client = Command::new(&client_bin)
        .current_dir(&source)
        .env("XDG_STATE_HOME", &state)
        .env_remove("INDENTURED_SERVER_ENDPOINT")
        .env_remove("INDENTURED_SERVER_TOKEN_FILE")
        .env_remove("INDENTURED_SERVER_CONFIG")
        .arg("run")
        .arg("--result-root")
        .arg(&result_base)
        .arg("package_probe")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start packaged client");

    let (line_tx, line_rx) = mpsc::channel();
    let stdout = client.stdout.take().unwrap();
    let stdout_tx = line_tx.clone();
    let stdout_reader = thread::spawn(move || {
        let mut captured = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            captured.push_str(&line);
            captured.push('\n');
            let _ = stdout_tx.send((false, line));
        }
        captured
    });
    let stderr = client.stderr.take().unwrap();
    let stderr_reader = thread::spawn(move || {
        let mut captured = String::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            captured.push_str(&line);
            captured.push('\n');
            let _ = line_tx.send((true, line));
        }
        captured
    });

    let stream_deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_stdout = false;
    let mut saw_stderr = false;
    let mut early_status = None;
    while !(saw_stdout && saw_stderr) {
        if let Some(status) = client.try_wait().unwrap() {
            early_status = Some(status);
            break;
        }
        assert!(
            Instant::now() < stream_deadline,
            "stream markers not observed"
        );
        if let Ok((is_stderr, line)) = line_rx.recv_timeout(Duration::from_millis(100)) {
            saw_stdout |= !is_stderr && line == STDOUT_MARKER;
            saw_stderr |= is_stderr && line == STDERR_MARKER;
        }
    }
    if early_status.is_none() {
        assert!(
            client.try_wait().unwrap().is_none(),
            "markers must stream before task exit"
        );
    }

    let status = early_status
        .unwrap_or_else(|| wait_bounded(&mut client, Instant::now() + Duration::from_secs(15)));
    let stdout = stdout_reader.join().unwrap();
    let stderr = stderr_reader.join().unwrap();
    assert!(
        saw_stdout && saw_stderr,
        "markers did not stream; status={status}; stdout={stdout}; stderr={stderr}"
    );
    assert_eq!(status.code(), Some(7), "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains(STDOUT_MARKER));
    assert!(stderr.contains(STDERR_MARKER));
    assert!(stderr.contains("results:"));

    let run = one_child(&result_base);
    assert_eq!(
        fs::metadata(&run).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for log in [
        "stdout.log",
        "stderr.log",
        "source-manifest.json",
        "provenance.json",
    ] {
        assert_eq!(
            fs::metadata(run.join(log)).unwrap().permissions().mode() & 0o777,
            0o600,
            "unexpected mode for {log}"
        );
    }
    assert_eq!(
        fs::read_to_string(run.join("stdout.log")).unwrap(),
        format!("{STDOUT_MARKER}\n")
    );
    assert_eq!(
        fs::read_to_string(run.join("stderr.log")).unwrap(),
        format!("{STDERR_MARKER}\n")
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("source-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["entry_count"], 2);
    assert!(manifest["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["path"] == "input.txt"));
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["remote_exit_code"], 7);
    assert_eq!(provenance["timed_out"], false);
    assert_eq!(provenance["status"], "failed");
    assert_eq!(
        fs::read_to_string(run.join("artifacts/out/result.txt")).unwrap(),
        "server-policy:uploaded-source\n"
    );

    let workspace_entries: Vec<_> = fs::read_dir(server_root.join("workspaces"))
        .unwrap()
        .collect();
    assert!(
        workspace_entries.is_empty(),
        "fresh workspace was not cleaned"
    );
}
