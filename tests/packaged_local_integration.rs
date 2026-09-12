#![cfg(unix)]

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const STDOUT_MARKER: &str = "packaged-local-stdout:uploaded-source";
const STDERR_MARKER: &str = "packaged-local-stderr:server-owned-task";
const CANCEL_MARKER: &str = "packaged-local-cancel:running";

struct ChildGuard(Child);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }

    fn terminate(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn child_guard_kills_and_reaps_during_unwind() {
    let child = Command::new("/bin/sh")
        .args(["-c", "while :; do :; done"])
        .spawn()
        .expect("spawn guarded child");
    let pid = child.id() as libc::pid_t;
    let unwind = std::panic::catch_unwind(move || {
        let _guard = ChildGuard(child);
        panic!("deliberate guard cleanup probe");
    });
    assert!(unwind.is_err());
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "guarded child remained alive or unreaped after panic"
    );
}

fn assert_no_packaged_binary_descendants(server: &Path, client: &Path) {
    thread::sleep(Duration::from_millis(100));
    for entry in fs::read_dir("/proc").expect("private procfs must be mounted") {
        let entry = entry.unwrap();
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let Ok(command) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let executable = command.split(|byte| *byte == 0).next().unwrap_or_default();
        assert_ne!(executable, server.as_os_str().as_encoded_bytes());
        assert_ne!(executable, client.as_os_str().as_encoded_bytes());
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

#[derive(Clone, Copy)]
enum ServerConfigMode {
    Full,
    ChangedSessionPolicy,
    WithoutSessionTask,
}

fn task_identity() -> (String, String) {
    (
        std::env::var("INDENTURED_TEST_TASK_USER")
            .expect("INDENTURED_TEST_TASK_USER must name the isolated task user"),
        std::env::var("INDENTURED_TEST_TASK_GROUP")
            .expect("INDENTURED_TEST_TASK_GROUP must name the isolated task group"),
    )
}

fn render_server_config(root: &Path, port: u16, mode: ServerConfigMode) -> PathBuf {
    let config = root.join("server.toml");
    let (task_user, task_group) = task_identity();
    let task_state = toml_path(&root.join("task-state"));
    let id_command = std::env::var("INDENTURED_TEST_ID_COMMAND")
        .expect("INDENTURED_TEST_ID_COMMAND must be an absolute id executable");
    assert!(Path::new(&id_command).is_absolute());
    let teardown_state = match mode {
        ServerConfigMode::Full => Some("torn-down"),
        ServerConfigMode::ChangedSessionPolicy => Some("torn-down-drift"),
        ServerConfigMode::WithoutSessionTask => None,
    };
    let session_task = teardown_state.map_or_else(String::new, |teardown_state| {
        format!(
            r#"
[tasks.session_probe]
script = '''
IFS= read -r prepared < .setup-complete
test "$prepared" = prepared
name=${{PWD##*/}}
uid=$("{id_command}" -u)
gid=$("{id_command}" -g)
groups=
for group in $("{id_command}" -G); do groups=${{groups:+$groups,}}$group; done
printf 'uid=%s gid=%s groups=%s\n' "$uid" "$gid" "$groups" > "{task_state}/$name.identity"
printf 'ready\n' > "{task_state}/$name.status"
printf 'initialized\n'
'''
cwd = "."
timeout_sec = 2
workspace = "fresh"
[tasks.session_probe.setup]
script = "printf 'prepared\\n' > .setup-complete"
timeout_sec = 2
[tasks.session_probe.environment]
PATH = "/usr/bin:/bin"
LANG = "C"
[tasks.session_probe.artifacts]
include = ["final/**"]
exclude = ["final/.keep"]
[tasks.session_probe.session]
idle_timeout_sec = 4
max_lifetime_sec = 15
[tasks.session_probe.session.services.fake]
script = '''
ready_fd=${{INDENTURED_SERVICE_READY_FD:?}}
unset INDENTURED_SERVICE_READY_FD
eval "printf 'service-starting\\n'"
eval "printf 'ready\\n' >&$ready_fd"
eval "exec $ready_fd>&-"
# Block without consuming a CPU. SIGSTOP deliberately exercises KILL escalation.
kill -STOP $$
'''
startup_timeout_sec = 2
shutdown_timeout_sec = 1
diagnostic_tail_bytes = 128
[tasks.session_probe.session.teardown]
script = '''
name=${{PWD##*/}}
printf '{teardown_state}\n' > "{task_state}/$name.status"
printf 'teardown\n' > final/teardown.txt
'''
timeout_sec = 2
[tasks.session_probe.session.actions.observe]
script = '''
IFS= read -r payload || test -n "$payload"
IFS= read -r count < counter
count=$((count + 1))
printf '%s\n' "$count" > counter
printf 'observed:%s:%s\n' "$count" "$payload" > evidence/observe.txt
printf 'observed:%s\n' "$count"
'''
timeout_sec = 2
[tasks.session_probe.session.actions.observe.artifacts]
include = ["evidence/**"]
exclude = ["evidence/.keep"]
[tasks.session_probe.session.actions.fail]
script = '''
IFS= read -r payload || test -n "$payload"
printf 'ordinary-failure:%s\n' "$payload" >&2
exit 9
'''
timeout_sec = 2
[tasks.session_probe.session.actions.hold]
script = '''
IFS= read -r payload || test -n "$payload"
printf 'holding:%s\n' "$payload"
while :; do :; done
'''
timeout_sec = 10

[tasks.dispatch_probe]
script = '''
IFS= read -r prepared < .setup-complete
test "$prepared" = prepared
name=${{PWD##*/}}
uid=$("{id_command}" -u)
gid=$("{id_command}" -g)
groups=
for group in $("{id_command}" -G); do groups=${{groups:+$groups,}}$group; done
printf 'uid=%s gid=%s groups=%s\n' "$uid" "$gid" "$groups" > "{task_state}/$name.identity"
printf 'ready\n' > "{task_state}/$name.status"
printf 'initialized\n'
'''
cwd = "."
timeout_sec = 2
workspace = "fresh"
[tasks.dispatch_probe.setup]
script = "printf 'prepared\\n' > .setup-complete"
timeout_sec = 2
[tasks.dispatch_probe.environment]
PATH = "/usr/bin:/bin"
LANG = "C"
[tasks.dispatch_probe.artifacts]
include = ["final/**"]
exclude = ["final/.keep"]
[tasks.dispatch_probe.session]
idle_timeout_sec = 4
max_lifetime_sec = 15
[tasks.dispatch_probe.session.teardown]
script = '''
name=${{PWD##*/}}
printf '{teardown_state}\n' > "{task_state}/$name.status"
printf 'teardown\n' > final/teardown.txt
'''
timeout_sec = 2
[tasks.dispatch_probe.session.action_dispatcher]
script = '''
IFS= read -r envelope || test -n "$envelope"
case "$envelope" in
  '{{"schema_version":"1","action":"observe-later","input":{{"step":1}}}}'|'{{"schema_version":"1","action":"observe-again","input":{{"step":1}}}}')
    IFS= read -r count < counter
    count=$((count + 1))
    printf '%s\n' "$count" > counter
    printf '%s\n' "$envelope" > evidence/dispatch.txt
    printf 'dispatched:%s\n' "$count"
    ;;
  '{{"schema_version":"1","action":"fail-later","input":{{"step":1}}}}')
    printf 'ordinary-dispatch-failure:%s\n' "$envelope" >&2
    exit 9
    ;;
  '{{"schema_version":"1","action":"timeout-later","input":{{"step":1}}}}')
    trap '' TERM
    while :; do :; done
    ;;
  '{{"schema_version":"1","action":"hold-later","input":{{"step":1}}}}')
    printf 'holding-dispatch\n'
    while :; do :; done
    ;;
  *)
    printf 'unsupported-action\n' >&2
    exit 64
    ;;
esac
'''
timeout_sec = 2
allow_unlisted = true
[tasks.dispatch_probe.session.action_dispatcher.artifacts]
include = ["evidence/**"]
exclude = ["evidence/.keep"]
[tasks.dispatch_probe.session.action_dispatcher.actions.observe-later]
timeout_sec = 3
"#,
        )
    });
    fs::write(
        &config,
        format!(
            r#"schema_version = "12"
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
run_as_user = "{task_user}"
run_as_group = "{task_group}"
[tasks.package_probe]
script = '''
IFS= read -r prepared < .setup-complete
test "$prepared" = prepared
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
[tasks.package_probe.setup]
script = "printf 'prepared\\n' > .setup-complete"
timeout_sec = 5
[tasks.package_probe.environment]
PATH = "/usr/bin:/bin"
LANG = "C"
[tasks.package_probe.artifacts]
include = ["out/**"]
exclude = ["out/.keep"]
[tasks.cancel_probe]
script = '''
IFS= read -r prepared < .setup-complete
test "$prepared" = prepared
printf '{cancel_marker}\n'
while :; do :; done
'''
cwd = "."
timeout_sec = 10
workspace = "fresh"
[tasks.cancel_probe.setup]
script = "printf 'prepared\\n' > .setup-complete"
timeout_sec = 2
[tasks.cancel_probe.environment]
PATH = "/usr/bin:/bin"
LANG = "C"
[tasks.cancel_probe.artifacts]
include = []
exclude = []
{session_task}
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
            cancel_marker = CANCEL_MARKER,
        ),
    )
    .unwrap();
    config
}

fn start_packaged_server(
    server_bin: &Path,
    root: &Path,
    mode: ServerConfigMode,
) -> (String, ChildGuard) {
    for _ in 0..5 {
        let port = reserve_port();
        let config = render_server_config(root, port, mode);
        let stderr = fs::File::create(root.join("server.stderr")).unwrap();
        let child = Command::new(server_bin)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
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
    panic!(
        "packaged server did not bind after bounded retries: {}",
        fs::read_to_string(root.join("server.stderr")).unwrap_or_default()
    );
}

fn write_client_config(source: &Path, endpoint: &str) {
    let directory = source.join(".indentured-server");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("config.toml"),
        format!(
            r#"[sources]
include = ["input.txt", "out/.keep", "counter", "evidence/.keep", "final/.keep"]
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
    let (endpoint, mut server) =
        start_packaged_server(&server_bin, &server_root, ServerConfigMode::Full);
    write_client_config(&source, &endpoint);

    let mut client = ChildGuard(
        Command::new(&client_bin)
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
            .expect("start packaged client"),
    );

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
    assert_eq!(provenance["schema_version"], 2);
    assert_eq!(provenance["remote_exit_code"], 7);
    assert_eq!(provenance["timed_out"], false);
    assert_eq!(provenance["status"], "failed");
    assert_eq!(provenance["failed_phase"], "run");
    let phases = provenance["phases"].as_array().unwrap();
    assert_eq!(
        phases.len(),
        2,
        "one-shot must report exactly setup then run"
    );
    assert_eq!(phases[0]["phase"], "setup");
    assert_eq!(phases[0]["exit_code"], 0);
    assert_eq!(phases[0]["timed_out"], false);
    assert_eq!(phases[1]["phase"], "run");
    assert_eq!(phases[1]["exit_code"], 7);
    assert_eq!(phases[1]["timed_out"], false);
    assert_eq!(
        fs::read_to_string(run.join("artifacts/out/result.txt")).unwrap(),
        "server-policy:uploaded-source\n"
    );

    // The exact packaged one-shot client disconnects and cancels a setup+run task.
    let mut cancelled = ChildGuard(
        Command::new(&client_bin)
            .current_dir(&source)
            .env("XDG_STATE_HOME", &state)
            .env_remove("INDENTURED_SERVER_ENDPOINT")
            .env_remove("INDENTURED_SERVER_TOKEN_FILE")
            .env_remove("INDENTURED_SERVER_CONFIG")
            .arg("run")
            .arg("--result-root")
            .arg(&result_base)
            .arg("cancel_probe")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start packaged cancellation probe"),
    );
    let cancel_stdout = cancelled.stdout.take().unwrap();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let cancel_reader = thread::spawn(move || {
        let mut captured = String::new();
        for line in BufReader::new(cancel_stdout).lines() {
            let line = line.unwrap();
            captured.push_str(&line);
            captured.push('\n');
            if line == CANCEL_MARKER {
                let _ = cancel_tx.send(());
            }
        }
        captured
    });
    let cancel_stderr = cancelled.stderr.take().unwrap();
    let cancel_error_reader = thread::spawn(move || {
        let mut captured = String::new();
        BufReader::new(cancel_stderr)
            .read_to_string(&mut captured)
            .unwrap();
        captured
    });
    cancel_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cancellation marker did not stream");
    assert_eq!(
        unsafe { libc::kill(cancelled.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let cancelled_status = wait_bounded(&mut cancelled, Instant::now() + Duration::from_secs(10));
    let cancel_stdout = cancel_reader.join().unwrap();
    let cancel_stderr = cancel_error_reader.join().unwrap();
    assert_eq!(
        cancelled_status.code(),
        Some(130),
        "stdout={cancel_stdout} stderr={cancel_stderr}"
    );

    wait_until(
        || workspace_count(&server_root) == 0,
        "packaged SIGINT did not clean the one-shot workspace",
    );
    let workspace_entries: Vec<_> = fs::read_dir(server_root.join("workspaces"))
        .unwrap()
        .collect();
    assert!(
        workspace_entries.is_empty(),
        "fresh workspace was not cleaned"
    );
    server.terminate();
    assert_no_packaged_binary_descendants(&server_bin, &client_bin);
}

fn resolved_id(flag: &str, name: &str) -> u32 {
    let output = Command::new("id")
        .args([flag, name])
        .output()
        .expect("resolve packaged task identity");
    assert!(
        output.status.success(),
        "cannot resolve task identity {name}"
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn prepare_task_state(root: &Path) -> PathBuf {
    let (user, _) = task_identity();
    let uid = resolved_id("-u", &user);
    let gid = resolved_id("-g", &user);
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
    let state = root.join("task-state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::ffi::CString::new(state.as_os_str().as_encoded_bytes()).unwrap();
    let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    assert_eq!(result, 0, "failed to assign fake state to task identity");
    state
}

fn session_source(root: &Path) -> PathBuf {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("input.txt"), "uploaded-source\n").unwrap();
    fs::write(source.join("counter"), "0\n").unwrap();
    for directory in ["out", "evidence", "final"] {
        fs::create_dir(source.join(directory)).unwrap();
        fs::write(source.join(directory).join(".keep"), "").unwrap();
    }
    source
}

fn packaged_client(client: &Path, source: &Path, state: &Path) -> Command {
    let mut command = Command::new(client);
    command
        .current_dir(source)
        .env("XDG_STATE_HOME", state)
        .env_remove("INDENTURED_SERVER_ENDPOINT")
        .env_remove("INDENTURED_SERVER_TOKEN_FILE")
        .env_remove("INDENTURED_SERVER_CONFIG");
    command
}

fn start_session_for_task(
    client: &Path,
    source: &Path,
    state: &Path,
    results: &Path,
    task: &str,
) -> String {
    let output = packaged_client(client, source, state)
        .args(["session", "start", "--result-root"])
        .arg(results)
        .arg(task)
        .output()
        .expect("start packaged managed session");
    assert_success(&output, "session start");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let id = stdout.trim();
    assert!(
        id.starts_with("ses_"),
        "unexpected session stdout: {stdout:?}"
    );
    assert_eq!(
        stdout,
        format!("{id}\n"),
        "session stdout must be machine-clean"
    );
    id.to_string()
}

fn session_action(
    client: &Path,
    source: &Path,
    state: &Path,
    results: &Path,
    session: &str,
    action: &str,
) -> Output {
    packaged_client(client, source, state)
        .args(["session", "action", session, action, "--input"])
        .arg(source.join("action.json"))
        .arg("--result-root")
        .arg(results)
        .output()
        .expect("run packaged managed action")
}

fn stop_session(
    client: &Path,
    source: &Path,
    state: &Path,
    results: &Path,
    session: &str,
) -> Output {
    packaged_client(client, source, state)
        .args(["session", "stop", session, "--result-root"])
        .arg(results)
        .output()
        .expect("stop packaged managed session")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn workspace_count(server_root: &Path) -> usize {
    let workspace_root = server_root.join("workspaces");
    if !workspace_root.exists() {
        return 0;
    }
    fs::read_dir(workspace_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != ".sessions")
        .count()
}

fn metadata_count(server_root: &Path) -> usize {
    let root = server_root.join("workspaces/.sessions");
    if !root.exists() {
        return 0;
    }
    fs::read_dir(root).unwrap().filter_map(Result::ok).count()
}

#[derive(Debug)]
struct RecordedServiceProcess {
    supervisor_pid: libc::pid_t,
    service_pgid: libc::pid_t,
    shutdown_timeout_sec: u64,
}

fn assert_no_service_metadata(server_root: &Path, session_id: &str) {
    let path = server_root
        .join("workspaces/.sessions")
        .join(format!("{session_id}.json"));
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(value["version"], 2);
    assert!(
        value.get("services").is_none() && value.get("state").is_none(),
        "a no-services session gained retained-service metadata: {value}"
    );
}

fn recorded_service_processes(server_root: &Path) -> Vec<RecordedServiceProcess> {
    let root = server_root.join("workspaces/.sessions");
    let mut recorded = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(entry.unwrap().path()).unwrap()).unwrap();
        for service in value["services"].as_array().unwrap() {
            recorded.push(RecordedServiceProcess {
                supervisor_pid: service["supervisor_pid"].as_i64().unwrap() as libc::pid_t,
                service_pgid: service["service_pgid"].as_i64().unwrap() as libc::pid_t,
                shutdown_timeout_sec: service["shutdown_timeout_sec"].as_u64().unwrap(),
            });
        }
    }
    assert!(
        !recorded.is_empty(),
        "service metadata was not durably recorded"
    );
    recorded
}

#[cfg(target_os = "linux")]
fn become_test_subreaper() {
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0,
        "failed to make the isolated harness the service-supervisor subreaper"
    );
}

#[cfg(not(target_os = "linux"))]
fn become_test_subreaper() {
    panic!("packaged retained-service lifecycle requires Linux subreaper support");
}

fn reap_recorded_supervisors(processes: &[RecordedServiceProcess]) {
    for process in processes {
        let deadline = Instant::now()
            + Duration::from_secs(process.shutdown_timeout_sec)
            + Duration::from_secs(6);
        loop {
            let result = unsafe {
                libc::waitpid(process.supervisor_pid, std::ptr::null_mut(), libc::WNOHANG)
            };
            if result == process.supervisor_pid {
                break;
            }
            if result < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD),
                    "failed to reap recorded service supervisor {}",
                    process.supervisor_pid
                );
                assert_eq!(unsafe { libc::kill(process.supervisor_pid, 0) }, -1);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "recorded service supervisor {} did not exit after daemon control EOF",
                process.supervisor_pid
            );
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            unsafe { libc::killpg(process.service_pgid, 0) },
            -1,
            "service process group {} survived its supervisor",
            process.service_pgid
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "service process group lookup failed unexpectedly"
        );
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !predicate() {
        assert!(Instant::now() < deadline, "{message}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn task_status_paths(task_state: &Path) -> HashSet<PathBuf> {
    if !task_state.exists() {
        return HashSet::new();
    }
    fs::read_dir(task_state)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "status")
        })
        .collect()
}

fn start_session_with_state(
    client: &Path,
    source: &Path,
    state: &Path,
    results: &Path,
    task_state: &Path,
) -> (String, PathBuf) {
    start_session_with_state_for_task(client, source, state, results, task_state, "session_probe")
}

fn start_session_with_state_for_task(
    client: &Path,
    source: &Path,
    state: &Path,
    results: &Path,
    task_state: &Path,
    task: &str,
) -> (String, PathBuf) {
    let before = task_status_paths(task_state);
    let session = start_session_for_task(client, source, state, results, task);
    let mut created = None;
    wait_until(
        || {
            let new: Vec<_> = task_status_paths(task_state)
                .difference(&before)
                .cloned()
                .collect();
            if new.len() == 1 {
                created = new.into_iter().next();
                true
            } else {
                false
            }
        },
        "session initialization did not publish distinguishable fake state",
    );
    let status = created.unwrap();
    assert_eq!(fs::read_to_string(&status).unwrap(), "ready\n");
    assert_task_identity(&status.with_extension("identity"));
    (session, status)
}

fn numeric_groups(command: &str, user: &str) -> Vec<u32> {
    let output = Command::new(command)
        .args(["-G", user])
        .output()
        .expect("resolve expected supplementary groups");
    assert!(output.status.success());
    let mut groups: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .split_ascii_whitespace()
        .map(|group| group.parse::<u32>().unwrap())
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}

fn assert_task_identity(identity: &Path) {
    let value = fs::read_to_string(identity).expect("task identity evidence");
    let fields: Vec<_> = value.split_ascii_whitespace().collect();
    assert_eq!(fields.len(), 3, "malformed task identity evidence: {value}");
    let uid = fields[0]
        .strip_prefix("uid=")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let gid = fields[1]
        .strip_prefix("gid=")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let mut groups: Vec<_> = fields[2]
        .strip_prefix("groups=")
        .unwrap()
        .split(',')
        .map(|group| group.parse::<u32>().unwrap())
        .collect();
    groups.sort_unstable();
    groups.dedup();

    let (user, _) = task_identity();
    let expected_uid = resolved_id("-u", &user);
    let expected_gid = resolved_id("-g", &user);
    let id_command = std::env::var("INDENTURED_TEST_ID_COMMAND").unwrap();
    assert_eq!(uid, expected_uid);
    assert_eq!(gid, expected_gid);
    assert_ne!(uid, 0, "packaged task must not retain root UID");
    assert_ne!(gid, 0, "packaged task must not retain root primary GID");
    assert!(!groups.contains(&0), "packaged task retained root group");
    assert_eq!(groups, numeric_groups(&id_command, &user));
}

fn wait_for_teardown(status: &Path, expected: &str, message: &str) {
    wait_until(
        || fs::read_to_string(status).ok().as_deref() == Some(expected),
        message,
    );
}

fn assert_action_provenance(results: &Path, action: &str, exit_code: i32) {
    let found = fs::read_dir(results)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read(entry.path().join("provenance.json")).ok())
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .any(|value| {
            value["operation"] == "action"
                && value["action"] == action
                && value["remote_exit_code"] == exit_code
        });
    assert!(
        found,
        "missing action provenance for {action} exit {exit_code}"
    );
}

fn assert_result_artifact(results: &Path, suffix: &Path, expected: &str) {
    let found = fs::read_dir(results)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("artifacts").join(suffix))
        .find(|path| path.is_file() && fs::read_to_string(path).unwrap() == expected);
    assert!(
        found.is_some(),
        "missing packaged evidence artifact {}",
        suffix.display()
    );
}

#[test]
#[ignore = "run through scripts/check-packaged-local-integration.sh with Nix package paths"]
fn packaged_managed_session_flow() {
    become_test_subreaper();
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "session harness needs root authority"
    );
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
    let server_root = root.path().join("server");
    let state = root.path().join("state");
    let results = root.path().join("results");
    fs::create_dir(&server_root).unwrap();
    fs::create_dir(&state).unwrap();
    let task_state = prepare_task_state(&server_root);
    let source = session_source(root.path());
    fs::write(source.join("action.json"), "{\"step\":1}\n").unwrap();

    let (mut endpoint, mut server) =
        start_packaged_server(&server_bin, &server_root, ServerConfigMode::Full);
    write_client_config(&source, &endpoint);

    // One fixed dispatcher receives arbitrary names only through its bounded stdin envelope.
    let (dispatched, dispatched_status) = start_session_with_state_for_task(
        &client_bin,
        &source,
        &state,
        &results,
        &task_state,
        "dispatch_probe",
    );
    assert_no_service_metadata(&server_root, &dispatched);
    let observed = session_action(
        &client_bin,
        &source,
        &state,
        &results,
        &dispatched,
        "observe-later",
    );
    assert_success(&observed, "dispatcher observe-later");
    assert!(String::from_utf8_lossy(&observed.stdout).contains("dispatched:1"));
    let failed = session_action(
        &client_bin,
        &source,
        &state,
        &results,
        &dispatched,
        "fail-later",
    );
    assert_eq!(failed.status.code(), Some(9));
    let unknown_started = Instant::now();
    let unknown = session_action(
        &client_bin,
        &source,
        &state,
        &results,
        &dispatched,
        "not-supported",
    );
    assert_eq!(unknown.status.code(), Some(64));
    assert!(unknown_started.elapsed() < Duration::from_secs(2));
    let reused = session_action(
        &client_bin,
        &source,
        &state,
        &results,
        &dispatched,
        "observe-again",
    );
    assert_success(&reused, "dispatcher reuse after nonzero exits");
    assert!(String::from_utf8_lossy(&reused.stdout).contains("dispatched:2"));
    assert_action_provenance(&results, "observe-later", 0);
    assert_action_provenance(&results, "fail-later", 9);
    assert_action_provenance(&results, "not-supported", 64);
    assert_action_provenance(&results, "observe-again", 0);
    assert_result_artifact(
        &results,
        Path::new("evidence/dispatch.txt"),
        "{\"schema_version\":\"1\",\"action\":\"observe-again\",\"input\":{\"step\":1}}\n",
    );
    assert_success(
        &stop_session(&client_bin, &source, &state, &results, &dispatched),
        "dispatcher explicit stop",
    );
    wait_for_teardown(
        &dispatched_status,
        "torn-down\n",
        "dispatcher stop did not run teardown",
    );
    wait_until(
        || workspace_count(&server_root) == 0 && metadata_count(&server_root) == 0,
        "dispatcher stop did not remove session state",
    );

    let (timed_dispatch, timed_dispatch_status) = start_session_with_state_for_task(
        &client_bin,
        &source,
        &state,
        &results,
        &task_state,
        "dispatch_probe",
    );
    let timed = session_action(
        &client_bin,
        &source,
        &state,
        &results,
        &timed_dispatch,
        "timeout-later",
    );
    assert_eq!(timed.status.code(), Some(124));
    wait_for_teardown(
        &timed_dispatch_status,
        "torn-down\n",
        "dispatcher timeout did not run teardown",
    );
    wait_until(
        || workspace_count(&server_root) == 0,
        "dispatcher timeout did not destroy the session",
    );

    let (dropped_dispatch, dropped_dispatch_status) = start_session_with_state_for_task(
        &client_bin,
        &source,
        &state,
        &results,
        &task_state,
        "dispatch_probe",
    );
    let mut dropped = ChildGuard(
        packaged_client(&client_bin, &source, &state)
            .args([
                "session",
                "action",
                &dropped_dispatch,
                "hold-later",
                "--input",
            ])
            .arg(source.join("action.json"))
            .arg("--result-root")
            .arg(&results)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut dropped_stdout = BufReader::new(dropped.stdout.take().unwrap());
    let mut marker = String::new();
    dropped_stdout.read_line(&mut marker).unwrap();
    assert_eq!(marker, "holding-dispatch\n");
    dropped.kill().unwrap();
    dropped.wait().unwrap();
    wait_for_teardown(
        &dropped_dispatch_status,
        "torn-down\n",
        "dispatcher disconnect did not run teardown",
    );
    wait_until(
        || workspace_count(&server_root) == 0,
        "dispatcher disconnect did not destroy the session",
    );

    // Initialization is reused across successful and ordinary nonzero named actions.
    let (session, explicit_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    assert_eq!(workspace_count(&server_root), 1);
    for expected in [1, 2] {
        let output = session_action(&client_bin, &source, &state, &results, &session, "observe");
        if !output.status.success() {
            let provenance = fs::read_dir(&results)
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| fs::read_to_string(entry.path().join("provenance.json")).ok())
                .collect::<Vec<_>>();
            panic!(
                "observe action failed: stdout={} stderr={} provenance={provenance:?} server={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                fs::read_to_string(server_root.join("server.stderr")).unwrap_or_default()
            );
        }
        assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("observed:{expected}")));
    }
    let failed = session_action(&client_bin, &source, &state, &results, &session, "fail");
    assert_eq!(failed.status.code(), Some(9));
    let reused = session_action(&client_bin, &source, &state, &results, &session, "observe");
    assert_success(&reused, "observe after ordinary nonzero action");
    assert!(String::from_utf8_lossy(&reused.stdout).contains("observed:3"));
    assert_result_artifact(
        &results,
        Path::new("evidence/observe.txt"),
        "observed:3:{\"step\":1}\n",
    );

    // A Ready session owns the sole global permit until explicit teardown.
    let busy = packaged_client(&client_bin, &source, &state)
        .args(["run", "--result-root"])
        .arg(&results)
        .arg("package_probe")
        .output()
        .unwrap();
    assert!(!busy.status.success());
    let busy_stderr = String::from_utf8_lossy(&busy.stderr);
    assert!(
        busy_stderr.contains("busy") || busy_stderr.contains("503"),
        "unexpected retained-permit diagnostic: {busy_stderr}"
    );
    let stopped = stop_session(&client_bin, &source, &state, &results, &session);
    assert_success(&stopped, "explicit stop");
    wait_for_teardown(
        &explicit_status,
        "torn-down\n",
        "explicit stop did not run configured teardown",
    );
    assert_result_artifact(&results, Path::new("final/teardown.txt"), "teardown\n");
    wait_until(
        || workspace_count(&server_root) == 0 && metadata_count(&server_root) == 0,
        "explicit stop did not remove session state",
    );

    // Idle expiry performs automatic teardown and makes the ID unavailable.
    let (idle, idle_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    let idle_wait_started = Instant::now();
    wait_for_teardown(
        &idle_status,
        "torn-down\n",
        "idle expiry did not run configured teardown",
    );
    assert!(
        idle_wait_started.elapsed() < Duration::from_secs(6),
        "idle cleanup lost to the later maximum-lifetime trigger"
    );
    wait_until(
        || workspace_count(&server_root) == 0,
        "idle expiry did not remove workspace",
    );
    let expired = session_action(&client_bin, &source, &state, &results, &idle, "observe");
    assert!(!expired.status.success());
    let expired_stderr = String::from_utf8_lossy(&expired.stderr);
    assert!(
        expired_stderr.contains("session")
            && (expired_stderr.contains("missing")
                || expired_stderr.contains("expired")
                || expired_stderr.contains("404")),
        "unexpected idle-expiry diagnostic: {expired_stderr}"
    );

    // Activity resets idle time, but never extends the hard maximum lifetime.
    let (lifetime, lifetime_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    let lifetime_started = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(400));
        let output = session_action(&client_bin, &source, &state, &results, &lifetime, "observe");
        if !output.status.success() {
            break;
        }
        assert!(
            lifetime_started.elapsed() < Duration::from_secs(18),
            "hard lifetime did not expire"
        );
    }
    assert!(lifetime_started.elapsed() >= Duration::from_secs(14));
    wait_for_teardown(
        &lifetime_status,
        "torn-down\n",
        "maximum lifetime did not run configured teardown",
    );
    wait_until(
        || workspace_count(&server_root) == 0,
        "maximum lifetime did not remove workspace",
    );

    // Killing an action client disconnects the stream and destroys the session.
    let (disconnected, disconnected_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    let mut action = ChildGuard(
        packaged_client(&client_bin, &source, &state)
            .args(["session", "action", &disconnected, "hold", "--input"])
            .arg(source.join("action.json"))
            .arg("--result-root")
            .arg(&results)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = action.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            let done = line.starts_with("holding:");
            let _ = line_tx.send(done);
            if done {
                break;
            }
        }
    });
    assert!(
        line_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "hold action did not stream before disconnect"
    );
    let disconnected_at = Instant::now();
    action.kill().unwrap();
    action.wait().unwrap();
    reader.join().unwrap();
    wait_for_teardown(
        &disconnected_status,
        "torn-down\n",
        "action disconnect did not run configured teardown",
    );
    assert!(
        disconnected_at.elapsed() < Duration::from_secs(5),
        "disconnect cleanup lost to the later action-timeout trigger"
    );
    wait_until(
        || workspace_count(&server_root) == 0,
        "action disconnect did not destroy session",
    );

    // A genuine daemon death leaves durable state; restart reconciles with teardown.
    let (restart, restart_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    assert!(restart.starts_with("ses_"));
    let restart_services = recorded_service_processes(&server_root);
    server.terminate();
    reap_recorded_supervisors(&restart_services);
    let restarted = start_packaged_server(&server_bin, &server_root, ServerConfigMode::Full);
    endpoint = restarted.0;
    server = restarted.1;
    write_client_config(&source, &endpoint);
    wait_for_teardown(
        &restart_status,
        "torn-down\n",
        "restart reconciliation did not run stale teardown",
    );
    wait_until(
        || workspace_count(&server_root) == 0 && metadata_count(&server_root) == 0,
        "restart reconciliation did not remove stale session",
    );

    // Configuration drift with current teardown authority uses the current policy.
    let (drift_available, drift_available_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    assert!(drift_available.starts_with("ses_"));
    let drift_available_services = recorded_service_processes(&server_root);
    server.terminate();
    reap_recorded_supervisors(&drift_available_services);
    let changed_server = start_packaged_server(
        &server_bin,
        &server_root,
        ServerConfigMode::ChangedSessionPolicy,
    );
    endpoint = changed_server.0;
    server = changed_server.1;
    write_client_config(&source, &endpoint);
    wait_for_teardown(
        &drift_available_status,
        "torn-down-drift\n",
        "configuration drift with available policy did not run current teardown",
    );
    wait_until(
        || workspace_count(&server_root) == 0 && metadata_count(&server_root) == 0,
        "configuration drift with available policy did not remove stale session",
    );

    // If task policy is removed, restart performs root cleanup without inventing teardown.
    let (drifted, drifted_status) =
        start_session_with_state(&client_bin, &source, &state, &results, &task_state);
    assert!(drifted.starts_with("ses_"));
    let drifted_services = recorded_service_processes(&server_root);
    server.terminate();
    reap_recorded_supervisors(&drifted_services);
    let drifted_server = start_packaged_server(
        &server_bin,
        &server_root,
        ServerConfigMode::WithoutSessionTask,
    );
    endpoint = drifted_server.0;
    server = drifted_server.1;
    write_client_config(&source, &endpoint);
    wait_until(
        || workspace_count(&server_root) == 0 && metadata_count(&server_root) == 0,
        "configuration-drift restart did not remove stale session",
    );
    assert_eq!(
        fs::read_to_string(&drifted_status).unwrap(),
        "ready\n",
        "removed task configuration must not invent teardown authority"
    );

    // Reconciliation released the permit: the exact packaged one-shot path runs again.
    let post_restart = packaged_client(&client_bin, &source, &state)
        .args(["run", "--result-root"])
        .arg(&results)
        .arg("package_probe")
        .output()
        .unwrap();
    assert_eq!(post_restart.status.code(), Some(7));
    server.terminate();
    assert_no_packaged_binary_descendants(&server_bin, &client_bin);
}

#[cfg(target_os = "linux")]
#[path = "support/host_builtin.rs"]
mod host_builtin;

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Nix-packaged binaries; run integration:packaged-local"]
fn packaged_host_observation_is_source_free_and_uses_normal_artifacts() {
    if std::env::var_os("INDENTURED_HOST_TEST_ROOT").is_none() {
        let status = Command::new("/bin/sh")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/check-packaged-host-isolated.sh"
            ))
            .arg(std::env::current_exe().unwrap())
            .status()
            .unwrap();
        assert!(status.success(), "isolated packaged host fixture failed");
        return;
    }
    let server = required_package_binary(
        "INDENTURED_TEST_SERVER_BIN",
        "indentured-server",
        "indentured",
    );
    let client = required_package_binary(
        "INDENTURED_TEST_CLIENT_BIN",
        "indentured",
        "indentured-server",
    );
    host_builtin::round_trip(&server, &client);
}
