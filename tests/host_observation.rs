use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn action(cwd: &Path, socket: &Path, input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured-host"))
        .args(["action", "--socket"])
        .arg(socket)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn helper_help_and_invalid_envelopes_are_offline_and_structured() {
    let help = Command::new(env!("CARGO_BIN_EXE_indentured-host"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("permissions"));
    let cwd = TempDir::new().unwrap();
    for input in [
        &b"malformed zellij input\x1b[200~"[..],
        &b"{\"schema_version\":\"1\",\"action\":\"host-capture\",\"input\":{\"target\":\"desktop\",\"path\":\"/tmp/escape\"}}"[..],
    ] {
        let result = action(cwd.path(), Path::new("/missing/helper.sock"), input);
        assert!(!result.status.success());
        let manifest: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(manifest["status"], "failed");
        assert_eq!(manifest["images"], serde_json::json!([]));
        let id = manifest["observation_id"].as_str().unwrap();
        let saved = cwd.path().join(".indentured-output/action").join(id).join("manifest.json");
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&fs::read(saved).unwrap()).unwrap(), manifest);
    }
}

#[test]
fn cross_uid_requires_explicit_socket_group_before_serving() {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().canonicalize().unwrap().join("helper.sock");
    let other_uid = unsafe { libc::geteuid() }.wrapping_add(1).to_string();
    let result = Command::new(env!("CARGO_BIN_EXE_indentured-host"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .args(["--allow-uid", &other_uid])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires --socket-group"));
    assert!(!socket.exists());
}

#[test]
fn action_reports_missing_gui_helper_and_refuses_symlink_output() {
    let cwd = TempDir::new().unwrap();
    let socket_dir = TempDir::new().unwrap();
    fs::set_permissions(socket_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = socket_dir
        .path()
        .canonicalize()
        .unwrap()
        .join("helper.sock");
    let input = br#"{"schema_version":"1","action":"host-list","input":{}}"#;
    let result = action(cwd.path(), &socket, input);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("GUI helper socket unavailable"));
    let other_cwd = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    symlink(outside.path(), other_cwd.path().join(".indentured-output")).unwrap();
    let result = action(other_cwd.path(), &socket, input);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("publish host observation"));
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn linux_native_capture_fails_explicitly_and_broker_remains_reusable() {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let permissions = Command::new(env!("CARGO_BIN_EXE_indentured-host"))
        .arg("permissions")
        .output()
        .unwrap();
    assert!(!permissions.status.success());
    assert!(String::from_utf8_lossy(&permissions.stderr).contains("only available on macOS"));
    let socket_dir = TempDir::new().unwrap();
    fs::set_permissions(socket_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = socket_dir
        .path()
        .canonicalize()
        .unwrap()
        .join("helper.sock");
    let mut broker = Child(
        Command::new(env!("CARGO_BIN_EXE_indentured-host"))
            .args(["serve", "--socket"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "broker never bound socket");
        assert!(
            broker.0.try_wait().unwrap().is_none(),
            "broker exited early"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // A malformed/oversized broker frame must not terminate the service.
    let mut malformed = UnixStream::connect(&socket).unwrap();
    malformed.write_all(&u32::MAX.to_be_bytes()).unwrap();
    drop(malformed);
    let cwd = TempDir::new().unwrap();
    for name in ["host-list", "host-capture"] {
        let input = if name == "host-list" {
            serde_json::json!({})
        } else {
            serde_json::json!({"target":"desktop"})
        };
        let envelope = serde_json::json!({"schema_version":"1", "action":name, "input":input});
        let result = action(cwd.path(), &socket, &serde_json::to_vec(&envelope).unwrap());
        assert!(!result.status.success());
        let manifest: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(manifest["status"], "failed");
        assert!(manifest["errors"][0]
            .as_str()
            .unwrap()
            .contains("this platform is unsupported"));
        assert_eq!(manifest["images"], serde_json::json!([]));
        assert!(broker.0.try_wait().unwrap().is_none());
    }
    unsafe {
        libc::kill(broker.0.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while broker.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "broker did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !socket.exists(),
        "orderly shutdown must remove its socket for restart"
    );
}
