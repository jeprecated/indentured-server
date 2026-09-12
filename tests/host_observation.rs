use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn helper_only_exposes_broker_and_permission_provisioning() {
    let help = Command::new(env!("CARGO_BIN_EXE_indentured-host"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("permissions"));
    assert!(!Command::new(env!("CARGO_BIN_EXE_indentured-host"))
        .arg("action")
        .output()
        .unwrap()
        .status
        .success());
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

#[cfg(not(target_os = "macos"))]
#[test]
fn linux_native_capture_fails_explicitly_and_broker_remains_reusable() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
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
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().canonicalize().unwrap().join("helper.sock");
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
        assert!(Instant::now() < deadline && broker.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut malformed = UnixStream::connect(&socket).unwrap();
    malformed.write_all(&u32::MAX.to_be_bytes()).unwrap();
    drop(malformed);
    for request in [
        r#"{"operation":"list"}"#,
        r#"{"operation":"capture","target":{"target":"desktop"}}"#,
    ] {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut bytes).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_reader(archive.by_name("manifest.json").unwrap()).unwrap();
        assert_eq!(manifest["status"], "failed");
        assert!(manifest["errors"][0]
            .as_str()
            .unwrap()
            .contains("this platform is unsupported"));
        assert_eq!(manifest["images"], serde_json::json!([]));
    }
    unsafe {
        libc::kill(broker.0.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while broker.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!socket.exists());
}
