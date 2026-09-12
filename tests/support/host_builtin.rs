// Shared by ordinary and Nix-packaged end-to-end tests. No GUI or task executes.
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn round_trip(server: &Path, client: &Path) {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let cwd = root_path.join("empty-client-directory");
    fs::create_dir(&cwd).unwrap();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| format!("/run/user/{}", unsafe { libc::getuid() }).into());
    let credentials = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(runtime)
        .unwrap();
    let token = credentials.path().join("host-test-token");
    fs::write(&token, b"offline-host-test-token").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let socket = root_path.join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let task_identity = if unsafe { libc::geteuid() } == 0 {
        let user = std::env::var("INDENTURED_TEST_TASK_USER").unwrap_or_else(|_| "nobody".into());
        let group =
            std::env::var("INDENTURED_TEST_TASK_GROUP").unwrap_or_else(|_| "nogroup".into());
        format!("run_as_user = {user:?}\nrun_as_group = {group:?}\n")
    } else {
        String::new()
    };
    let config = format!(
        r#"schema_version = "12"
tasks = {{}}
[service.http]
enabled = true
listen_addr = "127.0.0.1:{port}"
[service.http.auth]
required = true
token_files = [{token:?}]
[service.socket]
enabled = false
[build]
workspace_root = {workspace:?}
{task_identity}
[host_observation]
enabled = true
socket = {socket:?}
peer_uid = {uid}
[artifacts]
storage_root = {artifacts:?}
[logging]
directory = {logs:?}
console = false
"#,
        token = token.to_str().unwrap(),
        workspace = root_path.join("workspaces").to_str().unwrap(),
        socket = socket.to_str().unwrap(),
        uid = unsafe { libc::geteuid() },
        artifacts = root_path.join("stored-artifacts").to_str().unwrap(),
        logs = root_path.join("logs").to_str().unwrap()
    );
    let config_path = root_path.join("server.toml");
    fs::write(&config_path, config).unwrap();
    let stderr_path = root_path.join("server.stderr");
    let mut daemon = Child(
        Command::new(server)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr_path).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(&stderr_path).unwrap()
        );
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    let worker = std::thread::spawn(move || {
        for images in [false, true] {
            let mut poll = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert!(
                unsafe { libc::poll(&mut poll, 1, 10000) } > 0,
                "broker was not contacted"
            );
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(
                request,
                if images {
                    serde_json::json!({"operation":"capture","target":{"target":"desktop"}})
                } else {
                    serde_json::json!({"operation":"list"})
                }
            );
            let manifest = serde_json::json!({
                "schema_version":"1", "observation_id":"host-11111111-1111-4111-8111-111111111111", "captured_at":"2026-01-01T00:00:00Z", "status":"succeeded",
                "inventory":{"applications":[{"pid":123,"name":"Test app","bundle_id":null,"hidden":false}],"windows":[],"displays":[]},
                "images":if images {serde_json::json!([{"path":"image-0000.png","display_id":123}])} else {serde_json::json!([])}, "errors":[],
            });
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let options = zip::write::SimpleFileOptions::default().unix_permissions(0o600);
            zip.start_file("manifest.json", options).unwrap();
            zip.write_all(&serde_json::to_vec(&manifest).unwrap())
                .unwrap();
            if images {
                zip.start_file("image-0000.png", options).unwrap();
                zip.write_all(include_bytes!("../fixtures/host-observation.png"))
                    .unwrap();
            }
            let bytes = zip.finish().unwrap().into_inner();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
        }
    });
    let results = root_path.join("results");
    for images in [false, true] {
        if images {
            fs::create_dir(cwd.join(".indentured-server")).unwrap();
            fs::write(
                cwd.join(".indentured-server/config.toml"),
                "invalid project config, MUST NOT LOAD",
            )
            .unwrap();
            fs::write(cwd.join("source-canary"), "MUST NOT UPLOAD").unwrap();
        }
        let mut command = Command::new(client);
        command
            .current_dir(&cwd)
            .args([
                "--endpoint",
                &format!("http://127.0.0.1:{port}"),
                "--token-file",
            ])
            .arg(&token)
            .args(["host", "--result-root"])
            .arg(&results);
        if images {
            command.args(["capture", "desktop"]);
        } else {
            command.arg("list");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(manifest["status"], "succeeded");
        assert_eq!(manifest["inventory"]["applications"][0]["name"], "Test app");
        let id = manifest["observation_id"].as_str().unwrap();
        assert_ne!(id, "host-11111111-1111-4111-8111-111111111111");
        let directory = fs::read_dir(&results)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                fs::read_to_string(p.join("manifest.json"))
                    .unwrap()
                    .contains(id)
            })
            .unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!directory.join("source-manifest.json").exists());
        assert!(
            !directory.join("provenance.json").exists(),
            "must not synthesize build/session provenance"
        );
        if images {
            let image = directory
                .join("artifacts")
                .join(manifest["images"][0]["path"].as_str().unwrap());
            let reported =
                std::path::Path::new(manifest["images"][0]["local_path"].as_str().unwrap());
            assert!(reported.is_absolute());
            assert_eq!(reported, image);
            assert_eq!(
                fs::read(&image).unwrap(),
                include_bytes!("../fixtures/host-observation.png")
            );
            assert_eq!(fs::metadata(image).unwrap().permissions().mode() & 0o077, 0);
        }
    }
    worker.join().unwrap();
}
