use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: String,
    body: Vec<u8>,
}

struct ResponseSpec {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0u8; 8192];
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let mut lines = headers.lines();
    let request_line = lines.next().unwrap();
    let mut request = request_line.split_whitespace();
    let method = request.next().unwrap().to_string();
    let path = request.next().unwrap().to_string();
    let content_length = lines
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
        })
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        let mut buffer = [0u8; 8192];
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "request ended before body");
        bytes.extend_from_slice(&buffer[..read]);
    }
    CapturedRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

fn serve(
    specs: Vec<ResponseSpec>,
) -> (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for spec in specs {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_request(&mut stream)).unwrap();
            write!(
                stream,
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                spec.status,
                spec.content_type,
                spec.body.len()
            )
            .unwrap();
            stream.write_all(&spec.body).unwrap();
        }
    });
    (format!("http://{address}"), rx, handle)
}

fn write_config(repo: &TempDir, endpoint: &str) {
    let directory = repo.path().join(".indentured-server");
    fs::create_dir(&directory).unwrap();
    fs::write(
        directory.join("config.toml"),
        format!("[sources]\ninclude = [\"input.txt\"]\n[connection]\nendpoint = \"{endpoint}\"\n"),
    )
    .unwrap();
    fs::write(repo.path().join("input.txt"), "source-only-on-start\n").unwrap();
}

fn zip_artifact(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut bytes = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut bytes);
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(contents).unwrap();
        zip.finish().unwrap();
    }
    bytes.into_inner()
}

fn wait_for_status(root: &TempDir, expected: &str) {
    wait_for_provenance(root, |value| value["status"].as_str() == Some(expected));
}

fn wait_for_session_id(root: &TempDir, expected: &str) {
    wait_for_provenance(root, |value| value["session_id"].as_str() == Some(expected));
}

fn wait_for_provenance(root: &TempDir, matches: impl Fn(&serde_json::Value) -> bool) {
    for _ in 0..200 {
        let provenance = walkdir::WalkDir::new(root.path())
            .into_iter()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name() == "provenance.json")
            .and_then(|entry| fs::read(entry.path()).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        if provenance.as_ref().is_some_and(&matches) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for session provenance condition");
}

fn multipart_metadata(body: &[u8]) -> serde_json::Value {
    let start = body
        .windows(b"{\"schema_version\"".len())
        .position(|window| window == b"{\"schema_version\"")
        .unwrap();
    let end = body[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap()
        + start;
    serde_json::from_slice(&body[start..end]).unwrap()
}

fn only_result(root: &TempDir) -> std::path::PathBuf {
    let provenance: Vec<_> = walkdir::WalkDir::new(root.path())
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() == "provenance.json")
        .map(|entry| entry.into_path())
        .collect();
    assert_eq!(provenance.len(), 1, "expected one evidence directory");
    let directory = provenance[0].parent().unwrap().to_path_buf();
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    directory
}

#[test]
fn separate_start_action_and_stop_invocations_preserve_evidence_and_authority() {
    let start_body = concat!(
        "{\"type\":\"session\",\"id\":\"ses_cli\",\"status\":\"started\"}\n",
        "{\"type\":\"stdout\",\"data\":\"initialized\"}\n",
        "{\"type\":\"ready\",\"session_id\":\"ses_cli\"}\n"
    )
    .as_bytes()
    .to_vec();
    let (endpoint, captured, server) = serve(vec![ResponseSpec {
        status: "200 OK",
        content_type: "application/x-ndjson",
        body: start_body,
    }]);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .env("INDENTURED_SERVER_STDOUT_MAX_LINES", "0")
        .args(["session", "start", "build"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ses_cli\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("stdout lines suppressed"));
    let request = captured.recv().unwrap();
    server.join().unwrap();
    assert_eq!(
        (request.method.as_str(), request.path.as_str()),
        ("POST", "/v1/sessions")
    );
    assert!(request.headers.contains("multipart/form-data"));
    assert!(request
        .body
        .windows("source.zip".len())
        .any(|window| window == b"source.zip"));
    assert!(request
        .body
        .windows("\"task\":\"build\"".len())
        .any(|window| window == b"\"task\":\"build\""));
    let start_result = only_result(&state);
    assert_eq!(
        fs::read_to_string(start_result.join("stdout.log")).unwrap(),
        "initialized"
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(start_result.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["operation"], "start");
    assert_eq!(provenance["session_id"], "ses_cli");
    assert_eq!(provenance["status"], "ready");

    // Real image bytes must survive the action archive and become locally
    // readable evidence, not merely a path printed by the remote task.
    let image_path = ".indentured-output/action/host-test/image-0001.png";
    let image = include_bytes!("fixtures/host-observation.png");
    let archive = zip_artifact(image_path, image);
    let action_exit = format!(
        concat!(
            "{{\"type\":\"action\",\"session_id\":\"ses_cli\",\"action_id\":\"act_cli\",\"action\":\"observe\",\"status\":\"started\"}}\n",
            "{{\"type\":\"stdout\",\"data\":\"observed\\n\"}}\n",
            "{{\"type\":\"exit\",\"session_id\":\"ses_cli\",\"action_id\":\"act_cli\",\"action\":\"observe\",\"code\":0,\"timed_out\":false,",
            "\"artifacts\":{{\"path\":\"/v1/builds/bld_cli/artifacts.zip\",\"size\":{}}},",
            "\"artifact_restrictions\":{{\"omitted_count\":1,\"matched_patterns\":[\"**/*.key\"]}}}}\n"
        ),
        archive.len()
    )
    .into_bytes();
    let (endpoint, captured, server) = serve(vec![
        ResponseSpec {
            status: "200 OK",
            content_type: "application/x-ndjson",
            body: action_exit,
        },
        ResponseSpec {
            status: "200 OK",
            content_type: "application/zip",
            body: archive,
        },
    ]);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "action", "ses_cli", "observe", "--input", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"operator_data":"only"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "observed\n");
    let action_request = captured.recv().unwrap();
    let artifact_request = captured.recv().unwrap();
    server.join().unwrap();
    assert_eq!(action_request.path, "/v1/sessions/ses_cli/actions/observe");
    assert!(action_request.headers.contains("application/json"));
    let value: serde_json::Value = serde_json::from_slice(&action_request.body).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"schema_version":"1","input":{"operator_data":"only"}})
    );
    assert!(!String::from_utf8_lossy(&action_request.body).contains("source-only-on-start"));
    assert_eq!(artifact_request.path, "/v1/builds/bld_cli/artifacts.zip");
    let result = only_result(&state);
    assert_eq!(
        fs::read(result.join("artifacts").join(image_path)).unwrap(),
        image
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(result.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["action_id"], "act_cli");
    assert_eq!(provenance["artifact_restrictions"]["omitted_count"], 1);

    let final_archive = zip_artifact("final.txt", b"done");
    let stop_body = serde_json::to_vec(&serde_json::json!({
        "session_id":"ses_cli",
        "teardown":{"duration_ms":12,"exit_code":7,"timed_out":false},
        "artifacts":{"path":"/v1/builds/bld_final/artifacts.zip","size":final_archive.len()}
    }))
    .unwrap();
    let (endpoint, captured, server) = serve(vec![
        ResponseSpec {
            status: "200 OK",
            content_type: "application/json",
            body: stop_body,
        },
        ResponseSpec {
            status: "200 OK",
            content_type: "application/zip",
            body: final_archive,
        },
    ]);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "stop", "ses_cli"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    let delete = captured.recv().unwrap();
    let artifact = captured.recv().unwrap();
    server.join().unwrap();
    assert_eq!(
        (delete.method.as_str(), delete.path.as_str()),
        ("DELETE", "/v1/sessions/ses_cli")
    );
    assert_eq!(artifact.path, "/v1/builds/bld_final/artifacts.zip");
    let result = only_result(&state);
    assert_eq!(
        fs::read(result.join("artifacts/final.txt")).unwrap(),
        b"done"
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(result.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["teardown"]["exit_code"], 7);
    assert_eq!(provenance["status"], "failed");
}

#[test]
fn update_posts_explicit_deterministic_source_and_prints_only_revision() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let metadata = multipart_metadata(&request.body);
        let response = serde_json::to_vec(&serde_json::json!({
            "session_id":"ses_update",
            "update_id":"upd_1",
            "request_id":metadata["request_id"],
            "base_revision":"rev_4",
            "workspace_revision":"rev_5",
            "changed":[{"path":"changed.txt","sha256":format!("{:x}", Sha256::digest(b"changed\n"))}],
            "deleted":[{"path":"gone.txt","sha256":"b".repeat(64)}]
        }))
        .unwrap();
        request_tx.send(request).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .unwrap();
        stream.write_all(&response).unwrap();
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    fs::write(repo.path().join("changed.txt"), b"changed\n").unwrap();
    fs::write(repo.path().join("undeclared.txt"), b"secret").unwrap();
    let runtime_root = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
    let credentials = tempfile::tempdir_in(runtime_root).unwrap();
    let token = credentials.path().join("token");
    fs::write(&token, b"update-token").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["--token-file", token.to_str().unwrap()])
        .args([
            "session",
            "update",
            "ses_update",
            "--revision",
            "rev_4",
            "--file",
            "changed.txt",
            "--delete",
            "gone.txt",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"rev_5\n");
    let request = request_rx.recv().unwrap();
    server.join().unwrap();
    assert_eq!(
        (request.method.as_str(), request.path.as_str()),
        ("POST", "/v1/sessions/ses_update/updates")
    );
    assert!(request
        .headers
        .contains("authorization: Bearer update-token"));
    let metadata_position = request
        .body
        .windows(b"name=\"metadata\"".len())
        .position(|window| window == b"name=\"metadata\"")
        .unwrap();
    let source_position = request
        .body
        .windows(b"name=\"source\"".len())
        .position(|window| window == b"name=\"source\"")
        .unwrap();
    assert!(metadata_position < source_position);
    let metadata = multipart_metadata(&request.body);
    let request_id = metadata["request_id"].as_str().unwrap();
    assert!(!request_id.is_empty());
    assert_eq!(metadata["base_revision"], "rev_4");
    assert_eq!(metadata["changes"][0]["path"], "changed.txt");
    assert_eq!(metadata["changes"][1]["path"], "gone.txt");
    let zip_start = request
        .body
        .windows(4)
        .position(|window| window == b"PK\x03\x04")
        .unwrap();
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(&request.body[zip_start..])).unwrap();
    assert_eq!(archive.len(), 1);
    assert_eq!(archive.by_index(0).unwrap().name(), "changed.txt");
    assert!(archive.by_name("undeclared.txt").is_err());
    assert!(archive.by_name("gone.txt").is_err());

    let result = only_result(&state);
    let provenance_bytes = fs::read(result.join("provenance.json")).unwrap();
    let provenance: serde_json::Value = serde_json::from_slice(&provenance_bytes).unwrap();
    assert_eq!(provenance["operation"], "update");
    assert_eq!(provenance["request_id"], request_id);
    assert_eq!(provenance["base_revision"], "rev_4");
    assert_eq!(provenance["workspace_revision"], "rev_5");
    assert_eq!(provenance["update_id"], "upd_1");
    assert_eq!(provenance["source"]["mode"], "filesystem");
    assert_eq!(provenance["changed"][0]["path"], "changed.txt");
    assert_eq!(provenance["deleted"][0]["path"], "gone.txt");
    assert_eq!(provenance["metadata_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        provenance["source"]["archive_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(!String::from_utf8_lossy(&provenance_bytes).contains("undeclared.txt"));
    assert!(!String::from_utf8_lossy(&provenance_bytes).contains("update-token"));
}

#[test]
fn update_local_validation_prevents_network_and_conflict_surfaces_current_revision() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    fs::write(repo.path().join("same"), b"x").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "update",
            "ses_1",
            "--revision",
            "rev_0",
            "--file",
            "same",
            "--delete",
            "same",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cross-list"));
    assert!(matches!(listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock));

    drop(listener);
    let body = br#"{"error":"revision_conflict","current_revision":"rev_9"}"#.to_vec();
    let (endpoint, captured, server) = serve(vec![ResponseSpec {
        status: "409 Conflict",
        content_type: "application/json",
        body,
    }]);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    fs::write(repo.path().join("changed"), b"x").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "update",
            "ses_1",
            "--revision",
            "rev_0",
            "--file",
            "changed",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("current_revision=rev_9"));
    assert_eq!(captured.recv().unwrap().path, "/v1/sessions/ses_1/updates");
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "failed");
    assert_eq!(provenance["base_revision"], "rev_0");
    assert_eq!(provenance["source"]["mode"], "filesystem");
}

#[test]
fn update_structured_http_errors_are_actionable_and_preserve_evidence() {
    for (status, body, expected) in [
        (
            "400 Bad Request",
            br#"{"error":"invalid update"}"#.as_slice(),
            "rejected update metadata or source",
        ),
        (
            "404 Not Found",
            br#"{"error":"missing"}"#.as_slice(),
            "does not support source updates",
        ),
        (
            "413 Payload Too Large",
            br#"{"error":"too_large"}"#.as_slice(),
            "source-update limits",
        ),
        (
            "500 Internal Server Error",
            br#"{"error":"update_failed"}"#.as_slice(),
            "failed to apply the update",
        ),
    ] {
        let (endpoint, captured, server) = serve(vec![ResponseSpec {
            status,
            content_type: "application/json",
            body: body.to_vec(),
        }]);
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        write_config(&repo, &endpoint);
        fs::write(repo.path().join("changed"), b"x").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .args([
                "session",
                "update",
                "ses_error",
                "--revision",
                "rev_0",
                "--file",
                "changed",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            captured.recv().unwrap().path,
            "/v1/sessions/ses_error/updates"
        );
        server.join().unwrap();
        let provenance: serde_json::Value =
            serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(provenance["status"], "failed");
        assert!(!provenance["request_id"].as_str().unwrap().is_empty());
    }
}

#[test]
fn update_sigint_disconnects_without_stopping_and_preserves_retry_evidence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (received_tx, received_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut update, _) = listener.accept().unwrap();
        let request = read_request(&mut update);
        assert_eq!(request.path, "/v1/sessions/ses_interrupt/updates");
        received_tx.send(()).unwrap();
        update
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut remainder = Vec::new();
        assert_eq!(update.read_to_end(&mut remainder).unwrap(), 0);
        listener.set_nonblocking(true).unwrap();
        assert!(
            matches!(listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
        );
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    fs::write(repo.path().join("changed"), b"x").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "update",
            "ses_interrupt",
            "--revision",
            "rev_0",
            "--file",
            "changed",
        ])
        .spawn()
        .unwrap();
    received_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    assert_eq!(child.wait().unwrap().code(), Some(130));
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert_eq!(provenance["operation"], "update");
    assert!(!provenance["request_id"].as_str().unwrap().is_empty());
    assert_eq!(provenance["base_revision"], "rev_0");
    assert_eq!(provenance["changed"][0]["path"], "changed");
}

#[test]
fn update_transport_failure_preserves_generated_request_evidence() {
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", unavailable.local_addr().unwrap());
    drop(unavailable);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    fs::write(repo.path().join("changed"), b"x").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "update",
            "ses_transport",
            "--revision",
            "rev_0",
            "--file",
            "changed",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot reach endpoint"));
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "failed");
    assert!(!provenance["request_id"].as_str().unwrap().is_empty());
    assert_eq!(provenance["source"]["mode"], "filesystem");
    assert_eq!(provenance["metadata_sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn observed_start_id_is_stopped_and_preserved_on_later_stream_error() {
    let events = concat!(
        "{\"type\":\"session\",\"id\":\"ses_start_error\",\"status\":\"started\"}\n",
        "not-json\n"
    )
    .as_bytes()
    .to_vec();
    let stop = br#"{"session_id":"ses_start_error","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#.to_vec();
    let (endpoint, captured, server) = serve(vec![
        ResponseSpec {
            status: "200 OK",
            content_type: "application/x-ndjson",
            body: events,
        },
        ResponseSpec {
            status: "200 OK",
            content_type: "application/json",
            body: stop,
        },
    ]);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "start", "build"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let start = captured.recv().unwrap();
    let stop = captured.recv().unwrap();
    server.join().unwrap();
    assert_eq!(start.path, "/v1/sessions");
    assert_eq!(
        (stop.method.as_str(), stop.path.as_str()),
        ("DELETE", "/v1/sessions/ses_start_error")
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["session_id"], "ses_start_error");
    assert_eq!(provenance["cleanup_status"], "succeeded");
    assert_eq!(provenance["status"], "failed");
}

#[test]
fn start_final_provenance_failure_stops_ready_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let state_path = state.path().to_path_buf();
    let server = thread::spawn(move || {
        let (mut start, _) = listener.accept().unwrap();
        let request = read_request(&mut start);
        assert_eq!(request.path, "/v1/sessions");
        let started =
            b"{\"type\":\"session\",\"id\":\"ses_ready_persist\",\"status\":\"started\"}\n";
        write!(
            start,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            started.len()
        )
        .unwrap();
        start.write_all(started).unwrap();
        start.write_all(b"\r\n").unwrap();
        start.flush().unwrap();
        thread::sleep(Duration::from_millis(100));
        let provenance = walkdir::WalkDir::new(&state_path)
            .into_iter()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name() == "provenance.json")
            .unwrap()
            .into_path();
        fs::remove_file(&provenance).unwrap();
        fs::create_dir(&provenance).unwrap();
        let ready = b"{\"type\":\"ready\",\"session_id\":\"ses_ready_persist\"}\n";
        write!(start, "{:x}\r\n", ready.len()).unwrap();
        start.write_all(ready).unwrap();
        start.write_all(b"\r\n0\r\n\r\n").unwrap();
        start.flush().unwrap();
        let (mut stop, _) = listener.accept().unwrap();
        let request = read_request(&mut stop);
        assert_eq!(request.path, "/v1/sessions/ses_ready_persist");
        let body = br#"{"session_id":"ses_ready_persist","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#;
        write!(
            stop,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stop.write_all(body).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "start", "build"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("provenance persistence failed"));
    server.join().unwrap();
}

#[test]
fn start_sigint_before_ready_disconnects_and_records_interruption() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (started_tx, started_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut start, _) = listener.accept().unwrap();
        let request = read_request(&mut start);
        assert_eq!(request.path, "/v1/sessions");
        let event = b"{\"type\":\"session\",\"id\":\"ses_initializing\",\"status\":\"started\"}\n";
        write!(
            start,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            event.len()
        )
        .unwrap();
        start.write_all(event).unwrap();
        start.write_all(b"\r\n").unwrap();
        start.flush().unwrap();
        thread::sleep(Duration::from_millis(100));
        started_tx.send(()).unwrap();
        let (mut stop, _) = listener.accept().unwrap();
        let request = read_request(&mut stop);
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("DELETE", "/v1/sessions/ses_initializing")
        );
        let body = br#"{"session_id":"ses_initializing","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#;
        write!(
            stop,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stop.write_all(body).unwrap();
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "start", "build"])
        .spawn()
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    assert_eq!(child.wait().unwrap().code(), Some(130));
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert_eq!(provenance["session_id"], "ses_initializing");
    assert_eq!(provenance["cleanup_status"], "succeeded");
}

#[test]
fn start_sigint_before_any_id_records_unavailable_cleanup_without_delete() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (request_sender, request_receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut start, _) = listener.accept().unwrap();
        let request = read_request(&mut start);
        assert_eq!(request.path, "/v1/sessions");
        write!(
            start,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        start.flush().unwrap();
        request_sender.send(()).unwrap();
        let mut disconnected = Vec::new();
        start.read_to_end(&mut disconnected).unwrap();
        listener.set_nonblocking(true).unwrap();
        let err = listener.accept().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "start", "build"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    request_receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert!(provenance["session_id"].is_null());
    assert_eq!(
        provenance["cleanup_status"],
        "not attempted: session ID unavailable"
    );
}

#[test]
fn sigint_after_ready_before_transport_eof_wins_and_stops_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut start, _) = listener.accept().unwrap();
        let request = read_request(&mut start);
        assert_eq!(request.path, "/v1/sessions");
        let events = concat!(
            "{\"type\":\"session\",\"id\":\"ses_ready_race\",\"status\":\"started\"}\n",
            "{\"type\":\"ready\",\"session_id\":\"ses_ready_race\"}\n"
        )
        .as_bytes();
        write!(
            start,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            events.len()
        )
        .unwrap();
        start.write_all(events).unwrap();
        start.write_all(b"\r\n").unwrap();
        start.flush().unwrap();

        let (mut stop, _) = listener.accept().unwrap();
        let request = read_request(&mut stop);
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("DELETE", "/v1/sessions/ses_ready_race")
        );
        let body = br#"{"session_id":"ses_ready_race","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#;
        write!(
            stop,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stop.write_all(body).unwrap();
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "start", "build"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_session_id(&state, "ses_ready_race");
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert_eq!(provenance["session_id"], "ses_ready_race");
    assert_eq!(provenance["cleanup_status"], "succeeded");
}

#[test]
fn sigint_while_machine_id_output_is_blocked_stops_ready_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (cleanup_sender, cleanup_receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut start, _) = listener.accept().unwrap();
        let request = read_request(&mut start);
        assert_eq!(request.path, "/v1/sessions");
        let events = concat!(
            "{\"type\":\"session\",\"id\":\"ses_output_race\",\"status\":\"started\"}\n",
            "{\"type\":\"ready\",\"session_id\":\"ses_output_race\"}\n"
        );
        write!(
            start,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            events.len(),
            events
        )
        .unwrap();
        let (mut stop, _) = listener.accept().unwrap();
        let request = read_request(&mut stop);
        assert_eq!(request.path, "/v1/sessions/ses_output_race");
        let body = br#"{"session_id":"ses_output_race","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#;
        write!(
            stop,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stop.write_all(body).unwrap();
        cleanup_sender.send(()).unwrap();
    });
    let mut descriptors = [0; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    let mut read_pipe = unsafe { fs::File::from_raw_fd(descriptors[0]) };
    let mut write_pipe = unsafe { fs::File::from_raw_fd(descriptors[1]) };
    let write_flags = unsafe { libc::fcntl(descriptors[1], libc::F_GETFL) };
    assert!(write_flags >= 0);
    assert_eq!(
        unsafe {
            libc::fcntl(
                descriptors[1],
                libc::F_SETFL,
                write_flags | libc::O_NONBLOCK,
            )
        },
        0
    );
    let filler = [b'x'; 4096];
    let mut filled = 0usize;
    loop {
        match write_pipe.write(&filler) {
            Ok(written) => filled += written,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => panic!("failed to fill stdout pipe: {err}"),
        }
    }
    assert_eq!(
        unsafe { libc::fcntl(descriptors[1], libc::F_SETFL, write_flags) },
        0
    );
    let read_flags = unsafe { libc::fcntl(descriptors[0], libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(descriptors[0], libc::F_SETFL, read_flags | libc::O_NONBLOCK) },
        0
    );
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "start", "build"])
        .stdout(Stdio::from(write_pipe))
        .spawn()
        .unwrap();
    wait_for_status(&state, "ready");
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    cleanup_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("SIGINT was not synchronously elected before blocked ID output");
    assert_eq!(child.wait().unwrap().code(), Some(130));
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match read_pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => output.extend_from_slice(&buffer[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => panic!("failed to inspect stdout pipe: {err}"),
        }
    }
    assert_eq!(output.len(), filled);
    assert!(output.iter().all(|byte| *byte == b'x'));
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert_eq!(provenance["cleanup_status"], "succeeded");
}

#[test]
fn blocked_stdin_and_fifo_sigint_are_interruptible_and_record_cleanup_failures() {
    for (use_fifo, response_session, teardown, expected_cleanup) in [
        (
            false,
            "ses_blocked",
            serde_json::json!({"duration_ms":1,"exit_code":0,"timed_out":true}),
            "failed: teardown timed out",
        ),
        (
            true,
            "ses_blocked",
            serde_json::json!({"duration_ms":1,"exit_code":9,"timed_out":false}),
            "failed: teardown exit code 9",
        ),
        (
            false,
            "ses_wrong",
            serde_json::json!({"duration_ms":1,"exit_code":0,"timed_out":false}),
            "failed: stop response session identity mismatch",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stop, _) = listener.accept().unwrap();
            let request = read_request(&mut stop);
            assert_eq!(
                (request.method.as_str(), request.path.as_str()),
                ("DELETE", "/v1/sessions/ses_blocked")
            );
            let body = serde_json::to_vec(&serde_json::json!({
                "session_id":response_session,
                "teardown":teardown
            }))
            .unwrap();
            write!(
                stop,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stop.write_all(&body).unwrap();
        });
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        write_config(&repo, &endpoint);
        let input = if use_fifo {
            let fifo = repo.path().join("input.fifo");
            let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            fifo.display().to_string()
        } else {
            "-".to_string()
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_indentured"));
        command
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .args([
                "session",
                "action",
                "ses_blocked",
                "observe",
                "--input",
                &input,
            ]);
        if !use_fifo {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        let _stdin_guard = if use_fifo { None } else { child.stdin.take() };
        wait_for_status(&state, "reading_input");
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
        assert_eq!(child.wait().unwrap().code(), Some(130));
        server.join().unwrap();
        let provenance: serde_json::Value =
            serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(provenance["status"], "interrupted");
        assert!(provenance["cleanup_status"]
            .as_str()
            .unwrap()
            .contains(expected_cleanup));
        assert!(provenance["action_id"].is_null());
        assert!(provenance["errors"][0]
            .as_str()
            .unwrap()
            .contains(expected_cleanup));
    }
}

#[test]
fn action_sigint_disconnects_and_records_best_effort_stop() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (started_tx, started_rx) = mpsc::channel();
    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut action, _) = listener.accept().unwrap();
        request_tx.send(read_request(&mut action)).unwrap();
        let event = b"{\"type\":\"action\",\"session_id\":\"ses_interrupt\",\"action_id\":\"act_interrupt\",\"action\":\"observe\",\"status\":\"started\"}\n";
        write!(
            action,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            event.len()
        )
        .unwrap();
        action.write_all(event).unwrap();
        action.write_all(b"\r\n").unwrap();
        action.flush().unwrap();
        thread::sleep(Duration::from_millis(100));
        started_tx.send(()).unwrap();

        let (mut stop, _) = listener.accept().unwrap();
        request_tx.send(read_request(&mut stop)).unwrap();
        let body = br#"{"session_id":"ses_interrupt","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#;
        write!(
            stop,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stop.write_all(body).unwrap();
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let input = repo.path().join("input.json");
    fs::write(&input, "{}").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "action",
            "ses_interrupt",
            "observe",
            "--input",
            input.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(130));
    let action = request_rx.recv().unwrap();
    let stop = request_rx.recv().unwrap();
    server.join().unwrap();
    assert_eq!(action.path, "/v1/sessions/ses_interrupt/actions/observe");
    assert_eq!(
        (stop.method.as_str(), stop.path.as_str()),
        ("DELETE", "/v1/sessions/ses_interrupt")
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert_eq!(provenance["action_id"], "act_interrupt");
    assert_eq!(provenance["cleanup_status"], "succeeded");
}

#[test]
fn artifact_download_sigint_waits_for_final_eof_and_stops_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (download_tx, download_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut action, _) = listener.accept().unwrap();
        let request = read_request(&mut action);
        assert_eq!(request.path, "/v1/sessions/ses_download/actions/observe");
        let events = concat!(
            "{\"type\":\"action\",\"session_id\":\"ses_download\",\"action_id\":\"act_download\",\"action\":\"observe\",\"status\":\"started\"}\n",
            "{\"type\":\"exit\",\"session_id\":\"ses_download\",\"action_id\":\"act_download\",\"action\":\"observe\",\"code\":0,\"timed_out\":false,\"artifacts\":{\"path\":\"/v1/builds/bld_download/artifacts.zip\",\"size\":100}}\n"
        )
        .as_bytes();
        write!(
            action,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            events.len()
        )
        .unwrap();
        action.write_all(events).unwrap();
        action.write_all(b"\r\n").unwrap();
        action.flush().unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(
            matches!(listener.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
        );
        listener.set_nonblocking(false).unwrap();
        action.write_all(b"0\r\n\r\n").unwrap();
        action.flush().unwrap();

        let (mut artifact, _) = listener.accept().unwrap();
        let request = read_request(&mut artifact);
        assert_eq!(request.path, "/v1/builds/bld_download/artifacts.zip");
        artifact
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx")
            .unwrap();
        artifact.flush().unwrap();
        download_tx.send(()).unwrap();

        let (mut stop, _) = listener.accept().unwrap();
        let request = read_request(&mut stop);
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("DELETE", "/v1/sessions/ses_download")
        );
        let body = br#"{"session_id":"ses_download","teardown":{"duration_ms":1,"exit_code":0,"timed_out":false}}"#;
        write!(
            stop,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stop.write_all(body).unwrap();
    });
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let input = repo.path().join("input.json");
    fs::write(&input, "{}").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "action",
            "ses_download",
            "observe",
            "--input",
            input.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    download_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    assert_eq!(child.wait().unwrap().code(), Some(130));
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "interrupted");
    assert_eq!(provenance["action_id"], "act_download");
    assert_eq!(provenance["cleanup_status"], "succeeded");
    assert!(!only_result(&state).join("artifacts").exists());
}

#[test]
fn stop_preserves_timeout_and_configured_teardown_failure_outcomes() {
    for (teardown, exit_code, expected_error) in [
        (
            serde_json::json!({"duration_ms":5,"exit_code":0,"timed_out":true}),
            124,
            None,
        ),
        (
            serde_json::json!({"duration_ms":5,"timed_out":false,"error_code":"spawn_failed"}),
            1,
            Some("teardown failed: spawn_failed"),
        ),
    ] {
        let body = serde_json::to_vec(&serde_json::json!({
            "session_id":"ses_1",
            "teardown":teardown
        }))
        .unwrap();
        let (endpoint, _captured, server) = serve(vec![ResponseSpec {
            status: "200 OK",
            content_type: "application/json",
            body,
        }]);
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        write_config(&repo, &endpoint);
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["session", "stop", "ses_1"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit_code));
        if let Some(expected) = expected_error {
            assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        }
        server.join().unwrap();
        let provenance: serde_json::Value =
            serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(provenance["status"], "failed");
        assert_eq!(provenance["teardown"]["duration_ms"], 5);
    }
}

#[test]
fn events_after_final_exit_are_rejected_even_in_the_same_chunk() {
    let events = concat!(
        "{\"type\":\"action\",\"session_id\":\"ses_1\",\"action_id\":\"act_1\",\"action\":\"observe\",\"status\":\"started\"}\n",
        "{\"type\":\"exit\",\"session_id\":\"ses_1\",\"action_id\":\"act_1\",\"action\":\"observe\",\"code\":0,\"timed_out\":false}\n",
        "{\"type\":\"stdout\",\"data\":\"too late\"}\n"
    )
    .as_bytes()
    .to_vec();
    let (endpoint, _captured, server) = serve(vec![ResponseSpec {
        status: "200 OK",
        content_type: "application/x-ndjson",
        body: events,
    }]);
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let input = repo.path().join("input.json");
    fs::write(&input, "{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "action",
            "ses_1",
            "observe",
            "--input",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("after the exit event"));
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["action_id"], "act_1");
    assert_eq!(provenance["status"], "failed");
}

#[test]
fn action_id_survives_malformed_premature_and_artifact_failure_paths() {
    for (body, artifact_response) in [
        (
            concat!(
                "{\"type\":\"action\",\"session_id\":\"ses_error\",\"action_id\":\"act_error\",\"action\":\"observe\",\"status\":\"started\"}\n",
                "not-json\n"
            )
            .as_bytes()
            .to_vec(),
            None,
        ),
        (
            "{\"type\":\"action\",\"session_id\":\"ses_error\",\"action_id\":\"act_error\",\"action\":\"observe\",\"status\":\"started\"}\n"
                .as_bytes()
                .to_vec(),
            None,
        ),
        (
            concat!(
                "{\"type\":\"action\",\"session_id\":\"ses_error\",\"action_id\":\"act_error\",\"action\":\"observe\",\"status\":\"started\"}\n",
                "{\"type\":\"exit\",\"session_id\":\"ses_error\",\"action_id\":\"act_error\",\"action\":\"observe\",\"code\":0,\"timed_out\":false,\"artifacts\":{\"path\":\"/v1/builds/bad/artifacts.zip\",\"size\":1}}\n"
            )
            .as_bytes()
            .to_vec(),
            Some(b"x".to_vec()),
        ),
    ] {
        let mut responses = vec![ResponseSpec {
            status: "200 OK",
            content_type: "application/x-ndjson",
            body,
        }];
        if let Some(artifact) = artifact_response {
            responses.push(ResponseSpec {
                status: "200 OK",
                content_type: "application/zip",
                body: artifact,
            });
        }
        let (endpoint, _captured, server) = serve(responses);
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        write_config(&repo, &endpoint);
        let input = repo.path().join("input.json");
        fs::write(&input, "{}").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .args([
                "session",
                "action",
                "ses_error",
                "observe",
                "--input",
                input.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        server.join().unwrap();
        let provenance: serde_json::Value = serde_json::from_slice(
            &fs::read(only_result(&state).join("provenance.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(provenance["action_id"], "act_error");
        assert_eq!(provenance["status"], "failed");
    }
}

#[test]
fn action_id_survives_terminal_output_failure() {
    let events = concat!(
        "{\"type\":\"action\",\"session_id\":\"ses_output_error\",\"action_id\":\"act_output_error\",\"action\":\"observe\",\"status\":\"started\"}\n",
        "{\"type\":\"stdout\",\"data\":\"cannot-write\"}\n"
    )
    .as_bytes()
    .to_vec();
    let (endpoint, _captured, server) = serve(vec![ResponseSpec {
        status: "200 OK",
        content_type: "application/x-ndjson",
        body: events,
    }]);
    let mut descriptors = [0; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    unsafe { libc::close(descriptors[0]) };
    let write_pipe = unsafe { fs::File::from_raw_fd(descriptors[1]) };
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let input = repo.path().join("input.json");
    fs::write(&input, "{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "action",
            "ses_output_error",
            "observe",
            "--input",
            input.to_str().unwrap(),
        ])
        .stdout(Stdio::from(write_pipe))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    server.join().unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["action_id"], "act_output_error");
    assert_eq!(provenance["status"], "failed");
}

#[test]
fn fifo_client_config_is_rejected_promptly_without_a_writer() {
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let directory = repo.path().join(".indentured-server");
    fs::create_dir(&directory).unwrap();
    let config = directory.join("config.toml");
    let path = std::ffi::CString::new(config.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["session", "stop", "ses_1"])
        .spawn()
        .unwrap();
    let status = (0..200)
        .find_map(|_| {
            let status = child.try_wait().unwrap();
            if status.is_none() {
                thread::sleep(Duration::from_millis(10));
            }
            status
        })
        .unwrap_or_else(|| {
            child.kill().unwrap();
            panic!("FIFO client configuration was not rejected promptly")
        });
    assert_eq!(status.code(), Some(1));
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(provenance["status"], "failed");
    assert!(provenance["errors"][0]
        .as_str()
        .unwrap()
        .contains("client configuration must be a regular file"));
}

#[test]
fn session_config_disabled_errors_and_connection_fallback_preserve_evidence() {
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);
    for (config, expected_code, expected_error) in [
        (
            "[connection]\nenabled = false\n".to_string(),
            222,
            "disabled",
        ),
        (
            "[connection\nenabled = false\n".to_string(),
            1,
            "failed to load client configuration",
        ),
        (
            format!(
                "[connection]\nendpoint = \"http://{unavailable_address}\"\nlocal_fallback = true\n"
            ),
            222,
            "cannot reach endpoint",
        ),
    ] {
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let directory = repo.path().join(".indentured-server");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("config.toml"), config).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["session", "stop", "ses_1"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected_code));
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected_error));
        let provenance: serde_json::Value =
            serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(provenance["status"], "failed");
        assert!(!provenance["errors"].as_array().unwrap().is_empty());
    }
}

#[test]
fn provenance_rename_failure_prevents_success_exit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    write_config(&repo, &endpoint);
    let state_path = state.path().to_path_buf();
    let server = thread::spawn(move || {
        let (mut action, _) = listener.accept().unwrap();
        let request = read_request(&mut action);
        assert_eq!(request.path, "/v1/sessions/ses_1/actions/observe");
        let provenance = walkdir::WalkDir::new(&state_path)
            .into_iter()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name() == "provenance.json")
            .unwrap()
            .into_path();
        fs::remove_file(&provenance).unwrap();
        fs::create_dir(&provenance).unwrap();
        let events = concat!(
            "{\"type\":\"action\",\"session_id\":\"ses_1\",\"action_id\":\"act_1\",\"action\":\"observe\",\"status\":\"started\"}\n",
            "{\"type\":\"exit\",\"session_id\":\"ses_1\",\"action_id\":\"act_1\",\"action\":\"observe\",\"code\":0,\"timed_out\":false}\n"
        );
        write!(
            action,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            events.len(),
            events
        )
        .unwrap();
    });
    let input = repo.path().join("input.json");
    fs::write(&input, "{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "session",
            "action",
            "ses_1",
            "observe",
            "--input",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("provenance persistence failed"));
    server.join().unwrap();
}

#[test]
fn old_server_conflict_and_missing_session_diagnostics_are_actionable() {
    for (command, status, body, expected, exit_code) in [
        (
            vec!["session", "start", "build"],
            "404 Not Found",
            b"not found".as_slice(),
            "server does not support managed sessions",
            1,
        ),
        (
            vec!["session", "action", "ses_1", "observe", "--input", "INPUT"],
            "409 Conflict",
            b"session_conflict".as_slice(),
            "session is busy or terminating",
            1,
        ),
        (
            vec!["session", "stop", "ses_1"],
            "404 Not Found",
            b"session_not_found".as_slice(),
            "session is missing or expired",
            1,
        ),
        (
            vec!["session", "action", "ses_1", "observe", "--input", "INPUT"],
            "408 Request Timeout",
            b"session_lifetime".as_slice(),
            "action timed out",
            124,
        ),
        (
            vec!["session", "stop", "ses_1"],
            "401 Unauthorized",
            b"unauthorized".as_slice(),
            "authentication failed",
            1,
        ),
        (
            vec!["session", "start", "build"],
            "503 Service Unavailable",
            b"busy".as_slice(),
            "server capacity is busy",
            1,
        ),
    ] {
        let (endpoint, _captured, server) = serve(vec![ResponseSpec {
            status,
            content_type: "text/plain",
            body: body.to_vec(),
        }]);
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        write_config(&repo, &endpoint);
        let input = repo.path().join("input.json");
        fs::write(&input, "{}").unwrap();
        let args: Vec<String> = command
            .into_iter()
            .map(|argument| {
                if argument == "INPUT" {
                    input.display().to_string()
                } else {
                    argument.to_string()
                }
            })
            .collect();
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("XDG_STATE_HOME", state.path())
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit_code));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        server.join().unwrap();
        let provenance: serde_json::Value =
            serde_json::from_slice(&fs::read(only_result(&state).join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(provenance["status"], "failed");
        if exit_code == 124 {
            assert_eq!(provenance["timed_out"], true);
        }
        assert!(!provenance["errors"].as_array().unwrap().is_empty());
    }
}
