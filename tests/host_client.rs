use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpListener;
use std::process::Command;

const ID: &str = "host-11111111-1111-4111-8111-111111111111";
fn read_request(stream: &mut impl Read) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut size = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header == "\r\n" {
            break;
        }
        assert!(!header.is_empty());
        if let Some(length) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            size = length.trim().parse().unwrap();
        }
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).unwrap();
    (line, bytes)
}
fn respond(stream: &mut impl Write, bytes: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .unwrap();
    stream.write_all(bytes).unwrap();
}
fn manifest() -> serde_json::Value {
    serde_json::json!({"schema_version":"1", "observation_id":ID, "captured_at":"2026-01-01T00:00:00Z", "status":"succeeded", "inventory":{"applications":[],"windows":[],"displays":[]}, "images":[{"path":format!("observations/{ID}/image-0000.png"), "display_id":123},{"path":format!("observations/{ID}/image-0001.png"), "display_id":124}], "errors":[]})
}
fn archive() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().unix_permissions(0o600);
    for index in 0..2 {
        zip.start_file(format!("observations/{ID}/image-{index:04}.png"), options)
            .unwrap();
        zip.write_all(include_bytes!("fixtures/host-observation.png"))
            .unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn client(
    endpoint: &str,
    cwd: &std::path::Path,
    results: &std::path::Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(cwd)
        .env_remove("INDENTURED_SERVER_TOKEN_FILE")
        .env("INDENTURED_SERVER_ENABLED", "true")
        .args(["--endpoint", endpoint, "host", "--result-root"])
        .arg(results)
        .args(["capture", "desktop"])
        .output()
        .unwrap()
}

#[test]
fn host_help_explains_targets_and_local_images() {
    for (args, expected) in [
        (
            vec!["host", "--help"],
            vec!["List graphical", "absolute local PNG paths"],
        ),
        (
            vec!["host", "capture", "--help"],
            vec!["logical display", "eligible windows", "owner PID"],
        ),
        (
            vec!["host", "capture", "application", "--help"],
            vec!["inventory.applications[].pid", "fresh host list"],
        ),
        (
            vec!["host", "capture", "window", "--help"],
            vec![
                "Owner PID",
                "inventory.windows[].window_id",
                "fresh host list",
            ],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        for text in expected {
            assert!(help.contains(text), "missing {text:?}: {help}");
        }
    }
}

#[test]
fn host_connection_diagnostics_ignore_project_config_and_preserve_disabled_exit_code() {
    let cwd = tempfile::tempdir().unwrap();
    fs::create_dir(cwd.path().join(".indentured-server")).unwrap();
    fs::write(
        cwd.path().join(".indentured-server/config.toml"),
        "invalid project config",
    )
    .unwrap();
    let results = cwd.path().join("must-not-be-created");
    for enabled in ["true", "0", "false"] {
        let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(cwd.path())
            .env_remove("INDENTURED_SERVER_ENDPOINT")
            .env_remove("INDENTURED_SERVER_TOKEN_FILE")
            .env("INDENTURED_SERVER_ENABLED", enabled)
            .args(["host", "--result-root"])
            .arg(&results)
            .arg("list")
            .output()
            .unwrap();
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(output.stdout.is_empty());
        assert!(!results.exists());
        if enabled == "true" {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                error.contains("--endpoint or INDENTURED_SERVER_ENDPOINT"),
                "{error}"
            );
            assert!(error.contains("ignore project configuration"), "{error}");
            assert!(!error.contains("or client config"), "{error}");
        } else {
            assert_eq!(output.status.code(), Some(222));
            assert!(
                error.contains("disabled (INDENTURED_SERVER_ENABLED)"),
                "{error}"
            );
        }
    }
}

#[test]
fn missing_host_route_explains_daemon_version_without_masking_disabled_error() {
    for body in ["", " \n", "{\"error\":\"host_observation_disabled\"}"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let cwd = tempfile::tempdir().unwrap();
        let results = tempfile::tempdir().unwrap();
        let output = client(&endpoint, cwd.path(), results.path());
        worker.join().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        if body.trim().is_empty() {
            assert!(error.contains("verify the endpoint URL"), "{error}");
            assert!(
                error.contains("daemon version supports host observation"),
                "{error}"
            );
        } else {
            assert!(error.contains("host_observation_disabled"), "{error}");
            assert!(!error.contains("daemon version"), "{error}");
        }
    }
}

#[test]
fn host_artifact_redirects_are_not_followed_even_on_the_same_origin() {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    for cross_origin in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let redirect = if cross_origin {
            format!("http://{}/unexpected.zip", trap.local_addr().unwrap())
        } else {
            "/unexpected.zip".to_string()
        };
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let response = serde_json::json!({"manifest":manifest(), "artifacts":{"path":format!("/v1/host/observations/{ID}/artifacts.zip"),"size":archive().len()}, "artifact_restrictions":null});
            respond(&mut stream, &serde_json::to_vec(&response).unwrap());
            let (mut stream, _) = listener.accept().unwrap();
            let (line, _) = read_request(&mut stream);
            assert_eq!(
                line,
                format!("GET /v1/host/observations/{ID}/artifacts.zip HTTP/1.1\r\n")
            );
            write!(stream, "HTTP/1.1 302 Found\r\nLocation: {redirect}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            listener
        });
        let cwd = tempfile::tempdir().unwrap();
        let results = tempfile::tempdir().unwrap();
        let output = client(&endpoint, cwd.path(), results.path());
        let listener = worker.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("artifact download failed 302"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            trap.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let directory = fs::read_dir(results.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(!directory.join("manifest.json").exists());
        assert!(!directory.join("artifacts").exists());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(directory.join("result.json")).unwrap()
            )
            .unwrap()["status"],
            "failed"
        );
    }
}

#[test]
fn client_ignores_projects_and_downloads_real_png_without_uploading() {
    for broken_project in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let archive = archive();
            let response = serde_json::json!({"manifest":manifest(), "artifacts":{"path":format!("/v1/host/observations/{ID}/artifacts.zip"),"size":archive.len()}, "artifact_restrictions":null});
            let (mut stream, _) = listener.accept().unwrap();
            let (line, body) = read_request(&mut stream);
            assert_eq!(line, "POST /v1/host/observations HTTP/1.1\r\n");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"operation":"capture","target":{"target":"desktop"}})
            );
            respond(&mut stream, &serde_json::to_vec(&response).unwrap());
            let (mut stream, _) = listener.accept().unwrap();
            let (line, body) = read_request(&mut stream);
            assert_eq!(
                line,
                format!("GET /v1/host/observations/{ID}/artifacts.zip HTTP/1.1\r\n")
            );
            assert!(body.is_empty());
            respond(&mut stream, &archive);
        });
        let cwd = tempfile::tempdir().unwrap();
        let results = tempfile::tempdir().unwrap();
        if broken_project {
            fs::create_dir(cwd.path().join(".indentured-server")).unwrap();
            fs::write(
                cwd.path().join(".indentured-server/config.toml"),
                "invalid project config",
            )
            .unwrap();
            fs::write(cwd.path().join("source-canary"), "must not upload").unwrap();
        }
        let output = client(&endpoint, cwd.path(), results.path());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        worker.join().unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["images"].as_array().unwrap().len(), 2);
        for image in report["images"].as_array().unwrap() {
            let path = std::path::Path::new(image["local_path"].as_str().unwrap());
            assert!(path.is_absolute());
            assert_eq!(
                fs::read(path).unwrap(),
                include_bytes!("fixtures/host-observation.png")
            );
        }
        let directory = fs::read_dir(results.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::read(
                directory
                    .join("artifacts")
                    .join(format!("observations/{ID}/image-0000.png"))
            )
            .unwrap(),
            include_bytes!("fixtures/host-observation.png")
        );
        assert!(!directory.join("source-manifest.json").exists());
        assert!(!directory.join("provenance.json").exists());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(directory.join("result.json")).unwrap()
            )
            .unwrap()["status"],
            "succeeded"
        );
    }
}

#[test]
fn client_refuses_arbitrary_artifact_urls_and_paths() {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    for path in [
        format!("http://{}/stolen", trap.local_addr().unwrap()),
        "/v1/builds/bld_fake/artifacts.zip".into(),
        format!("/v1/host/observations/{ID}/../artifacts.zip"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, &serde_json::to_vec(&serde_json::json!({"manifest":manifest(), "artifacts":{"path":path,"size":1}, "artifact_restrictions":null})).unwrap());
        });
        let cwd = tempfile::tempdir().unwrap();
        let results = tempfile::tempdir().unwrap();
        let output = client(&endpoint, cwd.path(), results.path());
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid host artifact path"));
        worker.join().unwrap();
        assert_eq!(
            trap.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn host_client_supports_protected_unix_endpoint_without_a_project() {
    let directory = tempfile::tempdir().unwrap();
    let results = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (line, body) = read_request(&mut stream);
        assert_eq!(line, "POST /v1/host/observations HTTP/1.1\r\n");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"operation":"list"})
        );
        let mut manifest = manifest();
        manifest["images"] = serde_json::json!([]);
        respond(&mut stream, &serde_json::to_vec(&serde_json::json!({"manifest":manifest,"artifacts":null,"artifact_restrictions":null})).unwrap());
    });
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(directory.path())
        .env_remove("INDENTURED_SERVER_TOKEN_FILE")
        .env("INDENTURED_SERVER_ENABLED", "true")
        .args([
            "--endpoint",
            &format!("unix://{}", socket.display()),
            "host",
            "list",
            "--result-root",
        ])
        .arg(results.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    worker.join().unwrap();
}

#[test]
fn no_success_or_local_paths_are_emitted_on_download_png_or_restriction_failure() {
    for failure in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let options = zip::write::SimpleFileOptions::default().unix_permissions(0o600);
            for index in 0..2 {
                zip.start_file(format!("observations/{ID}/image-{index:04}.png"), options)
                    .unwrap();
                if failure == 0 && index == 1 {
                    zip.write_all(b"not a PNG").unwrap();
                } else {
                    zip.write_all(include_bytes!("fixtures/host-observation.png"))
                        .unwrap();
                }
            }
            let archive = zip.finish().unwrap().into_inner();
            let restrictions = if failure == 2 {
                serde_json::json!({"omitted_count":1,"matched_patterns":["**/*.png"]})
            } else {
                serde_json::Value::Null
            };
            let response = serde_json::json!({"manifest":manifest(), "artifacts":{"path":format!("/v1/host/observations/{ID}/artifacts.zip"),"size":archive.len()}, "artifact_restrictions":restrictions});
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, &serde_json::to_vec(&response).unwrap());
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            if failure == 1 {
                stream
                    .write_all(
                        b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            } else {
                respond(&mut stream, &archive);
            }
        });
        let cwd = tempfile::tempdir().unwrap();
        let results = tempfile::tempdir().unwrap();
        let output = client(&endpoint, cwd.path(), results.path());
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "success/paths leaked before validation"
        );
        worker.join().unwrap();
        let directory = fs::read_dir(results.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(!directory.join("manifest.json").exists());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(directory.join("result.json")).unwrap()
            )
            .unwrap()["status"],
            "failed"
        );
    }
}
