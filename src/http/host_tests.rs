use super::*;
use std::io::{Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use tempfile::TempDir;

struct Fixture {
    state: AppState,
    listener: UnixListener,
    _temp: TempDir,
}
impl Fixture {
    fn new(enabled: bool, mutate: impl FnOnce(&mut Config)) -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = UnixListener::bind(root.join("broker.sock")).unwrap();
        std::fs::set_permissions(
            root.join("broker.sock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let mut config: Config = toml::from_str("schema_version = '12'").unwrap();
        config.build.workspace_root = root.join("workspaces");
        config.artifacts.storage_root = root.join("artifacts");
        config.host_observation = crate::config::HostObservationConfig {
            enabled,
            socket: Some(root.join("broker.sock")),
            peer_uid: Some(unsafe { libc::geteuid() }),
        };
        mutate(&mut config);
        crate::artifacts::prepare_artifact_storage_root(&config.artifacts.storage_root).unwrap();
        let config = Arc::new(config);
        let state = AppState {
            config: config.clone(),
            auth: Arc::new(AuthSecrets {
                digests: vec![Sha256::digest(b"host-test-token").into()],
            }),
            auth_required: true,
            build_slots: Arc::new(Semaphore::new(0)), // All build capacity occupied.
            host_slots: Arc::new(Semaphore::new(1)),
            sessions: SessionManager::new_disabled(config),
            managed_sessions_enabled: false,
        };
        Self {
            state,
            listener,
            _temp: temp,
        }
    }
    fn no_connection(&self) {
        self.listener.set_nonblocking(true).unwrap();
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer host-test-token"),
    );
    headers
}
fn broker_archive(images: bool, denied: bool) -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema_version":"1", "observation_id":"host-11111111-1111-4111-8111-111111111111",
        "captured_at":"2026-01-01T00:00:00Z", "status":if denied {"failed"} else {"succeeded"},
        "inventory":{"applications":[],"windows":[],"displays":[]},
        "images":if images {serde_json::json!([{"path":"image-0000.png","display_id":123}])} else {serde_json::json!([])},
        "errors":if denied {vec!["Screen Recording denied"]} else {vec![]},
    });
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().unix_permissions(0o600);
    zip.start_file("manifest.json", options).unwrap();
    zip.write_all(&serde_json::to_vec(&manifest).unwrap())
        .unwrap();
    if images {
        zip.start_file("image-0000.png", options).unwrap();
        zip.write_all(include_bytes!("../../tests/fixtures/host-observation.png"))
            .unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn broker(
    listener: UnixListener,
    archive: Vec<u8>,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<std::sync::mpsc::Receiver<()>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(
            unsafe { libc::poll(&mut poll, 1, 12000) } > 0,
            "broker never contacted"
        );
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut request = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut request).unwrap();
        host_observation::parse_request(&request).unwrap();
        if let Some(ready) = ready {
            ready.send(()).unwrap();
        }
        if let Some(release) = release {
            release.recv_timeout(Duration::from_secs(10)).unwrap();
        }
        stream
            .write_all(&(archive.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&archive).unwrap();
    })
}
async fn json(response: Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn authorization_disable_and_strict_body_precede_broker_access() {
    let fixture = Fixture::new(false, |_| {});
    assert_eq!(
        observe(
            State(fixture.state.clone()),
            HeaderMap::new(),
            Body::from("bad")
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        observe(State(fixture.state.clone()), headers(), Body::from("bad"))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        artifact(
            State(fixture.state.clone()),
            headers(),
            AxumPath("host-11111111-1111-4111-8111-111111111111".into())
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    fixture.no_connection();
    let fixture = Fixture::new(true, |_| {});
    for body in [
        "bad".into(),
        "[]".into(),
        "{\"operation\":\"list\",\"task\":\"host_observation\"}".into(),
        "{\"operation\":\"list\",\"source\":{}}".into(),
        "x".repeat(4097),
    ] {
        assert_eq!(
            observe(State(fixture.state.clone()), headers(), Body::from(body))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::<
        std::result::Result<Bytes, io::Error>,
    >::new(tokio::sync::mpsc::channel(1).1));
    // A closed stream is an invalid empty request, never a broker operation.
    assert_eq!(
        observe(State(fixture.state.clone()), headers(), body)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    fixture.no_connection();
}

#[tokio::test]
async fn list_capture_and_artifacts_are_independent_of_build_slots_and_tasks() {
    for images in [false, true] {
        let fixture = Fixture::new(true, |_| {});
        assert!(fixture.state.config.tasks.is_empty());
        let worker = broker(
            fixture.listener.try_clone().unwrap(),
            broker_archive(images, false),
            None,
            None,
        );
        let response = observe(
            State(fixture.state.clone()),
            headers(),
            Body::from(if images {
                r#"{"operation":"capture","target":{"target":"desktop"}}"#
            } else {
                r#"{"operation":"list"}"#
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: ObservationResponse = serde_json::from_value(json(response).await).unwrap();
        assert_eq!(
            response.manifest.status, "succeeded",
            "{:?}",
            response.manifest.errors
        );
        worker.join().unwrap();
        let id = response.manifest.observation_id;
        assert_ne!(
            id, "host-11111111-1111-4111-8111-111111111111",
            "daemon must assign fresh identity"
        );
        assert_eq!(response.manifest.status, "succeeded");
        assert_eq!(
            response.artifacts.unwrap().path,
            format!("/v1/host/observations/{id}/artifacts.zip")
        );
        assert_eq!(
            artifact(
                State(fixture.state.clone()),
                HeaderMap::new(),
                AxumPath(id.clone())
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            super::super::get_artifact(
                State(fixture.state.clone()),
                headers(),
                AxumPath(id.clone())
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        for invalid in [
            "../escape",
            "bld_11111111111111111111111111111111",
            "host-INVALID",
        ] {
            assert_eq!(
                artifact(
                    State(fixture.state.clone()),
                    headers(),
                    AxumPath(invalid.into())
                )
                .await
                .status(),
                StatusCode::NOT_FOUND
            );
        }
        let download = artifact(
            State(fixture.state.clone()),
            headers(),
            AxumPath(id.clone()),
        )
        .await;
        assert_eq!(download.status(), StatusCode::OK);
        let bytes = to_bytes(download.into_body(), 1024 * 1024).await.unwrap();
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        if images {
            let mut bytes = Vec::new();
            zip.by_name(&format!("observations/{id}/image-0000.png"))
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(
                bytes,
                include_bytes!("../../tests/fixtures/host-observation.png")
            );
        }
        let mut disabled = fixture.state.clone();
        Arc::make_mut(&mut disabled.config).host_observation.enabled = false;
        assert_eq!(
            artifact(State(disabled), headers(), AxumPath(id))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn closed_broker_connection_reports_daemon_uid_and_helper_log_guidance() {
    let fixture = Fixture::new(true, |_| {});
    let listener = fixture.listener.try_clone().unwrap();
    let worker = std::thread::spawn(move || {
        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut poll, 1, 12000) } > 0);
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut request = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut request).unwrap();
        // Simulate a broker closing without returning a response. The daemon
        // may offer provisioning guidance but must not claim it knows why.
    });
    let response = observe(
        State(fixture.state),
        headers(),
        Body::from(r#"{"operation":"list"}"#),
    )
    .await;
    worker.join().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = json(response).await;
    assert_eq!(response["manifest"]["status"], "failed");
    assert!(response["manifest"]["images"]
        .as_array()
        .unwrap()
        .is_empty());
    let error = response["manifest"]["errors"][0].as_str().unwrap();
    assert!(error.contains("broker connection closed"), "{error}");
    assert!(error.contains("inspect the GUI helper log"), "{error}");
    assert!(
        error.contains(&format!(
            "--allow-uid matches the daemon service UID ({})",
            unsafe { libc::geteuid() }
        )),
        "{error}"
    );
}

#[tokio::test]
async fn missing_denied_wrong_uid_and_artifact_policy_are_explicit() {
    for case in 0..5 {
        let fixture = Fixture::new(true, |config| match case {
            0 => {
                config.host_observation.socket =
                    Some(config.build.workspace_root.join("missing.sock"))
            }
            1 => {
                config.host_observation.peer_uid = Some(unsafe { libc::geteuid() }.wrapping_add(1))
            }
            3 => config.artifacts.restricted_patterns = vec!["**/*.png".into()],
            4 => config.artifacts.max_transfer_bytes = 1,
            _ => {}
        });
        let worker = if case >= 2 {
            Some(broker(
                fixture.listener.try_clone().unwrap(),
                broker_archive(case != 2, case == 2),
                None,
                None,
            ))
        } else {
            None
        };
        let response = observe(
            State(fixture.state.clone()),
            headers(),
            Body::from(r#"{"operation":"list"}"#),
        )
        .await;
        if case == 4 {
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        } else {
            let response: ObservationResponse =
                serde_json::from_value(json(response).await).unwrap();
            if case < 3 {
                assert_eq!(response.manifest.status, "failed");
                assert!(response.manifest.images.is_empty());
                assert!(!response.manifest.errors.is_empty());
            } else {
                assert_eq!(response.artifact_restrictions.unwrap().omitted_count, 1);
            }
        }
        if let Some(worker) = worker {
            worker.join().unwrap();
        } else {
            fixture.no_connection();
        }
    }
}

#[tokio::test]
async fn disconnect_does_not_release_admission_until_blocking_broker_finishes() {
    let fixture = Fixture::new(true, |_| {});
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = broker(
        fixture.listener.try_clone().unwrap(),
        broker_archive(false, false),
        Some(ready_tx),
        Some(release_rx),
    );
    let request = tokio::spawn(observe(
        State(fixture.state.clone()),
        headers(),
        Body::from(r#"{"operation":"list"}"#),
    ));
    tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .unwrap()
        .unwrap();
    request.abort();
    let _ = request.await;
    assert_eq!(
        observe(
            State(fixture.state.clone()),
            headers(),
            Body::from(r#"{"operation":"list"}"#)
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    let permit = tokio::time::timeout(Duration::from_secs(10), fixture.state.host_slots.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(permit);
}

#[tokio::test]
async fn stalled_body_has_absolute_timeout_without_broker_access() {
    let fixture = Fixture::new(true, |_| {});
    let (sender, receiver) = tokio::sync::mpsc::channel::<std::result::Result<Bytes, io::Error>>(1);
    sender.send(Ok(Bytes::from_static(b"{"))).await.unwrap();
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver));
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        observe(State(fixture.state.clone()), headers(), body),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    drop(sender);
    fixture.no_connection();
}

#[tokio::test]
async fn protected_control_socket_uses_existing_filesystem_authority() {
    let mut fixture = Fixture::new(true, |_| {});
    fixture.state.auth_required = false; // The run_uds transport sets this.
    let worker = broker(
        fixture.listener.try_clone().unwrap(),
        broker_archive(false, false),
        None,
        None,
    );
    let response = observe(
        State(fixture.state.clone()),
        HeaderMap::new(),
        Body::from(r#"{"operation":"list"}"#),
    )
    .await;
    assert_eq!(json(response).await["manifest"]["status"], "succeeded");
    worker.join().unwrap();
}
