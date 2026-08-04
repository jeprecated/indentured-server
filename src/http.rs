use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, Multipart, Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::{Stream, StreamExt};
use tokio_util::io::ReaderStream;
use tracing::{error, warn};

use crate::bearer_token::{BearerToken, MAX_BEARER_TOKEN_FILE_BYTES};
use crate::build::{execute_build, validate_request, CancellationFlag};
use crate::config::{Config, SocketModeError};
use crate::protocol::{
    parse_request_metadata, parse_session_action_request, parse_session_start_metadata,
    valid_session_id, valid_task_id, MAX_SESSION_ACTION_BODY_BYTES,
};
use crate::sessions::{ActionError, SessionManager, StopError};
use crate::user::UserError;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("http server failed: {0}")]
    Serve(String),

    #[error("tls configuration error: {0}")]
    Tls(String),

    #[error("invalid socket mode: {0}")]
    SocketMode(#[from] SocketModeError),

    #[error("group lookup failed: {0}")]
    GroupLookup(#[from] UserError),

    #[error("credential configuration error: {0}")]
    Credential(String),
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    auth: Arc<AuthSecrets>,
    auth_required: bool,
    build_slots: Arc<Semaphore>,
    sessions: SessionManager,
    managed_sessions_enabled: bool,
}

struct AuthSecrets {
    digests: Vec<[u8; 32]>,
}

struct BuildEventStream {
    receiver: mpsc::Receiver<crate::protocol::ResponseEvent>,
    cancellation: CancellationFlag,
}

struct SessionEventStream {
    receiver: mpsc::Receiver<crate::protocol::SessionStartEvent>,
    sessions: SessionManager,
    session_id: String,
}

struct SessionActionEventStream {
    receiver: mpsc::Receiver<crate::protocol::SessionActionStreamItem>,
    sessions: SessionManager,
    session_id: String,
    action_id: String,
    pending_ack: Option<std::sync::mpsc::SyncSender<bool>>,
}

impl Stream for BuildEventStream {
    type Item = crate::protocol::ResponseEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

impl Drop for BuildEventStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Stream for SessionEventStream {
    type Item = crate::protocol::SessionStartEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

impl Drop for SessionEventStream {
    fn drop(&mut self) {
        self.sessions.disconnect(&self.session_id);
    }
}

impl Stream for SessionActionEventStream {
    type Item = crate::protocol::SessionActionEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(ack) = self.pending_ack.take() {
            let accepted = self
                .sessions
                .acknowledge_action_delivery(&self.session_id, &self.action_id);
            let _ = ack.send(accepted);
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(item)) => {
                self.pending_ack = item.final_ack;
                Poll::Ready(Some(item.event))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SessionActionEventStream {
    fn drop(&mut self) {
        self.sessions
            .disconnect_action(&self.session_id, &self.action_id);
    }
}

impl std::fmt::Debug for AuthSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSecrets")
            .field("credential_count", &self.digests.len())
            .finish()
    }
}

impl AuthSecrets {
    fn empty() -> Self {
        Self {
            digests: Vec::new(),
        }
    }

    #[cfg(test)]
    fn load(paths: &[PathBuf], task_uid: Option<u32>) -> Result<Self, HttpError> {
        Self::load_with_groups(paths, task_uid, &[])
    }

    fn load_with_groups(
        paths: &[PathBuf],
        task_uid: Option<u32>,
        task_group_ids: &[u32],
    ) -> Result<Self, HttpError> {
        let daemon_uid = unsafe { libc::geteuid() };
        let mut digests = Vec::with_capacity(paths.len());
        for path in paths {
            validate_credential_parent(path, daemon_uid, task_uid, task_group_ids)?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| {
                    HttpError::Credential(format!("cannot open credential file {path:?}"))
                })?;
            let metadata = file.metadata().map_err(|_| {
                HttpError::Credential(format!("cannot inspect credential file {path:?}"))
            })?;
            if !metadata.is_file()
                || metadata.uid() != daemon_uid
                || metadata.permissions().mode() & 0o077 != 0
                || task_uid.is_some_and(|uid| metadata.uid() == uid)
            {
                return Err(HttpError::Credential(format!(
                    "credential file {path:?} must be regular, daemon-owned, and inaccessible to the task identity"
                )));
            }
            if metadata.len() == 0 || metadata.len() > MAX_BEARER_TOKEN_FILE_BYTES as u64 {
                return Err(HttpError::Credential(format!(
                    "credential file {path:?} must contain 1-4096 bytes"
                )));
            }
            let mut raw =
                Vec::with_capacity((metadata.len() as usize).min(MAX_BEARER_TOKEN_FILE_BYTES + 1));
            Read::by_ref(&mut file)
                .take((MAX_BEARER_TOKEN_FILE_BYTES + 1) as u64)
                .read_to_end(&mut raw)
                .map_err(|_| {
                    HttpError::Credential(format!("cannot read credential file {path:?}"))
                })?;
            if raw.len() > MAX_BEARER_TOKEN_FILE_BYTES {
                raw.fill(0);
                return Err(HttpError::Credential(format!(
                    "credential file {path:?} must contain 1-4096 bytes"
                )));
            }
            let digest = match BearerToken::parse_file(&raw) {
                Ok(token) => Sha256::digest(token.as_bytes()).into(),
                Err(_) => {
                    raw.fill(0);
                    return Err(HttpError::Credential(format!(
                        "credential file {path:?} must contain one RFC 6750 b64token line"
                    )));
                }
            };
            digests.push(digest);
            raw.fill(0);
        }
        Ok(Self { digests })
    }

    fn matches(&self, token: &[u8]) -> bool {
        let candidate: [u8; 32] = Sha256::digest(token).into();
        let mut matched = subtle::Choice::from(0);
        for digest in &self.digests {
            matched |= digest.ct_eq(&candidate);
        }
        bool::from(matched)
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_task_group_ids(stdout: &[u8], primary_gid: u32) -> Result<Vec<u32>, HttpError> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| HttpError::Credential("task groups are malformed".to_string()))?;
    let mut groups = stdout
        .split_ascii_whitespace()
        .map(|group| {
            group
                .parse::<u32>()
                .map_err(|_| HttpError::Credential("task groups are malformed".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if groups.is_empty() {
        return Err(HttpError::Credential(
            "task groups are malformed".to_string(),
        ));
    }
    if !groups.contains(&primary_gid) {
        groups.push(primary_gid);
    }
    Ok(groups)
}

fn resolved_task_group_ids(
    username: Option<&str>,
    primary_gid: Option<u32>,
) -> Result<Vec<u32>, HttpError> {
    #[cfg(target_os = "macos")]
    {
        let username = username.ok_or_else(|| {
            HttpError::Credential("cannot resolve task groups without a task user".to_string())
        })?;
        let primary_gid = primary_gid.ok_or_else(|| {
            HttpError::Credential("cannot resolve task groups without a primary group".to_string())
        })?;
        let output = Command::new("/usr/bin/id")
            .args(["-G", username])
            .env_clear()
            .output()
            .map_err(|_| HttpError::Credential("cannot inspect task groups".to_string()))?;
        if !output.status.success() {
            return Err(HttpError::Credential(
                "cannot inspect task groups".to_string(),
            ));
        }
        parse_task_group_ids(&output.stdout, primary_gid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (username, primary_gid);
        Ok(Vec::new())
    }
}

#[derive(Clone, Copy)]
struct RuntimeAuthorityMetadata {
    is_symlink: bool,
    is_directory: bool,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
}

fn is_trusted_runtime_authority(
    authority: &Path,
    metadata: RuntimeAuthorityMetadata,
    task_uid: Option<u32>,
    task_group_ids: &[u32],
    macos: bool,
) -> bool {
    (authority == Path::new("/var/run") && metadata.is_symlink)
        || (macos
            && authority == Path::new("/private/var/run")
            && !metadata.is_symlink
            && metadata.is_directory
            && metadata.owner_uid == 0
            && task_uid != Some(0)
            && !task_group_ids.contains(&metadata.owner_gid)
            && metadata.mode & 0o002 == 0)
}

fn validate_credential_parent(
    path: &Path,
    daemon_uid: u32,
    task_uid: Option<u32>,
    task_group_ids: &[u32],
) -> Result<(), HttpError> {
    let parent = path.parent().ok_or_else(|| {
        HttpError::Credential(format!(
            "credential file {path:?} must have a runtime parent"
        ))
    })?;
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| {
        HttpError::Credential(format!(
            "cannot inspect credential runtime directory {parent:?}"
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != daemon_uid
        || metadata.permissions().mode() & 0o022 != 0
        || task_uid.is_some_and(|uid| metadata.uid() == uid)
    {
        return Err(HttpError::Credential(format!(
            "credential runtime directory {parent:?} must be a daemon-owned real directory that the task identity cannot replace or modify"
        )));
    }

    for authority in parent.ancestors().skip(1) {
        let authority_metadata = std::fs::symlink_metadata(authority).map_err(|_| {
            HttpError::Credential(format!(
                "cannot inspect containing runtime directory {authority:?}"
            ))
        })?;
        let authority_mode = authority_metadata.permissions().mode();
        if is_trusted_runtime_authority(
            authority,
            RuntimeAuthorityMetadata {
                is_symlink: authority_metadata.file_type().is_symlink(),
                is_directory: authority_metadata.is_dir(),
                owner_uid: authority_metadata.uid(),
                owner_gid: authority_metadata.gid(),
                mode: authority_mode,
            },
            task_uid,
            task_group_ids,
            cfg!(target_os = "macos"),
        ) {
            continue;
        }
        if authority_metadata.file_type().is_symlink()
            || !authority_metadata.is_dir()
            || (task_uid.is_some_and(|uid| authority_metadata.uid() == uid))
            || (authority_metadata.uid() != daemon_uid && authority_metadata.uid() != 0)
            || (authority_mode & 0o022 != 0 && authority_mode & 0o1000 == 0)
        {
            return Err(HttpError::Credential(format!(
                "containing runtime directory {authority:?} must be a real directory owned by the daemon or root and prevent replacement of the credential path"
            )));
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(config: Arc<Config>) -> Result<(), HttpError> {
    prepare_protected_directory(&config.build.workspace_root, 0o711)?;
    crate::artifacts::prepare_artifact_storage_root(&config.artifacts.storage_root)
        .map_err(|err| HttpError::Serve(err.to_string()))?;
    crate::build::preflight_run_as(&config).map_err(|err| HttpError::Serve(err.to_string()))?;
    let task_identity = crate::build::resolved_run_as_identity(&config)
        .map_err(|err| HttpError::Serve(err.to_string()))?;
    let task_uid = task_identity.as_ref().map(|identity| identity.0);
    let task_group_ids = if config.service.http.auth.required {
        resolved_task_group_ids(
            task_identity.as_ref().map(|identity| identity.1.as_str()),
            task_identity.as_ref().map(|identity| identity.2),
        )?
    } else {
        Vec::new()
    };
    let auth = if config.service.http.auth.required {
        Arc::new(AuthSecrets::load_with_groups(
            &config.service.http.auth.token_files,
            task_uid,
            &task_group_ids,
        )?)
    } else {
        Arc::new(AuthSecrets::empty())
    };
    let build_slots = Arc::new(Semaphore::new(config.service.max_concurrent_builds));
    let managed_sessions_enabled =
        managed_session_authority_available(unsafe { libc::geteuid() }, task_uid);
    let sessions = if managed_sessions_enabled {
        SessionManager::new(Arc::clone(&config))?
    } else {
        SessionManager::new_disabled(Arc::clone(&config))
    };
    let base_state = AppState {
        config: Arc::clone(&config),
        auth,
        auth_required: false,
        build_slots,
        sessions,
        managed_sessions_enabled,
    };
    match (config.service.http.enabled, config.service.socket.enabled) {
        (true, true) => {
            let tcp = run_tcp(Arc::clone(&config), base_state.clone());
            let uds = run_uds(Arc::clone(&config), base_state);
            tokio::try_join!(tcp, uds)?;
        }
        (true, false) => run_tcp(config, base_state).await?,
        (false, true) => run_uds(config, base_state).await?,
        (false, false) => {}
    }
    Ok(())
}

fn managed_session_authority_available(daemon_uid: u32, task_uid: Option<u32>) -> bool {
    daemon_uid == 0 && task_uid.is_some_and(|uid| uid != 0)
}

fn prepare_protected_directory(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected directory must be a daemon-owned real directory",
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

async fn run_tcp(config: Arc<Config>, mut state: AppState) -> Result<(), HttpError> {
    let addr: std::net::SocketAddr = config
        .service
        .http
        .listen_addr
        .parse()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    state.auth_required = config.service.http.auth.required;
    let app = build_router(state, config.sources.max_transfer_bytes);

    if config.service.http.tls.enabled {
        let tls_config = build_tls_config(config.as_ref())?;
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .map_err(|err| HttpError::Serve(err.to_string()))?;
    } else {
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .map_err(|err| HttpError::Serve(err.to_string()))?;
    }

    Ok(())
}

async fn run_uds(config: Arc<Config>, mut state: AppState) -> Result<(), HttpError> {
    let listener = setup_socket(&config)?;
    state.auth_required = false;
    let app = build_router(state, config.sources.max_transfer_bytes);

    loop {
        let (stream, _) = listener.accept().await?;
        let service = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, service)
                .await
            {
                warn!("uds connection failed: {err}");
            }
        });
    }
}

fn build_router(state: AppState, max_transfer_bytes: u64) -> Router {
    let max_body =
        usize::try_from(max_transfer_bytes.saturating_add(1024 * 1024)).unwrap_or(usize::MAX);
    Router::new()
        .route("/v1/builds", post(start_build))
        .route("/v1/builds/:build_id/artifacts.zip", get(get_artifact))
        .route("/v1/sessions", post(start_session))
        .route("/v1/sessions/:session_id", delete(stop_session))
        .route(
            "/v1/sessions/:session_id/actions/:action",
            post(run_session_action),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body))
}

async fn start_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }

    let mut metadata_field = match multipart.next_field().await {
        Ok(Some(field)) if field.name() == Some("metadata") => field,
        Ok(Some(_)) => return bad_request("metadata must be the first multipart field"),
        Ok(None) => return bad_request("missing metadata field"),
        Err(err) => return bad_request(&format!("invalid multipart metadata field: {err}")),
    };
    let mut metadata_bytes = Vec::new();
    loop {
        match metadata_field.chunk().await {
            Ok(Some(chunk)) => {
                if metadata_bytes.len().saturating_add(chunk.len()) > 64 * 1024 {
                    return payload_too_large("metadata exceeds 65536 bytes");
                }
                metadata_bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => return bad_request(&format!("failed to read metadata: {err}")),
        }
    }
    drop(metadata_field);

    let request = match parse_request_metadata(&metadata_bytes) {
        Ok(request) => request,
        Err(err) => return bad_request(&err.to_string()),
    };
    let validated = match validate_request(request, &state.config) {
        Ok(validated) => validated,
        Err(err) => return bad_request(&err.message),
    };

    let permit = match Arc::clone(&state.build_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return busy_response(),
    };

    let upload_deadline = Duration::from_secs(state.config.sources.upload_timeout_sec);
    let source_path =
        match tokio::time::timeout(upload_deadline, receive_source_upload(&state, multipart)).await
        {
            Ok(Ok(path)) => path,
            Ok(Err(response)) => return response,
            Err(_) => return source_upload_timeout(),
        };
    let (tx, rx) = mpsc::channel(128);
    let config = Arc::clone(&state.config);
    let cancellation = CancellationFlag::default();
    let stream_cancellation = cancellation.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        execute_build(validated, config, source_path, tx, cancellation)
    });

    let stream = BuildEventStream {
        receiver: rx,
        cancellation: stream_cancellation,
    }
    .map(|event| {
        let line = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                format!("{{\"type\":\"error\",\"code\":\"serialization\",\"message\":\"{err}\"}}")
            }
        };
        Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!("{line}\n")))
    });

    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

async fn start_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }
    if !state.managed_sessions_enabled {
        return managed_sessions_unavailable();
    }

    let mut metadata_field = match multipart.next_field().await {
        Ok(Some(field)) if field.name() == Some("metadata") => field,
        Ok(Some(_)) => return bad_request("metadata must be the first multipart field"),
        Ok(None) => return bad_request("missing metadata field"),
        Err(err) => return bad_request(&format!("invalid multipart metadata field: {err}")),
    };
    let mut metadata_bytes = Vec::new();
    loop {
        match metadata_field.chunk().await {
            Ok(Some(chunk)) => {
                if metadata_bytes.len().saturating_add(chunk.len()) > 64 * 1024 {
                    return payload_too_large("metadata exceeds 65536 bytes");
                }
                metadata_bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => return bad_request(&format!("failed to read metadata: {err}")),
        }
    }
    drop(metadata_field);

    let request = match parse_session_start_metadata(&metadata_bytes) {
        Ok(request) => request,
        Err(err) => return bad_request(&err.to_string()),
    };
    let task = match state.config.tasks.get(&request.task).cloned() {
        Some(task) if task.session.is_some() => task,
        Some(_) => return bad_request("task does not configure managed sessions"),
        None => return bad_request(&format!("unknown task {}", request.task)),
    };
    let validated = crate::build::ValidatedRequest {
        request_id: request.request_id,
        task_id: request.task,
        task,
    };
    let permit = match Arc::clone(&state.build_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return busy_response(),
    };
    let sessions = state.sessions.clone();
    let reservation = sessions.reserve(validated, permit);
    let session_id = reservation.id().to_string();
    let upload_deadline = Duration::from_secs(state.config.sources.upload_timeout_sec);
    let remaining_lifetime = reservation.remaining_lifetime();
    let lifetime_limits_upload = remaining_lifetime <= upload_deadline;
    let effective_upload_deadline = upload_deadline.min(remaining_lifetime);
    let upload_result = tokio::select! {
        result = tokio::time::timeout(
            effective_upload_deadline,
            receive_source_upload(&state, multipart),
        ) => match result {
            Ok(result) => result,
            Err(_) if lifetime_limits_upload => Err(session_lifetime_timeout()),
            Err(_) => Err(source_upload_timeout()),
        },
        () = reservation.cancelled() => Err(session_lifetime_timeout()),
    };
    let source_path = match upload_result {
        Ok(path) => path,
        Err(response) => {
            sessions.cancel_upload(&reservation);
            return response;
        }
    };
    if !sessions.begin_initialization(&reservation) {
        return session_lifetime_timeout();
    }
    let (tx, rx) = mpsc::channel(128);
    let worker_sessions = sessions.clone();
    tokio::task::spawn_blocking(move || {
        worker_sessions.initialize(reservation, source_path, tx);
    });

    let stream = SessionEventStream {
        receiver: rx,
        sessions,
        session_id,
    }
    .map(|event| {
        let line = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                format!("{{\"type\":\"error\",\"code\":\"serialization\",\"message\":\"{err}\"}}")
            }
        };
        Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!("{line}\n")))
    });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

async fn run_session_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((session_id, action)): AxumPath<(String, String)>,
    body: Body,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }
    if !state.managed_sessions_enabled {
        return managed_sessions_unavailable();
    }
    if !valid_session_id(&session_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !valid_task_id(&action) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return bad_request("session action body must use application/json");
    }
    let body = match to_bytes(body, MAX_SESSION_ACTION_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return payload_too_large("session action body exceeds 65536 bytes"),
    };
    let request = match parse_session_action_request(&body) {
        Ok(request) => request,
        Err(err) => return bad_request(&err.to_string()),
    };
    let sessions = state.sessions.clone();
    let reservation = match sessions.start_action(&session_id, &action) {
        Ok(reservation) => reservation,
        Err(ActionError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(ActionError::UnknownAction) => {
            let body = Json(ErrorResponse {
                error: "unknown_action".to_string(),
            });
            return (StatusCode::NOT_FOUND, body).into_response();
        }
        Err(ActionError::Conflict) => {
            let body = Json(ErrorResponse {
                error: "session_conflict".to_string(),
            });
            return (StatusCode::CONFLICT, body).into_response();
        }
    };
    let input = reservation.encode_input(&request.input);
    let action_id = reservation.action_id().to_string();
    let reserved_session_id = reservation.session_id().to_string();
    let (sender, receiver) = mpsc::channel(128);
    let worker_sessions = sessions.clone();
    tokio::task::spawn_blocking(move || {
        worker_sessions.execute_action(reservation, input, sender);
    });
    let stream = SessionActionEventStream {
        receiver,
        sessions,
        session_id: reserved_session_id,
        action_id,
        pending_ack: None,
    }
    .map(|event| {
        let line = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                format!("{{\"type\":\"error\",\"code\":\"serialization\",\"message\":\"{err}\"}}")
            }
        };
        Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!("{line}\n")))
    });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

async fn stop_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }
    if !state.managed_sessions_enabled {
        return managed_sessions_unavailable();
    }
    if !valid_session_id(&session_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let sessions = state.sessions.clone();
    match tokio::task::spawn_blocking(move || sessions.stop(&session_id)).await {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(StopError::NotFound)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(StopError::Conflict)) => {
            let body = Json(ErrorResponse {
                error: "session_conflict".to_string(),
            });
            (StatusCode::CONFLICT, body).into_response()
        }
        Err(err) => server_error(&format!("session stop task failed: {err}")),
    }
}

async fn receive_source_upload(
    state: &AppState,
    mut multipart: Multipart,
) -> Result<tempfile::TempPath, Response> {
    let mut source_field = match multipart.next_field().await {
        Ok(Some(field)) if field.name() == Some("source") => field,
        Ok(Some(_)) => return Err(bad_request("source must follow metadata")),
        Ok(None) => return Err(bad_request("missing source field")),
        Err(err) => {
            return Err(bad_request(&format!(
                "invalid multipart source field: {err}"
            )))
        }
    };

    if let Err(err) = std::fs::create_dir_all(&state.config.build.workspace_root) {
        return Err(server_error(&format!(
            "failed to create workspace root: {err}"
        )));
    }
    let mut source_temp = tempfile::Builder::new()
        .prefix("indentured-server-src-")
        .suffix(".zip")
        .tempfile_in(&state.config.build.workspace_root)
        .map_err(|err| server_error(&format!("failed to create source temp file: {err}")))?;
    let mut source_bytes = 0u64;
    loop {
        match source_field.chunk().await {
            Ok(Some(chunk)) => {
                source_bytes = source_bytes.saturating_add(chunk.len() as u64);
                if source_bytes > state.config.sources.max_transfer_bytes {
                    return Err(payload_too_large(
                        "source archive exceeds sources.max_transfer_bytes",
                    ));
                }
                source_temp
                    .write_all(&chunk)
                    .map_err(|err| server_error(&format!("failed to write source: {err}")))?;
            }
            Ok(None) => break,
            Err(err) => {
                return Err(bad_request(&format!("failed to read source: {err}")));
            }
        }
    }
    drop(source_field);

    match multipart.next_field().await {
        Ok(None) => {}
        Ok(Some(field)) => {
            let name = field.name().unwrap_or("unnamed");
            return Err(bad_request(&format!(
                "unexpected or duplicate multipart field {name}"
            )));
        }
        Err(err) => {
            return Err(bad_request(&format!("invalid multipart trailer: {err}")));
        }
    }

    Ok(source_temp.into_temp_path())
}

async fn get_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(build_id): AxumPath<String>,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }

    if !valid_build_id(&build_id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let root = state.config.artifacts.storage_root.join(&build_id);
    let candidate = root.join("artifacts.zip");

    let resolved_root = match std::fs::canonicalize(&root) {
        Ok(path) => path,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let resolved = match std::fs::canonicalize(&candidate) {
        Ok(path) => path,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    if !resolved.starts_with(&resolved_root) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let file = match tokio::fs::File::open(&resolved).await {
        Ok(file) => file,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let stream = ReaderStream::new(file);
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response
}

fn authorize(headers: &HeaderMap, auth: &AuthSecrets, enforce: bool) -> Option<Response> {
    if !enforce {
        return None;
    }

    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().and_then(|value| value.to_str().ok());
    let duplicate = values.next().is_some();
    let token = value
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|token| BearerToken::parse(token.as_bytes()).ok());

    if duplicate || token.is_none() || !auth.matches(token.map_or(&[], BearerToken::as_bytes)) {
        let body = Json(ErrorResponse {
            error: "unauthorized".to_string(),
        });
        return Some((StatusCode::UNAUTHORIZED, body).into_response());
    }

    None
}

fn busy_response() -> Response {
    let body = Json(ErrorResponse {
        error: "busy".to_string(),
    });
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("0"));
    response
}

fn managed_sessions_unavailable() -> Response {
    let body = Json(ErrorResponse {
        error: "managed_sessions_unavailable".to_string(),
    });
    (StatusCode::SERVICE_UNAVAILABLE, body).into_response()
}

fn valid_build_id(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("bld_")
        && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn setup_socket(config: &Config) -> Result<UnixListener, HttpError> {
    let socket_path = &config.service.socket.path;

    if let Some(parent) = socket_path.parent() {
        prepare_protected_directory(parent, 0o700)?;
    }

    if socket_path.exists() {
        let meta = std::fs::symlink_metadata(socket_path)?;
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("socket path exists and is not a socket: {socket_path:?}"),
            )
            .into());
        }
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    let gid = match config.service.socket.group.as_deref() {
        Some(group) => Some(crate::user::lookup_group_gid(group)?),
        None => None,
    };
    apply_socket_permissions(socket_path, gid, config.service.socket.parse_mode()?)?;

    Ok(listener)
}

fn apply_socket_permissions(path: &Path, gid: Option<u32>, mode: u32) -> io::Result<()> {
    if let Some(gid) = gid {
        let gid_t = gid as libc::gid_t;
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket path"))?;
        let uid = !0 as libc::uid_t;
        let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid_t) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)?;

    Ok(())
}

fn build_tls_config(config: &Config) -> Result<axum_server::tls_rustls::RustlsConfig, HttpError> {
    let tls = &config.service.http.tls;
    let cert_path = tls
        .cert_path
        .as_ref()
        .ok_or_else(|| HttpError::Tls("service.http.tls.cert_path must be set".to_string()))?;
    let key_path = tls
        .key_path
        .as_ref()
        .ok_or_else(|| HttpError::Tls("service.http.tls.key_path must be set".to_string()))?;

    let certs = load_certs(cert_path).map_err(HttpError::Tls)?;
    let key = load_private_key(key_path).map_err(HttpError::Tls)?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| HttpError::Tls(err.to_string()))?;

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = io::BufReader::new(std::fs::File::open(path).map_err(|err| err.to_string())?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    if certs.is_empty() {
        return Err("no certificates found".to_string());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = io::BufReader::new(std::fs::File::open(path).map_err(|err| err.to_string())?);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "no private key found".to_string())?;
    Ok(key)
}

fn bad_request(message: &str) -> Response {
    let body = Json(ErrorResponse {
        error: message.to_string(),
    });
    (StatusCode::BAD_REQUEST, body).into_response()
}

fn payload_too_large(message: &str) -> Response {
    let body = Json(ErrorResponse {
        error: message.to_string(),
    });
    (StatusCode::PAYLOAD_TOO_LARGE, body).into_response()
}

fn source_upload_timeout() -> Response {
    let body = Json(ErrorResponse {
        error: "source_upload_timeout".to_string(),
    });
    (StatusCode::REQUEST_TIMEOUT, body).into_response()
}

fn session_lifetime_timeout() -> Response {
    let body = Json(ErrorResponse {
        error: "session_lifetime".to_string(),
    });
    (StatusCode::REQUEST_TIMEOUT, body).into_response()
}

fn server_error(message: &str) -> Response {
    error!("http handler error: {message}");
    let body = Json(ErrorResponse {
        error: "internal error".to_string(),
    });
    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::ArtifactSnapshotCheckpoint;
    use crate::config::{
        ArtifactSpec, ArtifactsConfig, BuildConfig, Config, LoggingConfig, ScriptText,
        ServiceConfig, SessionActionConfig, SessionTeardownConfig, SourcesConfig, TaskConfig,
        TaskSessionConfig, TaskSetupConfig, WorkspacePolicy, CONFIG_SCHEMA_VERSION,
    };
    use crate::protocol::{
        BuildPhase, Request, ResponseEvent, SessionActionEvent, SessionStartEvent,
        SessionStopResponse, SourceFormat, SourceMetadata,
    };
    use reqwest::blocking::multipart::{Form, Part};
    use reqwest::blocking::Client;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Cursor, Read, Write};
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tempfile::{tempdir, NamedTempFile, TempDir};
    use zip::write::SimpleFileOptions as FileOptions;
    use zip::ZipWriter;

    struct TestEnv {
        temp: TempDir,
        app: Router,
        workspace_root: PathBuf,
        marker: PathBuf,
        process_pids: PathBuf,
        build_slots: Arc<Semaphore>,
        sessions: SessionManager,
        config: Arc<Config>,
    }

    const LIFECYCLE_HTTP_TIMEOUT: Duration = Duration::from_secs(12);
    const LIFECYCLE_SCENARIO_TIMEOUT: Duration = Duration::from_secs(30);

    fn bounded_lifecycle_client() -> Client {
        Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(LIFECYCLE_HTTP_TIMEOUT)
            .build()
            .expect("bounded lifecycle client")
    }

    #[tokio::test]
    async fn http_named_task_uses_only_server_policy_and_cleans_workspace() {
        let env = setup_env();
        let workspace_root = env.workspace_root.clone();
        let marker = env.marker.clone();
        let (addr, server) = start_http_server(env.app).await;
        let zip = tokio::task::spawn_blocking(move || {
            run_build_and_fetch(Client::new(), format!("http://{addr}"))
        })
        .await
        .expect("client task");

        assert_zip_exactly_contains(
            &zip,
            &["work/out/result.txt"],
            "work/out/result.txt",
            "source:fixed:server",
        );
        assert!(marker.is_file(), "configured task did not run");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_dir_empty(&workspace_root);
        server.abort();
    }

    #[tokio::test]
    async fn uds_named_task_flow_still_works() {
        let env = setup_env();
        let socket = env.temp.path().join("server.sock");
        let server = start_uds_server(env.app, &socket).await;
        let zip = tokio::task::spawn_blocking(move || {
            let client = Client::builder()
                .unix_socket(socket)
                .build()
                .expect("client");
            run_build_and_fetch(client, "http://localhost".to_string())
        })
        .await
        .expect("client task");
        assert_zip_exactly_contains(
            &zip,
            &["work/out/result.txt"],
            "work/out/result.txt",
            "source:fixed:server",
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_versions_tasks_and_authority_before_source_or_spawn() {
        let env = setup_env();
        let workspace_root = env.workspace_root.clone();
        let marker = env.marker.clone();
        std::fs::remove_dir(&workspace_root).expect("start without workspace root");
        assert!(!workspace_root.exists());
        let request_workspace_root = workspace_root.clone();
        let request_marker = marker.clone();
        let (addr, server) = start_http_server(env.app).await;

        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let client = Client::new();
            let base_value = serde_json::json!({
                "schema_version": "1",
                "request_id": "reject-test",
                "task": "build",
                "source": {"format": "zip"}
            });

            let mut invalid = Vec::new();
            let mut missing = base_value.clone();
            missing.as_object_mut().unwrap().remove("schema_version");
            invalid.push(("missing schema version".to_string(), missing));
            for version in ["3", "999"] {
                let mut value = base_value.clone();
                value["schema_version"] = serde_json::json!(version);
                invalid.push((format!("schema version {version}"), value));
            }
            let mut unknown_task = base_value.clone();
            unknown_task["task"] = serde_json::json!("unknown");
            invalid.push(("unknown task".to_string(), unknown_task));
            for field in [
                "command",
                "args",
                "argv",
                "cwd",
                "env",
                "environment",
                "timeout",
                "timeout_sec",
                "artifacts",
                "workspace",
                "reuse",
                "id",
                "identifier",
                "create",
                "refresh",
                "ttl",
                "TTL",
                "ttl_sec",
                "ttl_seconds",
                "arbitrary_field",
            ] {
                let mut value = base_value.clone();
                value[field] = serde_json::json!("client-override");
                invalid.push((format!("authority field {field}"), value));
            }
            let mut nested_source_override = base_value.clone();
            nested_source_override["source"]["path"] = serde_json::json!("/tmp/client-override");
            invalid.push(("nested source override".to_string(), nested_source_override));

            for (case, value) in invalid {
                let response = post_raw(&client, &base, value, false);
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
                assert!(
                    !request_workspace_root.exists(),
                    "{case} created or persisted source in the workspace root"
                );
                assert!(
                    !request_marker.exists(),
                    "{case} spawned the configured task"
                );
            }
            let source_first = post_raw(&client, &base, base_value, true);
            assert_eq!(source_first.status(), StatusCode::BAD_REQUEST);
            assert!(!request_workspace_root.exists());
            assert!(!request_marker.exists());
        })
        .await
        .expect("client task");

        assert!(
            !marker.exists(),
            "rejected request spawned the configured task"
        );
        assert!(
            !workspace_root.exists(),
            "rejected request created the workspace root"
        );
        server.abort();
    }

    #[test]
    fn protected_state_rejects_symlinks_and_sets_explicit_modes() {
        let temp = tempdir().unwrap();
        let state = temp.path().join("state");
        prepare_protected_directory(&state, 0o700).unwrap();
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(prepare_protected_directory(&link, 0o700).is_err());
    }

    #[test]
    fn task_group_parser_includes_the_configured_primary_group() {
        assert_eq!(parse_task_group_ids(b"1 2\n", 550).unwrap(), [1, 2, 550]);
        assert_eq!(parse_task_group_ids(b"1 550\n", 550).unwrap(), [1, 550]);
        assert!(parse_task_group_ids(b"", 550).is_err());
        assert!(parse_task_group_ids(b"1 nope\n", 550).is_err());
    }

    #[test]
    fn managed_session_authority_requires_root_daemon_and_distinct_non_root_task() {
        assert!(managed_session_authority_available(0, Some(501)));
        assert!(!managed_session_authority_available(0, None));
        assert!(!managed_session_authority_available(0, Some(0)));
        assert!(!managed_session_authority_available(501, None));
        assert!(!managed_session_authority_available(501, Some(502)));
    }

    #[tokio::test]
    async fn unavailable_managed_authority_rejects_sessions_but_preserves_one_shot_builds() {
        let env = setup_env_with_options(SourcesConfig::default().upload_timeout_sec, false);
        let metadata_root = env.sessions.metadata_root().to_path_buf();
        let workspace_root = env.workspace_root.clone();
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let response = post_session(&Client::new(), &base, "managed");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response
                .text()
                .unwrap()
                .contains(r#"{"error":"managed_sessions_unavailable"}"#));
            let stop = Client::new()
                .delete(format!("{base}/v1/sessions/ses_unavailable"))
                .send()
                .unwrap();
            assert_eq!(stop.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(stop
                .text()
                .unwrap()
                .contains(r#"{"error":"managed_sessions_unavailable"}"#));

            let events = run_task_events_through_eof(&Client::new(), &base, "build");
            assert!(matches!(
                events.last(),
                Some(ResponseEvent::Exit {
                    code: 0,
                    timed_out: false,
                    ..
                })
            ));
            wait_for_slot_and_cleanup(&env.build_slots, &workspace_root);
        })
        .await
        .unwrap();
        assert!(matches!(
            std::fs::symlink_metadata(metadata_root),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        server.abort();
    }

    #[test]
    fn runtime_authority_accepts_only_the_exact_native_macos_root() {
        let macos_var_run = Path::new("/private/var/run");
        let native = RuntimeAuthorityMetadata {
            is_symlink: false,
            is_directory: true,
            owner_uid: 0,
            owner_gid: 1,
            mode: 0o040775,
        };
        assert!(is_trusted_runtime_authority(
            macos_var_run,
            native,
            Some(550),
            &[550],
            true,
        ));
        assert!(is_trusted_runtime_authority(
            Path::new("/var/run"),
            RuntimeAuthorityMetadata {
                is_symlink: true,
                is_directory: false,
                owner_uid: 0,
                owner_gid: 0,
                mode: 0o120777,
            },
            Some(550),
            &[550],
            false,
        ));
        assert!(!is_trusted_runtime_authority(
            macos_var_run,
            native,
            Some(550),
            &[1, 550],
            true,
        ));
        for invalid in [
            RuntimeAuthorityMetadata {
                is_symlink: true,
                ..native
            },
            RuntimeAuthorityMetadata {
                owner_uid: 1,
                ..native
            },
            RuntimeAuthorityMetadata {
                mode: 0o040777,
                ..native
            },
        ] {
            assert!(!is_trusted_runtime_authority(
                macos_var_run,
                invalid,
                Some(550),
                &[550],
                true,
            ));
        }
        assert!(!is_trusted_runtime_authority(
            macos_var_run,
            native,
            Some(0),
            &[550],
            true,
        ));
        assert!(!is_trusted_runtime_authority(
            macos_var_run,
            native,
            Some(550),
            &[550],
            false,
        ));
        assert!(!is_trusted_runtime_authority(
            Path::new("/private/var/tmp"),
            native,
            Some(550),
            &[550],
            true,
        ));
    }

    #[test]
    fn daemon_credential_loader_enforces_shared_bearer_token_grammar() {
        let temp = tempdir().expect("tempdir");
        let token_path = temp.path().join("token");
        let write_token = |contents: &[u8]| {
            std::fs::write(&token_path, contents).unwrap();
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };

        let mut max_with_lf = vec![b'x'; 4095];
        max_with_lf.push(b'\n');
        for (contents, expected) in [
            (b"A".to_vec(), b"A".to_vec()),
            (b"azAZ09-._~+/===\n".to_vec(), b"azAZ09-._~+/===".to_vec()),
            (vec![b'x'; 4096], vec![b'x'; 4096]),
            (max_with_lf, vec![b'x'; 4095]),
        ] {
            write_token(&contents);
            let auth = AuthSecrets::load(std::slice::from_ref(&token_path), None).unwrap();
            assert!(auth.matches(&expected));
        }

        let mut token_plus_lf_overflow = vec![b'x'; 4096];
        token_plus_lf_overflow.push(b'\n');
        for contents in [
            Vec::new(),
            vec![b'x'; 4097],
            token_plus_lf_overflow,
            vec![0xff],
            "é".as_bytes().to_vec(),
            b"x\x01y".to_vec(),
            b"x\x7fy".to_vec(),
            b"x y".to_vec(),
            b"x\ty".to_vec(),
            b"x\r".to_vec(),
            b"x\r\n".to_vec(),
            b"x\ny".to_vec(),
            b"x\n\n".to_vec(),
            b"x\0y".to_vec(),
            b"=x".to_vec(),
            b"==".to_vec(),
            b"x=y".to_vec(),
            b"x==y".to_vec(),
        ] {
            write_token(&contents);
            assert!(AuthSecrets::load(std::slice::from_ref(&token_path), None).is_err());
        }

        write_token(b"sentinel-secret:");
        let error = AuthSecrets::load(std::slice::from_ref(&token_path), None).unwrap_err();
        assert!(!error.to_string().contains("sentinel-secret"));
    }

    #[test]
    fn credential_files_and_constant_time_bearer_auth_fail_closed() {
        let temp = tempdir().expect("tempdir");
        let token_path = temp.path().join("token");
        std::fs::write(&token_path, "sentinel-secret\n").unwrap();
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let auth = AuthSecrets::load(std::slice::from_ref(&token_path), None).expect("load token");
        assert!(!format!("{auth:?}").contains("sentinel-secret"));

        let mut headers = HeaderMap::new();
        assert_eq!(
            authorize(&headers, &auth, true).unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert_eq!(
            authorize(&headers, &auth, true).unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sentinel-secret"),
        );
        assert!(authorize(&headers, &auth, true).is_none());
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sentinel-secret"),
        );
        assert_eq!(
            authorize(&headers, &auth, true).unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let owner = std::fs::metadata(&token_path).unwrap().uid();
        assert!(AuthSecrets::load(std::slice::from_ref(&token_path), Some(owner)).is_err());
        let link = temp.path().join("token-link");
        std::os::unix::fs::symlink(&token_path, &link).unwrap();
        assert!(AuthSecrets::load(&[link], None).is_err());
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(AuthSecrets::load(std::slice::from_ref(&token_path), None).is_err());
        std::fs::write(&token_path, vec![b'x'; 4097]).unwrap();
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuthSecrets::load(&[token_path], None).is_err());
    }

    #[test]
    fn credential_runtime_parent_is_daemon_owned_real_and_not_replaceable() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let token = runtime.join("token");
        std::fs::write(&token, "parent-authority\n").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        AuthSecrets::load(std::slice::from_ref(&token), None).expect("secure runtime parent");

        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o720)).unwrap();
        assert!(AuthSecrets::load(std::slice::from_ref(&token), None).is_err());
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();

        let runtime_link = temp.path().join("runtime-link");
        std::os::unix::fs::symlink(&runtime, &runtime_link).unwrap();
        assert!(AuthSecrets::load(&[runtime_link.join("token")], None).is_err());

        let real_authority = temp.path().join("real-authority");
        let authority_runtime = real_authority.join("runtime");
        std::fs::create_dir_all(&authority_runtime).unwrap();
        std::fs::set_permissions(&real_authority, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&authority_runtime, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let authority_token = authority_runtime.join("token");
        std::fs::write(&authority_token, "symlink-authority\n").unwrap();
        std::fs::set_permissions(&authority_token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let authority_link = temp.path().join("authority-link");
        std::os::unix::fs::symlink(&real_authority, &authority_link).unwrap();
        assert!(AuthSecrets::load(&[authority_link.join("runtime/token")], None).is_err());

        let replaceable = temp.path().join("replaceable");
        std::fs::create_dir(&replaceable).unwrap();
        std::fs::set_permissions(&replaceable, std::fs::Permissions::from_mode(0o777)).unwrap();
        let nested_runtime = replaceable.join("runtime");
        std::fs::create_dir(&nested_runtime).unwrap();
        std::fs::set_permissions(&nested_runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let replaceable_token = nested_runtime.join("token");
        std::fs::write(&replaceable_token, "replaceable-parent\n").unwrap();
        std::fs::set_permissions(&replaceable_token, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(AuthSecrets::load(&[replaceable_token], None).is_err());

        if unsafe { libc::geteuid() } == 0 {
            let wrong_owner_file = runtime.join("wrong-owner-token");
            std::fs::write(&wrong_owner_file, "wrong-owner\n").unwrap();
            std::fs::set_permissions(&wrong_owner_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let c_path = CString::new(wrong_owner_file.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(c_path.as_ptr(), 1, !0 as libc::gid_t) },
                0
            );
            assert!(AuthSecrets::load(&[wrong_owner_file], None).is_err());

            let wrong_owner_runtime = temp.path().join("wrong-owner-runtime");
            std::fs::create_dir(&wrong_owner_runtime).unwrap();
            std::fs::set_permissions(&wrong_owner_runtime, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let parent_token = wrong_owner_runtime.join("token");
            std::fs::write(&parent_token, "wrong-parent\n").unwrap();
            std::fs::set_permissions(&parent_token, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let c_parent = CString::new(wrong_owner_runtime.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(c_parent.as_ptr(), 1, !0 as libc::gid_t) },
                0
            );
            assert!(AuthSecrets::load(&[parent_token], None).is_err());

            let foreign_ancestor = temp.path().join("foreign-ancestor");
            let foreign_runtime = foreign_ancestor.join("runtime");
            std::fs::create_dir_all(&foreign_runtime).unwrap();
            std::fs::set_permissions(&foreign_ancestor, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&foreign_runtime, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let foreign_token = foreign_runtime.join("token");
            std::fs::write(&foreign_token, "foreign-ancestor\n").unwrap();
            std::fs::set_permissions(&foreign_token, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let c_ancestor = CString::new(foreign_ancestor.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(c_ancestor.as_ptr(), 1, !0 as libc::gid_t) },
                0
            );
            assert!(AuthSecrets::load(&[foreign_token], None).is_err());

            std::fs::create_dir_all(&foreign_runtime).unwrap();
            let c_task_ancestor = CString::new(foreign_ancestor.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(c_task_ancestor.as_ptr(), 1, !0 as libc::gid_t) },
                0
            );
            assert!(AuthSecrets::load(&[foreign_runtime.join("token")], Some(1)).is_err());
        }
    }

    #[tokio::test]
    async fn busy_request_is_rejected_immediately_before_source_persistence() {
        let env = setup_env();
        let permit = Arc::clone(&env.build_slots).acquire_owned().await.unwrap();
        let workspace_root = env.workspace_root.clone();
        std::fs::remove_dir(&workspace_root).expect("remove empty root");
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let started = std::time::Instant::now();
            let response = post_raw(
                &Client::new(),
                &format!("http://{addr}"),
                serde_json::json!({
                    "schema_version": "1",
                    "request_id": "busy",
                    "task": "build",
                    "source": {"format": "zip"}
                }),
                false,
            );
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "0");
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(response.text().unwrap(), r#"{"error":"busy"}"#);
        })
        .await
        .unwrap();
        assert!(!workspace_root.exists());
        drop(permit);
        assert_eq!(env.build_slots.available_permits(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn stalled_source_upload_times_out_cleans_temp_and_releases_permit() {
        let env = setup_env_with_upload_timeout(1);
        let workspace_root = env.workspace_root.clone();
        let build_slots = Arc::clone(&env.build_slots);
        let (addr, server) = start_http_server(env.app).await;

        let response = tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect raw upload");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let boundary = "indentured-stalled-upload";
            let metadata = r#"{"schema_version":"1","request_id":"stalled","task":"build","source":{"format":"zip"}}"#;
            let partial = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"source\"; filename=\"source.zip\"\r\nContent-Type: application/zip\r\n\r\nPK"
            );
            let request = format!(
                "POST /v1/builds HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: 1000000\r\n\r\n{partial}"
            );
            stream.write_all(request.as_bytes()).expect("write partial upload");
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            String::from_utf8(bytes).expect("HTTP response")
        })
        .await
        .expect("raw upload task");

        assert!(
            response.contains(" 408 "),
            "unexpected response: {response}"
        );
        assert!(response.contains(r#"{"error":"source_upload_timeout"}"#));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_dir_empty(&workspace_root);
        let permit = build_slots
            .try_acquire_owned()
            .expect("upload timeout must release global permit");
        drop(permit);
        server.abort();
    }

    #[tokio::test]
    async fn blocked_session_upload_obeys_absolute_lifetime_and_cleans_reservation() {
        let env = setup_env_with_session_lifetime(2);
        let workspace_root = env.workspace_root.clone();
        let build_slots = Arc::clone(&env.build_slots);
        let sessions = env.sessions.clone();
        let (addr, server) = start_http_server(env.app).await;

        let response = tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect raw upload");
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let boundary = "indentured-stalled-session-upload";
            let metadata = r#"{"schema_version":"1","request_id":"stalled-session","task":"managed","source":{"format":"zip"}}"#;
            let partial = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"source\"; filename=\"source.zip\"\r\nContent-Type: application/zip\r\n\r\nPK"
            );
            let request = format!(
                "POST /v1/sessions HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: 1000000\r\n\r\n{partial}"
            );
            let started = std::time::Instant::now();
            stream.write_all(request.as_bytes()).expect("write partial upload");
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            (started.elapsed(), String::from_utf8(bytes).expect("HTTP response"))
        })
        .await
        .expect("raw session upload task");

        assert!(response.0 < Duration::from_secs(4));
        assert!(
            response.1.contains(" 408 "),
            "unexpected response: {}",
            response.1
        );
        assert!(response.1.contains(r#"{"error":"session_lifetime"}"#));
        tokio::task::spawn_blocking(move || {
            wait_for_session_cleanup(&build_slots, &workspace_root)
        })
        .await
        .unwrap();
        assert_eq!(sessions.active_count(), 0);
        server.abort();
    }

    #[tokio::test]
    async fn completed_success_and_error_streams_reach_eof_promptly() {
        let env = setup_env();
        let (addr, server) = start_http_server(env.app).await;
        let events = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let client = Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .expect("client");
                let base = format!("http://{addr}");
                let success = run_task_events_through_eof(&client, &base, "build");
                let error = run_task_events_through_eof(&client, &base, "error");
                (success, error)
            }),
        )
        .await
        .expect("NDJSON bodies did not reach EOF within the bounded timeout")
        .expect("client task");

        assert!(matches!(
            events.0.last(),
            Some(ResponseEvent::Exit {
                code: 0,
                timed_out: false,
                ..
            })
        ));
        assert!(matches!(
            events.1.last(),
            Some(ResponseEvent::Exit {
                code: 7,
                timed_out: false,
                ..
            })
        ));
        server.abort();
    }

    #[tokio::test]
    async fn nonreading_connected_client_cannot_retain_workspace_or_build_slot() {
        let env = setup_env();
        let workspace_root = env.workspace_root.clone();
        let nonreader_pid_path = env.process_pids.join("nonreader.pid");
        let slots = Arc::clone(&env.build_slots);
        let (addr, server) = start_http_server(env.app).await;
        tokio::time::timeout(
            LIFECYCLE_SCENARIO_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let base = format!("http://{addr}");
                let response = post_raw(
                    &bounded_lifecycle_client(),
                    &base,
                    serde_json::json!({
                        "schema_version": "1",
                        "request_id": "nonreader",
                        "task": "nonreader",
                        "source": {"format": "zip"}
                    }),
                    false,
                );
                assert_eq!(response.status(), StatusCode::OK);

                let pid_deadline = std::time::Instant::now() + Duration::from_secs(2);
                while !nonreader_pid_path.exists() && std::time::Instant::now() < pid_deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let nonreader_pid = read_pid(&nonreader_pid_path);

                // The task emits 16 MiB against a 32 MiB output limit and has a
                // 10-second timeout, so cleanup inside 8 seconds is caused by the
                // forwarding deadline while this connected response remains unread.
                let deadline = std::time::Instant::now() + Duration::from_secs(8);
                while (slots.available_permits() != 1
                    || std::fs::read_dir(&workspace_root)
                        .map(|mut entries| entries.next().is_some())
                        .unwrap_or(true))
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(25));
                }
                assert_eq!(slots.available_permits(), 1, "build slot remained held");
                assert_dir_empty(&workspace_root);
                assert!(!process_exists(nonreader_pid));

                // Keep the first response connected and unread while proving the released
                // slot can serve a real successful build.
                let zip = run_build_and_fetch(bounded_lifecycle_client(), base);
                assert_zip_exactly_contains(
                    &zip,
                    &["work/out/result.txt"],
                    "work/out/result.txt",
                    "source:fixed:server",
                );
                drop(response);
            }),
        )
        .await
        .expect("non-reading-client lifecycle scenario exceeded its deadline")
        .expect("non-reading-client lifecycle task");
        server.abort();
    }

    #[tokio::test]
    async fn setup_and_run_share_one_stream_workspace_and_cleanup_contract() {
        let env = setup_env();
        let workspace_root = env.workspace_root.clone();
        let process_pids = env.process_pids.clone();
        let slots = Arc::clone(&env.build_slots);
        let (addr, server) = start_http_server(env.app).await;
        tokio::time::timeout(
            LIFECYCLE_SCENARIO_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let base = format!("http://{addr}");
                let client = bounded_lifecycle_client();

                let events = run_task_events_through_eof(&client, &base, "phased");
                let finished: Vec<_> = events
                    .iter()
                    .filter_map(|event| match event {
                        ResponseEvent::Build {
                            status,
                            phase: Some(phase),
                            duration_ms: Some(_),
                            ..
                        } if status == "phase_finished" => Some(*phase),
                        _ => None,
                    })
                    .collect();
                assert_eq!(finished, [BuildPhase::Setup, BuildPhase::Run]);
                assert!(matches!(
                    events.last(),
                    Some(ResponseEvent::Exit {
                        code: 0,
                        timed_out: false,
                        failed_phase: None,
                        phases,
                        ..
                    }) if phases.iter().map(|result| result.phase).collect::<Vec<_>>()
                        == [BuildPhase::Setup, BuildPhase::Run]
                ));
                wait_for_slot_and_cleanup(&slots, &workspace_root);

                let (errors, exit) = run_task_events(&client, &base, "shared-output");
                assert!(errors.iter().any(|code| code == "output_limit"));
                assert_eq!(exit, (1, false));
                wait_for_slot_and_cleanup(&slots, &workspace_root);

                let events = run_task_events_through_eof(&client, &base, "setup-error");
                assert!(matches!(
                    events.last(),
                    Some(ResponseEvent::Exit {
                        code: 9,
                        timed_out: false,
                        failed_phase: Some(BuildPhase::Setup),
                        phases,
                        ..
                    }) if phases.len() == 1 && phases[0].phase == BuildPhase::Setup
                ));
                assert!(!process_pids.join("run-after-setup-error").exists());
                wait_for_slot_and_cleanup(&slots, &workspace_root);

                let events = run_task_events_through_eof(&client, &base, "setup-timeout");
                assert!(matches!(
                    events.last(),
                    Some(ResponseEvent::Exit {
                        timed_out: true,
                        failed_phase: Some(BuildPhase::Setup),
                        phases,
                        ..
                    }) if phases.len() == 1
                        && phases[0].phase == BuildPhase::Setup
                        && phases[0].timed_out
                ));
                let setup_pid = read_pid(&process_pids.join("setup-timeout.pid"));
                assert!(!process_exists(setup_pid));
                assert!(!process_pids.join("run-after-setup-timeout").exists());
                wait_for_slot_and_cleanup(&slots, &workspace_root);
            }),
        )
        .await
        .expect("two-phase lifecycle scenario exceeded its deadline")
        .expect("two-phase lifecycle task");
        server.abort();
    }

    #[tokio::test]
    async fn real_error_timeout_output_limit_and_disconnect_release_slot_and_cleanup() {
        let env = setup_env();
        let workspace_root = env.workspace_root.clone();
        let process_pids = env.process_pids.clone();
        let slots = Arc::clone(&env.build_slots);
        let (addr, server) = start_http_server(env.app).await;
        tokio::time::timeout(
            LIFECYCLE_SCENARIO_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let base = format!("http://{addr}");
                let client = bounded_lifecycle_client();

                let (errors, exit) = run_task_events(&client, &base, "error");
                assert!(errors.is_empty());
                assert_eq!(exit, (7, false));
                wait_for_slot_and_cleanup(&slots, &workspace_root);

                for (task, marker) in [("errexit", "errexit-marker"), ("nounset", "nounset-marker")]
                {
                    let (errors, exit) = run_task_events(&client, &base, task);
                    assert!(errors.is_empty());
                    assert_ne!(exit.0, 0, "{task} must fail under /bin/sh -eu");
                    assert!(!process_pids.join(marker).exists());
                    wait_for_slot_and_cleanup(&slots, &workspace_root);
                }

                let timeout_pid_path = process_pids.join("timeout.pid");
                let (errors, exit) = run_task_events(&client, &base, "timeout");
                assert!(errors.is_empty());
                assert!(exit.1, "expected timeout exit, got {exit:?}");
                let timeout_pid = read_pid(&timeout_pid_path);
                assert!(!process_exists(timeout_pid));
                wait_for_slot_and_cleanup(&slots, &workspace_root);

                let output_pid_path = process_pids.join("output.pid");
                let (errors, exit) = run_task_events(&client, &base, "output");
                assert!(errors.iter().any(|code| code == "output_limit"));
                assert_eq!(exit, (1, false));
                let output_pid = read_pid(&output_pid_path);
                assert!(!process_exists(output_pid));
                wait_for_slot_and_cleanup(&slots, &workspace_root);

                let response = post_task(&client, &base, "disconnect");
                assert_eq!(response.status(), StatusCode::OK);
                let disconnect_pid_path = process_pids.join("disconnect.pid");
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while !disconnect_pid_path.exists() && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let disconnect_pid = read_pid(&disconnect_pid_path);
                drop(response);
                wait_for_slot_and_cleanup(&slots, &workspace_root);
                assert!(!process_exists(disconnect_pid));

                let zip = run_build_and_fetch(bounded_lifecycle_client(), base);
                assert_zip_exactly_contains(
                    &zip,
                    &["work/out/result.txt"],
                    "work/out/result.txt",
                    "source:fixed:server",
                );
                wait_for_slot_and_cleanup(&slots, &workspace_root);
            }),
        )
        .await
        .expect("combined lifecycle scenario exceeded its deadline")
        .expect("combined lifecycle task");
        server.abort();
    }

    #[tokio::test]
    async fn managed_session_start_stop_retains_capacity_and_tears_down_once() {
        let env = setup_env();
        let slots = Arc::clone(&env.build_slots);
        let sessions = env.sessions.clone();
        let metadata_root = sessions.metadata_root().to_path_buf();
        let teardown_log = env.process_pids.join("teardown.log");
        let workspace_root = env.workspace_root.clone();
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let session_id = start_managed_session(&Client::new(), &base, "managed");
            assert_eq!(slots.available_permits(), 0);
            assert_eq!(sessions.active_count(), 1);
            let metadata = std::fs::metadata(metadata_root.join(format!("{session_id}.json")))
                .expect("durable ready metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                post_task(&Client::new(), &base, "build").status(),
                StatusCode::SERVICE_UNAVAILABLE
            );

            let first_url = format!("{base}/v1/sessions/{session_id}");
            let second_url = first_url.clone();
            let stop_barrier = Arc::new(std::sync::Barrier::new(3));
            let (first, second) = std::thread::scope(|scope| {
                let first_barrier = Arc::clone(&stop_barrier);
                let first = scope.spawn(move || {
                    first_barrier.wait();
                    let response = Client::new().delete(first_url).send().unwrap();
                    (response.status(), response.text().unwrap())
                });
                let second_barrier = Arc::clone(&stop_barrier);
                let second = scope.spawn(move || {
                    second_barrier.wait();
                    let response = Client::new().delete(second_url).send().unwrap();
                    (response.status(), response.text().unwrap())
                });
                stop_barrier.wait();
                (first.join().unwrap(), second.join().unwrap())
            });
            let statuses = [first.0, second.0];
            assert!(statuses.contains(&StatusCode::OK));
            assert!(statuses.contains(&StatusCode::CONFLICT));
            let success_body = if first.0 == StatusCode::OK {
                first.1
            } else {
                second.1
            };
            let stopped: SessionStopResponse = serde_json::from_str(&success_body).unwrap();
            assert_eq!(stopped.teardown.exit_code, Some(0));
            assert!(!stopped.teardown.timed_out);
            assert!(stopped.artifacts.is_some());
            assert_eq!(
                Client::new()
                    .delete(format!("{base}/v1/sessions/{session_id}"))
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
            wait_for_session_cleanup(&slots, &workspace_root);
            assert_eq!(
                std::fs::read_to_string(teardown_log)
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
        })
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn managed_session_idle_timer_terminates_without_final_artifacts() {
        let env = setup_env();
        let (session_id, mut receiver, worker) = spawn_direct_session(&env, "managed", 128);
        worker.await.unwrap();
        assert!(std::iter::from_fn(|| receiver.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let timer_handles = env.sessions.timer_handles_for_test(&session_id);
        let sessions = env.sessions.clone();
        let id = session_id.clone();
        let stopped = tokio::time::timeout(
            Duration::from_secs(4),
            tokio::task::spawn_blocking(move || sessions.wait_for_terminated_for_test(&id)),
        )
        .await
        .expect("idle timer boundary")
        .unwrap();
        assert!(stopped.artifacts.is_none());
        assert_eq!(env.sessions.active_count(), 0);
        assert_eq!(env.build_slots.available_permits(), 1);
        assert!(timer_handles.iter().all(|handle| handle.is_finished()));
        assert_dir_empty(env.temp.path().join("artifacts").as_path());
    }

    #[tokio::test]
    async fn managed_session_failure_and_pre_ready_disconnect_cleanup() {
        let env = setup_env();
        let slots = Arc::clone(&env.build_slots);
        let sessions = env.sessions.clone();
        let teardown_log = env.process_pids.join("teardown.log");
        let workspace_root = env.workspace_root.clone();
        let disconnect_pid_path = env.process_pids.join("disconnect.pid");
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let response = post_session(&Client::new(), &base, "managed-failure");
            let events = BufReader::new(response)
                .lines()
                .map(|line| serde_json::from_str::<SessionStartEvent>(&line.unwrap()).unwrap())
                .collect::<Vec<_>>();
            assert!(events
                .iter()
                .any(|event| matches!(event, SessionStartEvent::Exit { code: 7, .. })));
            wait_for_session_cleanup(&slots, &workspace_root);

            let response = post_session(&Client::new(), &base, "managed-disconnect");
            let mut reader = BufReader::new(response);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<SessionStartEvent>(line.trim()).unwrap(),
                SessionStartEvent::Session { .. }
            ));
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !disconnect_pid_path.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(reader);
            wait_for_session_cleanup(&slots, &workspace_root);
            assert_eq!(sessions.active_count(), 0);
            assert_eq!(
                std::fs::read_to_string(teardown_log)
                    .unwrap()
                    .lines()
                    .count(),
                2
            );
        })
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn nonreading_session_stream_cannot_block_cleanup_or_timers() {
        let env = setup_env();
        let (session_id, _receiver, worker) = spawn_direct_session(&env, "managed", 1);
        let timer_handles = env.sessions.timer_handles_for_test(&session_id);
        tokio::time::timeout(Duration::from_secs(4), worker)
            .await
            .expect("nonreader cleanup deadline")
            .unwrap();
        assert_eq!(env.sessions.active_count(), 0);
        assert_eq!(env.build_slots.available_permits(), 1);
        assert!(timer_handles.iter().all(|handle| handle.is_finished()));

        let slots = Arc::clone(&env.build_slots);
        let workspace_root = env.workspace_root.clone();
        let pid_path = env.process_pids.join("nonreader.pid");
        let (addr, server) = start_http_server(env.app).await;
        tokio::time::timeout(
            Duration::from_secs(8),
            tokio::task::spawn_blocking(move || {
                let base = format!("http://{addr}");
                let response = post_session(&Client::new(), &base, "managed-nonreader");
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let pid = loop {
                    if let Ok(pid) = std::fs::read_to_string(&pid_path)
                        .ok()
                        .and_then(|value| value.trim().parse::<i32>().ok())
                        .ok_or(())
                    {
                        break pid;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "nonreader pid was not published"
                    );
                    std::thread::yield_now();
                };
                wait_for_session_cleanup(&slots, &workspace_root);
                assert!(!process_exists(pid));
                drop(response);
            }),
        )
        .await
        .expect("connected nonreader cleanup deadline")
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn commit_barriers_enforce_pre_and_post_ready_disconnect_semantics() {
        let pre = setup_env();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        pre.sessions
            .install_commit_election_hook(Arc::clone(&arrived), Arc::clone(&release));
        let (pre_id, mut pre_events, pre_worker) = spawn_direct_session(&pre, "managed", 128);
        wait_barrier(arrived).await;
        pre.sessions.disconnect(&pre_id);
        wait_barrier(release).await;
        pre_worker.await.unwrap();
        assert!(!std::iter::from_fn(|| pre_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        assert_eq!(pre.sessions.active_count(), 0);
        assert_eq!(pre.build_slots.available_permits(), 1);

        let post = setup_env();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        post.sessions
            .install_after_commit_hook(Arc::clone(&arrived), Arc::clone(&release));
        let (post_id, mut post_events, post_worker) = spawn_direct_session(&post, "managed", 128);
        wait_barrier(arrived).await;
        post.sessions.disconnect(&post_id);
        assert_eq!(post.sessions.active_count(), 1);
        wait_barrier(release).await;
        post_worker.await.unwrap();
        assert!(std::iter::from_fn(|| post_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let stopped = post.sessions.stop(&post_id).unwrap();
        assert_eq!(stopped.teardown.exit_code, Some(0));
        assert_eq!(post.build_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn disconnect_cancellation_is_forced_at_each_initialization_phase_boundary() {
        use crate::build::InitializationCheckpoint;

        for checkpoint in [
            InitializationCheckpoint::Extraction,
            InitializationCheckpoint::Ownership,
            InitializationCheckpoint::Setup,
            InitializationCheckpoint::Run,
        ] {
            let env = setup_env();
            let arrived = Arc::new(std::sync::Barrier::new(2));
            let release = Arc::new(std::sync::Barrier::new(2));
            env.sessions.install_initialization_checkpoint_hook(
                checkpoint,
                Arc::clone(&arrived),
                Arc::clone(&release),
            );
            let (session_id, mut events, worker) =
                spawn_direct_session(&env, "managed-phased", 128);
            wait_barrier(arrived).await;
            env.sessions.disconnect(&session_id);
            wait_barrier(release).await;
            worker.await.unwrap();
            let events = std::iter::from_fn(|| events.try_recv().ok()).collect::<Vec<_>>();
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, SessionStartEvent::Ready { .. })),
                "{checkpoint:?} cancellation published Ready"
            );
            let setup_marker = env.process_pids.join("teardown.log.setup");
            if checkpoint == InitializationCheckpoint::Run {
                assert!(
                    setup_marker.is_file(),
                    "setup did not finish before run boundary"
                );
            } else if checkpoint == InitializationCheckpoint::Setup {
                assert!(!setup_marker.exists(), "setup ran before its boundary");
            }
            assert_eq!(env.sessions.active_count(), 0, "{checkpoint:?}");
            assert_eq!(env.build_slots.available_permits(), 1, "{checkpoint:?}");
        }
    }

    #[tokio::test]
    async fn maximum_lifetime_and_explicit_stop_terminate_initialization_at_barrier() {
        let expired = setup_env();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        expired.sessions.install_initialization_checkpoint_hook(
            crate::build::InitializationCheckpoint::Extraction,
            Arc::clone(&arrived),
            Arc::clone(&release),
        );
        let (expired_id, mut expired_events, expired_worker) =
            spawn_direct_session(&expired, "managed", 128);
        wait_barrier(arrived).await;
        let sessions = expired.sessions.clone();
        let id = expired_id.clone();
        tokio::time::timeout(
            Duration::from_secs(4),
            tokio::task::spawn_blocking(move || sessions.wait_for_terminating_for_test(&id)),
        )
        .await
        .expect("maximum lifetime during initialization")
        .unwrap();
        wait_barrier(release).await;
        expired_worker.await.unwrap();
        assert!(!std::iter::from_fn(|| expired_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        assert_eq!(expired.sessions.active_count(), 0);
        assert_eq!(expired.build_slots.available_permits(), 1);

        let stopped = setup_env();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        stopped.sessions.install_initialization_checkpoint_hook(
            crate::build::InitializationCheckpoint::Extraction,
            Arc::clone(&arrived),
            Arc::clone(&release),
        );
        let (stopped_id, _events, stopped_worker) = spawn_direct_session(&stopped, "managed", 128);
        wait_barrier(arrived).await;
        let sessions = stopped.sessions.clone();
        let id = stopped_id.clone();
        let stop = tokio::task::spawn_blocking(move || sessions.stop(&id));
        let sessions = stopped.sessions.clone();
        let id = stopped_id.clone();
        tokio::task::spawn_blocking(move || sessions.wait_for_terminating_for_test(&id))
            .await
            .unwrap();
        wait_barrier(release).await;
        let response = stop.await.unwrap().unwrap();
        stopped_worker.await.unwrap();
        assert!(response.teardown.error_code.is_some());
        assert!(response.artifacts.is_none());
        assert_eq!(stopped.sessions.active_count(), 0);
        assert_eq!(stopped.build_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn metadata_commit_failure_removes_temp_and_cleans_session() {
        let env = setup_env();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        env.sessions
            .install_before_commit_hook(Arc::clone(&arrived), Arc::clone(&release));
        let (session_id, mut events, worker) = spawn_direct_session(&env, "managed", 128);
        wait_barrier(arrived).await;
        let metadata_root = env.sessions.metadata_root();
        std::fs::create_dir_all(metadata_root).unwrap();
        std::fs::set_permissions(metadata_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let temp_metadata = metadata_root.join(format!(".{session_id}.tmp"));
        std::fs::write(&temp_metadata, "force create_new failure").unwrap();
        wait_barrier(release).await;
        worker.await.unwrap();
        let events = std::iter::from_fn(|| events.try_recv().ok()).collect::<Vec<_>>();
        assert!(events.iter().any(|event| matches!(
            event,
            SessionStartEvent::Error { code, .. } if code == "session_commit_failed"
        )));
        assert!(!events
            .iter()
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        assert!(!temp_metadata.exists());
        assert_eq!(env.sessions.active_count(), 0);
        assert_eq!(env.build_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn stop_and_automatic_cleanup_have_stable_lock_elected_results() {
        let explicit = setup_env();
        let (session_id, mut events, worker) = spawn_direct_session(&explicit, "managed", 128);
        worker.await.unwrap();
        assert!(std::iter::from_fn(|| events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        explicit
            .sessions
            .install_explicit_cleanup_hook(Arc::clone(&arrived), Arc::clone(&release));
        let sessions = explicit.sessions.clone();
        let stop_id = session_id.clone();
        let stop = tokio::task::spawn_blocking(move || sessions.stop(&stop_id));
        wait_barrier(arrived).await;
        explicit.sessions.force_lifetime_for_test(&session_id);
        wait_barrier(release).await;
        let response = stop.await.unwrap().unwrap();
        assert!(response.artifacts.is_some());
        assert_eq!(explicit.sessions.active_count(), 0);
        assert_eq!(explicit.build_slots.available_permits(), 1);

        let automatic = setup_env();
        let (session_id, mut events, worker) = spawn_direct_session(&automatic, "managed", 128);
        worker.await.unwrap();
        assert!(std::iter::from_fn(|| events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let timer_handles = automatic.sessions.timer_handles_for_test(&session_id);
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        automatic
            .sessions
            .install_automatic_cleanup_hook(Arc::clone(&arrived), Arc::clone(&release));
        let sessions = automatic.sessions.clone();
        let lifetime_id = session_id.clone();
        let lifetime = tokio::task::spawn_blocking(move || {
            sessions.force_lifetime_for_test(&lifetime_id);
        });
        wait_barrier(arrived).await;
        assert!(matches!(
            automatic.sessions.stop(&session_id),
            Err(StopError::Conflict)
        ));
        wait_barrier(release).await;
        lifetime.await.unwrap();
        assert_eq!(automatic.sessions.active_count(), 0);
        assert_eq!(automatic.build_slots.available_permits(), 1);
        assert_dir_empty(automatic.temp.path().join("artifacts").as_path());
        assert!(timer_handles.iter().all(|handle| handle.is_finished()));

        let idle = setup_env();
        let (session_id, mut events, worker) = spawn_direct_session(&idle, "managed", 128);
        worker.await.unwrap();
        assert!(std::iter::from_fn(|| events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        idle.sessions
            .install_automatic_cleanup_hook(Arc::clone(&arrived), Arc::clone(&release));
        let sessions = idle.sessions.clone();
        let idle_id = session_id.clone();
        let expiry = tokio::task::spawn_blocking(move || {
            sessions.force_idle_for_test(&idle_id);
        });
        wait_barrier(arrived).await;
        assert!(matches!(
            idle.sessions.stop(&session_id),
            Err(StopError::Conflict)
        ));
        wait_barrier(release).await;
        expiry.await.unwrap();
        assert_eq!(idle.sessions.active_count(), 0);
        assert_eq!(idle.build_slots.available_permits(), 1);
        assert_dir_empty(idle.temp.path().join("artifacts").as_path());
    }

    #[tokio::test]
    async fn workspace_lifecycle_routes_are_absent() {
        let env = setup_env();
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let client = Client::new();
            assert_eq!(
                client
                    .post(format!("http://{addr}/v1/workspaces/x/reset"))
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                client
                    .delete(format!("http://{addr}/v1/workspaces/x"))
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        })
        .await
        .expect("client task");
        server.abort();
    }

    #[tokio::test]
    async fn configured_session_actions_stream_input_evidence_and_nonzero_reuse() {
        let env = setup_env();
        let slots = Arc::clone(&env.build_slots);
        let workspace_root = env.workspace_root.clone();
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let client = bounded_lifecycle_client();
            let session_id = start_managed_session(&client, &base, "managed");
            let events = run_action_events(
                &client,
                &base,
                &session_id,
                "observe",
                serde_json::json!({"operator_data": "value", "argv": ["only-data"]}),
            );
            assert!(matches!(
                events.first(),
                Some(SessionActionEvent::Action {
                    session_id: id,
                    action,
                    status: crate::protocol::SessionActionStatus::Started,
                    ..
                }) if id == &session_id && action == "observe"
            ));
            assert!(events.iter().any(|event| matches!(
                event,
                SessionActionEvent::Stdout { data } if data.contains("observed")
            )));
            assert!(events.iter().any(|event| matches!(
                event,
                SessionActionEvent::Action {
                    status: crate::protocol::SessionActionStatus::Snapshotting,
                    ..
                }
            )));
            let (archive_path, restrictions) = match events.last().unwrap() {
                SessionActionEvent::Exit {
                    session_id: id,
                    action_id,
                    action,
                    code: 0,
                    timed_out: false,
                    artifacts: Some(archive),
                    artifact_restrictions: Some(restrictions),
                } => {
                    assert_eq!(id, &session_id);
                    assert!(action_id.starts_with("act_"));
                    assert_eq!(action, "observe");
                    (archive.path.clone(), restrictions.clone())
                }
                event => panic!("unexpected final action event: {event:?}"),
            };
            assert_eq!(restrictions.omitted_count, 1);
            assert_eq!(
                restrictions.matched_patterns,
                ["work/screenshots/secret.txt"]
            );
            let zip = client
                .get(format!("{base}{archive_path}"))
                .send()
                .unwrap()
                .bytes()
                .unwrap();
            let expected_input = serde_json::json!({
                "operator_data": "value",
                "argv": ["only-data"]
            })
            .to_string();
            assert_zip_exactly_contains(
                &zip,
                &["work/screenshots/input.json"],
                "work/screenshots/input.json",
                &expected_input,
            );

            let nonzero = run_action_events(
                &client,
                &base,
                &session_id,
                "nonzero",
                serde_json::json!({"diagnostic": true}),
            );
            assert!(matches!(
                nonzero.last(),
                Some(SessionActionEvent::Exit {
                    code: 7,
                    timed_out: false,
                    ..
                })
            ));
            let reused = run_action_events(
                &client,
                &base,
                &session_id,
                "early",
                serde_json::json!({"ignored": "stdin"}),
            );
            assert!(matches!(
                reused.last(),
                Some(SessionActionEvent::Exit {
                    code: 0,
                    timed_out: false,
                    ..
                })
            ));
            assert_eq!(
                client
                    .delete(format!("{base}/v1/sessions/{session_id}"))
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
            wait_for_session_cleanup(&slots, &workspace_root);
        })
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn action_json_authority_and_exact_body_boundary_are_enforced() {
        let env = setup_env();
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let client = bounded_lifecycle_client();
            let session_id = start_managed_session(&client, &base, "managed");
            for body in [
                serde_json::json!([]),
                serde_json::json!({"schema_version": "1", "input": []}),
                serde_json::json!({"schema_version": "1", "input": {}, "argv": ["forbidden"]}),
                serde_json::json!({"schema_version": "1", "input": {}, "cwd": "/tmp"}),
                serde_json::json!({"schema_version": "1", "input": {}, "timeout_sec": 999}),
            ] {
                assert_eq!(
                    post_action(&client, &base, &session_id, "early", body).status(),
                    StatusCode::BAD_REQUEST
                );
            }
            assert_eq!(
                post_action(
                    &client,
                    &base,
                    &session_id,
                    "missing",
                    serde_json::json!({"schema_version": "1", "input": {}}),
                )
                .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                client
                    .delete(format!("{base}/v1/sessions/{session_id}"))
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
            let session_id = start_managed_session(&client, &base, "managed-dispatch");

            let prefix = r#"{"schema_version":"1","input":{"padding":""#;
            let suffix = r#""}}"#;
            let padding = "x".repeat(MAX_SESSION_ACTION_BODY_BYTES - prefix.len() - suffix.len());
            let exact = format!("{prefix}{padding}{suffix}");
            assert_eq!(exact.len(), MAX_SESSION_ACTION_BODY_BYTES);
            let exact_response = client
                .post(format!(
                    "{base}/v1/sessions/{session_id}/actions/observe-later"
                ))
                .header(header::CONTENT_TYPE.as_str(), "application/json")
                .body(exact)
                .send()
                .unwrap();
            assert_eq!(exact_response.status(), StatusCode::OK);
            let exact_events: Vec<SessionActionEvent> = BufReader::new(exact_response)
                .lines()
                .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
                .collect();
            assert!(exact_events.iter().any(
                |event| matches!(event, SessionActionEvent::Stdout { data } if data == "dispatched")
            ));
            assert!(matches!(
                exact_events.last(),
                Some(SessionActionEvent::Exit {
                    action,
                    code: 0,
                    ..
                }) if action == "observe-later"
            ));

            let oversized = "x".repeat(MAX_SESSION_ACTION_BODY_BYTES + 1);
            assert_eq!(
                client
                    .post(format!("{base}/v1/sessions/{session_id}/actions/early"))
                    .header(header::CONTENT_TYPE.as_str(), "application/json")
                    .body(oversized)
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            let _ = client
                .delete(format!("{base}/v1/sessions/{session_id}"))
                .send()
                .unwrap();
        })
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn action_conflicts_disconnects_and_destructive_failures_cleanup() {
        let env = setup_env_with_session_lifetime(60);
        let slots = Arc::clone(&env.build_slots);
        let workspace_root = env.workspace_root.clone();
        let process_pids = env.process_pids.clone();
        let sessions = env.sessions.clone();
        let (addr, server) = start_http_server(env.app).await;
        tokio::task::spawn_blocking(move || {
            let base = format!("http://{addr}");
            let client = bounded_lifecycle_client();
            let session_id = start_managed_session(&client, &base, "managed");
            let response = post_action(
                &client,
                &base,
                &session_id,
                "block",
                serde_json::json!({"schema_version": "1", "input": {}}),
            );
            assert_eq!(response.status(), StatusCode::OK);
            let mut reader = BufReader::new(response);
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            assert!(matches!(
                serde_json::from_str::<SessionActionEvent>(line.trim()).unwrap(),
                SessionActionEvent::Action {
                    status: crate::protocol::SessionActionStatus::Started,
                    ..
                }
            ));
            assert_eq!(
                post_action(
                    &client,
                    &base,
                    &session_id,
                    "early",
                    serde_json::json!({"schema_version": "1", "input": {}}),
                )
                .status(),
                StatusCode::CONFLICT
            );
            let pid_path = process_pids.join("action-block.pid");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !pid_path.is_file() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            sessions.force_lifetime_for_test(&session_id);
            drop(reader);
            wait_for_session_cleanup(&slots, &workspace_root);
            if pid_path.is_file() {
                let pid = std::fs::read_to_string(&pid_path)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                assert!(!process_exists(pid));
            }

            let _ = std::fs::remove_file(&pid_path);
            let disconnect_id = start_managed_session(&client, &base, "managed");
            let response = post_action(
                &client,
                &base,
                &disconnect_id,
                "block",
                serde_json::json!({"schema_version": "1", "input": {}}),
            );
            let mut disconnected = BufReader::new(response);
            line.clear();
            assert!(disconnected.read_line(&mut line).unwrap() > 0);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !pid_path.is_file() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(disconnected);
            wait_for_session_cleanup(&slots, &workspace_root);
            if pid_path.is_file() {
                let pid = std::fs::read_to_string(&pid_path)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                assert!(!process_exists(pid));
            }

            let timeout_id = start_managed_session(&client, &base, "managed");
            let timeout = run_action_events(
                &client,
                &base,
                &timeout_id,
                "timeout",
                serde_json::json!({"ignored": true}),
            );
            assert!(matches!(
                timeout.last(),
                Some(SessionActionEvent::Exit {
                    timed_out: true,
                    ..
                })
            ));
            wait_for_session_cleanup(&slots, &workspace_root);
            assert_eq!(
                client
                    .delete(format!("{base}/v1/sessions/{timeout_id}"))
                    .send()
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );

            let output_id = start_managed_session(&client, &base, "managed");
            let output =
                run_action_events(&client, &base, &output_id, "output", serde_json::json!({}));
            assert!(output.iter().any(|event| matches!(
                event,
                SessionActionEvent::Error { code, .. } if code == "output_limit"
            )));
            wait_for_session_cleanup(&slots, &workspace_root);
            assert_eq!(
                std::fs::read_to_string(process_pids.join("teardown.log"))
                    .unwrap()
                    .lines()
                    .count(),
                4,
                "lifetime, disconnect, timeout, and output exhaustion must each teardown once"
            );
        })
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn stop_preempts_snapshot_and_idle_expiry_hides_half_torn_session() {
        let snapshot = setup_env();
        let (snapshot_addr, snapshot_server) = start_http_server(snapshot.app).await;
        let snapshot_base = format!("http://{snapshot_addr}");
        let session_id = tokio::task::spawn_blocking({
            let base = snapshot_base.clone();
            move || start_managed_session(&bounded_lifecycle_client(), &base, "managed")
        })
        .await
        .unwrap();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        snapshot
            .sessions
            .install_action_snapshot_hook(Arc::clone(&arrived), Arc::clone(&release));
        let action = tokio::task::spawn_blocking({
            let base = snapshot_base.clone();
            let id = session_id.clone();
            move || {
                run_action_events(
                    &bounded_lifecycle_client(),
                    &base,
                    &id,
                    "observe",
                    serde_json::json!({"snapshot": true}),
                )
            }
        });
        wait_barrier(arrived).await;
        let stop = tokio::task::spawn_blocking({
            let base = snapshot_base.clone();
            let id = session_id.clone();
            move || {
                bounded_lifecycle_client()
                    .delete(format!("{base}/v1/sessions/{id}"))
                    .send()
                    .unwrap()
            }
        });
        tokio::task::spawn_blocking({
            let sessions = snapshot.sessions.clone();
            let id = session_id.clone();
            move || sessions.wait_for_terminating_for_test(&id)
        })
        .await
        .unwrap();
        wait_barrier(release).await;
        assert_eq!(stop.await.unwrap().status(), StatusCode::OK);
        let action_events = action.await.unwrap();
        assert!(action_events.iter().any(|event| matches!(
            event,
            SessionActionEvent::Action {
                status: crate::protocol::SessionActionStatus::Snapshotting,
                ..
            }
        )));
        assert!(!action_events
            .iter()
            .any(|event| matches!(event, SessionActionEvent::Exit { .. })));
        assert_eq!(snapshot.sessions.active_count(), 0);
        snapshot_server.abort();

        let idle = setup_env();
        let (idle_addr, idle_server) = start_http_server(idle.app).await;
        let idle_base = format!("http://{idle_addr}");
        let idle_id = tokio::task::spawn_blocking({
            let base = idle_base.clone();
            move || start_managed_session(&bounded_lifecycle_client(), &base, "managed")
        })
        .await
        .unwrap();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        idle.sessions
            .install_automatic_cleanup_hook(Arc::clone(&arrived), Arc::clone(&release));
        let expiry = tokio::task::spawn_blocking({
            let sessions = idle.sessions.clone();
            let id = idle_id.clone();
            move || sessions.force_idle_for_test(&id)
        });
        wait_barrier(arrived).await;
        let status = tokio::task::spawn_blocking({
            let base = idle_base.clone();
            let id = idle_id.clone();
            move || {
                post_action(
                    &bounded_lifecycle_client(),
                    &base,
                    &id,
                    "early",
                    serde_json::json!({"schema_version": "1", "input": {}}),
                )
                .status()
            }
        })
        .await
        .unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
        wait_barrier(release).await;
        expiry.await.unwrap();
        assert_eq!(idle.sessions.active_count(), 0);
        idle_server.abort();
    }

    #[tokio::test]
    async fn stop_and_lifetime_preempt_every_snapshot_stage_with_single_teardown() {
        for checkpoint in [
            ArtifactSnapshotCheckpoint::Traversal,
            ArtifactSnapshotCheckpoint::ArchiveWrite,
            ArtifactSnapshotCheckpoint::Published,
        ] {
            let env = setup_env_with_session_lifetime(60);
            let (session_id, mut ready_events, initializer) =
                spawn_direct_session(&env, "managed", 128);
            initializer.await.unwrap();
            assert!(std::iter::from_fn(|| ready_events.try_recv().ok())
                .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
            let arrived = Arc::new(std::sync::Barrier::new(2));
            let release = Arc::new(std::sync::Barrier::new(2));
            env.sessions.install_artifact_checkpoint_hook(
                checkpoint,
                Arc::clone(&arrived),
                Arc::clone(&release),
            );
            let reservation = env.sessions.start_action(&session_id, "observe").unwrap();
            let (sender, _receiver) = mpsc::channel(128);
            let sessions = env.sessions.clone();
            let worker = tokio::task::spawn_blocking(move || {
                sessions.execute_action(reservation, br#"{}"#.to_vec(), sender);
            });
            wait_barrier(arrived).await;
            assert!(matches!(
                env.sessions.start_action(&session_id, "early"),
                Err(ActionError::Conflict)
            ));
            if checkpoint == ArtifactSnapshotCheckpoint::Published {
                assert!(std::fs::read_dir(env.temp.path().join("artifacts"))
                    .unwrap()
                    .next()
                    .is_some());
            }
            let stop = tokio::task::spawn_blocking({
                let sessions = env.sessions.clone();
                let id = session_id.clone();
                move || sessions.stop(&id).unwrap()
            });
            tokio::task::spawn_blocking({
                let sessions = env.sessions.clone();
                let id = session_id.clone();
                move || sessions.wait_for_terminating_for_test(&id)
            })
            .await
            .unwrap();
            wait_barrier(release).await;
            let stopped = stop.await.unwrap();
            assert_eq!(stopped.teardown.exit_code, Some(0));
            assert!(stopped.artifacts.is_some());
            worker.await.unwrap();
            assert_eq!(env.sessions.active_count(), 0);
            assert_eq!(
                std::fs::read_dir(env.temp.path().join("artifacts"))
                    .unwrap()
                    .count(),
                1,
                "cancelled action archive leaked alongside explicit-stop archive"
            );
            assert_eq!(
                std::fs::read_to_string(env.process_pids.join("teardown.log"))
                    .unwrap()
                    .lines()
                    .count(),
                1,
                "{checkpoint:?} teardown count"
            );
        }

        let env = setup_env_with_session_lifetime(60);
        let (session_id, mut ready_events, initializer) =
            spawn_direct_session(&env, "managed", 128);
        initializer.await.unwrap();
        assert!(std::iter::from_fn(|| ready_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        env.sessions.install_artifact_checkpoint_hook(
            ArtifactSnapshotCheckpoint::Published,
            Arc::clone(&arrived),
            Arc::clone(&release),
        );
        let reservation = env.sessions.start_action(&session_id, "observe").unwrap();
        let (sender, _receiver) = mpsc::channel(128);
        let sessions = env.sessions.clone();
        let worker = tokio::task::spawn_blocking(move || {
            sessions.execute_action(reservation, br#"{}"#.to_vec(), sender);
        });
        wait_barrier(arrived).await;
        env.sessions.force_lifetime_for_test(&session_id);
        wait_barrier(release).await;
        worker.await.unwrap();
        assert_eq!(env.sessions.active_count(), 0);
        assert_dir_empty(&env.temp.path().join("artifacts"));
        assert_eq!(
            std::fs::read_to_string(env.process_pids.join("teardown.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn final_enqueue_without_delivery_ack_destroys_session_and_archive() {
        let env = setup_env();
        let (session_id, mut ready_events, initializer) =
            spawn_direct_session(&env, "managed", 128);
        initializer.await.unwrap();
        assert!(std::iter::from_fn(|| ready_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        env.sessions
            .install_final_enqueued_hook(Arc::clone(&arrived), Arc::clone(&release));
        let reservation = env.sessions.start_action(&session_id, "observe").unwrap();
        let action_id = reservation.action_id().to_string();
        let (sender, _receiver) = mpsc::channel(128);
        let sessions = env.sessions.clone();
        let worker = tokio::task::spawn_blocking(move || {
            sessions.execute_action(reservation, br#"{"late":true}"#.to_vec(), sender);
        });
        wait_barrier(arrived).await;
        assert!(std::fs::read_dir(env.temp.path().join("artifacts"))
            .unwrap()
            .next()
            .is_some());
        env.sessions.disconnect_action(&session_id, &action_id);
        wait_barrier(release).await;
        worker.await.unwrap();
        assert_eq!(env.sessions.active_count(), 0);
        assert_dir_empty(&env.temp.path().join("artifacts"));
        assert_eq!(
            std::fs::read_to_string(env.process_pids.join("teardown.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn dropping_stream_after_final_poll_but_before_delivery_ack_destroys_session() {
        let env = setup_env();
        let (session_id, mut ready_events, initializer) =
            spawn_direct_session(&env, "managed", 128);
        initializer.await.unwrap();
        assert!(std::iter::from_fn(|| ready_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        let reservation = env.sessions.start_action(&session_id, "observe").unwrap();
        let action_id = reservation.action_id().to_string();
        let (sender, receiver) = mpsc::channel(128);
        let sessions = env.sessions.clone();
        let worker = tokio::task::spawn_blocking(move || {
            sessions.execute_action(reservation, br#"{}"#.to_vec(), sender);
        });
        let mut stream = SessionActionEventStream {
            receiver,
            sessions: env.sessions.clone(),
            session_id: session_id.clone(),
            action_id,
            pending_ack: None,
        };
        loop {
            let event = stream.next().await.expect("action stream event");
            if matches!(event, SessionActionEvent::Exit { .. }) {
                break;
            }
        }
        assert!(stream.pending_ack.is_some());
        drop(stream);
        worker.await.unwrap();
        assert_eq!(env.sessions.active_count(), 0);
        assert_dir_empty(&env.temp.path().join("artifacts"));
        assert_eq!(
            std::fs::read_to_string(env.process_pids.join("teardown.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn forced_post_spawn_action_setup_failure_destroys_session_once() {
        let env = setup_env();
        let (session_id, mut ready_events, initializer) =
            spawn_direct_session(&env, "managed", 128);
        initializer.await.unwrap();
        assert!(std::iter::from_fn(|| ready_events.try_recv().ok())
            .any(|event| matches!(event, SessionStartEvent::Ready { .. })));
        env.sessions.force_next_action_setup_failure();
        let reservation = env.sessions.start_action(&session_id, "block").unwrap();
        let (sender, mut receiver) = mpsc::channel(128);
        let sessions = env.sessions.clone();
        tokio::task::spawn_blocking(move || {
            sessions.execute_action(reservation, br#"{}"#.to_vec(), sender);
        })
        .await
        .unwrap();
        let events = std::iter::from_fn(|| receiver.try_recv().ok())
            .map(|item| item.event)
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| matches!(
            event,
            SessionActionEvent::Error { code, .. } if code == "stdin_write_failed"
        )));
        assert_eq!(env.sessions.active_count(), 0);
        assert_eq!(
            std::fs::read_to_string(env.process_pids.join("teardown.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    fn setup_env() -> TestEnv {
        setup_env_with_options(SourcesConfig::default().upload_timeout_sec, true)
    }

    fn setup_env_with_upload_timeout(upload_timeout_sec: u64) -> TestEnv {
        setup_env_with_options(upload_timeout_sec, true)
    }

    fn setup_env_with_options(upload_timeout_sec: u64, managed_sessions_enabled: bool) -> TestEnv {
        setup_env_with_options_and_lifetime(upload_timeout_sec, managed_sessions_enabled, 2)
    }

    fn setup_env_with_session_lifetime(max_lifetime_sec: u64) -> TestEnv {
        setup_env_with_options_and_lifetime(
            SourcesConfig::default().upload_timeout_sec,
            true,
            max_lifetime_sec,
        )
    }

    fn setup_env_with_options_and_lifetime(
        upload_timeout_sec: u64,
        managed_sessions_enabled: bool,
        max_lifetime_sec: u64,
    ) -> TestEnv {
        let temp = tempdir().expect("tempdir");
        let workspace_root = temp.path().join("workspaces");
        let artifacts_root = temp.path().join("artifacts");
        let marker = temp.path().join("spawned");
        let process_pids = temp.path().join("process-pids");
        std::fs::create_dir(&process_pids).expect("pid directory");
        std::fs::create_dir_all(&workspace_root).expect("workspace root");
        std::fs::create_dir_all(&artifacts_root).expect("artifacts root");
        let script = temp.path().join("task.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\ntest \"$FIXED\" = server\nprintf spawned > {}\ncase \"$1\" in\n  fixed) IFS= read -r input < input.txt || true; printf '%s:%s:%s' \"$input\" \"$1\" \"$FIXED\" > out/result.txt ;;\n  teardown) printf 'teardown\\n' >> \"$TEARDOWN_LOG\"; sleep 0.2 ;;\n  setup) printf 'prepared\n' > setup.txt ;;\n  managed-setup) printf 'prepared\n' > setup.txt; printf complete > \"$TEARDOWN_LOG.setup\" ;;\n  setup-error) printf setup-failed > out/setup-failed.txt; exit 9 ;;\n  setup-timeout) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; exec sleep 60 ;;\n  phase-output) dd if=/dev/zero bs=1048576 count=17 2>/dev/null ;;\n  error) exit 7 ;;\n  timeout|disconnect) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; exec sleep 60 ;;\n  output) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; dd if=/dev/zero bs=1048576 count=33 2>/dev/null; exec sleep 60 ;;\n  nonreader) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; dd if=/dev/zero bs=1048576 count=16 2>/dev/null; exec sleep 60 ;;\n  action-observe) mkdir -p screenshots; cat > screenshots/input.json; printf observed; printf secret > screenshots/secret.txt ;;\n  action-dispatch) mkdir -p screenshots; cat > screenshots/input.json; printf dispatched ;;\n  action-nonzero) cat > action-nonzero.json; exit 7 ;;\n  action-timeout) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; exec sleep 60 ;;\n  action-output) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; dd if=/dev/zero bs=1048576 count=33 2>/dev/null | tr '\\000' x; exec sleep 60 ;;\n  action-early) exit 0 ;;\n  action-block) trap '' TERM; sleep 60 & echo $! > {}/$1.pid; exec sleep 60 ;;\n  *) exit 64 ;;\nesac\n",
                marker.display(),
                process_pids.display(),
                process_pids.display(),
                process_pids.display(),
                process_pids.display(),
                process_pids.display(),
                process_pids.display(),
                process_pids.display()
            ),
        )
        .expect("script");
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let artifacts = ArtifactsConfig {
            storage_root: artifacts_root,
            restricted_patterns: vec!["work/screenshots/secret.txt".to_string()],
            ..ArtifactsConfig::default()
        };
        let mut service = ServiceConfig::default();
        service.http.enabled = true;
        let config = Config {
            schema_version: CONFIG_SCHEMA_VERSION.to_string(),
            service,
            build: BuildConfig {
                workspace_root: workspace_root.clone(),
                max_timeout_sec: 60,
                max_output_bytes: 32 * 1024 * 1024,
                run_as_user: None,
                run_as_group: None,
            },
            tasks: {
                let build_task = TaskConfig {
                    script: None,
                    executable: Some(script.clone()),
                    args: vec!["fixed".to_string()],
                    setup: None,
                    session: None,
                    cwd: "work".to_string(),
                    timeout_sec: 30,
                    environment: HashMap::from([
                        ("FIXED".to_string(), "server".to_string()),
                        (
                            "TEARDOWN_LOG".to_string(),
                            process_pids.join("teardown.log").display().to_string(),
                        ),
                        (
                            "PATH".to_string(),
                            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
                        ),
                    ]),
                    artifacts: ArtifactSpec {
                        include: vec!["work/out/**".to_string()],
                        exclude: Vec::new(),
                    },
                    workspace: WorkspacePolicy::Fresh,
                };
                let process_task = |name: &str, timeout_sec: u64| {
                    let mut task = build_task.clone();
                    task.script = Some(ScriptText::new(format!(
                        "exec '{}' '{}'",
                        script.display(),
                        name
                    )));
                    task.executable = None;
                    task.args.clear();
                    task.timeout_sec = timeout_sec;
                    task.artifacts.include.clear();
                    task
                };
                let shell_behavior_task = |script_text: String| {
                    let mut task = build_task.clone();
                    task.script = Some(ScriptText::new(script_text));
                    task.executable = None;
                    task.args.clear();
                    task.artifacts.include.clear();
                    task
                };
                let phased_task = |setup_arg: &str, setup_timeout_sec: u64| {
                    let mut task = build_task.clone();
                    task.script = Some(ScriptText::new(format!(
                        "IFS= read -r prepared < setup.txt\ntest \"$prepared\" = prepared\nexec '{}' fixed",
                        script.display()
                    )));
                    task.executable = None;
                    task.args.clear();
                    task.setup = Some(TaskSetupConfig {
                        script: None,
                        executable: Some(script.clone()),
                        args: vec![setup_arg.to_string()],
                        timeout_sec: setup_timeout_sec,
                    });
                    task
                };
                let action =
                    |arg: &str, timeout_sec: u64, artifacts: ArtifactSpec| SessionActionConfig {
                        script: None,
                        executable: Some(script.clone()),
                        args: vec![arg.to_string()],
                        timeout_sec,
                        artifacts,
                    };
                let mut managed = build_task.clone();
                managed.session = Some(TaskSessionConfig {
                    idle_timeout_sec: max_lifetime_sec / 2,
                    max_lifetime_sec,
                    teardown: SessionTeardownConfig {
                        script: None,
                        executable: Some(script.clone()),
                        args: vec!["teardown".to_string()],
                        timeout_sec: 3,
                    },
                    actions: HashMap::from([
                        (
                            "observe".to_string(),
                            action(
                                "action-observe",
                                3,
                                ArtifactSpec {
                                    include: vec!["work/screenshots/**".to_string()],
                                    exclude: Vec::new(),
                                },
                            ),
                        ),
                        (
                            "nonzero".to_string(),
                            action("action-nonzero", 3, ArtifactSpec::default()),
                        ),
                        (
                            "timeout".to_string(),
                            action("action-timeout", 1, ArtifactSpec::default()),
                        ),
                        (
                            "output".to_string(),
                            action("action-output", 9, ArtifactSpec::default()),
                        ),
                        (
                            "early".to_string(),
                            action("action-early", 3, ArtifactSpec::default()),
                        ),
                        (
                            "block".to_string(),
                            action("action-block", 30, ArtifactSpec::default()),
                        ),
                    ]),
                    action_dispatcher: None,
                });
                let mut managed_dispatch = managed.clone();
                let dispatch_session = managed_dispatch.session.as_mut().unwrap();
                let mut dispatcher = dispatch_session.actions.remove("observe").unwrap();
                dispatcher.args = vec!["action-dispatch".to_string()];
                dispatch_session.actions.clear();
                dispatch_session.action_dispatcher = Some(dispatcher);
                let mut managed_phased = phased_task("managed-setup", 3);
                managed_phased.session = managed.session.clone();
                let mut managed_failure = process_task("error", 3);
                managed_failure.session = managed.session.clone();
                let mut managed_disconnect = process_task("disconnect", 30);
                managed_disconnect.session = managed.session.clone();
                let mut managed_nonreader = process_task("nonreader", 10);
                managed_nonreader.session = managed.session.clone();
                let mut setup_error = phased_task("setup-error", 30);
                setup_error.script = Some(ScriptText::new(format!(
                    "printf forbidden > '{}'",
                    process_pids.join("run-after-setup-error").display()
                )));
                let mut setup_timeout = phased_task("setup-timeout", 1);
                setup_timeout.script = Some(ScriptText::new(format!(
                    "printf forbidden > '{}'",
                    process_pids.join("run-after-setup-timeout").display()
                )));
                let mut shared_output = phased_task("phase-output", 30);
                shared_output.script = Some(ScriptText::new(format!(
                    "exec '{}' phase-output",
                    script.display()
                )));
                shared_output.artifacts.include.clear();
                HashMap::from([
                    ("build".to_string(), build_task.clone()),
                    ("managed".to_string(), managed),
                    ("managed-dispatch".to_string(), managed_dispatch),
                    ("managed-phased".to_string(), managed_phased),
                    ("managed-failure".to_string(), managed_failure),
                    ("managed-disconnect".to_string(), managed_disconnect),
                    ("managed-nonreader".to_string(), managed_nonreader),
                    ("error".to_string(), process_task("error", 30)),
                    ("timeout".to_string(), process_task("timeout", 1)),
                    ("disconnect".to_string(), process_task("disconnect", 30)),
                    ("output".to_string(), process_task("output", 30)),
                    ("nonreader".to_string(), process_task("nonreader", 10)),
                    ("phased".to_string(), phased_task("setup", 10)),
                    ("setup-error".to_string(), setup_error),
                    ("setup-timeout".to_string(), setup_timeout),
                    ("shared-output".to_string(), shared_output),
                    (
                        "errexit".to_string(),
                        shell_behavior_task(format!(
                            "false\nprintf forbidden > '{}'",
                            process_pids.join("errexit-marker").display()
                        )),
                    ),
                    (
                        "nounset".to_string(),
                        shell_behavior_task(format!(
                            "printf '%s' \"$INDENTURED_UNSET_VALUE\"\nprintf forbidden > '{}'",
                            process_pids.join("nounset-marker").display()
                        )),
                    ),
                ])
            },
            sources: SourcesConfig {
                upload_timeout_sec,
                ..SourcesConfig::default()
            },
            artifacts,
            logging: LoggingConfig::default(),
        };
        config.validate().expect("valid test config");
        let max_transfer_bytes = config.sources.max_transfer_bytes;
        let build_slots = Arc::new(Semaphore::new(1));
        let config = Arc::new(config);
        let sessions = SessionManager::new(Arc::clone(&config)).expect("session manager");
        let app = build_router(
            AppState {
                config: Arc::clone(&config),
                auth: Arc::new(AuthSecrets::empty()),
                auth_required: false,
                build_slots: Arc::clone(&build_slots),
                sessions: sessions.clone(),
                managed_sessions_enabled,
            },
            max_transfer_bytes,
        );
        TestEnv {
            temp,
            app,
            workspace_root,
            marker,
            process_pids,
            build_slots,
            sessions,
            config,
        }
    }

    async fn start_http_server(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let server = axum_server::from_tcp(listener)
            .expect("server")
            .serve(app.into_make_service());
        let handle = tokio::spawn(async move {
            let _ = server.await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        (addr, handle)
    }

    async fn start_uds_server(app: Router, socket: &Path) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(socket).expect("bind uds");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let service = TowerToHyperService::new(app.clone());
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        handle
    }

    fn run_build_and_fetch(client: Client, base: String) -> Vec<u8> {
        let source = source_zip();
        let request = Request {
            schema_version: "1".to_string(),
            request_id: Some("integration".to_string()),
            task: "build".to_string(),
            source: SourceMetadata {
                format: SourceFormat::Zip,
            },
        };
        let response = client
            .post(format!("{base}/v1/builds"))
            .multipart(
                Form::new()
                    .part(
                        "metadata",
                        Part::text(serde_json::to_string(&request).unwrap())
                            .mime_str("application/json")
                            .unwrap(),
                    )
                    .part(
                        "source",
                        Part::file(source.path())
                            .unwrap()
                            .mime_str("application/zip")
                            .unwrap(),
                    ),
            )
            .send()
            .expect("post build");
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            panic!("build failed with {status}: {body}");
        }
        let mut reader = BufReader::new(response);
        let mut line = String::new();
        let archive_path = loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            let event: ResponseEvent = serde_json::from_str(line.trim()).expect("event");
            if let ResponseEvent::Exit {
                code, artifacts, ..
            } = event
            {
                assert_eq!(code, 0);
                break artifacts.expect("artifact archive").path;
            }
        };
        let mut response = client
            .get(format!("{base}{archive_path}"))
            .send()
            .expect("get artifacts");
        let mut bytes = Vec::new();
        response.copy_to(&mut bytes).unwrap();
        bytes
    }

    fn post_task(client: &Client, base: &str, task: &str) -> reqwest::blocking::Response {
        post_raw(
            client,
            base,
            serde_json::json!({
                "schema_version": "1",
                "request_id": format!("{task}-integration"),
                "task": task,
                "source": {"format": "zip"}
            }),
            false,
        )
    }

    fn spawn_direct_session(
        env: &TestEnv,
        task: &str,
        channel_capacity: usize,
    ) -> (
        String,
        mpsc::Receiver<SessionStartEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        let permit = Arc::clone(&env.build_slots)
            .try_acquire_owned()
            .expect("test session permit");
        let validated = crate::build::ValidatedRequest {
            request_id: Some(format!("{task}-direct")),
            task_id: task.to_string(),
            task: env.config.tasks.get(task).unwrap().clone(),
        };
        let reservation = env.sessions.reserve(validated, permit);
        let session_id = reservation.id().to_string();
        assert!(env.sessions.begin_initialization(&reservation));
        let source = source_zip().into_temp_path();
        let sessions = env.sessions.clone();
        let (sender, receiver) = mpsc::channel(channel_capacity);
        let worker = tokio::task::spawn_blocking(move || {
            sessions.initialize(reservation, source, sender);
        });
        (session_id, receiver, worker)
    }

    async fn wait_barrier(barrier: Arc<std::sync::Barrier>) {
        tokio::task::spawn_blocking(move || barrier.wait())
            .await
            .unwrap();
    }

    fn post_session(client: &Client, base: &str, task: &str) -> reqwest::blocking::Response {
        let source = source_zip();
        client
            .post(format!("{base}/v1/sessions"))
            .multipart(
                Form::new()
                    .part(
                        "metadata",
                        Part::text(
                            serde_json::json!({
                                "schema_version": "1",
                                "request_id": format!("{task}-session"),
                                "task": task,
                                "source": {"format": "zip"}
                            })
                            .to_string(),
                        )
                        .mime_str("application/json")
                        .unwrap(),
                    )
                    .part(
                        "source",
                        Part::file(source.path())
                            .unwrap()
                            .mime_str("application/zip")
                            .unwrap(),
                    ),
            )
            .send()
            .expect("post session")
    }

    fn start_managed_session(client: &Client, base: &str, task: &str) -> String {
        let response = post_session(client, base, task);
        assert_eq!(response.status(), StatusCode::OK);
        let mut reader = BufReader::new(response);
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            match serde_json::from_str::<SessionStartEvent>(line.trim()).unwrap() {
                SessionStartEvent::Ready { session_id, .. } => return session_id,
                SessionStartEvent::Exit { code, .. } => {
                    panic!("session initialization exited {code}")
                }
                _ => {}
            }
        }
    }

    fn post_action(
        client: &Client,
        base: &str,
        session_id: &str,
        action: &str,
        body: serde_json::Value,
    ) -> reqwest::blocking::Response {
        client
            .post(format!("{base}/v1/sessions/{session_id}/actions/{action}"))
            .json(&body)
            .send()
            .expect("post session action")
    }

    fn run_action_events(
        client: &Client,
        base: &str,
        session_id: &str,
        action: &str,
        input: serde_json::Value,
    ) -> Vec<SessionActionEvent> {
        let response = post_action(
            client,
            base,
            session_id,
            action,
            serde_json::json!({"schema_version": "1", "input": input}),
        );
        assert_eq!(response.status(), StatusCode::OK);
        let mut reader = BufReader::new(response);
        let mut events = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            events.push(serde_json::from_str(line.trim()).expect("session action event"));
        }
        events
    }

    fn run_task_events(client: &Client, base: &str, task: &str) -> (Vec<String>, (i32, bool)) {
        let response = post_task(client, base, task);
        assert_eq!(response.status(), StatusCode::OK);
        let mut reader = BufReader::new(response);
        let mut errors = Vec::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            match serde_json::from_str::<ResponseEvent>(line.trim()).unwrap() {
                ResponseEvent::Error { code, .. } => errors.push(code),
                ResponseEvent::Exit {
                    code, timed_out, ..
                } => return (errors, (code, timed_out)),
                _ => {}
            }
        }
    }

    fn run_task_events_through_eof(client: &Client, base: &str, task: &str) -> Vec<ResponseEvent> {
        let response = post_task(client, base, task);
        assert_eq!(response.status(), StatusCode::OK);
        let mut reader = BufReader::new(response);
        let mut events = Vec::new();
        let mut final_event_at = None;
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line).expect("read NDJSON response");
            if read == 0 {
                break;
            }
            let event = serde_json::from_str::<ResponseEvent>(line.trim()).expect("event");
            if matches!(event, ResponseEvent::Exit { .. }) {
                final_event_at = Some(std::time::Instant::now());
            }
            events.push(event);
        }
        let final_event_at = final_event_at.expect("final exit event");
        assert!(
            final_event_at.elapsed() < Duration::from_millis(500),
            "NDJSON body did not reach EOF promptly after its final event"
        );
        events
    }

    fn wait_for_slot_and_cleanup(slots: &Semaphore, workspace_root: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while (slots.available_permits() != 1
            || std::fs::read_dir(workspace_root)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(true))
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(slots.available_permits(), 1);
        assert_dir_empty(workspace_root);
    }

    fn wait_for_session_cleanup(slots: &Semaphore, workspace_root: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while (slots.available_permits() != 1
            || std::fs::read_dir(workspace_root)
                .map(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .any(|entry| entry.file_name() != ".sessions")
                })
                .unwrap_or(true))
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(slots.available_permits(), 1);
        let remaining = std::fs::read_dir(workspace_root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name != ".sessions")
            .collect::<Vec<_>>();
        assert!(
            remaining.is_empty(),
            "session workspace not clean: {remaining:?}"
        );
    }

    fn read_pid(path: &Path) -> i32 {
        std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("missing descendant pid at {}: {err}", path.display()))
            .trim()
            .parse()
            .unwrap()
    }

    fn process_exists(pid: i32) -> bool {
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    fn post_raw(
        client: &Client,
        base: &str,
        metadata: serde_json::Value,
        source_first: bool,
    ) -> reqwest::blocking::Response {
        let source = source_zip();
        let metadata = Part::text(metadata.to_string())
            .mime_str("application/json")
            .unwrap();
        let source_part = Part::file(source.path())
            .unwrap()
            .mime_str("application/zip")
            .unwrap();
        let form = if source_first {
            Form::new()
                .part("source", source_part)
                .part("metadata", metadata)
        } else {
            Form::new()
                .part("metadata", metadata)
                .part("source", source_part)
        };
        client
            .post(format!("{base}/v1/builds"))
            .multipart(form)
            .send()
            .expect("post invalid")
    }

    fn source_zip() -> NamedTempFile {
        let temp = NamedTempFile::new().expect("temp source");
        let mut zip = ZipWriter::new(temp.reopen().unwrap());
        zip.add_directory("work/out/", FileOptions::default().unix_permissions(0o755))
            .unwrap();
        zip.start_file(
            "work/input.txt",
            FileOptions::default().unix_permissions(0o644),
        )
        .unwrap();
        zip.write_all(b"source").unwrap();
        zip.finish().unwrap();
        temp
    }

    fn assert_zip_exactly_contains(
        bytes: &[u8],
        expected_names: &[&str],
        content_name: &str,
        expected_content: &str,
    ) {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip");
        let names: Vec<String> = (0..zip.len())
            .map(|index| zip.by_index(index).unwrap().name().to_string())
            .collect();
        assert_eq!(names, expected_names);
        let mut file = zip.by_name(content_name).expect("artifact entry");
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text, expected_content);
    }

    fn assert_dir_empty(path: &Path) {
        let entries: Vec<_> = std::fs::read_dir(path)
            .expect("workspace root")
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!(entries.is_empty(), "workspace root not clean: {entries:?}");
    }
}
