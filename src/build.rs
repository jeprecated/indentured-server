use std::collections::HashSet;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{error::TrySendError, Sender};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::artifacts::{collect_artifacts_zip, ArtifactError};
use crate::config::{Config, TaskConfig, TaskExecution, SCRIPT_SHELL};
use crate::protocol::{ArtifactArchive, Request, ResponseEvent, REQUEST_SCHEMA_VERSION};
use crate::user::{lookup_group_gid, lookup_user, lookup_user_by_name, UserInfo};
use crate::validation::{validate_cwd, validate_relative_path, ValidationError};

const TIMEOUT_EXIT_CODE: i32 = 124;
#[cfg(not(test))]
const TIMEOUT_KILL_GRACE: Duration = Duration::from_secs(5);
#[cfg(test)]
const TIMEOUT_KILL_GRACE: Duration = Duration::from_millis(500);
const OUTPUT_CHUNK_SIZE: usize = 4096;
#[cfg(not(test))]
const OUTPUT_FORWARD_GRACE: Duration = Duration::from_secs(2);
#[cfg(test)]
const OUTPUT_FORWARD_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Default)]
pub struct CancellationFlag(Arc<AtomicBool>);

impl CancellationFlag {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub struct BuildError {
    pub code: &'static str,
    pub message: String,
    pub pattern: Option<String>,
}

impl BuildError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            pattern: None,
        }
    }

    fn with_pattern(code: &'static str, message: impl Into<String>, pattern: String) -> Self {
        Self {
            code,
            message: message.into(),
            pattern: Some(pattern),
        }
    }
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BuildError {}

pub struct ValidatedRequest {
    pub request_id: Option<String>,
    pub task_id: String,
    pub task: TaskConfig,
}

pub fn validate_request(request: Request, config: &Config) -> Result<ValidatedRequest, BuildError> {
    if request.schema_version != REQUEST_SCHEMA_VERSION {
        return Err(BuildError::new(
            "schema_version",
            format!("unsupported schema_version {}", request.schema_version),
        ));
    }
    let task =
        config.tasks.get(&request.task).cloned().ok_or_else(|| {
            BuildError::new("unknown_task", format!("unknown task {}", request.task))
        })?;
    Ok(ValidatedRequest {
        request_id: request.request_id,
        task_id: request.task,
        task,
    })
}

pub fn execute_build(
    validated: ValidatedRequest,
    config: Arc<Config>,
    source_archive: tempfile::TempPath,
    sender: Sender<ResponseEvent>,
    cancellation: CancellationFlag,
) {
    if let Err(err) = run_build(validated, &config, &source_archive, &sender, &cancellation) {
        let _ = send_response(
            &sender,
            ResponseEvent::Error {
                code: err.code.to_string(),
                message: Some(err.message),
                pattern: err.pattern,
            },
        );
        let _ = send_response(
            &sender,
            ResponseEvent::Exit {
                code: 1,
                timed_out: false,
                artifacts: None,
                artifact_restrictions: None,
            },
        );
    }
}

fn run_build(
    validated: ValidatedRequest,
    config: &Config,
    source_archive: &Path,
    sender: &Sender<ResponseEvent>,
    cancellation: &CancellationFlag,
) -> Result<(), BuildError> {
    let build_id = format!("bld_{}", Uuid::new_v4().simple());
    send_response(
        sender,
        ResponseEvent::Build {
            id: build_id.clone(),
            status: "started".to_string(),
        },
    )
    .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;

    let run_as = resolve_run_as(config)?;
    validate_run_as_uid(&run_as, unsafe { libc::geteuid() })?;
    std::fs::create_dir_all(&config.build.workspace_root).map_err(|err| {
        BuildError::new(
            "workspace_create_failed",
            format!("failed to create workspace root: {err}"),
        )
    })?;
    let workspace = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(&config.build.workspace_root)
        .map_err(|err| {
            BuildError::new(
                "workspace_create_failed",
                format!("failed to create fresh workspace: {err}"),
            )
        })?;
    extract_source_archive(
        source_archive,
        workspace.path(),
        config.sources.max_uncompressed_bytes,
        config.sources.max_files,
        config.sources.max_depth,
    )?;
    prepare_workspace_ownership(workspace.path(), &run_as)?;

    run_build_in_workspace(
        &validated,
        config,
        &run_as,
        workspace.path(),
        &build_id,
        sender,
        cancellation,
    )
}

fn run_build_in_workspace(
    validated: &ValidatedRequest,
    config: &Config,
    run_as: &RunAs,
    workspace_root: &Path,
    build_id: &str,
    sender: &Sender<ResponseEvent>,
    cancellation: &CancellationFlag,
) -> Result<(), BuildError> {
    let cwd = resolve_cwd(workspace_root, Some(&validated.task.cwd))?;
    let request_id = validated.request_id.as_deref().unwrap_or("-");
    info!(
        "build started build_id={} request_id={} task={}",
        build_id, request_id, validated.task_id
    );

    let env = build_env(&validated.task, &run_as.user);
    let mut command = match validated.task.execution() {
        TaskExecution::Script(script) => {
            let mut command = Command::new(SCRIPT_SHELL);
            command.arg("-eu").arg("-c").arg(script);
            command
        }
        TaskExecution::Executable { path, args } => {
            let mut command = Command::new(path);
            command.args(args);
            command
        }
    };
    command
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    configure_command(&mut command, run_as)?;

    let mut child = command
        .spawn()
        .map_err(|err| BuildError::new("spawn_failed", format!("failed to spawn task: {err}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BuildError::new("io", "failed to capture stdout from task"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BuildError::new("io", "failed to capture stderr from task"))?;
    let output_bytes = Arc::new(AtomicU64::new(0));
    let output_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_handle = spawn_output_thread(
        stdout,
        sender.clone(),
        StreamKind::Stdout,
        config.build.max_output_bytes,
        Arc::clone(&output_bytes),
        Arc::clone(&output_exceeded),
        cancellation.clone(),
    );
    let stderr_handle = spawn_output_thread(
        stderr,
        sender.clone(),
        StreamKind::Stderr,
        config.build.max_output_bytes,
        Arc::clone(&output_bytes),
        Arc::clone(&output_exceeded),
        cancellation.clone(),
    );

    let start = Instant::now();
    let outcome = wait_with_timeout(&mut child, validated.task.timeout_sec, cancellation)
        .map_err(|err| BuildError::new("wait_failed", err.to_string()))?;
    join_output_thread(stdout_handle);
    join_output_thread(stderr_handle);

    if output_exceeded.load(Ordering::SeqCst) {
        return Err(BuildError::new(
            "output_limit",
            format!(
                "task output exceeds build.max_output_bytes ({} bytes)",
                config.build.max_output_bytes
            ),
        ));
    }

    let (exit_code, timed_out) = match outcome {
        WaitOutcome::Exited { code, timed_out } => (code, timed_out),
        WaitOutcome::Cancelled => {
            warn!(
                "task cancelled build_id={} request_id={} duration_sec={} cwd={}",
                build_id,
                request_id,
                start.elapsed().as_secs(),
                cwd.display()
            );
            return Err(BuildError::new("stream_closed", "client disconnected"));
        }
    };

    if timed_out {
        warn!(
            "task timed out build_id={} request_id={} duration_sec={} cwd={}",
            build_id,
            request_id,
            start.elapsed().as_secs(),
            cwd.display()
        );
    } else if exit_code == 0 {
        info!(
            "task completed build_id={} task={} exit_code=0 duration_sec={}",
            build_id,
            validated.task_id,
            start.elapsed().as_secs()
        );
    } else {
        error!(
            "task completed build_id={} task={} exit_code={} duration_sec={}",
            build_id,
            validated.task_id,
            exit_code,
            start.elapsed().as_secs()
        );
    }

    // The terminated task no longer owns the fresh workspace. Collect its
    // configured outputs for success, ordinary failure, and timeout alike;
    // the exit event below always preserves the original task status.
    let artifacts = match collect_artifacts_zip(
        workspace_root,
        &validated.task.artifacts,
        &config.artifacts,
        build_id,
    ) {
        Ok(archive) => archive,
        Err(err) => {
            let build_err = map_artifact_error(err);
            send_response(
                sender,
                ResponseEvent::Error {
                    code: build_err.code.to_string(),
                    message: Some(build_err.message.clone()),
                    pattern: build_err.pattern.clone(),
                },
            )
            .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
            send_response(
                sender,
                ResponseEvent::Exit {
                    code: if exit_code == 0 && !timed_out {
                        1
                    } else {
                        exit_code
                    },
                    timed_out,
                    artifacts: None,
                    artifact_restrictions: None,
                },
            )
            .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
            return Ok(());
        }
    };

    send_response(
        sender,
        ResponseEvent::Exit {
            code: exit_code,
            timed_out,
            artifacts: artifacts.archive,
            artifact_restrictions: artifacts.restrictions,
        },
    )
    .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
    Ok(())
}

fn resolve_cwd(root: &Path, cwd: Option<&str>) -> Result<PathBuf, BuildError> {
    let candidate = match cwd {
        None => root.to_path_buf(),
        Some(value) if value.trim().is_empty() => root.to_path_buf(),
        Some(value) => {
            let rel = validate_relative_path(value, "cwd").map_err(to_validation_error)?;
            root.join(rel)
        }
    };

    validate_cwd(&candidate, root).map_err(to_validation_error)
}

fn to_validation_error(err: ValidationError) -> BuildError {
    BuildError::new("invalid_path", err.to_string())
}

fn map_artifact_error(err: ArtifactError) -> BuildError {
    match err {
        ArtifactError::GlobMiss { pattern } => BuildError::with_pattern(
            "artifact_glob_miss",
            "artifact pattern matched nothing",
            pattern,
        ),
        other => BuildError::new("artifact_collection_failed", other.to_string()),
    }
}

fn prepare_workspace_ownership(workspace: &Path, run_as: &RunAs) -> Result<(), BuildError> {
    if !run_as.set_ids {
        return Ok(());
    }
    for entry in walkdir::WalkDir::new(workspace).follow_links(false) {
        let entry = entry.map_err(|err| {
            BuildError::new(
                "workspace_ownership",
                format!("failed to inspect fresh workspace: {err}"),
            )
        })?;
        let path = CString::new(entry.path().as_os_str().as_bytes())
            .map_err(|_| BuildError::new("workspace_ownership", "workspace path contains NUL"))?;
        let result = unsafe {
            libc::lchown(
                path.as_ptr(),
                run_as.user.uid as libc::uid_t,
                run_as.gid as libc::gid_t,
            )
        };
        if result != 0 {
            return Err(BuildError::new(
                "workspace_ownership",
                format!(
                    "failed to assign fresh workspace to task user: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
    }
    Ok(())
}

fn extract_source_archive(
    source_archive: &Path,
    dest: &Path,
    max_uncompressed_bytes: u64,
    max_files: usize,
    max_depth: usize,
) -> Result<(), BuildError> {
    use std::os::unix::fs::PermissionsExt;

    preflight_source_archive(source_archive, max_uncompressed_bytes, max_files, max_depth)?;
    let file = std::fs::File::open(source_archive).map_err(|err| {
        BuildError::new(
            "source_archive",
            format!("failed to open source archive: {err}"),
        )
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| {
        BuildError::new(
            "source_archive",
            format!("failed to read source archive: {err}"),
        )
    })?;
    let mut extracted_bytes = 0u64;
    let mut buffer = vec![0u8; 8192];

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|err| {
            BuildError::new("source_archive", format!("failed to read zip entry: {err}"))
        })?;
        let is_symlink = entry.is_symlink();
        let normalized = normalized_zip_path(entry.name(), entry.is_dir(), max_depth)?;
        let output = dest.join(&normalized);
        if entry.is_dir() {
            std::fs::create_dir_all(&output)
                .map_err(|err| BuildError::new("source_archive", format!("mkdir failed: {err}")))?;
            if let Some(mode) = entry.unix_mode() {
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(mode & 0o777))
                    .map_err(|err| {
                        BuildError::new("source_archive", format!("set permissions failed: {err}"))
                    })?;
            }
            continue;
        }
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| BuildError::new("source_archive", format!("mkdir failed: {err}")))?;
        }
        if is_symlink {
            let mut target = Vec::new();
            entry.take(4097).read_to_end(&mut target).map_err(|err| {
                BuildError::new(
                    "source_archive",
                    format!("read symlink target failed: {err}"),
                )
            })?;
            extracted_bytes = extracted_bytes.saturating_add(target.len() as u64);
            if extracted_bytes > max_uncompressed_bytes {
                return Err(BuildError::new(
                    "source_archive",
                    "extracted size exceeds sources.max_uncompressed_bytes",
                ));
            }
            let target = std::str::from_utf8(&target)
                .map_err(|_| BuildError::new("source_archive", "symlink target is not UTF-8"))?;
            crate::client_source::validate_symlink_target(&normalized, target)
                .map_err(|err| BuildError::new("source_archive", err.to_string()))?;
            std::os::unix::fs::symlink(target, &output).map_err(|err| {
                BuildError::new("source_archive", format!("create symlink failed: {err}"))
            })?;
            continue;
        }
        let mut output_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|err| {
                BuildError::new("source_archive", format!("create file failed: {err}"))
            })?;
        loop {
            let bytes = entry.read(&mut buffer).map_err(|err| {
                BuildError::new("source_archive", format!("read zip entry failed: {err}"))
            })?;
            if bytes == 0 {
                break;
            }
            extracted_bytes = extracted_bytes.saturating_add(bytes as u64);
            if extracted_bytes > max_uncompressed_bytes {
                return Err(BuildError::new(
                    "source_archive",
                    format!("extracted size exceeds sources.max_uncompressed_bytes ({max_uncompressed_bytes} bytes)"),
                ));
            }
            output_file.write_all(&buffer[..bytes]).map_err(|err| {
                BuildError::new("source_archive", format!("write file failed: {err}"))
            })?;
        }
        if let Some(mode) = entry.unix_mode() {
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(mode & 0o777))
                .map_err(|err| {
                    BuildError::new("source_archive", format!("set permissions failed: {err}"))
                })?;
        }
    }
    Ok(())
}

fn preflight_source_archive(
    source_archive: &Path,
    max_uncompressed_bytes: u64,
    max_files: usize,
    max_depth: usize,
) -> Result<(), BuildError> {
    let file = std::fs::File::open(source_archive).map_err(|err| {
        BuildError::new(
            "source_archive",
            format!("failed to open source archive: {err}"),
        )
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| {
        BuildError::new(
            "source_archive",
            format!("failed to read source archive: {err}"),
        )
    })?;
    let mut exact = HashSet::new();
    let mut folded = HashSet::new();
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    let mut folded_files = HashSet::new();
    let mut folded_directories = HashSet::new();
    let mut declared_bytes = 0u64;
    let mut entry_count = 0usize;

    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|err| {
            BuildError::new("source_archive", format!("failed to read zip entry: {err}"))
        })?;
        entry_count = entry_count.saturating_add(1);
        if entry_count > max_files {
            return Err(BuildError::new(
                "source_archive",
                format!("source entry count exceeds sources.max_files ({max_files})"),
            ));
        }
        let is_dir = entry.is_dir();
        let is_symlink = entry.is_symlink();
        let normalized = normalized_zip_path(entry.name(), is_dir, max_depth)?;
        validate_zip_type(entry.unix_mode(), is_dir, is_symlink)?;
        if !exact.insert(normalized.clone()) || !folded.insert(normalized.to_ascii_lowercase()) {
            return Err(BuildError::new(
                "source_archive",
                "zip contains duplicate or case-colliding paths",
            ));
        }
        let components: Vec<&str> = normalized.split('/').collect();
        let mut ancestor = String::new();
        for component in &components[..components.len().saturating_sub(1)] {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            let folded_ancestor = ancestor.to_ascii_lowercase();
            if files.contains(&ancestor) || folded_files.contains(&folded_ancestor) {
                return Err(BuildError::new(
                    "source_archive",
                    "zip contains a file/directory path collision",
                ));
            }
            directories.insert(ancestor.clone());
            folded_directories.insert(folded_ancestor);
        }
        let folded_normalized = normalized.to_ascii_lowercase();
        if is_dir {
            if files.contains(&normalized) || folded_files.contains(&folded_normalized) {
                return Err(BuildError::new(
                    "source_archive",
                    "zip contains a file/directory path collision",
                ));
            }
            directories.insert(normalized);
            folded_directories.insert(folded_normalized);
        } else {
            if directories.contains(&normalized) || folded_directories.contains(&folded_normalized)
            {
                return Err(BuildError::new(
                    "source_archive",
                    "zip contains a file/directory path collision",
                ));
            }
            if is_symlink {
                let mut target = Vec::new();
                entry.take(4097).read_to_end(&mut target).map_err(|err| {
                    BuildError::new(
                        "source_archive",
                        format!("read symlink target failed: {err}"),
                    )
                })?;
                if target.len() > 4096 {
                    return Err(BuildError::new(
                        "source_archive",
                        "symlink target exceeds 4096 bytes",
                    ));
                }
                let target = std::str::from_utf8(&target).map_err(|_| {
                    BuildError::new("source_archive", "symlink target is not UTF-8")
                })?;
                crate::client_source::validate_symlink_target(&normalized, target)
                    .map_err(|err| BuildError::new("source_archive", err.to_string()))?;
                declared_bytes = declared_bytes.saturating_add(target.len() as u64);
            } else {
                declared_bytes = declared_bytes.saturating_add(entry.size());
            }
            folded_files.insert(folded_normalized);
            files.insert(normalized);
            if declared_bytes > max_uncompressed_bytes {
                return Err(BuildError::new("source_archive", format!("declared size exceeds sources.max_uncompressed_bytes ({max_uncompressed_bytes} bytes)")));
            }
        }
    }
    Ok(())
}

fn normalized_zip_path(name: &str, is_dir: bool, max_depth: usize) -> Result<String, BuildError> {
    if name.is_empty() || name.contains(['\\', '\0']) || !name.is_ascii() {
        return Err(BuildError::new(
            "source_archive",
            "zip entry had invalid path",
        ));
    }
    let trimmed = if is_dir {
        name.trim_end_matches('/')
    } else {
        name
    };
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|component| component.is_empty() || component == ".")
    {
        return Err(BuildError::new(
            "source_archive",
            "zip entry had invalid path",
        ));
    }
    let path = Path::new(trimmed);
    if path.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err(BuildError::new(
            "source_archive",
            "zip entry had invalid path",
        ));
    }
    let depth = trimmed.split('/').count();
    if depth > max_depth {
        return Err(BuildError::new(
            "source_archive",
            format!("source path depth exceeds sources.max_depth ({max_depth})"),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_zip_type(mode: Option<u32>, is_dir: bool, is_symlink: bool) -> Result<(), BuildError> {
    let Some(mode) = mode else {
        if is_symlink {
            return Err(BuildError::new(
                "source_archive",
                "symlink entry is missing Unix mode",
            ));
        }
        return Ok(());
    };
    let kind = mode & libc::S_IFMT;
    let expected = if is_dir {
        libc::S_IFDIR
    } else if is_symlink {
        libc::S_IFLNK
    } else {
        libc::S_IFREG
    };
    if kind != 0 && kind != expected {
        return Err(BuildError::new(
            "source_archive",
            "zip entry has an unsupported special file type",
        ));
    }
    Ok(())
}

struct RunAs {
    user: UserInfo,
    gid: u32,
    set_ids: bool,
}

pub fn preflight_run_as(config: &Config) -> Result<(), BuildError> {
    preflight_run_as_with_effective_uid(config, unsafe { libc::geteuid() })
}

fn preflight_run_as_with_effective_uid(
    config: &Config,
    effective_uid: u32,
) -> Result<(), BuildError> {
    let run_as = resolve_run_as(config)?;
    let transport_enabled = config.service.socket.enabled || config.service.http.enabled;
    if effective_uid == 0
        && transport_enabled
        && (!run_as.set_ids || run_as.user.uid == 0 || run_as.user.uid == effective_uid)
    {
        return Err(BuildError::new(
            "run_as_user",
            "a root daemon requires a configured distinct non-root task execution identity on every enabled transport",
        ));
    }

    if config.service.socket.enabled {
        if !run_as.set_ids {
            return Err(BuildError::new(
                "run_as_user",
                "enabled UDS requires a dedicated task execution identity",
            ));
        }
        if run_as.user.uid == 0 || run_as.user.uid == effective_uid {
            return Err(BuildError::new(
                "run_as_user",
                "enabled UDS requires a non-root task identity distinct from the daemon socket owner",
            ));
        }
        if effective_uid != 0 {
            return Err(BuildError::new(
                "run_as_user",
                "enabled UDS privilege dropping requires a root daemon",
            ));
        }
        let mode = config
            .service
            .socket
            .parse_mode()
            .map_err(|err| BuildError::new("socket_mode", err.to_string()))?;
        if mode & 0o077 != 0 || config.service.socket.group.is_some() {
            return Err(BuildError::new(
                "socket_mode",
                "enabled UDS must be owner-only with no socket group",
            ));
        }
    }
    if config.service.http.enabled && config.service.http.auth.required {
        if !run_as.set_ids {
            return Err(BuildError::new(
                "run_as_user",
                "authenticated HTTP service requires build.run_as_user",
            ));
        }
        if run_as.user.uid == 0 {
            return Err(BuildError::new(
                "run_as_user",
                "build.run_as_user must be a non-root identity",
            ));
        }
        if effective_uid != 0 {
            return Err(BuildError::new(
                "run_as_user",
                "authenticated HTTP privilege dropping requires a root daemon",
            ));
        }
    }
    Ok(())
}

pub fn resolved_run_as_uid(config: &Config) -> Result<Option<u32>, BuildError> {
    if config.build.run_as_user.is_none() && config.build.run_as_group.is_none() {
        return Ok(None);
    }
    Ok(Some(resolve_run_as(config)?.user.uid))
}

fn resolve_run_as(config: &Config) -> Result<RunAs, BuildError> {
    let set_ids = config.build.run_as_user.is_some() || config.build.run_as_group.is_some();

    let user = if let Some(user) = &config.build.run_as_user {
        lookup_user_by_name(user).map_err(|err| {
            BuildError::new(
                "run_as_user",
                format!("failed to resolve run_as_user: {err}"),
            )
        })?
    } else {
        let uid = unsafe { libc::getuid() };
        lookup_user(uid).map_err(|err| {
            BuildError::new(
                "run_as_user",
                format!("failed to resolve service user: {err}"),
            )
        })?
    };

    let gid = if let Some(group) = &config.build.run_as_group {
        lookup_group_gid(group).map_err(|err| {
            BuildError::new(
                "run_as_group",
                format!("failed to resolve run_as_group: {err}"),
            )
        })?
    } else {
        user.gid
    };

    Ok(RunAs { user, gid, set_ids })
}

fn validate_run_as_uid(run_as: &RunAs, effective_uid: u32) -> Result<(), BuildError> {
    if effective_uid == 0 && run_as.user.uid == 0 {
        return Err(BuildError::new(
            "run_as_user",
            "a root daemon must not execute tasks as UID 0",
        ));
    }
    Ok(())
}

fn build_env(task: &TaskConfig, user: &UserInfo) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = task
        .environment
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if !task.environment.contains_key("HOME") {
        result.push((
            "HOME".to_string(),
            user.home_dir.to_string_lossy().into_owned(),
        ));
    }
    if !task.environment.contains_key("USER") {
        result.push(("USER".to_string(), user.username.clone()));
    }
    if !task.environment.contains_key("LOGNAME") {
        result.push(("LOGNAME".to_string(), user.username.clone()));
    }
    result
}

trait PrivilegeDropOps {
    fn initgroups(&mut self, username: &CString, gid: u32) -> io::Result<()>;
    fn setgid(&mut self, gid: u32) -> io::Result<()>;
    fn setuid(&mut self, uid: u32) -> io::Result<()>;
}

struct LibcPrivilegeDropOps;

impl PrivilegeDropOps for LibcPrivilegeDropOps {
    fn initgroups(&mut self, username: &CString, gid: u32) -> io::Result<()> {
        initgroups_for_platform(username.as_ptr(), gid)
    }

    fn setgid(&mut self, gid: u32) -> io::Result<()> {
        if unsafe { libc::setgid(gid as libc::gid_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn setuid(&mut self, uid: u32) -> io::Result<()> {
        if unsafe { libc::setuid(uid as libc::uid_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn apply_privilege_drop(
    ops: &mut impl PrivilegeDropOps,
    username: &CString,
    gid: u32,
    uid: u32,
) -> io::Result<()> {
    ops.initgroups(username, gid)?;
    ops.setgid(gid)?;
    ops.setuid(uid)
}

fn configure_command(command: &mut Command, run_as: &RunAs) -> Result<(), BuildError> {
    validate_run_as_uid(run_as, unsafe { libc::geteuid() })?;
    let should_set_ids = run_as.set_ids;
    let username = run_as.user.username.clone();
    let gid = run_as.gid;
    let uid = run_as.user.uid;

    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::geteuid() == 0 && uid == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "a root daemon must not execute tasks as UID 0",
                ));
            }
            if should_set_ids {
                let c_username = CString::new(username.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid username"))?;
                apply_privilege_drop(&mut LibcPrivilegeDropOps, &c_username, gid, uid)?;
            }
            Ok(())
        });
    }

    Ok(())
}

#[cfg(target_vendor = "apple")]
fn initgroups_for_platform(user: *const libc::c_char, gid: u32) -> io::Result<()> {
    let basegroup: libc::c_int = gid
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gid out of range"))?;
    if unsafe { libc::initgroups(user, basegroup) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_vendor = "apple"))]
fn initgroups_for_platform(user: *const libc::c_char, gid: u32) -> io::Result<()> {
    if unsafe { libc::initgroups(user, gid as libc::gid_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn spawn_output_thread(
    stream: impl Read + Send + 'static,
    sender: Sender<ResponseEvent>,
    kind: StreamKind,
    max_bytes: u64,
    output_bytes: Arc<AtomicU64>,
    output_exceeded: Arc<AtomicBool>,
    cancellation: CancellationFlag,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        stream_output(
            stream,
            sender,
            kind,
            max_bytes,
            &output_bytes,
            &output_exceeded,
            &cancellation,
        );
    })
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

fn send_response(sender: &Sender<ResponseEvent>, mut event: ResponseEvent) -> Result<(), ()> {
    let deadline = Instant::now() + OUTPUT_FORWARD_GRACE;
    loop {
        match sender.try_send(event) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Closed(_)) => return Err(()),
            Err(TrySendError::Full(returned)) => {
                event = returned;
                if Instant::now() >= deadline {
                    return Err(());
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn forward_output(
    sender: &Sender<ResponseEvent>,
    mut event: ResponseEvent,
    cancellation: &CancellationFlag,
) -> bool {
    let deadline = Instant::now() + OUTPUT_FORWARD_GRACE;
    loop {
        if cancellation.is_cancelled() {
            return false;
        }
        match sender.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Closed(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                event = returned;
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn join_output_thread(handle: thread::JoinHandle<()>) {
    let deadline = Instant::now() + OUTPUT_FORWARD_GRACE;
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if handle.is_finished() {
        let _ = handle.join();
    } else {
        warn!("output reader did not stop within bounded forwarding grace; detaching it");
    }
}

fn stream_output(
    mut reader: impl Read,
    sender: Sender<ResponseEvent>,
    kind: StreamKind,
    max_bytes: u64,
    output_bytes: &AtomicU64,
    output_exceeded: &AtomicBool,
    cancellation: &CancellationFlag,
) {
    let mut buf = vec![0u8; OUTPUT_CHUNK_SIZE];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let previous = output_bytes.fetch_add(n as u64, Ordering::SeqCst);
                if previous.saturating_add(n as u64) > max_bytes {
                    output_exceeded.store(true, Ordering::SeqCst);
                    cancellation.cancel();
                    break;
                }
                let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                let event = match kind {
                    StreamKind::Stdout => ResponseEvent::Stdout { data },
                    StreamKind::Stderr => ResponseEvent::Stderr { data },
                };

                if !forward_output(&sender, event, cancellation) {
                    cancellation.cancel();
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

enum WaitOutcome {
    Exited { code: i32, timed_out: bool },
    Cancelled,
}

enum TerminationReason {
    Timeout,
    Cancelled,
}

fn wait_with_timeout(
    child: &mut Child,
    timeout_sec: u64,
    cancellation: &CancellationFlag,
) -> io::Result<WaitOutcome> {
    let timeout = Duration::from_secs(timeout_sec);
    let start = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            let code = exit_code(status);
            terminate_remaining_group(child.id() as i32)?;
            return Ok(WaitOutcome::Exited {
                code,
                timed_out: false,
            });
        }

        if cancellation.is_cancelled() {
            terminate_process(child, TerminationReason::Cancelled)?;
            return Ok(WaitOutcome::Cancelled);
        }

        if start.elapsed() >= timeout {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let code = terminate_process(child, TerminationReason::Timeout)?;
    Ok(WaitOutcome::Exited {
        code,
        timed_out: true,
    })
}

fn terminate_process(child: &mut Child, reason: TerminationReason) -> io::Result<i32> {
    let label = match reason {
        TerminationReason::Timeout => "timed-out",
        TerminationReason::Cancelled => "cancelled",
    };
    let pgid = child.id() as i32;
    if let Err(err) = signal_process_group(child, libc::SIGTERM) {
        warn!("failed to terminate {label} process group (pid {pgid}): {err}");
    }
    let (mut code, group_gone) = wait_for_group_and_exit(child, pgid, TIMEOUT_KILL_GRACE)?;
    if !group_gone {
        if let Err(err) = signal_group(pgid, libc::SIGKILL) {
            warn!("failed to force kill {label} process group (pid {pgid}): {err}");
        }
        let result = wait_for_group_and_exit(child, pgid, TIMEOUT_KILL_GRACE)?;
        code = code.or(result.0);
        if !result.1 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process group survived SIGKILL",
            ));
        }
    }
    if code.is_none() {
        code = child.try_wait()?.map(exit_code);
    }
    Ok(code.unwrap_or(TIMEOUT_EXIT_CODE))
}

fn terminate_remaining_group(pgid: i32) -> io::Result<()> {
    if !process_group_exists(pgid)? {
        return Ok(());
    }
    signal_group(pgid, libc::SIGTERM)?;
    let start = Instant::now();
    while start.elapsed() < TIMEOUT_KILL_GRACE {
        if !process_group_exists(pgid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    signal_group(pgid, libc::SIGKILL)?;
    let start = Instant::now();
    while start.elapsed() < TIMEOUT_KILL_GRACE {
        if !process_group_exists(pgid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "process group survived SIGKILL",
    ))
}

fn wait_for_group_and_exit(
    child: &mut Child,
    pgid: i32,
    timeout: Duration,
) -> io::Result<(Option<i32>, bool)> {
    let start = Instant::now();
    let mut code = None;
    loop {
        if code.is_none() {
            code = child.try_wait()?.map(exit_code);
        }
        let group_gone = !process_group_exists(pgid)?;
        if group_gone {
            return Ok((code, true));
        }
        if start.elapsed() >= timeout {
            return Ok((code, false));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn process_group_exists(pgid: i32) -> io::Result<bool> {
    if unsafe { libc::killpg(pgid, 0) } == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(err),
    }
}

fn signal_group(pgid: i32, signal: i32) -> io::Result<()> {
    if unsafe { libc::killpg(pgid, signal) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err)
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| match status.signal() {
        Some(signal) => 128 + signal,
        None => 1,
    })
}

fn signal_process_group(child: &Child, signal: i32) -> io::Result<()> {
    let pid = child.id() as i32;
    if unsafe { libc::killpg(pid, signal) } == 0 {
        return Ok(());
    }

    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(err)
}

#[allow(clippy::module_name_repetitions)]
pub fn artifacts_for_build(build_id: &str, config: &Config) -> Option<ArtifactArchive> {
    let path = config
        .artifacts
        .storage_root
        .join(build_id)
        .join("artifacts.zip");
    let size = match std::fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(_) => return None,
    };

    Some(ArtifactArchive {
        path: format!("/v1/builds/{build_id}/artifacts.zip"),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::{tempdir, NamedTempFile};
    use zip::write::SimpleFileOptions as FileOptions;
    use zip::ZipWriter;

    #[test]
    fn root_http_daemon_requires_distinct_non_root_task_identity_even_without_auth() {
        let raw = r#"
schema_version = "6"
tasks = {}
[service.http]
enabled = true
[service.http.auth]
required = false
"#;
        let mut config: Config = toml::from_str(raw).expect("minimal HTTP config");
        let error = preflight_run_as_with_effective_uid(&config, 0).unwrap_err();
        assert!(error.message.contains("root daemon"));

        let current_uid = unsafe { libc::geteuid() };
        if current_uid != 0 {
            preflight_run_as_with_effective_uid(&config, current_uid)
                .expect("non-root development HTTP remains usable without privilege drop");
            let current = lookup_user(current_uid).expect("current user");
            config.build.run_as_user = Some(current.username);
            preflight_run_as_with_effective_uid(&config, 0)
                .expect("simulated root daemon accepts a configured non-root identity");
        }
    }

    #[test]
    fn execution_time_resolution_rejects_root_task_uid_for_root_daemon() {
        let run_as = RunAs {
            user: UserInfo {
                username: "root-after-nss-change".to_string(),
                uid: 0,
                gid: 0,
                home_dir: PathBuf::from("/root"),
            },
            gid: 0,
            set_ids: true,
        };
        let error = validate_run_as_uid(&run_as, 0).unwrap_err();
        assert_eq!(error.code, "run_as_user");
        assert!(error.message.contains("UID 0"));
        let mut no_privilege_drop = run_as;
        no_privilege_drop.set_ids = false;
        assert!(validate_run_as_uid(&no_privilege_drop, 0).is_err());
        validate_run_as_uid(&no_privilege_drop, 1000)
            .expect("non-root daemons cannot setuid to root");
    }

    #[test]
    fn command_configuration_rejects_numeric_root_target_before_spawn() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping root-only command guard test");
            return;
        }
        let run_as = RunAs {
            user: UserInfo {
                username: "inconsistent-nss-root".to_string(),
                uid: 0,
                gid: 0,
                home_dir: PathBuf::from("/root"),
            },
            gid: 0,
            set_ids: true,
        };
        let mut command = Command::new("true");
        let error = configure_command(&mut command, &run_as).unwrap_err();
        assert_eq!(error.code, "run_as_user");
        assert!(error.message.contains("UID 0"));
    }

    #[test]
    fn extract_source_archive_enforces_uncompressed_limit() {
        let temp = tempdir().expect("tempdir");
        let source = create_test_zip("input.txt", b"0123456789").expect("zip");
        let err = extract_source_archive(source.path(), temp.path(), 5, 10, 10).unwrap_err();
        assert_eq!(err.code, "source_archive");
        assert!(err.message.contains("sources.max_uncompressed_bytes"));
    }

    #[test]
    fn extract_source_archive_rejects_traversal_and_backslashes() {
        for path in ["../outside", "foo/../outside", "..\\outside"] {
            let temp = tempdir().expect("tempdir");
            let source = create_test_zip(path, b"bad").expect("zip");
            let err = extract_source_archive(source.path(), temp.path(), 1024, 10, 10).unwrap_err();
            assert_eq!(err.code, "source_archive", "{path}");
            assert!(err.message.contains("invalid path"), "{path}: {err}");
        }
    }

    #[test]
    fn source_archive_rejects_case_collisions_file_count_depth_and_special_files() {
        let temp = tempdir().expect("tempdir");
        let duplicate = create_multi_zip(&[("Out/file", b"a", 0o644), ("out/FILE", b"b", 0o644)]);
        assert!(
            extract_source_archive(duplicate.path(), temp.path(), 1024, 10, 10)
                .unwrap_err()
                .message
                .contains("colliding")
        );

        let prefix = create_multi_zip(&[("prefix", b"a", 0o644), ("prefix/file", b"b", 0o644)]);
        assert!(
            extract_source_archive(prefix.path(), temp.path(), 1024, 10, 10)
                .unwrap_err()
                .message
                .contains("file/directory")
        );
        for entries in [
            [
                ("Foo", b"a".as_slice(), 0o644),
                ("foo/bar", b"b".as_slice(), 0o644),
            ],
            [
                ("foo/bar", b"b".as_slice(), 0o644),
                ("Foo", b"a".as_slice(), 0o644),
            ],
        ] {
            let collision = create_multi_zip(&entries);
            assert!(
                extract_source_archive(collision.path(), temp.path(), 1024, 10, 10)
                    .unwrap_err()
                    .message
                    .contains("file/directory")
            );
        }

        let count = create_multi_zip(&[("a", b"a", 0o644), ("b", b"b", 0o644)]);
        assert!(
            extract_source_archive(count.path(), temp.path(), 1024, 1, 10)
                .unwrap_err()
                .message
                .contains("max_files")
        );

        let depth = create_test_zip("a/b/c", b"x").expect("zip");
        assert!(
            extract_source_archive(depth.path(), temp.path(), 1024, 10, 2)
                .unwrap_err()
                .message
                .contains("max_depth")
        );

        assert!(validate_zip_type(Some(libc::S_IFLNK | 0o777), false, true).is_ok());
    }

    #[test]
    fn source_archive_round_trips_safe_symlinks_and_rejects_escaping_targets() {
        let archive = NamedTempFile::new().unwrap();
        let mut zip = ZipWriter::new(archive.reopen().unwrap());
        zip.start_file("dir/target", FileOptions::default().unix_permissions(0o644))
            .unwrap();
        zip.write_all(b"target").unwrap();
        zip.add_symlink("link", "dir/target", FileOptions::default())
            .unwrap();
        zip.finish().unwrap();
        let destination = tempdir().unwrap();
        extract_source_archive(archive.path(), destination.path(), 1024, 10, 10).unwrap();
        assert_eq!(
            std::fs::read_link(destination.path().join("link")).unwrap(),
            PathBuf::from("dir/target")
        );
        assert_eq!(
            std::fs::read(destination.path().join("dir/target")).unwrap(),
            b"target"
        );

        let unsafe_archive = NamedTempFile::new().unwrap();
        let mut zip = ZipWriter::new(unsafe_archive.reopen().unwrap());
        zip.add_symlink("link", "../escape", FileOptions::default())
            .unwrap();
        zip.finish().unwrap();
        let destination = tempdir().unwrap();
        assert!(
            extract_source_archive(unsafe_archive.path(), destination.path(), 1024, 10, 10)
                .is_err()
        );
        assert!(!destination.path().join("link").exists());
    }

    #[test]
    fn output_limit_counts_raw_combined_bytes_and_cancels() {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let bytes = AtomicU64::new(4);
        let exceeded = AtomicBool::new(false);
        let cancellation = CancellationFlag::default();
        stream_output(
            io::Cursor::new(vec![0xff, 0xfe]),
            sender,
            StreamKind::Stdout,
            5,
            &bytes,
            &exceeded,
            &cancellation,
        );
        assert!(exceeded.load(Ordering::SeqCst));
        assert!(cancellation.is_cancelled());
        assert_eq!(bytes.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn full_output_channel_cancels_at_forwarding_deadline_below_output_limit() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(ResponseEvent::Stdout {
                data: "channel-sentinel".to_string(),
            })
            .expect("prefill output channel");
        let bytes = Arc::new(AtomicU64::new(0));
        let exceeded = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationFlag::default();
        let produced = vec![b'x'; OUTPUT_CHUNK_SIZE];
        let max_bytes = (OUTPUT_CHUNK_SIZE * 2) as u64;
        let started = Instant::now();
        let output = spawn_output_thread(
            io::Cursor::new(produced),
            sender,
            StreamKind::Stdout,
            max_bytes,
            Arc::clone(&bytes),
            Arc::clone(&exceeded),
            cancellation.clone(),
        );

        let completion_deadline = Instant::now() + OUTPUT_FORWARD_GRACE + Duration::from_secs(1);
        while !output.is_finished() && Instant::now() < completion_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            output.is_finished(),
            "output forwarding thread exceeded its bounded deadline"
        );
        output.join().expect("output forwarding thread");

        assert!(started.elapsed() >= OUTPUT_FORWARD_GRACE);
        assert!(cancellation.is_cancelled());
        assert!(!exceeded.load(Ordering::SeqCst));
        assert_eq!(bytes.load(Ordering::SeqCst), OUTPUT_CHUNK_SIZE as u64);
        assert!(matches!(
            receiver.try_recv().expect("prefilled event"),
            ResponseEvent::Stdout { data } if data == "channel-sentinel"
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[derive(Default)]
    struct RecordingPrivilegeOps {
        calls: Vec<String>,
        fail_at: Option<&'static str>,
    }

    impl PrivilegeDropOps for RecordingPrivilegeOps {
        fn initgroups(&mut self, _username: &CString, gid: u32) -> io::Result<()> {
            self.calls.push(format!("initgroups:{gid}"));
            if self.fail_at == Some("initgroups") {
                return Err(io::Error::other("initgroups failed"));
            }
            Ok(())
        }

        fn setgid(&mut self, gid: u32) -> io::Result<()> {
            self.calls.push(format!("setgid:{gid}"));
            if self.fail_at == Some("setgid") {
                return Err(io::Error::other("setgid failed"));
            }
            Ok(())
        }

        fn setuid(&mut self, uid: u32) -> io::Result<()> {
            self.calls.push(format!("setuid:{uid}"));
            if self.fail_at == Some("setuid") {
                return Err(io::Error::other("setuid failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn portable_privilege_drop_harness_exercises_real_sequence_and_fail_closed_errors() {
        let username = CString::new("task-user").unwrap();
        let mut ops = RecordingPrivilegeOps::default();
        apply_privilege_drop(&mut ops, &username, 123, 456).unwrap();
        assert_eq!(ops.calls, ["initgroups:123", "setgid:123", "setuid:456"]);

        for failure in ["initgroups", "setgid", "setuid"] {
            let mut ops = RecordingPrivilegeOps {
                calls: Vec::new(),
                fail_at: Some(failure),
            };
            assert!(apply_privilege_drop(&mut ops, &username, 123, 456).is_err());
            assert_eq!(ops.calls.last().unwrap().split(':').next(), Some(failure));
        }
    }

    #[test]
    fn privileged_real_child_reports_dropped_identity_and_denied_daemon_state() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping real setuid child branch: test process is not root");
            return;
        }
        let Ok(task_user) = lookup_user_by_name("nobody") else {
            eprintln!("skipping real setuid child branch: nobody user is unavailable");
            return;
        };
        assert_ne!(task_user.uid, 0);
        let temp = tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let credential = temp.path().join("credential");
        std::fs::write(&credential, "secret").unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
        let artifacts = temp.path().join("artifacts");
        let state = temp.path().join("state");
        let control = temp.path().join("control");
        for directory in [&artifacts, &state, &control] {
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket = control.join("server.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();

        let run_as = RunAs {
            gid: task_user.gid,
            user: task_user.clone(),
            set_ids: true,
        };
        let script = format!(
            "set -eu; printf '%s\\n' \"$(id -u):$(id -g):$(id -G)\"; test ! -r '{}'; test ! -x '{}'; test ! -x '{}'; if command -v curl >/dev/null 2>&1; then ! curl --silent --max-time 1 --unix-socket '{}' http://localhost/ >/dev/null 2>&1; fi",
            credential.display(),
            artifacts.display(),
            state.display(),
            socket.display(),
        );
        let mut command = Command::new("sh");
        command.arg("-c").arg(script).stdout(Stdio::piped());
        configure_command(&mut command, &run_as).unwrap();
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = String::from_utf8(output.stdout).unwrap();
        let mut fields = report.trim().split(':');
        assert_eq!(
            fields.next().unwrap().parse::<u32>().unwrap(),
            task_user.uid
        );
        assert_eq!(
            fields.next().unwrap().parse::<u32>().unwrap(),
            task_user.gid
        );
        let groups: Vec<u32> = fields
            .next()
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert!(groups.contains(&task_user.gid));
        assert!(!groups.contains(&0));
    }

    #[test]
    fn wait_with_timeout_cancels_configured_process_group_and_descendant() {
        let user = lookup_user(unsafe { libc::getuid() }).expect("current user");
        let run_as = RunAs {
            gid: user.gid,
            user,
            set_ids: false,
        };
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("trap '' TERM; (trap '' TERM; sleep 60) & wait");
        configure_command(&mut command, &run_as).expect("configure process group");
        let mut child = command.spawn().expect("spawn process group");
        let pgid = child.id() as i32;
        let cancellation = CancellationFlag::default();
        let cancel_clone = cancellation.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            cancel_clone.cancel();
        });
        let outcome = wait_with_timeout(&mut child, 60, &cancellation).expect("wait");
        assert!(matches!(outcome, WaitOutcome::Cancelled));
        assert!(!process_group_exists(pgid).expect("group lookup"));
    }

    #[test]
    fn real_timeout_and_output_limit_remove_configured_process_groups() {
        let user = lookup_user(unsafe { libc::getuid() }).expect("current user");
        let run_as = RunAs {
            gid: user.gid,
            user,
            set_ids: false,
        };

        let mut timeout_command = Command::new("sh");
        timeout_command
            .arg("-c")
            .arg("trap '' TERM; (trap '' TERM; sleep 60) & wait");
        configure_command(&mut timeout_command, &run_as).unwrap();
        let mut timeout_child = timeout_command.spawn().unwrap();
        let timeout_pgid = timeout_child.id() as i32;
        let outcome =
            wait_with_timeout(&mut timeout_child, 0, &CancellationFlag::default()).unwrap();
        assert!(matches!(
            outcome,
            WaitOutcome::Exited {
                timed_out: true,
                ..
            }
        ));
        assert!(!process_group_exists(timeout_pgid).unwrap());

        let mut output_command = Command::new("sh");
        output_command
            .arg("-c")
            .arg("trap '' TERM; (trap '' TERM; while :; do printf 0123456789abcdef; done) & wait");
        output_command.stdout(Stdio::piped()).stderr(Stdio::null());
        configure_command(&mut output_command, &run_as).unwrap();
        let mut output_child = output_command.spawn().unwrap();
        let output_pgid = output_child.id() as i32;
        let stdout = output_child.stdout.take().unwrap();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let drain = thread::spawn(move || while receiver.blocking_recv().is_some() {});
        let bytes = Arc::new(AtomicU64::new(0));
        let exceeded = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationFlag::default();
        let output = spawn_output_thread(
            stdout,
            sender,
            StreamKind::Stdout,
            1024,
            Arc::clone(&bytes),
            Arc::clone(&exceeded),
            cancellation.clone(),
        );
        let outcome = wait_with_timeout(&mut output_child, 30, &cancellation).unwrap();
        join_output_thread(output);
        assert!(matches!(
            outcome,
            WaitOutcome::Cancelled
                | WaitOutcome::Exited {
                    timed_out: false,
                    ..
                }
        ));
        assert!(exceeded.load(Ordering::SeqCst));
        assert!(!process_group_exists(output_pgid).unwrap());
        drain.join().unwrap();
    }

    fn create_multi_zip(entries: &[(&str, &[u8], u32)]) -> NamedTempFile {
        let temp = NamedTempFile::new().expect("temp zip");
        let mut zip = ZipWriter::new(temp.reopen().unwrap());
        for (name, contents, mode) in entries {
            zip.start_file(
                *name,
                FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(*mode),
            )
            .unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();
        temp
    }

    fn create_test_zip(name: &str, contents: &[u8]) -> io::Result<NamedTempFile> {
        let temp = NamedTempFile::new()?;
        let mut zip = ZipWriter::new(temp.reopen()?);
        zip.start_file(
            name,
            FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644),
        )?;
        zip.write_all(contents)?;
        zip.finish()?;
        Ok(temp)
    }
}
