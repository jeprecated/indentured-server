use std::collections::HashSet;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{error::TrySendError, Sender};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::artifacts::{collect_artifacts_zip, ArtifactError};
use crate::config::{Config, SessionActionConfig, TaskConfig, TaskExecution, SCRIPT_SHELL};
use crate::protocol::{
    ArtifactArchive, BuildPhase, PhaseResult, Request, ResponseEvent, SessionActionEvent,
    SessionActionStatus, SessionActionStreamItem, SessionStartEvent, SessionStartStatus,
    SessionTeardownResult, REQUEST_SCHEMA_VERSION,
};
use crate::user::{lookup_group_gid, lookup_user, lookup_user_by_name, UserInfo};
use crate::validation::{validate_cwd, validate_relative_path, ValidationError};

const TIMEOUT_EXIT_CODE: i32 = 124;
#[cfg(not(test))]
const TIMEOUT_KILL_GRACE: Duration = Duration::from_secs(5);
#[cfg(test)]
const TIMEOUT_KILL_GRACE: Duration = Duration::from_millis(500);
const OUTPUT_CHUNK_SIZE: usize = 4096;
pub(crate) static PROCESS_SPAWN_LOCK: Mutex<()> = Mutex::new(());
#[cfg(not(test))]
const OUTPUT_FORWARD_GRACE: Duration = Duration::from_secs(2);
#[cfg(test)]
const OUTPUT_FORWARD_GRACE: Duration = Duration::from_millis(250);
#[cfg(not(test))]
const BRIDGE_SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
#[cfg(test)]
const BRIDGE_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

#[derive(Clone, Default)]
pub struct CancellationFlag {
    cancelled: Arc<AtomicBool>,
    #[cfg(test)]
    initialization_hook: Arc<Mutex<Option<InitializationCheckpointHook>>>,
    #[cfg(test)]
    force_post_spawn_setup_failure: Arc<AtomicBool>,
    #[cfg(test)]
    spawned_pid: Arc<AtomicU64>,
    #[cfg(test)]
    stdin_would_block: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitializationCheckpoint {
    Extraction,
    Ownership,
    Setup,
    Run,
}

#[cfg(test)]
struct InitializationCheckpointHook {
    checkpoint: InitializationCheckpoint,
    arrived: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

impl CancellationFlag {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn initialization_checkpoint(&self, checkpoint: InitializationCheckpoint) {
        #[cfg(test)]
        {
            let hook = {
                let mut installed = self.initialization_hook.lock().unwrap();
                if installed
                    .as_ref()
                    .is_some_and(|hook| hook.checkpoint == checkpoint)
                {
                    installed.take()
                } else {
                    None
                }
            };
            if let Some(hook) = hook {
                hook.arrived.wait();
                hook.release.wait();
            }
        }
        #[cfg(not(test))]
        let _ = checkpoint;
    }

    #[cfg(test)]
    fn should_force_post_spawn_setup_failure(&self) -> bool {
        self.force_post_spawn_setup_failure
            .swap(false, Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn force_post_spawn_setup_failure(&self) {
        self.force_post_spawn_setup_failure
            .store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn record_spawned_pid(&self, pid: u32) {
        self.spawned_pid.store(u64::from(pid), Ordering::SeqCst);
    }

    #[cfg(test)]
    fn spawned_pid(&self) -> Option<i32> {
        i32::try_from(self.spawned_pid.load(Ordering::SeqCst))
            .ok()
            .filter(|pid| *pid != 0)
    }

    #[cfg(test)]
    fn record_stdin_would_block(&self) {
        self.stdin_would_block.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn stdin_would_block(&self) -> bool {
        self.stdin_would_block.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn install_initialization_checkpoint_hook(
        &self,
        checkpoint: InitializationCheckpoint,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        *self.initialization_hook.lock().unwrap() = Some(InitializationCheckpointHook {
            checkpoint,
            arrived,
            release,
        });
    }
}

#[derive(Debug)]
pub struct BuildError {
    pub code: &'static str,
    pub message: String,
    pub pattern: Option<String>,
    pub phase: Option<BuildPhase>,
    pub phases: Vec<PhaseResult>,
}

impl BuildError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            pattern: None,
            phase: None,
            phases: Vec::new(),
        }
    }

    fn with_pattern(code: &'static str, message: impl Into<String>, pattern: String) -> Self {
        Self {
            code,
            message: message.into(),
            pattern: Some(pattern),
            phase: None,
            phases: Vec::new(),
        }
    }

    fn in_phase(mut self, phase: BuildPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    fn with_phases(mut self, phases: Vec<PhaseResult>) -> Self {
        self.phases = phases;
        self
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
        let BuildError {
            code,
            message,
            pattern,
            phase,
            phases,
        } = err;
        let _ = send_response(
            &sender,
            ResponseEvent::Error {
                code: code.to_string(),
                message: Some(message),
                pattern,
                phase,
            },
        );
        let _ = send_response(
            &sender,
            ResponseEvent::Exit {
                code: 1,
                timed_out: false,
                artifacts: None,
                artifact_restrictions: None,
                failed_phase: phase,
                phases,
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
            phase: None,
            duration_ms: None,
            exit_code: None,
            timed_out: None,
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
    let outcome = run_task_phases(
        validated,
        config,
        run_as,
        workspace_root,
        build_id,
        sender,
        cancellation,
    )?;
    finish_build(
        validated,
        config,
        workspace_root,
        build_id,
        sender,
        outcome.exit_code,
        outcome.timed_out,
        outcome.failed_phase,
        outcome.phases,
    )
}

#[derive(Debug)]
pub(crate) struct SessionInitializationOutcome {
    pub phases: Vec<PhaseResult>,
    pub exit_code: i32,
    pub timed_out: bool,
    pub failed_phase: Option<BuildPhase>,
}

struct TaskPhasesOutcome {
    phases: Vec<PhaseResult>,
    exit_code: i32,
    timed_out: bool,
    failed_phase: Option<BuildPhase>,
}

fn run_task_phases(
    validated: &ValidatedRequest,
    config: &Config,
    run_as: &RunAs,
    workspace_root: &Path,
    build_id: &str,
    sender: &Sender<ResponseEvent>,
    cancellation: &CancellationFlag,
) -> Result<TaskPhasesOutcome, BuildError> {
    let cwd = resolve_cwd(workspace_root, Some(&validated.task.cwd))?;
    let request_id = validated.request_id.as_deref().unwrap_or("-");
    info!(
        "build started build_id={} request_id={} task={}",
        build_id, request_id, validated.task_id
    );
    let env = build_env(&validated.task, &run_as.user);
    let output_bytes = Arc::new(AtomicU64::new(0));
    let output_exceeded = Arc::new(AtomicBool::new(false));
    let mut phases = Vec::with_capacity(2);

    if let Some(setup) = &validated.task.setup {
        cancellation.initialization_checkpoint(InitializationCheckpoint::Setup);
        let result = run_phase(
            setup.execution(),
            setup.timeout_sec,
            BuildPhase::Setup,
            validated,
            config,
            run_as,
            &cwd,
            build_id,
            request_id,
            &env,
            sender,
            cancellation,
            &output_bytes,
            &output_exceeded,
            None,
        )?;
        let failed = result.exit_code != 0 || result.timed_out;
        let exit_code = result.exit_code;
        let timed_out = result.timed_out;
        phases.push(result);
        if failed {
            return Ok(TaskPhasesOutcome {
                phases,
                exit_code,
                timed_out,
                failed_phase: Some(BuildPhase::Setup),
            });
        }
    }

    cancellation.initialization_checkpoint(InitializationCheckpoint::Run);
    let result = run_phase(
        validated.task.execution(),
        validated.task.timeout_sec,
        BuildPhase::Run,
        validated,
        config,
        run_as,
        &cwd,
        build_id,
        request_id,
        &env,
        sender,
        cancellation,
        &output_bytes,
        &output_exceeded,
        None,
    )
    .map_err(|err| err.with_phases(phases.clone()))?;
    let failed_phase = (result.exit_code != 0 || result.timed_out).then_some(BuildPhase::Run);
    let exit_code = result.exit_code;
    let timed_out = result.timed_out;
    phases.push(result);
    Ok(TaskPhasesOutcome {
        phases,
        exit_code,
        timed_out,
        failed_phase,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn initialize_session(
    validated: &ValidatedRequest,
    config: &Config,
    source_archive: &Path,
    workspace: &Path,
    session_id: &str,
    sender: &Sender<SessionStartEvent>,
    cancellation: &CancellationFlag,
    deadline: Instant,
) -> Result<SessionInitializationOutcome, BuildError> {
    send_session_response(
        sender,
        SessionStartEvent::Session {
            id: session_id.to_string(),
            status: SessionStartStatus::Started,
            phase: None,
            duration_ms: None,
            exit_code: None,
            timed_out: None,
        },
        cancellation,
    )?;
    check_initialization_cancel(cancellation, deadline, false)?;
    let run_as = resolve_run_as(config)?;
    validate_run_as_uid(&run_as, unsafe { libc::geteuid() })?;
    check_initialization_cancel(cancellation, deadline, false)?;
    std::fs::create_dir(workspace).map_err(|err| {
        BuildError::new(
            "workspace_create_failed",
            format!("failed to create fresh session workspace: {err}"),
        )
    })?;
    cancellation.initialization_checkpoint(InitializationCheckpoint::Extraction);
    check_initialization_cancel(cancellation, deadline, false)?;
    extract_source_archive_cancellable(
        source_archive,
        workspace,
        config.sources.max_uncompressed_bytes,
        config.sources.max_files,
        config.sources.max_depth,
        cancellation,
        deadline,
    )?;
    cancellation.initialization_checkpoint(InitializationCheckpoint::Ownership);
    check_initialization_cancel(cancellation, deadline, false)?;
    prepare_workspace_ownership_cancellable(workspace, &run_as, cancellation, deadline)?;
    check_initialization_cancel(cancellation, deadline, false)?;

    let (phase_sender, phase_receiver) = tokio::sync::mpsc::channel(128);
    let bridge_stop = Arc::new(AtomicBool::new(false));
    let bridge = spawn_session_event_bridge(
        phase_receiver,
        sender.clone(),
        cancellation.clone(),
        Arc::clone(&bridge_stop),
    );
    let outcome = run_task_phases(
        validated,
        config,
        &run_as,
        workspace,
        session_id,
        &phase_sender,
        cancellation,
    );
    bridge_stop.store(true, Ordering::SeqCst);
    drop(phase_sender);
    join_bounded_thread(bridge, "session event bridge");
    let outcome = outcome?;
    Ok(SessionInitializationOutcome {
        phases: outcome.phases,
        exit_code: outcome.exit_code,
        timed_out: outcome.timed_out,
        failed_phase: outcome.failed_phase,
    })
}

fn spawn_session_event_bridge(
    mut receiver: tokio::sync::mpsc::Receiver<ResponseEvent>,
    sender: Sender<SessionStartEvent>,
    cancellation: CancellationFlag,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        match receiver.try_recv() {
            Ok(event) => {
                let mapped = match event {
                    ResponseEvent::Build {
                        id,
                        status,
                        phase,
                        duration_ms,
                        exit_code,
                        timed_out,
                    } => {
                        let status = match status.as_str() {
                            "phase_started" => SessionStartStatus::PhaseStarted,
                            "phase_finished" => SessionStartStatus::PhaseFinished,
                            _ => continue,
                        };
                        SessionStartEvent::Session {
                            id,
                            status,
                            phase,
                            duration_ms,
                            exit_code,
                            timed_out,
                        }
                    }
                    ResponseEvent::Stdout { data } => SessionStartEvent::Stdout { data },
                    ResponseEvent::Stderr { data } => SessionStartEvent::Stderr { data },
                    ResponseEvent::Error {
                        code,
                        message,
                        phase,
                        ..
                    } => SessionStartEvent::Error {
                        code,
                        message,
                        phase,
                    },
                    ResponseEvent::Exit { .. } => continue,
                };
                if send_session_response(&sender, mapped, &cancellation).is_err() {
                    cancellation.cancel();
                    return;
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if stop.load(Ordering::SeqCst) || cancellation.is_cancelled() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
        }
    })
}

fn drain_response_events(
    mut receiver: tokio::sync::mpsc::Receiver<ResponseEvent>,
    stop: &AtomicBool,
) {
    loop {
        match receiver.try_recv() {
            Ok(_) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
        }
    }
}

fn join_bounded_thread(handle: thread::JoinHandle<()>, label: &str) {
    let deadline = Instant::now() + BRIDGE_SHUTDOWN_GRACE;
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if handle.is_finished() {
        let _ = handle.join();
    } else {
        warn!("{label} did not stop within bounded shutdown grace; detaching it");
    }
}

struct StdinWriter {
    handle: thread::JoinHandle<()>,
    result: std::sync::mpsc::Receiver<io::Result<()>>,
    stop: Arc<AtomicBool>,
}

fn spawn_stdin_writer(
    mut stdin: std::process::ChildStdin,
    input: Vec<u8>,
    cancellation: CancellationFlag,
) -> Result<StdinWriter, BuildError> {
    #[cfg(test)]
    if cancellation.should_force_post_spawn_setup_failure() {
        return Err(BuildError::new(
            "stdin_write_failed",
            "forced post-spawn stdin setup failure",
        ));
    }
    let fd = stdin.as_raw_fd();
    #[cfg(all(test, target_os = "linux"))]
    unsafe {
        libc::fcntl(fd, libc::F_SETPIPE_SZ, 4096);
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(BuildError::new(
            "stdin_write_failed",
            format!(
                "failed to make task stdin nonblocking: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let (result_sender, result) = std::sync::mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let mut written = 0usize;
        let outcome = loop {
            if thread_stop.load(Ordering::SeqCst) || cancellation.is_cancelled() {
                break Ok(());
            }
            match stdin.write(&input[written..]) {
                Ok(0) => {
                    break Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "task stdin closed",
                    ))
                }
                Ok(bytes) => {
                    written += bytes;
                    if written == input.len() {
                        break Ok(());
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::BrokenPipe => break Ok(()),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    cancellation.record_stdin_would_block();
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => break Err(err),
            }
        };
        let _ = result_sender.send(outcome);
    });
    Ok(StdinWriter {
        handle,
        result,
        stop,
    })
}

fn finish_stdin_writer(writer: StdinWriter) -> io::Result<()> {
    writer.stop.store(true, Ordering::SeqCst);
    let result = writer
        .result
        .recv_timeout(OUTPUT_FORWARD_GRACE)
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stdin writer did not stop",
            ))
        });
    join_bounded_thread(writer.handle, "task stdin writer");
    result
}

#[derive(Debug)]
pub(crate) struct SessionActionRunOutcome {
    pub code: i32,
    pub timed_out: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_session_action(
    task_id: &str,
    task: &TaskConfig,
    action: &SessionActionConfig,
    config: &Config,
    workspace: &Path,
    session_id: &str,
    action_id: &str,
    action_name: &str,
    workspace_revision: &str,
    input: &[u8],
    sender: &Sender<SessionActionStreamItem>,
    cancellation: &CancellationFlag,
) -> Result<SessionActionRunOutcome, BuildError> {
    send_action_response(
        sender,
        SessionActionEvent::Action {
            session_id: session_id.to_string(),
            action_id: action_id.to_string(),
            action: action_name.to_string(),
            workspace_revision: workspace_revision.to_string(),
            status: SessionActionStatus::Started,
        },
        cancellation,
    )?;
    let run_as = resolve_run_as(config)?;
    validate_run_as_uid(&run_as, unsafe { libc::geteuid() })?;
    let cwd = resolve_cwd(workspace, Some(&task.cwd))?;
    let env = build_env(task, &run_as.user);
    let validated = ValidatedRequest {
        request_id: None,
        task_id: task_id.to_string(),
        task: task.clone(),
    };
    let output_bytes = Arc::new(AtomicU64::new(0));
    let output_exceeded = Arc::new(AtomicBool::new(false));
    let (phase_sender, phase_receiver) = tokio::sync::mpsc::channel(128);
    let bridge_stop = Arc::new(AtomicBool::new(false));
    let bridge = spawn_action_event_bridge(
        phase_receiver,
        sender.clone(),
        cancellation.clone(),
        Arc::clone(&bridge_stop),
    );
    let result = run_phase(
        action.execution(),
        action.timeout_sec,
        BuildPhase::Run,
        &validated,
        config,
        &run_as,
        &cwd,
        action_id,
        "-",
        &env,
        &phase_sender,
        cancellation,
        &output_bytes,
        &output_exceeded,
        Some(input),
    );
    bridge_stop.store(true, Ordering::SeqCst);
    drop(phase_sender);
    join_bounded_thread(bridge, "session action event bridge");
    let result = result?;
    Ok(SessionActionRunOutcome {
        code: result.exit_code,
        timed_out: result.timed_out,
    })
}

fn spawn_action_event_bridge(
    mut receiver: tokio::sync::mpsc::Receiver<ResponseEvent>,
    sender: Sender<SessionActionStreamItem>,
    cancellation: CancellationFlag,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        match receiver.try_recv() {
            Ok(ResponseEvent::Stdout { data }) => {
                if send_action_response(&sender, SessionActionEvent::Stdout { data }, &cancellation)
                    .is_err()
                {
                    cancellation.cancel();
                    return;
                }
            }
            Ok(ResponseEvent::Stderr { data }) => {
                if send_action_response(&sender, SessionActionEvent::Stderr { data }, &cancellation)
                    .is_err()
                {
                    cancellation.cancel();
                    return;
                }
            }
            Ok(_) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if stop.load(Ordering::SeqCst) || cancellation.is_cancelled() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
        }
    })
}

pub(crate) fn send_action_response(
    sender: &Sender<SessionActionStreamItem>,
    event: SessionActionEvent,
    cancellation: &CancellationFlag,
) -> Result<(), BuildError> {
    let deadline = Instant::now() + OUTPUT_FORWARD_GRACE;
    let mut pending = SessionActionStreamItem {
        event,
        final_ack: None,
    };
    loop {
        if cancellation.is_cancelled() {
            return Err(BuildError::new("stream_closed", "session action cancelled"));
        }
        match sender.try_send(pending) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Closed(_)) => {
                cancellation.cancel();
                return Err(BuildError::new("stream_closed", "client disconnected"));
            }
            Err(TrySendError::Full(event)) => {
                pending = event;
                if Instant::now() >= deadline {
                    cancellation.cancel();
                    return Err(BuildError::new(
                        "stream_closed",
                        "client is not reading output",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

pub(crate) fn run_session_teardown(
    task_id: &str,
    task: &TaskConfig,
    config: &Config,
    workspace: &Path,
    session_id: &str,
) -> SessionTeardownResult {
    let started = Instant::now();
    let result = (|| -> Result<PhaseResult, BuildError> {
        let session = task.session.as_ref().ok_or_else(|| {
            BuildError::new("session_config_missing", "session configuration missing")
        })?;
        let run_as = resolve_run_as(config)?;
        validate_run_as_uid(&run_as, unsafe { libc::geteuid() })?;
        let cwd = resolve_cwd(workspace, Some(&task.cwd))?;
        let env = build_env(task, &run_as.user);
        let validated = ValidatedRequest {
            request_id: None,
            task_id: task_id.to_string(),
            task: task.clone(),
        };
        let output_bytes = Arc::new(AtomicU64::new(0));
        let output_exceeded = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationFlag::default();
        let (sender, receiver) = tokio::sync::mpsc::channel(128);
        let drain_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&drain_stop);
        let drain = thread::spawn(move || drain_response_events(receiver, &thread_stop));
        let result = run_phase(
            session.teardown.execution(),
            session.teardown.timeout_sec,
            BuildPhase::Run,
            &validated,
            config,
            &run_as,
            &cwd,
            session_id,
            "-",
            &env,
            &sender,
            &cancellation,
            &output_bytes,
            &output_exceeded,
            None,
        );
        drain_stop.store(true, Ordering::SeqCst);
        drop(sender);
        join_bounded_thread(drain, "teardown event drain");
        result
    })();
    match result {
        Ok(result) => SessionTeardownResult {
            duration_ms: result.duration_ms,
            exit_code: Some(result.exit_code),
            timed_out: result.timed_out,
            error_code: None,
        },
        Err(err) => SessionTeardownResult {
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            exit_code: None,
            timed_out: false,
            error_code: Some(err.code.to_string()),
        },
    }
}

pub(crate) fn send_session_response(
    sender: &Sender<SessionStartEvent>,
    event: SessionStartEvent,
    cancellation: &CancellationFlag,
) -> Result<(), BuildError> {
    let deadline = Instant::now() + OUTPUT_FORWARD_GRACE;
    let mut pending = event;
    loop {
        if cancellation.is_cancelled() {
            return Err(BuildError::new("stream_closed", "client disconnected"));
        }
        match sender.try_send(pending) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Closed(_)) => {
                cancellation.cancel();
                return Err(BuildError::new("stream_closed", "client disconnected"));
            }
            Err(TrySendError::Full(event)) => {
                pending = event;
                if Instant::now() >= deadline {
                    cancellation.cancel();
                    return Err(BuildError::new(
                        "stream_closed",
                        "client is not reading output",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_phase(
    execution: TaskExecution<'_>,
    timeout_sec: u64,
    phase: BuildPhase,
    validated: &ValidatedRequest,
    config: &Config,
    run_as: &RunAs,
    cwd: &Path,
    build_id: &str,
    request_id: &str,
    env: &[(String, String)],
    sender: &Sender<ResponseEvent>,
    cancellation: &CancellationFlag,
    output_bytes: &Arc<AtomicU64>,
    output_exceeded: &Arc<AtomicBool>,
    stdin: Option<&[u8]>,
) -> Result<PhaseResult, BuildError> {
    if cancellation.is_cancelled() {
        return Err(BuildError::new("stream_closed", "client disconnected").in_phase(phase));
    }
    send_response(
        sender,
        ResponseEvent::Build {
            id: build_id.to_string(),
            status: "phase_started".to_string(),
            phase: Some(phase),
            duration_ms: None,
            exit_code: None,
            timed_out: None,
        },
    )
    .map_err(|_| BuildError::new("stream_closed", "client disconnected").in_phase(phase))?;

    let start = Instant::now();
    let mut command = match execution {
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
        .current_dir(cwd)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    configure_command(&mut command, run_as).map_err(|err| err.in_phase(phase))?;

    let mut child = spawn_command(&mut command).map_err(|err| {
        BuildError::new(
            "spawn_failed",
            format!("failed to spawn {} phase: {err}", phase.as_str()),
        )
        .in_phase(phase)
    })?;
    #[cfg(test)]
    cancellation.record_spawned_pid(child.id());
    let io_setup = (|| {
        let stdout = child.stdout.take().ok_or_else(|| {
            BuildError::new("io", "failed to capture stdout from task").in_phase(phase)
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            BuildError::new("io", "failed to capture stderr from task").in_phase(phase)
        })?;
        let stdin_writer = match stdin {
            Some(input) => {
                let child_stdin = child.stdin.take().ok_or_else(|| {
                    BuildError::new("io", "failed to open task stdin").in_phase(phase)
                })?;
                Some(
                    spawn_stdin_writer(child_stdin, input.to_vec(), cancellation.clone())
                        .map_err(|err| err.in_phase(phase))?,
                )
            }
            None => None,
        };
        Ok::<_, BuildError>((stdin_writer, stdout, stderr))
    })();
    let (stdin_writer, stdout, stderr) = match io_setup {
        Ok(io) => io,
        Err(mut err) => {
            if let Err(cleanup) = terminate_process(&mut child, TerminationReason::Cancelled) {
                err.message = format!("{}; process cleanup failed: {cleanup}", err.message);
            }
            return Err(err);
        }
    };
    let stdout_handle = spawn_output_thread(
        stdout,
        sender.clone(),
        StreamKind::Stdout,
        config.build.max_output_bytes,
        Arc::clone(output_bytes),
        Arc::clone(output_exceeded),
        cancellation.clone(),
    );
    let stderr_handle = spawn_output_thread(
        stderr,
        sender.clone(),
        StreamKind::Stderr,
        config.build.max_output_bytes,
        Arc::clone(output_bytes),
        Arc::clone(output_exceeded),
        cancellation.clone(),
    );

    let outcome = wait_with_timeout(&mut child, timeout_sec, cancellation)
        .map_err(|err| BuildError::new("wait_failed", err.to_string()).in_phase(phase))?;
    join_output_thread(stdout_handle);
    join_output_thread(stderr_handle);
    if let Some(writer) = stdin_writer {
        finish_stdin_writer(writer).map_err(|err| {
            BuildError::new(
                "stdin_write_failed",
                format!("failed to write task stdin: {err}"),
            )
            .in_phase(phase)
        })?;
    }

    if output_exceeded.load(Ordering::SeqCst) {
        return Err(BuildError::new(
            "output_limit",
            format!(
                "task output exceeds build.max_output_bytes ({} bytes)",
                config.build.max_output_bytes
            ),
        )
        .in_phase(phase));
    }

    let (exit_code, timed_out, duration) = match outcome {
        WaitOutcome::Exited {
            code,
            timed_out,
            duration,
        } => (code, timed_out, duration),
        WaitOutcome::Cancelled => {
            let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            warn!(
                "task phase cancelled build_id={} request_id={} phase={} duration_ms={} cwd={}",
                build_id,
                request_id,
                phase.as_str(),
                duration_ms,
                cwd.display()
            );
            return Err(BuildError::new("stream_closed", "client disconnected").in_phase(phase));
        }
    };
    let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

    if timed_out {
        warn!(
            "task phase timed out build_id={} request_id={} phase={} duration_ms={} cwd={}",
            build_id,
            request_id,
            phase.as_str(),
            duration_ms,
            cwd.display()
        );
    } else if exit_code == 0 {
        info!(
            "task phase completed build_id={} task={} phase={} exit_code=0 duration_ms={}",
            build_id,
            validated.task_id,
            phase.as_str(),
            duration_ms
        );
    } else {
        error!(
            "task phase completed build_id={} task={} phase={} exit_code={} duration_ms={}",
            build_id,
            validated.task_id,
            phase.as_str(),
            exit_code,
            duration_ms
        );
    }

    send_response(
        sender,
        ResponseEvent::Build {
            id: build_id.to_string(),
            status: "phase_finished".to_string(),
            phase: Some(phase),
            duration_ms: Some(duration_ms),
            exit_code: Some(exit_code),
            timed_out: Some(timed_out),
        },
    )
    .map_err(|_| BuildError::new("stream_closed", "client disconnected").in_phase(phase))?;

    Ok(PhaseResult {
        phase,
        duration_ms,
        exit_code,
        timed_out,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_build(
    validated: &ValidatedRequest,
    config: &Config,
    workspace_root: &Path,
    build_id: &str,
    sender: &Sender<ResponseEvent>,
    exit_code: i32,
    timed_out: bool,
    failed_phase: Option<BuildPhase>,
    phases: Vec<PhaseResult>,
) -> Result<(), BuildError> {
    // The terminated phase no longer owns the fresh workspace. Collect the
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
                    phase: None,
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
                    failed_phase,
                    phases,
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
            failed_phase,
            phases,
        },
    )
    .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
    Ok(())
}

pub(crate) fn resolve_cwd(root: &Path, cwd: Option<&str>) -> Result<PathBuf, BuildError> {
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

fn check_initialization_cancel(
    cancellation: &CancellationFlag,
    deadline: Instant,
    filesystem_checkpoint: bool,
) -> Result<(), BuildError> {
    let _ = filesystem_checkpoint;
    if cancellation.is_cancelled() {
        return Err(BuildError::new(
            "stream_closed",
            "session initialization was cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(BuildError::new(
            "session_lifetime",
            "session maximum lifetime expired during initialization",
        ));
    }
    Ok(())
}

fn check_optional_initialization_cancel(
    guard: Option<(&CancellationFlag, Instant)>,
    filesystem_checkpoint: bool,
) -> Result<(), BuildError> {
    if let Some((cancellation, deadline)) = guard {
        check_initialization_cancel(cancellation, deadline, filesystem_checkpoint)?;
    }
    Ok(())
}

fn prepare_workspace_ownership(workspace: &Path, run_as: &RunAs) -> Result<(), BuildError> {
    prepare_workspace_ownership_inner(workspace, run_as, None)
}

fn prepare_workspace_ownership_cancellable(
    workspace: &Path,
    run_as: &RunAs,
    cancellation: &CancellationFlag,
    deadline: Instant,
) -> Result<(), BuildError> {
    prepare_workspace_ownership_inner(workspace, run_as, Some((cancellation, deadline)))
}

fn prepare_workspace_ownership_inner(
    workspace: &Path,
    run_as: &RunAs,
    guard: Option<(&CancellationFlag, Instant)>,
) -> Result<(), BuildError> {
    check_optional_initialization_cancel(guard, false)?;
    if !run_as.set_ids {
        return Ok(());
    }
    for entry in walkdir::WalkDir::new(workspace).follow_links(false) {
        check_optional_initialization_cancel(guard, true)?;
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
    extract_source_archive_inner(
        source_archive,
        dest,
        max_uncompressed_bytes,
        max_files,
        max_depth,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn extract_source_archive_cancellable(
    source_archive: &Path,
    dest: &Path,
    max_uncompressed_bytes: u64,
    max_files: usize,
    max_depth: usize,
    cancellation: &CancellationFlag,
    deadline: Instant,
) -> Result<(), BuildError> {
    extract_source_archive_inner(
        source_archive,
        dest,
        max_uncompressed_bytes,
        max_files,
        max_depth,
        Some((cancellation, deadline)),
    )
}

fn extract_source_archive_inner(
    source_archive: &Path,
    dest: &Path,
    max_uncompressed_bytes: u64,
    max_files: usize,
    max_depth: usize,
    guard: Option<(&CancellationFlag, Instant)>,
) -> Result<(), BuildError> {
    use std::os::unix::fs::PermissionsExt;

    check_optional_initialization_cancel(guard, false)?;
    preflight_source_archive(
        source_archive,
        max_uncompressed_bytes,
        max_files,
        max_depth,
        guard,
    )?;
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
        check_optional_initialization_cancel(guard, true)?;
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
            check_optional_initialization_cancel(guard, true)?;
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
    guard: Option<(&CancellationFlag, Instant)>,
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
        check_optional_initialization_cancel(guard, true)?;
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
    let kind = mode & 0o170000;
    let expected = if is_dir {
        0o040000
    } else if is_symlink {
        0o120000
    } else {
        0o100000
    };
    if kind != 0 && kind != expected {
        return Err(BuildError::new(
            "source_archive",
            "zip entry has an unsupported special file type",
        ));
    }
    Ok(())
}

pub(crate) struct RunAs {
    pub(crate) user: UserInfo,
    pub(crate) gid: u32,
    pub(crate) set_ids: bool,
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
    let has_session_services = config.tasks.values().any(|task| {
        task.session
            .as_ref()
            .is_some_and(|session| !session.services.is_empty())
    });
    if has_session_services
        && (effective_uid != 0 || !run_as.set_ids || run_as.user.uid == effective_uid)
    {
        return Err(BuildError::new(
            "run_as_user",
            "managed session services require a configured task identity distinct from the daemon effective UID",
        ));
    }
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

pub fn resolved_run_as_identity(config: &Config) -> Result<Option<(u32, String, u32)>, BuildError> {
    if config.build.run_as_user.is_none() && config.build.run_as_group.is_none() {
        return Ok(None);
    }
    let run_as = resolve_run_as(config)?;
    Ok(Some((run_as.user.uid, run_as.user.username, run_as.gid)))
}

pub(crate) fn resolve_run_as(config: &Config) -> Result<RunAs, BuildError> {
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

pub(crate) fn validate_run_as_uid(run_as: &RunAs, effective_uid: u32) -> Result<(), BuildError> {
    if effective_uid == 0 && run_as.user.uid == 0 {
        return Err(BuildError::new(
            "run_as_user",
            "a root daemon must not execute tasks as UID 0",
        ));
    }
    Ok(())
}

pub(crate) fn build_env(task: &TaskConfig, user: &UserInfo) -> Vec<(String, String)> {
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

pub(crate) fn spawn_command(command: &mut Command) -> io::Result<Child> {
    let _spawn_guard = PROCESS_SPAWN_LOCK.lock().expect("process spawn lock");
    command.spawn()
}

pub(crate) fn configure_command(command: &mut Command, run_as: &RunAs) -> Result<(), BuildError> {
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
    Exited {
        code: i32,
        timed_out: bool,
        duration: Duration,
    },
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
            let duration = start.elapsed();
            let code = exit_code(status);
            terminate_remaining_group(child.id() as i32)?;
            return Ok(WaitOutcome::Exited {
                code,
                timed_out: false,
                duration,
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

    let duration = start.elapsed();
    let code = terminate_process(child, TerminationReason::Timeout)?;
    Ok(WaitOutcome::Exited {
        code,
        timed_out: true,
        duration,
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

pub(crate) fn terminate_remaining_group(pgid: i32) -> io::Result<()> {
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

pub(crate) fn process_group_exists(pgid: i32) -> io::Result<bool> {
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

pub(crate) fn signal_group(pgid: i32, signal: i32) -> io::Result<()> {
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
schema_version = "12"
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
    fn retained_services_reject_same_daemon_identity_during_preflight() {
        let raw = r#"
schema_version = "12"
[service.http]
enabled = true
[tasks.managed]
executable = "/bin/sh"
cwd = "."
timeout_sec = 1
environment = {}
workspace = "fresh"
[tasks.managed.artifacts]
[tasks.managed.session]
idle_timeout_sec = 1
max_lifetime_sec = 2
[tasks.managed.session.teardown]
executable = "/bin/sh"
timeout_sec = 1
[tasks.managed.session.services.service]
executable = "/bin/sh"
startup_timeout_sec = 1
shutdown_timeout_sec = 1
diagnostic_tail_bytes = 1
[tasks.managed.session.actions.observe]
executable = "/bin/sh"
timeout_sec = 1
"#;
        let mut config: Config = toml::from_str(raw).unwrap();
        let uid = unsafe { libc::geteuid() };
        let current = lookup_user(uid).unwrap();
        config.build.run_as_user = Some(current.username);
        let error = preflight_run_as_with_effective_uid(&config, uid).unwrap_err();
        assert!(error.message.contains("distinct from the daemon"));
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

        assert!(validate_zip_type(Some(0o120777), false, true).is_ok());
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
    fn forced_post_spawn_stdin_setup_failure_reaps_the_action_process_group() {
        use crate::config::{
            ArtifactSpec, ArtifactsConfig, BuildConfig, LoggingConfig, ServiceConfig,
            SessionActionConfig, SessionTeardownConfig, SourcesConfig, TaskSessionConfig,
            WorkspacePolicy, CONFIG_SCHEMA_VERSION,
        };
        use std::collections::HashMap;

        let temp = tempdir().unwrap();
        let script = temp.path().join("action.sh");
        std::fs::write(&script, "#!/bin/sh\ntrap '' TERM\nwhile :; do :; done\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let action = SessionActionConfig {
            script: None,
            executable: Some(script.clone()),
            args: vec![],
            timeout_sec: 30,
            artifacts: ArtifactSpec::default(),
        };
        let task = TaskConfig {
            script: None,
            executable: Some(script.clone()),
            args: vec![],
            setup: None,
            session: Some(TaskSessionConfig {
                idle_timeout_sec: 1,
                max_lifetime_sec: 60,
                teardown: SessionTeardownConfig {
                    script: None,
                    executable: Some(script.clone()),
                    args: vec![],
                    timeout_sec: 1,
                },
                services: HashMap::new(),
                actions: HashMap::from([("forced".to_string(), action)]),
                action_dispatcher: None,
                source_updates: None,
            }),
            cwd: ".".to_string(),
            timeout_sec: 30,
            environment: HashMap::new(),
            artifacts: ArtifactSpec::default(),
            workspace: WorkspacePolicy::Fresh,
        };
        let config = Config {
            schema_version: CONFIG_SCHEMA_VERSION.to_string(),
            service: ServiceConfig::default(),
            build: BuildConfig {
                workspace_root: temp.path().join("workspaces"),
                max_timeout_sec: 60,
                max_output_bytes: 1024,
                run_as_user: None,
                run_as_group: None,
            },
            tasks: HashMap::from([("managed".to_string(), task.clone())]),
            sources: SourcesConfig::default(),
            artifacts: ArtifactsConfig {
                storage_root: temp.path().join("artifacts"),
                ..ArtifactsConfig::default()
            },
            logging: LoggingConfig::default(),
        };
        let cancellation = CancellationFlag::default();
        cancellation.force_post_spawn_setup_failure();
        let (sender, _receiver) = tokio::sync::mpsc::channel(8);
        let error = run_session_action(
            "managed",
            &task,
            task.session
                .as_ref()
                .unwrap()
                .actions
                .get("forced")
                .unwrap(),
            &config,
            temp.path(),
            "ses_forced",
            "act_forced",
            "forced",
            "rev_0",
            br#"{}"#,
            &sender,
            &cancellation,
        )
        .unwrap_err();
        assert_eq!(error.code, "stdin_write_failed");
        let pid = cancellation.spawned_pid().expect("spawned action pid");
        assert!(!process_group_exists(pid).unwrap());

        let mut blocking_task = task;
        blocking_task
            .session
            .as_mut()
            .unwrap()
            .actions
            .get_mut("forced")
            .unwrap()
            .timeout_sec = 1;
        let cancellation = CancellationFlag::default();
        let (sender, _receiver) = tokio::sync::mpsc::channel(8);
        let outcome = run_session_action(
            "managed",
            &blocking_task,
            blocking_task
                .session
                .as_ref()
                .unwrap()
                .actions
                .get("forced")
                .unwrap(),
            &config,
            temp.path(),
            "ses_blocked_stdin",
            "act_blocked_stdin",
            "forced",
            "rev_0",
            &vec![b'x'; crate::protocol::MAX_SESSION_ACTION_BODY_BYTES],
            &sender,
            &cancellation,
        )
        .unwrap();
        assert!(outcome.timed_out, "unexpected action outcome: {outcome:?}");
        assert!(cancellation.stdin_would_block());
        assert!(!process_group_exists(cancellation.spawned_pid().unwrap()).unwrap());
    }

    #[test]
    fn held_pipe_sender_clone_cannot_block_cancelled_session_bridge() {
        let (held_reader, held_writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (phase_sender, phase_receiver) = tokio::sync::mpsc::channel(1);
        let (event_sender, _event_receiver) = tokio::sync::mpsc::channel(1);
        let cancellation = CancellationFlag::default();
        let output_bytes = Arc::new(AtomicU64::new(0));
        let output_exceeded = Arc::new(AtomicBool::new(false));
        let reader = spawn_output_thread(
            held_reader,
            phase_sender.clone(),
            StreamKind::Stdout,
            1024,
            output_bytes,
            output_exceeded,
            cancellation.clone(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let bridge = spawn_session_event_bridge(
            phase_receiver,
            event_sender,
            cancellation.clone(),
            Arc::clone(&stop),
        );

        // Model a descendant outside the killed process group retaining the
        // write end. The reader cannot observe cancellation until that fd closes.
        cancellation.cancel();
        join_output_thread(reader);
        stop.store(true, Ordering::SeqCst);
        drop(phase_sender);
        let deadline = Instant::now() + BRIDGE_SHUTDOWN_GRACE;
        while !bridge.is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(
            bridge.is_finished(),
            "held descendant pipe retained the session bridge"
        );
        bridge.join().unwrap();
        drop(held_writer);
    }

    #[test]
    fn held_pipe_sender_clone_cannot_block_bounded_teardown_drain() {
        let (held_reader, held_writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (phase_sender, phase_receiver) = tokio::sync::mpsc::channel(1);
        let cancellation = CancellationFlag::default();
        let reader = spawn_output_thread(
            held_reader,
            phase_sender.clone(),
            StreamKind::Stdout,
            1024,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
            cancellation,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let drain = thread::spawn(move || drain_response_events(phase_receiver, &thread_stop));

        // This models teardown's phase reader being unable to reach EOF because
        // a descendant retained the write end after its parent exited.
        join_output_thread(reader);
        stop.store(true, Ordering::SeqCst);
        drop(phase_sender);
        let deadline = Instant::now() + BRIDGE_SHUTDOWN_GRACE;
        while !drain.is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(
            drain.is_finished(),
            "held descendant pipe retained the teardown drain"
        );
        drain.join().unwrap();
        drop(held_writer);
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
                duration,
                ..
            } if duration < TIMEOUT_KILL_GRACE
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
