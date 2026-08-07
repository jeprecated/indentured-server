use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::build::{
    build_env, configure_command, process_group_exists, resolve_cwd, resolve_run_as,
    send_session_response, signal_group, spawn_command, validate_run_as_uid, BuildError,
    CancellationFlag, RunAs, PROCESS_SPAWN_LOCK,
};
use crate::config::{
    SessionServiceConfig, TaskConfig, TaskExecution, SCRIPT_SHELL, SERVICE_READY_FD_ENV,
};
use crate::protocol::SessionStartEvent;
use crate::user::UserInfo;

const READY_MESSAGE: &[u8] = b"ready\n";
const POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const PROCESS_KILL_GRACE: Duration = Duration::from_secs(5);
#[cfg(test)]
const PROCESS_KILL_GRACE: Duration = Duration::from_millis(500);
const MAX_STATUS_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum OwnedExecution {
    Script(String),
    Executable { path: PathBuf, args: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorSpec {
    execution: OwnedExecution,
    cwd: PathBuf,
    environment: Vec<(String, String)>,
    username: String,
    home_dir: PathBuf,
    uid: u32,
    gid: u32,
    set_ids: bool,
    shutdown_timeout_sec: u64,
    readiness_fd: RawFd,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum SupervisorStatus {
    Spawned { pid: u32, pgid: i32 },
    Exited { code: i32 },
    Stopped,
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableServiceProcess {
    pub(crate) name: String,
    pub(crate) supervisor_pid: u32,
    pub(crate) service_pid: u32,
    pub(crate) service_pgid: i32,
    pub(crate) shutdown_timeout_sec: u64,
}

pub(crate) struct RunningService {
    pub(crate) process: DurableServiceProcess,
    control: Option<File>,
    stopping: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    output_failed: Arc<AtomicBool>,
    monitor: Option<thread::JoinHandle<()>>,
    monitor_outcome: Arc<Mutex<Option<Result<(), String>>>>,
    output_threads: Vec<thread::JoinHandle<()>>,
    readiness: Option<std::sync::mpsc::Receiver<Result<(), String>>>,
    readiness_thread: Option<thread::JoinHandle<()>>,
    startup_sender: Arc<Mutex<Option<Sender<SessionStartEvent>>>>,
    _diagnostic_tail: Arc<Mutex<VecDeque<u8>>>,
}

pub(crate) type ExitCallback = Arc<dyn Fn(String) + Send + Sync + 'static>;

pub(crate) struct ServiceStopError {
    message: String,
    cleanup_unproven: bool,
}

impl ServiceStopError {
    pub(crate) fn cleanup_unproven(&self) -> bool {
        self.cleanup_unproven
    }
}

impl std::fmt::Display for ServiceStopError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

struct PendingSupervisor {
    child: Option<Child>,
    control: Option<File>,
    shutdown_timeout_sec: u64,
}

impl PendingSupervisor {
    fn new(child: Child, control: File, shutdown_timeout_sec: u64) -> Self {
        Self {
            child: Some(child),
            control: Some(control),
            shutdown_timeout_sec,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("pending supervisor child")
    }

    fn disarm(mut self) -> (Child, File) {
        (
            self.child.take().expect("pending supervisor child"),
            self.control.take().expect("pending supervisor control"),
        )
    }
}

impl Drop for PendingSupervisor {
    fn drop(&mut self) {
        drop(self.control.take());
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let expected = Duration::from_secs(self.shutdown_timeout_sec)
            .saturating_add(PROCESS_KILL_GRACE)
            .saturating_add(Duration::from_secs(1));
        match stop_supervisor_process(child, expected) {
            Ok(true) => {}
            Ok(false) => warn!(
                "failed to prove pending service supervisor {} was reaped",
                child.id()
            ),
            Err(err) => warn!(
                "pending service supervisor {} cleanup failed: {err}",
                child.id()
            ),
        }
    }
}

struct SupervisedServiceChild {
    child: Option<Child>,
    control: Option<File>,
    pgid: i32,
    shutdown_timeout_sec: u64,
    finished: bool,
}

impl SupervisedServiceChild {
    fn new(child: Child, control: File, shutdown_timeout_sec: u64) -> Self {
        let pgid = child.id() as i32;
        Self {
            child: Some(child),
            control: Some(control),
            pgid,
            shutdown_timeout_sec,
            finished: false,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("supervised service child")
    }

    fn control_mut(&mut self) -> &mut File {
        self.control.as_mut().expect("supervisor control")
    }

    fn finish(mut self) -> io::Result<()> {
        if process_group_exists(self.pgid)? {
            return Err(io::Error::other(
                "service process group still exists at supervisor completion",
            ));
        }
        if !wait_child_bounded(self.child_mut(), Duration::ZERO)? {
            return Err(io::Error::other(
                "service child was not reaped at supervisor completion",
            ));
        }
        self.finished = true;
        drop(self.control.take());
        drop(self.child.take());
        Ok(())
    }
}

impl Drop for SupervisedServiceChild {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.control.take());
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if let Err(err) = stop_service_child(child, self.shutdown_timeout_sec) {
            warn!(
                "supervisor failed to clean service group {} after unfinished exit: {err}",
                self.pgid
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_service(
    name: &str,
    service: &SessionServiceConfig,
    task: &TaskConfig,
    config: &crate::config::Config,
    workspace: &Path,
    sender: &Sender<SessionStartEvent>,
    cancellation: &CancellationFlag,
    startup_deadline: Instant,
    session_deadline: Instant,
    retaining_output: Arc<AtomicBool>,
    on_exit: ExitCallback,
) -> Result<RunningService, BuildError> {
    let run_as = resolve_run_as(config)?;
    let daemon_uid = unsafe { libc::geteuid() };
    validate_run_as_uid(&run_as, daemon_uid)?;
    if !run_as.set_ids || run_as.user.uid == daemon_uid {
        return Err(BuildError::new(
            "run_as_user",
            "managed session services require a configured task identity distinct from the daemon effective UID",
        ));
    }
    let cwd = resolve_cwd(workspace, Some(&task.cwd))?;
    let spec = SupervisorSpec {
        execution: match service.execution() {
            TaskExecution::Script(script) => OwnedExecution::Script(script.to_string()),
            TaskExecution::Executable { path, args } => OwnedExecution::Executable {
                path: path.to_path_buf(),
                args: args.to_vec(),
            },
        },
        cwd,
        environment: build_env(task, &run_as.user),
        username: run_as.user.username.clone(),
        home_dir: run_as.user.home_dir.clone(),
        uid: run_as.user.uid,
        gid: run_as.gid,
        set_ids: run_as.set_ids,
        shutdown_timeout_sec: service.shutdown_timeout_sec,
        readiness_fd: -1,
    };

    let tail_limit = usize::try_from(service.diagnostic_tail_bytes).map_err(|_| {
        BuildError::new(
            "service_io",
            format!("service {name} diagnostic tail does not fit this platform"),
        )
    })?;

    // On Linux pipe2 makes every endpoint CLOEXEC atomically. Darwin has no
    // pipe2; the process-wide spawn lock closes its pipe/fcntl inheritance window.
    let spawn_guard = PROCESS_SPAWN_LOCK.lock().expect("process spawn lock");
    let (control_read, control_write) = pipe_cloexec().map_err(service_io_error)?;
    let (status_read, status_write) = pipe_cloexec().map_err(service_io_error)?;
    let (ready_read, ready_write) = pipe_cloexec().map_err(service_io_error)?;
    let control_fd = control_read.as_raw_fd();
    let status_fd = status_write.as_raw_fd();
    let ready_fd = ready_write.as_raw_fd();

    let executable = std::env::current_exe().map_err(service_io_error)?;
    let mut command = Command::new(executable);
    command
        .arg("--service-supervisor")
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--status-fd")
        .arg(status_fd.to_string())
        .arg("--readiness-fd")
        .arg(ready_fd.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    unsafe {
        command.pre_exec(move || {
            for fd in [control_fd, status_fd, ready_fd] {
                set_cloexec(fd, false)?;
            }
            Ok(())
        });
    }
    let supervisor = command.spawn().map_err(|err| {
        BuildError::new(
            "service_spawn_failed",
            format!("failed to spawn supervisor for service {name}: {err}"),
        )
    })?;
    drop(control_read);
    drop(status_write);
    drop(ready_write);
    drop(spawn_guard);

    let control_write = File::from(control_write);
    let mut pending =
        PendingSupervisor::new(supervisor, control_write, service.shutdown_timeout_sec);
    let supervisor = pending.child_mut();
    let mut encoded = spec;
    encoded.readiness_fd = ready_fd;
    let input = supervisor
        .stdin
        .take()
        .ok_or_else(|| BuildError::new("service_io", "failed to open service supervisor input"))?;
    serde_json::to_writer(input, &encoded).map_err(|err| {
        BuildError::new(
            "service_io",
            format!("failed to configure service supervisor: {err}"),
        )
    })?;

    let stdout = supervisor
        .stdout
        .take()
        .ok_or_else(|| BuildError::new("service_io", "failed to capture service stdout"))?;
    let stderr = supervisor
        .stderr
        .take()
        .ok_or_else(|| BuildError::new("service_io", "failed to capture service stderr"))?;
    let mut status_reader = StatusReader::new(File::from(status_read)).map_err(service_io_error)?;
    let status = wait_initial_status(
        &mut status_reader,
        name,
        cancellation,
        startup_deadline,
        session_deadline,
    )?;
    let (service_pid, service_pgid) = match status {
        SupervisorStatus::Spawned { pid, pgid } => (pid, pgid),
        SupervisorStatus::Failed { message } => {
            return Err(BuildError::new("service_spawn_failed", message));
        }
        other => {
            return Err(BuildError::new(
                "service_spawn_failed",
                format!("unexpected service supervisor status: {other:?}"),
            ));
        }
    };

    let supervisor_pid = supervisor.id();
    let (mut supervisor, control_write) = pending.disarm();
    let stopping = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let output_failed = Arc::new(AtomicBool::new(false));
    let monitor_stopping = Arc::clone(&stopping);
    let monitor_failed = Arc::clone(&failed);
    let monitor_name = name.to_string();
    let monitor_callback = Arc::clone(&on_exit);
    let monitor_outcome = Arc::new(Mutex::new(None));
    let thread_outcome = Arc::clone(&monitor_outcome);
    let monitor = thread::spawn(move || {
        let status = loop {
            match status_reader.try_read_status() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(POLL_INTERVAL),
                Err(err) => break Err(err),
            }
        };
        let reaped = stop_supervisor_process(&mut supervisor, PROCESS_KILL_GRACE);
        let outcome = match (&status, reaped) {
            (Ok(SupervisorStatus::Stopped), Ok(true)) => Ok(()),
            (Ok(SupervisorStatus::Exited { code }), Ok(true)) => {
                Err(format!("{monitor_name} exited ({code})"))
            }
            (Ok(SupervisorStatus::Failed { message }), Ok(true)) => {
                Err(format!("{monitor_name}: {message}"))
            }
            (Ok(other), Ok(true)) => Err(format!(
                "{monitor_name}: unexpected supervisor status {other:?}"
            )),
            (_, Ok(false)) => Err(format!("{monitor_name}: supervisor reap was not proven")),
            (_, Err(err)) => Err(format!("{monitor_name}: supervisor reap failed: {err}")),
            (Err(err), Ok(true)) => Err(format!("{monitor_name}: supervisor status failed: {err}")),
        };
        *thread_outcome.lock().expect("service monitor outcome lock") = Some(outcome.clone());
        if !monitor_stopping.load(Ordering::SeqCst) {
            monitor_failed.store(true, Ordering::SeqCst);
            let detail = outcome
                .err()
                .unwrap_or_else(|| format!("{monitor_name} stopped unexpectedly"));
            thread::spawn(move || monitor_callback(detail));
        }
    });

    let tail = Arc::new(Mutex::new(VecDeque::new()));
    let startup_sender = Arc::new(Mutex::new(Some(sender.clone())));
    let output_threads = vec![
        spawn_output_drain(
            stdout,
            Arc::clone(&startup_sender),
            cancellation.clone(),
            Arc::clone(&retaining_output),
            Arc::clone(&tail),
            tail_limit,
            false,
            Arc::clone(&output_failed),
            Arc::clone(&stopping),
            Arc::clone(&on_exit),
            name.to_string(),
        ),
        spawn_output_drain(
            stderr,
            Arc::clone(&startup_sender),
            cancellation.clone(),
            retaining_output,
            Arc::clone(&tail),
            tail_limit,
            true,
            Arc::clone(&output_failed),
            Arc::clone(&stopping),
            on_exit,
            name.to_string(),
        ),
    ];

    let (ready_sender, readiness) = std::sync::mpsc::sync_channel(1);
    let readiness_thread = thread::spawn(move || {
        let mut reader = File::from(ready_read);
        let mut bytes = Vec::with_capacity(READY_MESSAGE.len() + 1);
        let result = Read::by_ref(&mut reader)
            .take((READY_MESSAGE.len() + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|err| format!("readiness read failed: {err}"))
            .and_then(|_| {
                if bytes == READY_MESSAGE {
                    Ok(())
                } else {
                    Err(
                        "readiness channel must contain exactly ready\\n and then close"
                            .to_string(),
                    )
                }
            });
        let _ = ready_sender.send(result);
    });

    Ok(RunningService {
        process: DurableServiceProcess {
            name: name.to_string(),
            supervisor_pid,
            service_pid,
            service_pgid,
            shutdown_timeout_sec: service.shutdown_timeout_sec,
        },
        control: Some(control_write),
        stopping,
        failed,
        output_failed,
        monitor: Some(monitor),
        monitor_outcome,
        output_threads,
        readiness: Some(readiness),
        readiness_thread: Some(readiness_thread),
        startup_sender,
        _diagnostic_tail: tail,
    })
}

impl RunningService {
    #[cfg(test)]
    pub(crate) fn pathological_for_test(name: &str) -> Self {
        let (_sender, readiness) = std::sync::mpsc::sync_channel(1);
        Self {
            process: DurableServiceProcess {
                name: name.to_string(),
                supervisor_pid: u32::MAX,
                service_pid: u32::MAX,
                service_pgid: i32::MAX,
                shutdown_timeout_sec: 0,
            },
            control: None,
            stopping: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            output_failed: Arc::new(AtomicBool::new(false)),
            monitor: Some(thread::spawn(|| thread::sleep(Duration::from_secs(10)))),
            monitor_outcome: Arc::new(Mutex::new(None)),
            output_threads: Vec::new(),
            readiness: Some(readiness),
            readiness_thread: None,
            startup_sender: Arc::new(Mutex::new(None)),
            _diagnostic_tail: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub(crate) fn retain_output(&self) {
        self.startup_sender
            .lock()
            .expect("service startup sender lock")
            .take();
    }

    pub(crate) fn wait_ready(
        &mut self,
        startup_deadline: Instant,
        session_deadline: Instant,
        cancellation: &CancellationFlag,
    ) -> Result<(), BuildError> {
        let deadline = startup_deadline.min(session_deadline);
        let receiver = self.readiness.take().expect("readiness wait once");
        loop {
            if self.failed.load(Ordering::SeqCst) {
                return Err(BuildError::new(
                    "service_exited",
                    format!("service {} exited before readiness", self.process.name),
                ));
            }
            if self.output_failed.load(Ordering::SeqCst) {
                return Err(BuildError::new(
                    "service_output_failed",
                    format!("service {} startup output drain failed", self.process.name),
                ));
            }
            if cancellation.is_cancelled() {
                return Err(BuildError::new(
                    "service_start_cancelled",
                    "service startup was cancelled",
                ));
            }
            if Instant::now() >= deadline {
                let code = if Instant::now() >= session_deadline {
                    "session_lifetime"
                } else {
                    "service_start_timeout"
                };
                return Err(BuildError::new(
                    code,
                    format!("service {} did not become ready", self.process.name),
                ));
            }
            match receiver.recv_timeout(POLL_INTERVAL) {
                Ok(Ok(())) => {
                    if self.failed.load(Ordering::SeqCst) {
                        continue;
                    }
                    if let Some(handle) = self.readiness_thread.take() {
                        if !join_thread_bounded(handle, PROCESS_KILL_GRACE) {
                            return Err(BuildError::new(
                                "service_readiness",
                                "service readiness monitor did not finish within its bound",
                            ));
                        }
                    }
                    return Ok(());
                }
                Ok(Err(message)) => {
                    return Err(BuildError::new(
                        "service_readiness",
                        format!("service {}: {message}", self.process.name),
                    ));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(BuildError::new(
                        "service_readiness",
                        format!("service {} readiness monitor failed", self.process.name),
                    ));
                }
            }
        }
    }

    pub(crate) fn stop(mut self) -> Result<(), ServiceStopError> {
        self.stopping.store(true, Ordering::SeqCst);
        drop(self.control.take());
        let expected = Duration::from_secs(self.process.shutdown_timeout_sec)
            .saturating_add(PROCESS_KILL_GRACE)
            .saturating_add(Duration::from_secs(1));
        let mut errors = Vec::new();
        let mut cleanup_unproven = false;
        if let Some(handle) = self.monitor.take() {
            if !wait_thread_finished(&handle, expected) {
                let _ = signal_process(self.process.supervisor_pid, libc::SIGTERM);
                if !wait_thread_finished(&handle, PROCESS_KILL_GRACE) {
                    let _ = signal_process(self.process.supervisor_pid, libc::SIGKILL);
                }
            }
            if !join_thread_bounded(handle, PROCESS_KILL_GRACE) {
                cleanup_unproven = true;
                errors.push("supervisor was not reaped within its bounded cleanup".to_string());
            }
        }
        if let Some(outcome) = self
            .monitor_outcome
            .lock()
            .expect("service monitor outcome lock")
            .take()
        {
            if let Err(err) = outcome {
                errors.push(err);
            }
        } else {
            cleanup_unproven = true;
            errors.push("supervisor produced no bounded cleanup outcome".to_string());
        }

        if let Err(err) = terminate_recorded_service_group(
            self.process.service_pgid,
            self.process.shutdown_timeout_sec,
        ) {
            cleanup_unproven = true;
            errors.push(format!(
                "service group {} cleanup was not proven: {err}",
                self.process.service_pgid
            ));
        }

        if let Some(handle) = self.readiness_thread.take() {
            if !join_thread_bounded(handle, PROCESS_KILL_GRACE) {
                errors.push("readiness drain did not stop within its bound".to_string());
            }
        }
        for handle in self.output_threads {
            if !join_thread_bounded(handle, PROCESS_KILL_GRACE) {
                errors.push("service output drain did not stop within its bound".to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ServiceStopError {
                message: errors.join("; "),
                cleanup_unproven,
            })
        }
    }
}

fn wait_thread_finished(handle: &thread::JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(POLL_INTERVAL);
    }
    handle.is_finished()
}

fn join_thread_bounded(handle: thread::JoinHandle<()>, timeout: Duration) -> bool {
    if !wait_thread_finished(&handle, timeout) {
        return false;
    }
    handle.join().is_ok()
}

#[allow(clippy::too_many_arguments)]
fn spawn_output_drain(
    mut reader: impl Read + Send + 'static,
    startup_sender: Arc<Mutex<Option<Sender<SessionStartEvent>>>>,
    cancellation: CancellationFlag,
    retaining: Arc<AtomicBool>,
    tail: Arc<Mutex<VecDeque<u8>>>,
    tail_limit: usize,
    stderr: bool,
    failed: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    on_exit: ExitCallback,
    name: String,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) if retaining.load(Ordering::SeqCst) => {
                    let mut tail = tail.lock().expect("service diagnostic tail lock");
                    tail.extend(&buffer[..count]);
                    while tail.len() > tail_limit {
                        tail.pop_front();
                    }
                }
                Ok(count) => {
                    let data = String::from_utf8_lossy(&buffer[..count]).into_owned();
                    let event = if stderr {
                        SessionStartEvent::Stderr { data }
                    } else {
                        SessionStartEvent::Stdout { data }
                    };
                    let sender = startup_sender.lock().expect("service startup sender lock");
                    if sender.as_ref().is_some_and(|sender| {
                        send_session_response(sender, event, &cancellation).is_err()
                    }) {
                        failed.store(true, Ordering::SeqCst);
                        if !stopping.load(Ordering::SeqCst) {
                            thread::spawn(move || {
                                on_exit(format!("{name} startup output could not be drained"))
                            });
                        }
                        return;
                    }
                }
                Err(err) => {
                    failed.store(true, Ordering::SeqCst);
                    if !stopping.load(Ordering::SeqCst) {
                        thread::spawn(move || on_exit(format!("{name} output read failed: {err}")));
                    }
                    return;
                }
            }
        }
    })
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(target_vendor = "apple")]
    let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    #[cfg(target_vendor = "apple")]
    {
        // Darwin does not provide pipe2. The caller holds PROCESS_SPAWN_LOCK,
        // shared by every daemon Command spawn, across pipe creation and these
        // CLOEXEC updates.
        set_cloexec(read.as_raw_fd(), true)?;
        set_cloexec(write.as_raw_fd(), true)?;
    }
    Ok((read, write))
}

fn set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let updated = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_initial_status(
    reader: &mut StatusReader,
    name: &str,
    cancellation: &CancellationFlag,
    startup_deadline: Instant,
    session_deadline: Instant,
) -> Result<SupervisorStatus, BuildError> {
    loop {
        if cancellation.is_cancelled() {
            return Err(BuildError::new(
                "service_start_cancelled",
                format!("service {name} supervisor startup was cancelled"),
            ));
        }
        let now = Instant::now();
        if now >= startup_deadline || now >= session_deadline {
            let code = if now >= session_deadline {
                "session_lifetime"
            } else {
                "service_start_timeout"
            };
            return Err(BuildError::new(
                code,
                format!("service {name} supervisor did not report its process identity"),
            ));
        }
        match reader.try_read_status() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(err) => {
                return Err(BuildError::new(
                    "service_spawn_failed",
                    format!("service {name} supervisor failed before spawn: {err}"),
                ));
            }
        }
    }
}

struct StatusReader {
    file: File,
    buffer: Vec<u8>,
}

impl StatusReader {
    fn new(file: File) -> io::Result<Self> {
        make_nonblocking(file.as_raw_fd())?;
        Ok(Self {
            file,
            buffer: Vec::new(),
        })
    }

    fn try_read_status(&mut self) -> io::Result<Option<SupervisorStatus>> {
        loop {
            if let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<_> = self.buffer.drain(..=newline).collect();
                return serde_json::from_slice(&line[..line.len() - 1])
                    .map(Some)
                    .map_err(io::Error::other);
            }
            if self.buffer.len() >= MAX_STATUS_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "service supervisor status exceeded its bound",
                ));
            }
            let mut chunk = [0u8; 512];
            match self.file.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "service supervisor status closed",
                    ));
                }
                Ok(count) => self.buffer.extend_from_slice(&chunk[..count]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    }
}

fn write_status(writer: &mut File, status: &SupervisorStatus) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, status).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn service_io_error(err: io::Error) -> BuildError {
    BuildError::new("service_io", err.to_string())
}

pub fn run_supervisor(control_fd: RawFd, status_fd: RawFd, readiness_fd: RawFd) -> io::Result<()> {
    let mut status = unsafe { File::from_raw_fd(status_fd) };
    let control = unsafe { File::from_raw_fd(control_fd) };
    set_cloexec(status.as_raw_fd(), true)?;
    set_cloexec(control.as_raw_fd(), true)?;

    let result = (|| {
        let pid = unsafe { libc::getpid() };
        if unsafe { libc::getpgrp() } != pid && unsafe { libc::setpgid(0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let spec: SupervisorSpec =
            serde_json::from_reader(io::stdin()).map_err(io::Error::other)?;
        if spec.readiness_fd != readiness_fd {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "readiness FD mismatch",
            ));
        }
        enable_service_subreaper()?;
        supervise_service(spec, control, &mut status, readiness_fd, false)
    })();

    if let Err(err) = &result {
        let _ = write_status(
            &mut status,
            &SupervisorStatus::Failed {
                message: err.to_string(),
            },
        );
    }
    result
}

fn supervise_service(
    mut spec: SupervisorSpec,
    control: File,
    status: &mut File,
    readiness_fd: RawFd,
    inject_post_spawn_error: bool,
) -> io::Result<()> {
    let user = UserInfo {
        username: spec.username.clone(),
        uid: spec.uid,
        gid: spec.gid,
        home_dir: spec.home_dir.clone(),
    };
    let run_as = RunAs {
        user,
        gid: spec.gid,
        set_ids: spec.set_ids,
    };
    let mut command = match &spec.execution {
        OwnedExecution::Script(script) => {
            let mut command = Command::new(SCRIPT_SHELL);
            command.arg("-eu").arg("-c").arg(script);
            command
        }
        OwnedExecution::Executable { path, args } => {
            let mut command = Command::new(path);
            command.args(args);
            command
        }
    };
    command
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env_clear();
    for (key, value) in spec.environment.drain(..) {
        command.env(key, value);
    }
    command.env(SERVICE_READY_FD_ENV, readiness_fd.to_string());
    configure_command(&mut command, &run_as).map_err(|err| io::Error::other(err.to_string()))?;
    let child = spawn_command(&mut command)?;
    let mut service = SupervisedServiceChild::new(child, control, spec.shutdown_timeout_sec);
    unsafe { libc::close(readiness_fd) };
    let pgid = service.pgid;
    let pid = service.child_mut().id();
    write_status(status, &SupervisorStatus::Spawned { pid, pgid })?;
    if inject_post_spawn_error {
        return Err(io::Error::other("injected post-spawn supervisor failure"));
    }
    make_nonblocking(service.control_mut().as_raw_fd())?;

    loop {
        if let Some(exit) = service.child_mut().try_wait()? {
            let code = std::os::unix::process::ExitStatusExt::signal(&exit)
                .map_or_else(|| exit.code().unwrap_or(1), |signal| 128 + signal);
            terminate_service_group(pgid, spec.shutdown_timeout_sec)?;
            write_status(status, &SupervisorStatus::Exited { code })?;
            service.finish()?;
            return Ok(());
        }
        let mut byte = [0u8; 1];
        match service.control_mut().read(&mut byte) {
            Ok(_) => {
                stop_service_child(service.child_mut(), spec.shutdown_timeout_sec)?;
                write_status(status, &SupervisorStatus::Stopped)?;
                service.finish()?;
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_child_bounded(child: &mut Child, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn signal_process(pid: u32, signal: i32) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process ID out of range"))?;
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err)
}

fn stop_supervisor_process(child: &mut Child, expected: Duration) -> io::Result<bool> {
    if wait_child_bounded(child, expected)? {
        return Ok(true);
    }
    signal_process(child.id(), libc::SIGTERM)?;
    if wait_child_bounded(child, PROCESS_KILL_GRACE)? {
        return Ok(true);
    }
    signal_process(child.id(), libc::SIGKILL)?;
    wait_child_bounded(child, PROCESS_KILL_GRACE)
}

fn stop_service_child(child: &mut Child, shutdown_timeout_sec: u64) -> io::Result<()> {
    let pgid = child.id() as i32;
    signal_group(pgid, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_secs(shutdown_timeout_sec);
    while Instant::now() < deadline {
        let _ = child.try_wait()?;
        if !process_group_exists(pgid)? {
            let _ = child.try_wait()?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    signal_group(pgid, libc::SIGKILL)?;
    let deadline = Instant::now() + PROCESS_KILL_GRACE;
    loop {
        let _ = child.try_wait()?;
        reap_adopted_children(pgid)?;
        if !process_group_exists(pgid)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service process group survived bounded SIGKILL cleanup",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn terminate_service_group(pgid: i32, shutdown_timeout_sec: u64) -> io::Result<()> {
    terminate_service_group_with_reaping(pgid, shutdown_timeout_sec, true)
}

fn terminate_recorded_service_group(pgid: i32, shutdown_timeout_sec: u64) -> io::Result<()> {
    terminate_service_group_with_reaping(pgid, shutdown_timeout_sec, false)
}

fn terminate_service_group_with_reaping(
    pgid: i32,
    shutdown_timeout_sec: u64,
    reap_adopted: bool,
) -> io::Result<()> {
    if !process_group_exists(pgid)? {
        return Ok(());
    }
    signal_group(pgid, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_secs(shutdown_timeout_sec);
    while Instant::now() < deadline {
        if !process_group_exists(pgid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    signal_group(pgid, libc::SIGKILL)?;
    let deadline = Instant::now() + PROCESS_KILL_GRACE;
    loop {
        if reap_adopted {
            reap_adopted_children(pgid)?;
        }
        if !process_group_exists(pgid)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service descendants survived bounded SIGKILL cleanup",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
fn enable_service_subreaper() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_service_subreaper() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn reap_adopted_children(pgid: i32) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(50);
    loop {
        if Instant::now() >= deadline {
            return Ok(());
        }
        let result = unsafe { libc::waitpid(-pgid, std::ptr::null_mut(), libc::WNOHANG) };
        if result > 0 {
            continue;
        }
        if result == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        return Err(err);
    }
}

#[cfg(not(target_os = "linux"))]
fn reap_adopted_children(_pgid: i32) -> io::Result<()> {
    Ok(())
}

fn make_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_endpoints_are_cloexec_at_creation() {
        let (read, write) = pipe_cloexec().unwrap();
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn initial_status_wait_honors_cancellation_and_deadline() {
        let (read, _write) = pipe_cloexec().unwrap();
        let mut reader = StatusReader::new(File::from(read)).unwrap();
        let cancellation = CancellationFlag::default();
        cancellation.cancel();
        assert_eq!(
            wait_initial_status(
                &mut reader,
                "test",
                &cancellation,
                Instant::now() + Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err()
            .code,
            "service_start_cancelled"
        );

        let cancellation = CancellationFlag::default();
        assert_eq!(
            wait_initial_status(
                &mut reader,
                "test",
                &cancellation,
                Instant::now(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err()
            .code,
            "service_start_timeout"
        );
    }

    #[test]
    fn pending_supervisor_error_path_is_bounded_and_reaped() {
        let child = Command::new("/bin/sh")
            .args(["-c", "while :; do :; done"])
            .spawn()
            .unwrap();
        let pid = child.id();
        let (_read, write) = pipe_cloexec().unwrap();
        let pending = PendingSupervisor::new(child, File::from(write), 0);
        drop(pending);
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn post_spawn_supervisor_error_raii_reaps_service_group() {
        use std::os::fd::IntoRawFd;

        let user = crate::user::lookup_user(unsafe { libc::geteuid() }).unwrap();
        let spec = SupervisorSpec {
            execution: OwnedExecution::Script("while :; do :; done".to_string()),
            cwd: std::env::current_dir().unwrap(),
            environment: Vec::new(),
            username: user.username.clone(),
            home_dir: user.home_dir.clone(),
            uid: user.uid,
            gid: user.gid,
            set_ids: false,
            shutdown_timeout_sec: 0,
            readiness_fd: -1,
        };
        let (control_read, _control_write) = pipe_cloexec().unwrap();
        let (status_read, status_write) = pipe_cloexec().unwrap();
        let (_ready_read, ready_write) = pipe_cloexec().unwrap();
        set_cloexec(ready_write.as_raw_fd(), false).unwrap();
        let ready_fd = ready_write.into_raw_fd();
        let mut status = File::from(status_write);

        let error = supervise_service(spec, File::from(control_read), &mut status, ready_fd, true)
            .unwrap_err();
        assert_eq!(error.to_string(), "injected post-spawn supervisor failure");

        let mut reader = StatusReader::new(File::from(status_read)).unwrap();
        let SupervisorStatus::Spawned { pid, pgid } = reader.try_read_status().unwrap().unwrap()
        else {
            panic!("missing spawned status");
        };
        assert!(!process_group_exists(pgid).unwrap());
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stop_kills_service_group_after_supervisor_sigkill() {
        use std::io::BufRead;

        let mut supervisor = Command::new("/bin/sh")
            .args([
                "-c",
                "setsid /bin/sh -c 'trap \"\" TERM; echo $$; while :; do :; done' & trap '' TERM; while :; do :; done",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let supervisor_pid = supervisor.id();
        let mut service_identity = String::new();
        std::io::BufReader::new(supervisor.stdout.take().unwrap())
            .read_line(&mut service_identity)
            .unwrap();
        let service_pid: u32 = service_identity.trim().parse().unwrap();
        let service_pgid = service_pid as i32;
        assert!(process_group_exists(service_pgid).unwrap());
        let monitor_outcome = Arc::new(Mutex::new(None));
        let thread_outcome = Arc::clone(&monitor_outcome);
        let monitor = thread::spawn(move || {
            let mut supervisor = supervisor;
            let outcome = if wait_child_bounded(&mut supervisor, Duration::from_secs(2)).unwrap() {
                Err("supervisor was killed".to_string())
            } else {
                Err("supervisor was not reaped".to_string())
            };
            *thread_outcome.lock().unwrap() = Some(outcome);
        });
        signal_process(supervisor_pid, libc::SIGKILL).unwrap();

        let (_sender, readiness) = std::sync::mpsc::sync_channel(1);
        let service = RunningService {
            process: DurableServiceProcess {
                name: "test".to_string(),
                supervisor_pid,
                service_pid,
                service_pgid,
                shutdown_timeout_sec: 0,
            },
            control: None,
            stopping: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            output_failed: Arc::new(AtomicBool::new(false)),
            monitor: Some(monitor),
            monitor_outcome,
            output_threads: Vec::new(),
            readiness: Some(readiness),
            readiness_thread: None,
            startup_sender: Arc::new(Mutex::new(None)),
            _diagnostic_tail: Arc::new(Mutex::new(VecDeque::new())),
        };
        let error = service.stop().unwrap_err();
        assert!(!error.cleanup_unproven());
        assert!(!process_group_exists(service_pgid).unwrap());
        assert_eq!(unsafe { libc::kill(supervisor_pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn pathological_monitor_cleanup_returns_with_an_error_bound() {
        let service = RunningService::pathological_for_test("test");
        let started = Instant::now();
        assert!(service.stop().is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn readiness_is_exact_and_bounded() {
        for (bytes, expected) in [
            (b"ready\n".as_slice(), true),
            (b"ready".as_slice(), false),
            (b"ready\nextra".as_slice(), false),
            (b"wrong\n".as_slice(), false),
        ] {
            let mut read = bytes.take((READY_MESSAGE.len() + 1) as u64);
            let mut actual = Vec::new();
            read.read_to_end(&mut actual).unwrap();
            assert_eq!(actual == READY_MESSAGE, expected);
            assert!(actual.len() <= READY_MESSAGE.len() + 1);
        }
    }

    fn waiting_service(readiness: std::sync::mpsc::Receiver<Result<(), String>>) -> RunningService {
        RunningService {
            process: DurableServiceProcess {
                name: "test".to_string(),
                supervisor_pid: 1,
                service_pid: 1,
                service_pgid: 1,
                shutdown_timeout_sec: 1,
            },
            control: None,
            stopping: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            output_failed: Arc::new(AtomicBool::new(false)),
            monitor: None,
            monitor_outcome: Arc::new(Mutex::new(None)),
            output_threads: Vec::new(),
            readiness: Some(readiness),
            readiness_thread: None,
            startup_sender: Arc::new(Mutex::new(None)),
            _diagnostic_tail: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    #[test]
    fn readiness_wait_accepts_exact_and_rejects_bad_early_and_never_ready() {
        let cancellation = CancellationFlag::default();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send(Ok(())).unwrap();
        waiting_service(receiver)
            .wait_ready(
                Instant::now() + Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
                &cancellation,
            )
            .unwrap();

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Err("extra readiness bytes".to_string()))
            .unwrap();
        assert_eq!(
            waiting_service(receiver)
                .wait_ready(
                    Instant::now() + Duration::from_secs(1),
                    Instant::now() + Duration::from_secs(1),
                    &cancellation,
                )
                .unwrap_err()
                .code,
            "service_readiness"
        );

        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        assert_eq!(
            waiting_service(receiver)
                .wait_ready(
                    Instant::now() + Duration::from_secs(1),
                    Instant::now() + Duration::from_millis(20),
                    &cancellation,
                )
                .unwrap_err()
                .code,
            "session_lifetime"
        );

        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut service = waiting_service(receiver);
        service.failed.store(true, Ordering::SeqCst);
        assert_eq!(
            service
                .wait_ready(
                    Instant::now() + Duration::from_secs(1),
                    Instant::now() + Duration::from_secs(1),
                    &cancellation,
                )
                .unwrap_err()
                .code,
            "service_exited"
        );
    }

    #[test]
    fn diagnostic_tail_discards_oldest_bytes() {
        let mut tail = VecDeque::<u8>::new();
        tail.extend(b"abcdef");
        while tail.len() > 4 {
            tail.pop_front();
        }
        assert_eq!(tail.into_iter().collect::<Vec<_>>(), b"cdef");
    }
}
