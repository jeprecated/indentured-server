use std::collections::{HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::future::{pending, poll_fn, Future};
use std::io::{self, BufWriter, Read as _, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::task::Poll;
use std::time::Duration;

use clap::{ArgAction, Parser, Subcommand};
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::io::ReaderStream;

use indentured_server::bearer_token::{BearerToken, MAX_BEARER_TOKEN_FILE_BYTES};
use indentured_server::client_source::{
    find_jj_root, package_source_cancellable, FilesystemPatterns, SourceCancellation,
    SourceIdentity, SourceManifest,
};
use indentured_server::protocol::{
    valid_action_id, valid_session_id, valid_task_id, ArtifactArchive, ArtifactRestrictions,
    BuildPhase, PhaseResult, Request, ResponseEvent, SessionActionEvent, SessionActionRequest,
    SessionActionStatus, SessionStartEvent, SessionStartRequest, SessionStartStatus,
    SessionStopResponse, SessionTeardownResult, SourceFormat, SourceMetadata,
    MAX_SESSION_ACTION_BODY_BYTES, REQUEST_SCHEMA_VERSION, SESSION_REQUEST_SCHEMA_VERSION,
};
use indentured_server::validation::validate_relative_pattern;

const DEFAULT_SOCKET_PATH: &str = "/run/indentured-server/control/server.sock";
const CLIENT_CONFIG_DIR: &str = ".indentured-server";
const CLIENT_CONFIG_FILE: &str = "config.toml";
const CONNECTION_FALLBACK_EXIT_CODE: u8 = 222;
const OUTPUT_PREFIX: &str = "[indentured-server]";
const ENABLED_ENV: &str = "INDENTURED_SERVER_ENABLED";
const ENDPOINT_ENV: &str = "INDENTURED_SERVER_ENDPOINT";
const TOKEN_FILE_ENV: &str = "INDENTURED_SERVER_TOKEN_FILE";
const SOURCES_ENV: &str = "INDENTURED_SERVER_SOURCES";
const SOURCES_EXCLUDE_ENV: &str = "INDENTURED_SERVER_SOURCES_EXCLUDE";
const STDOUT_MAX_LINES_ENV: &str = "INDENTURED_SERVER_STDOUT_MAX_LINES";
const STDERR_MAX_LINES_ENV: &str = "INDENTURED_SERVER_STDERR_MAX_LINES";
#[derive(Clone, Copy, Eq, PartialEq)]
enum InterruptState {
    Pending,
    Triggered,
    Completed,
    Unavailable,
}

struct InterruptControl {
    state: InterruptState,
    signal: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
}

impl InterruptControl {
    async fn install() -> Self {
        let mut control = Self {
            state: InterruptState::Pending,
            signal: Box::pin(tokio::signal::ctrl_c()),
        };
        // Poll in the controlling task now, rather than relying on a spawned
        // listener to be scheduled later, so the OS handler is installed
        // before any session preparation starts.
        let _ = control.poll_pending().await;
        control
    }

    async fn poll_pending(&mut self) -> bool {
        if self.state == InterruptState::Triggered {
            return true;
        }
        if self.state != InterruptState::Pending {
            return false;
        }
        let signal = &mut self.signal;
        let observed = poll_fn(|cx| match signal.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some(result)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        if let Some(result) = observed {
            self.state = if result.is_ok() {
                InterruptState::Triggered
            } else {
                InterruptState::Unavailable
            };
        }
        self.state == InterruptState::Triggered
    }

    async fn claim_completion(&mut self) -> bool {
        if self.poll_pending().await {
            return false;
        }
        if matches!(
            self.state,
            InterruptState::Pending | InterruptState::Unavailable
        ) {
            self.state = InterruptState::Completed;
            true
        } else {
            false
        }
    }

    async fn interrupted(&mut self) {
        if self.state == InterruptState::Triggered {
            return;
        }
        if self.state != InterruptState::Pending {
            pending::<()>().await;
        }
        self.state = if self.signal.as_mut().await.is_ok() {
            InterruptState::Triggered
        } else {
            InterruptState::Unavailable
        };
        if self.state != InterruptState::Triggered {
            pending::<()>().await;
        }
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about = "Client for the indentured-server daemon")]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Endpoint URL (http://, https://, or unix://)"
    )]
    endpoint: Option<String>,

    #[arg(long, global = true, help = "Path to a bearer credential file")]
    token_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(RunArgs),
    Session(SessionArgs),
}

#[derive(Clone, Debug, Parser)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionCommands,
}

#[derive(Clone, Debug, Subcommand)]
enum SessionCommands {
    Start(SessionStartArgs),
    Action(SessionActionArgs),
    Stop(SessionStopArgs),
}

#[derive(Clone, Debug, Parser)]
struct SessionStartArgs {
    #[arg(long = "source", action = ArgAction::Append)]
    source: Vec<String>,

    #[arg(long = "source-exclude", action = ArgAction::Append)]
    source_exclude: Vec<String>,

    #[arg(long)]
    request_id: Option<String>,

    #[arg(
        long,
        help = "Absolute directory under which a unique session result is created"
    )]
    result_root: Option<PathBuf>,

    #[arg(required = true)]
    task: String,
}

#[derive(Clone, Debug, Parser)]
struct SessionActionArgs {
    #[arg(required = true)]
    session: String,

    #[arg(required = true)]
    action: String,

    #[arg(long, required = true, value_name = "FILE_OR_DASH")]
    input: String,

    #[arg(
        long,
        help = "Absolute directory under which a unique action result is created"
    )]
    result_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Parser)]
struct SessionStopArgs {
    #[arg(required = true)]
    session: String,

    #[arg(
        long,
        help = "Absolute directory under which a unique stop result is created"
    )]
    result_root: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct RunArgs {
    #[arg(long = "source", action = ArgAction::Append)]
    source: Vec<String>,

    #[arg(long = "source-exclude", action = ArgAction::Append)]
    source_exclude: Vec<String>,

    #[arg(long)]
    request_id: Option<String>,

    #[arg(
        long,
        help = "Absolute directory under which a unique run result is created"
    )]
    result_root: Option<PathBuf>,

    #[arg(required = true)]
    task: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    #[serde(default)]
    sources: PatternConfig,
    #[serde(default)]
    connection: Option<ConnectionConfig>,
    #[serde(default)]
    output: Option<OutputConfig>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PatternConfig {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConnectionConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    local_fallback: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct OutputConfig {
    #[serde(default)]
    stdout_max_lines: Option<usize>,
    #[serde(default)]
    stderr_max_lines: Option<usize>,
    #[serde(default)]
    stdout_tail_lines: usize,
    #[serde(default)]
    stderr_tail_lines: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
enum Endpoint {
    Http { base: String },
    Unix { path: PathBuf },
}

#[derive(Debug)]
enum BuildError {
    ConnectionFailed(String),
    TimedOut(String),
    Other(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::ConnectionFailed(msg)
            | BuildError::TimedOut(msg)
            | BuildError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

fn connection_failure_exit_code(local_fallback: bool) -> u8 {
    if local_fallback {
        CONNECTION_FALLBACK_EXIT_CODE
    } else {
        1
    }
}

fn is_connection_failure(err: &reqwest::Error) -> bool {
    if err.is_connect() || err.is_timeout() {
        return true;
    }

    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(io_err) = cause.downcast_ref::<io::Error>() {
            match io_err.kind() {
                io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::TimedOut
                | io::ErrorKind::NotFound
                | io::ErrorKind::PermissionDenied => {
                    return true;
                }
                _ => {}
            }
        }
        source = cause.source();
    }

    false
}

#[derive(Debug, Default, Clone)]
struct OutputLimits {
    stdout_max_lines: Option<usize>,
    stderr_max_lines: Option<usize>,
    stdout_tail_lines: usize,
    stderr_tail_lines: usize,
    log_dir: PathBuf,
}

fn resolve_output_limits(
    config: Option<&OutputConfig>,
    run_dir: &Path,
) -> io::Result<OutputLimits> {
    let stdout_max_lines = if let Ok(raw) = env::var(STDOUT_MAX_LINES_ENV) {
        parse_output_limit(&raw, STDOUT_MAX_LINES_ENV)?
            .or_else(|| config.and_then(|config| config.stdout_max_lines))
    } else {
        config.and_then(|config| config.stdout_max_lines)
    };

    let stderr_max_lines = if let Ok(raw) = env::var(STDERR_MAX_LINES_ENV) {
        parse_output_limit(&raw, STDERR_MAX_LINES_ENV)?
            .or_else(|| config.and_then(|config| config.stderr_max_lines))
    } else {
        config.and_then(|config| config.stderr_max_lines)
    };

    let stdout_tail_lines = config
        .map(|config| config.stdout_tail_lines)
        .unwrap_or_default();
    let stderr_tail_lines = config
        .map(|config| config.stderr_tail_lines)
        .unwrap_or_default();
    Ok(OutputLimits {
        stdout_max_lines,
        stderr_max_lines,
        stdout_tail_lines,
        stderr_tail_lines,
        log_dir: run_dir.to_path_buf(),
    })
}

fn parse_output_limit(raw: &str, var: &str) -> io::Result<Option<usize>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let parsed: usize = trimmed.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{var} must be a non-negative integer, got {trimmed}"),
        )
    })?;
    Ok(Some(parsed))
}

struct OutputLimiter {
    stdout: LineLimiter,
    stderr: LineLimiter,
}

impl OutputLimiter {
    fn new(limits: &OutputLimits) -> Self {
        Self {
            stdout: LineLimiter::new(
                "stdout",
                STDOUT_MAX_LINES_ENV,
                limits.stdout_max_lines,
                limits.stdout_tail_lines,
            ),
            stderr: LineLimiter::new(
                "stderr",
                STDERR_MAX_LINES_ENV,
                limits.stderr_max_lines,
                limits.stderr_tail_lines,
            ),
        }
    }

    fn set_log_paths(&mut self, paths: &StreamLogPaths) {
        self.stdout.set_log_path(paths.stdout.clone());
        self.stderr.set_log_path(paths.stderr.clone());
    }

    fn clear_log_paths(&mut self) {
        self.stdout.clear_log_path();
        self.stderr.clear_log_path();
    }

    fn write_stdout(&mut self, data: &str) -> io::Result<()> {
        let mut stdout = io::stdout();
        self.stdout.write_chunk(data, &mut stdout)
    }

    fn write_stdout_as_diagnostic(&mut self, data: &str) -> io::Result<()> {
        let mut stderr = io::stderr();
        self.stdout.write_chunk(data, &mut stderr)
    }

    fn write_stderr(&mut self, data: &str) -> io::Result<()> {
        let mut stderr = io::stderr();
        self.stderr.write_chunk(data, &mut stderr)
    }

    fn finish(&mut self) -> io::Result<()> {
        self.finish_routed(false)
    }

    fn finish_routed(&mut self, stdout_to_stderr: bool) -> io::Result<()> {
        self.stdout.finish();
        self.stderr.finish();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        if stdout_to_stderr {
            self.stdout.write_summary(&mut stderr, "stdout")?;
        } else {
            self.stdout.write_summary(&mut stdout, "stdout")?;
        }
        self.stderr.write_summary(&mut stderr, "stderr")?;
        stdout.flush()?;
        stderr.flush()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum BufferedStreamEvent {
    Stdout(String),
    Stderr(String),
}

struct LineLimiter {
    label: &'static str,
    env_var: &'static str,
    max_lines: Option<usize>,
    tail_lines: usize,
    printed_lines: usize,
    suppressed_lines: usize,
    at_line_start: bool,
    current_line_allowed: bool,
    suppression_notified: bool,
    suppressed_line: String,
    tail_buffer: VecDeque<String>,
    log_path: Option<PathBuf>,
}

impl LineLimiter {
    fn new(
        label: &'static str,
        env_var: &'static str,
        max_lines: Option<usize>,
        tail_lines: usize,
    ) -> Self {
        Self {
            label,
            env_var,
            max_lines,
            tail_lines,
            printed_lines: 0,
            suppressed_lines: 0,
            at_line_start: true,
            current_line_allowed: true,
            suppression_notified: false,
            suppressed_line: String::new(),
            tail_buffer: VecDeque::new(),
            log_path: None,
        }
    }

    fn set_log_path(&mut self, path: PathBuf) {
        self.log_path = Some(path);
    }

    fn clear_log_path(&mut self) {
        self.log_path = None;
    }

    fn write_chunk(&mut self, data: &str, writer: &mut dyn Write) -> io::Result<()> {
        if self.max_lines.is_none() {
            writer.write_all(data.as_bytes())?;
            writer.flush()?;
            return Ok(());
        }

        let mut output = String::new();
        for segment in data.split_inclusive('\n') {
            if self.at_line_start {
                self.current_line_allowed = self
                    .max_lines
                    .map(|max| self.printed_lines < max)
                    .unwrap_or(true);
                self.at_line_start = false;

                if !self.current_line_allowed && !self.suppression_notified {
                    output.push_str(&self.suppression_notice());
                    self.suppression_notified = true;
                }
            }

            if self.current_line_allowed {
                output.push_str(segment);
            } else if self.tail_lines > 0 {
                self.suppressed_line.push_str(segment);
            }

            if segment.ends_with('\n') {
                self.finish_line();
            }
        }

        if !output.is_empty() {
            writer.write_all(output.as_bytes())?;
            writer.flush()?;
        }

        Ok(())
    }

    fn finish(&mut self) {
        if self.max_lines.is_none() {
            return;
        }

        if !self.at_line_start {
            if self.current_line_allowed {
                self.printed_lines += 1;
            } else {
                self.suppressed_lines += 1;
                self.push_tail_line();
            }
            self.suppressed_line.clear();
            self.at_line_start = true;
        }
    }

    fn write_summary(&self, writer: &mut dyn Write, label: &str) -> io::Result<()> {
        if self.max_lines.is_none() || self.suppressed_lines == 0 {
            return Ok(());
        }

        writeln!(
            writer,
            "{OUTPUT_PREFIX} {} more {} lines suppressed",
            self.suppressed_lines, label
        )?;

        if !self.tail_buffer.is_empty() {
            for line in &self.tail_buffer {
                writer.write_all(line.as_bytes())?;
            }
        }

        Ok(())
    }

    fn finish_line(&mut self) {
        if self.current_line_allowed {
            self.printed_lines += 1;
        } else {
            self.suppressed_lines += 1;
            self.push_tail_line();
        }
        self.suppressed_line.clear();
        self.at_line_start = true;
    }

    fn push_tail_line(&mut self) {
        if self.tail_lines == 0 {
            return;
        }

        self.tail_buffer.push_back(self.suppressed_line.clone());
        if self.tail_buffer.len() > self.tail_lines {
            self.tail_buffer.pop_front();
        }
    }

    fn suppression_notice(&self) -> String {
        if let Some(log_path) = &self.log_path {
            format!(
                "{OUTPUT_PREFIX} suppressing {} output due to limits (full log: {})\n",
                self.label,
                log_path.display()
            )
        } else {
            format!(
                "{OUTPUT_PREFIX} suppressing {} output due to limits (increase output lines with {}=<lines>)\n",
                self.label,
                self.env_var
            )
        }
    }
}

#[derive(Debug, Clone)]
struct StreamLogPaths {
    stdout: PathBuf,
    stderr: PathBuf,
}

struct BuildLogSink {
    paths: StreamLogPaths,
    stdout_writer: BufWriter<Box<dyn Write>>,
    stderr_writer: BufWriter<Box<dyn Write>>,
}

impl BuildLogSink {
    fn new(base_dir: &Path, build_id: &str) -> io::Result<Self> {
        validate_build_id(build_id)?;
        let stdout_path = base_dir.join("stdout.log");
        let stderr_path = base_dir.join("stderr.log");
        let stdout = BufWriter::new(Box::new(
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(&stdout_path)?,
        ) as Box<dyn Write>);
        let stderr = BufWriter::new(Box::new(
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(&stderr_path)?,
        ) as Box<dyn Write>);

        Ok(Self {
            paths: StreamLogPaths {
                stdout: stdout_path,
                stderr: stderr_path,
            },
            stdout_writer: stdout,
            stderr_writer: stderr,
        })
    }

    fn paths(&self) -> &StreamLogPaths {
        &self.paths
    }

    fn write_stdout(&mut self, data: &str) -> io::Result<()> {
        self.stdout_writer.write_all(data.as_bytes())?;
        self.stdout_writer.flush()
    }

    fn write_stderr(&mut self, data: &str) -> io::Result<()> {
        self.stderr_writer.write_all(data.as_bytes())?;
        self.stderr_writer.flush()
    }
}

#[derive(Default)]
struct LogCaptureState {
    base_dir: Option<PathBuf>,
    sink: Option<BuildLogSink>,
    warning_emitted: bool,
}

impl LogCaptureState {
    fn new(output_limits: &OutputLimits) -> Self {
        Self {
            base_dir: Some(output_limits.log_dir.clone()),
            sink: None,
            warning_emitted: false,
        }
    }

    fn initialize(&mut self, build_id: &str) -> io::Result<Option<StreamLogPaths>> {
        let Some(base_dir) = self.base_dir.as_ref() else {
            return Ok(None);
        };

        if let Some(existing) = self.sink.as_ref() {
            return Ok(Some(existing.paths().clone()));
        }

        let sink = BuildLogSink::new(base_dir, build_id)?;
        let paths = sink.paths().clone();
        self.sink = Some(sink);
        Ok(Some(paths))
    }

    fn disable(&mut self) {
        self.base_dir = None;
        self.sink = None;
    }

    fn process_event(
        &mut self,
        event: BufferedStreamEvent,
        output: &mut OutputLimiter,
    ) -> io::Result<()> {
        self.process_event_routed(event, output, false)
    }

    fn process_event_routed(
        &mut self,
        event: BufferedStreamEvent,
        output: &mut OutputLimiter,
        stdout_to_stderr: bool,
    ) -> io::Result<()> {
        if let Some(sink) = self.sink.as_mut() {
            let log_result = match &event {
                BufferedStreamEvent::Stdout(data) => sink.write_stdout(data),
                BufferedStreamEvent::Stderr(data) => sink.write_stderr(data),
            };

            if let Err(err) = log_result {
                output.clear_log_paths();
                self.disable();
                self.write_warning(&err.to_string())?;
            }
        }

        if stdout_to_stderr {
            match event {
                BufferedStreamEvent::Stdout(data) => output.write_stdout_as_diagnostic(&data),
                BufferedStreamEvent::Stderr(data) => output.write_stderr(&data),
            }
        } else {
            write_event_to_terminal(event, output)
        }
    }

    fn completion_paths(&self) -> Option<&StreamLogPaths> {
        self.sink.as_ref().map(|sink| sink.paths())
    }

    fn write_warning(&mut self, message: &str) -> io::Result<()> {
        if self.warning_emitted {
            return Ok(());
        }

        self.warning_emitted = true;
        let mut stderr = io::stderr();
        writeln!(stderr, "{OUTPUT_PREFIX} log capture unavailable: {message}")?;
        stderr.flush()
    }

    fn write_completion_notice(&self) -> io::Result<()> {
        let Some(paths) = self.completion_paths() else {
            return Ok(());
        };

        let mut stderr = io::stderr();
        writeln!(
            stderr,
            "{OUTPUT_PREFIX} saved full logs: stdout={}, stderr={}",
            paths.stdout.display(),
            paths.stderr.display()
        )?;
        stderr.flush()
    }
}

fn write_event_to_terminal(
    event: BufferedStreamEvent,
    output: &mut OutputLimiter,
) -> io::Result<()> {
    match event {
        BufferedStreamEvent::Stdout(data) => output.write_stdout(&data),
        BufferedStreamEvent::Stderr(data) => output.write_stderr(&data),
    }
}

fn validate_build_id(build_id: &str) -> io::Result<()> {
    let trimmed = build_id.trim();
    if trimmed.is_empty() || matches!(trimmed, "." | "..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "build id must be a non-empty single path component",
        ));
    }

    if trimmed.contains('\0') || trimmed.contains('/') || trimmed.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "build id must not contain path separators or NUL bytes",
        ));
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct RunProvenance {
    schema_version: u32,
    run_id: String,
    status: String,
    source: Option<SourceIdentity>,
    source_root: PathBuf,
    result_path: PathBuf,
    started_at: String,
    finished_at: Option<String>,
    remote_build_id: Option<String>,
    remote_exit_code: Option<i32>,
    timed_out: Option<bool>,
    failed_phase: Option<BuildPhase>,
    phases: Vec<PhaseResult>,
    artifact_restrictions: Option<ArtifactRestrictions>,
    errors: Vec<String>,
}

struct RunEvidence {
    base: PathBuf,
    directory: PathBuf,
    provenance: RunProvenance,
}

impl RunEvidence {
    fn create(source_root: &Path, explicit_root: Option<&Path>) -> io::Result<Self> {
        let requested_base = resolve_result_root(explicit_root)?;
        let intended_base = canonicalize_intended(&requested_base)?;
        reject_overlap(source_root, &intended_base)?;
        fs::create_dir_all(&requested_base)?;
        let base = fs::canonicalize(&requested_base)?;
        reject_overlap(source_root, &base)?;
        let run_id = uuid::Uuid::new_v4().to_string();
        let directory = base.join(&run_id);
        fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&directory)?;
        for name in ["stdout.log", "stderr.log"] {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(name))?;
        }
        let provenance = RunProvenance {
            schema_version: 2,
            run_id,
            status: "preparing".to_string(),
            source: None,
            source_root: source_root.to_path_buf(),
            result_path: directory.clone(),
            started_at: now_string(),
            finished_at: None,
            remote_build_id: None,
            remote_exit_code: None,
            timed_out: None,
            failed_phase: None,
            phases: Vec::new(),
            artifact_restrictions: None,
            errors: Vec::new(),
        };
        let evidence = Self {
            base,
            directory,
            provenance,
        };
        evidence.write_provenance()?;
        eprintln!("{OUTPUT_PREFIX} results: {}", evidence.directory.display());
        Ok(evidence)
    }

    fn write_manifest(&self, manifest: &SourceManifest) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(manifest).map_err(io::Error::other)?;
        if data.len() > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source manifest exceeds 16 MiB",
            ));
        }
        write_new_private(&self.directory.join("source-manifest.json"), &data)
    }

    fn write_provenance(&self) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(&self.provenance).map_err(io::Error::other)?;
        let mut temp = tempfile::Builder::new()
            .prefix(".provenance-")
            .tempfile_in(&self.directory)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temp.write_all(&data)?;
        temp.as_file().sync_all()?;
        temp.persist(self.directory.join("provenance.json"))
            .map_err(|err| err.error)?;
        Ok(())
    }

    fn set_status(&mut self, status: &str) -> io::Result<()> {
        self.provenance.status = status.to_string();
        self.write_provenance()
    }

    fn finish(&mut self, status: &str) -> io::Result<()> {
        self.provenance.status = status.to_string();
        self.provenance.finished_at = Some(now_string());
        self.write_provenance()
    }

    fn error(&mut self, message: impl Into<String>) -> io::Result<()> {
        if self.provenance.errors.len() < 32 {
            let mut message = message.into();
            truncate_utf8(&mut message, 4096);
            self.provenance.errors.push(message);
        }
        self.write_provenance()
    }
}

#[derive(Debug, Serialize)]
struct SessionProvenance {
    schema_version: u32,
    invocation_id: String,
    operation: String,
    status: String,
    result_path: PathBuf,
    started_at: String,
    finished_at: Option<String>,
    session_id: Option<String>,
    action: Option<String>,
    action_id: Option<String>,
    source: Option<SourceIdentity>,
    remote_exit_code: Option<i32>,
    timed_out: Option<bool>,
    phases: Vec<PhaseResult>,
    teardown: Option<SessionTeardownResult>,
    artifact_restrictions: Option<ArtifactRestrictions>,
    cleanup_status: Option<String>,
    errors: Vec<String>,
}

struct SessionEvidence {
    base: PathBuf,
    directory: PathBuf,
    provenance: SessionProvenance,
    persistence_failure: Option<String>,
}

impl SessionEvidence {
    fn create(
        operation: &str,
        session_id: Option<&str>,
        action: Option<&str>,
        explicit_root: Option<&Path>,
        source_root: Option<&Path>,
    ) -> io::Result<Self> {
        let requested_base = resolve_result_root(explicit_root)?;
        if let Some(source_root) = source_root {
            let intended_base = canonicalize_intended(&requested_base)?;
            reject_overlap(source_root, &intended_base)?;
        }
        fs::create_dir_all(&requested_base)?;
        let base = fs::canonicalize(&requested_base)?;
        if let Some(source_root) = source_root {
            reject_overlap(source_root, &base)?;
        }
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let directory = base.join(&invocation_id);
        fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&directory)?;
        for name in ["stdout.log", "stderr.log"] {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(name))?;
        }
        let provenance = SessionProvenance {
            schema_version: 1,
            invocation_id,
            operation: operation.to_string(),
            status: "preparing".to_string(),
            result_path: directory.clone(),
            started_at: now_string(),
            finished_at: None,
            session_id: session_id.map(ToString::to_string),
            action: action.map(ToString::to_string),
            action_id: None,
            source: None,
            remote_exit_code: None,
            timed_out: None,
            phases: Vec::new(),
            teardown: None,
            artifact_restrictions: None,
            cleanup_status: None,
            errors: Vec::new(),
        };
        let evidence = Self {
            base,
            directory,
            provenance,
            persistence_failure: None,
        };
        evidence.write_provenance()?;
        eprintln!("{OUTPUT_PREFIX} results: {}", evidence.directory.display());
        Ok(evidence)
    }

    fn write_manifest(&self, manifest: &SourceManifest) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(manifest).map_err(io::Error::other)?;
        if data.len() > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source manifest exceeds 16 MiB",
            ));
        }
        write_new_private(&self.directory.join("source-manifest.json"), &data)
    }

    fn write_provenance(&self) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(&self.provenance).map_err(io::Error::other)?;
        let mut temp = tempfile::Builder::new()
            .prefix(".provenance-")
            .tempfile_in(&self.directory)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temp.write_all(&data)?;
        temp.as_file().sync_all()?;
        temp.persist(self.directory.join("provenance.json"))
            .map_err(|err| err.error)?;
        Ok(())
    }

    fn record_persistence(&mut self, result: io::Result<()>) -> io::Result<()> {
        if let Err(err) = result {
            let message = format!("provenance persistence failed: {err}");
            self.persistence_failure.get_or_insert(message);
            return Err(err);
        }
        Ok(())
    }

    fn set_status(&mut self, status: &str) -> io::Result<()> {
        self.provenance.status = status.to_string();
        let result = self.write_provenance();
        self.record_persistence(result)
    }

    fn set_session_id(&mut self, session_id: &str) -> io::Result<()> {
        self.provenance.session_id = Some(session_id.to_string());
        let result = self.write_provenance();
        self.record_persistence(result)
    }

    fn set_action_id(&mut self, action_id: &str) -> io::Result<()> {
        self.provenance.action_id = Some(action_id.to_string());
        let result = self.write_provenance();
        self.record_persistence(result)
    }

    fn set_cleanup_status(&mut self, status: String) -> io::Result<()> {
        self.provenance.cleanup_status = Some(status);
        let result = self.write_provenance();
        self.record_persistence(result)
    }

    fn finish(&mut self, status: &str) -> io::Result<()> {
        self.provenance.status = status.to_string();
        self.provenance.finished_at = Some(now_string());
        let result = self.write_provenance();
        self.record_persistence(result)
    }

    fn error(&mut self, message: impl Into<String>) -> io::Result<()> {
        if self.provenance.errors.len() < 32 {
            let mut message = message.into();
            truncate_utf8(&mut message, 4096);
            self.provenance.errors.push(message);
        }
        let result = self.write_provenance();
        self.record_persistence(result)
    }
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

fn now_string() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

fn resolve_result_root(explicit: Option<&Path>) -> io::Result<PathBuf> {
    resolve_result_root_from(explicit, env::var_os("XDG_STATE_HOME"), env::var_os("HOME"))
}

fn resolve_result_root_from(
    explicit: Option<&Path>,
    xdg_state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--result-root must be absolute",
            ));
        }
        return Ok(path.to_path_buf());
    }
    if let Some(value) = xdg_state_home {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XDG_STATE_HOME must be absolute",
            ));
        }
        return Ok(path.join("indentured/runs"));
    }
    let home = home.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "HOME or XDG_STATE_HOME is required for run results",
        )
    })?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HOME must be absolute",
        ));
    }
    Ok(home.join(".local/state/indentured/runs"))
}

fn canonicalize_intended(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path);
    }
    let mut cursor = path;
    let mut missing = Vec::new();
    while !cursor.exists() {
        let name = cursor.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "result root has no existing ancestor",
            )
        })?;
        missing.push(name.to_os_string());
        cursor = cursor.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "result root has no existing ancestor",
            )
        })?;
    }
    let mut resolved = fs::canonicalize(cursor)?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn reject_overlap(source: &Path, results: &Path) -> io::Result<()> {
    let source = fs::canonicalize(source)?;
    let results = canonicalize_intended(results)?;
    if source == results || source.starts_with(&results) || results.starts_with(&source) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "result root must not equal, contain, or be contained by the submitted source root",
        ));
    }
    Ok(())
}

fn reject_credential_overlap(
    credential: &Path,
    source_root: &Path,
    result_base: &Path,
) -> io::Result<()> {
    let credential = fs::canonicalize(credential)?;
    let source_root = fs::canonicalize(source_root)?;
    let result_base = fs::canonicalize(result_base)?;
    if credential.starts_with(&source_root) || credential.starts_with(&result_base) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential file must be outside source and the configured result-root base",
        ));
    }
    Ok(())
}

fn reject_credential_result_overlap(credential: &Path, result_base: &Path) -> io::Result<()> {
    let credential = fs::canonicalize(credential)?;
    let result_base = fs::canonicalize(result_base)?;
    if credential.starts_with(&result_base) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential file must be outside the configured result-root base",
        ));
    }
    Ok(())
}

fn write_new_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

struct PreparedSession {
    evidence: SessionEvidence,
    source_root: Option<PathBuf>,
}

struct SessionCommandContext {
    interrupt: InterruptControl,
    endpoint_arg: Option<String>,
    token_file_arg: Option<PathBuf>,
    invocation_dir: PathBuf,
    filesystem_root: PathBuf,
    client_config: ClientConfig,
    config_loaded: bool,
}

fn prepare_session_evidence(
    command: &SessionCommands,
    invocation_dir: &Path,
    filesystem_root: &Path,
) -> io::Result<PreparedSession> {
    match command {
        SessionCommands::Start(args) => {
            let source_root = match find_jj_root(invocation_dir)? {
                Some(root) => root,
                None => fs::canonicalize(filesystem_root)?,
            };
            let evidence = SessionEvidence::create(
                "start",
                None,
                None,
                args.result_root.as_deref(),
                Some(&source_root),
            )?;
            Ok(PreparedSession {
                evidence,
                source_root: Some(source_root),
            })
        }
        SessionCommands::Action(args) => Ok(PreparedSession {
            evidence: SessionEvidence::create(
                "action",
                Some(&args.session),
                Some(&args.action),
                args.result_root.as_deref(),
                None,
            )?,
            source_root: None,
        }),
        SessionCommands::Stop(args) => Ok(PreparedSession {
            evidence: SessionEvidence::create(
                "stop",
                Some(&args.session),
                None,
                args.result_root.as_deref(),
                None,
            )?,
            source_root: None,
        }),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let run_dir = match env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("failed to resolve current directory: {err}");
            return ExitCode::from(1);
        }
    };

    let mut session_interrupt = match &cli.command {
        Commands::Session(_) => Some(InterruptControl::install().await),
        Commands::Run(_) => None,
    };

    let config_path = find_client_config_path(&run_dir);
    let repo_root = config_path
        .as_ref()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| run_dir.clone());
    let mut prepared_session = match &cli.command {
        Commands::Session(args) => {
            let command = args.command.clone();
            let invocation_dir = run_dir.clone();
            let filesystem_root = repo_root.clone();
            let mut preparation = tokio::task::spawn_blocking(move || {
                prepare_session_evidence(&command, &invocation_dir, &filesystem_root)
            });
            let (interrupted, preparation_result) = tokio::select! {
                biased;
                _ = session_interrupt.as_mut().expect("session interrupt installed").interrupted() => (true, preparation.await),
                result = &mut preparation => (false, result),
            };
            let prepared = match preparation_result {
                Ok(Ok(prepared)) => prepared,
                Ok(Err(err)) => {
                    eprintln!("failed to create session evidence: {err}");
                    return ExitCode::from(1);
                }
                Err(err) => {
                    eprintln!("session evidence worker failed: {err}");
                    return ExitCode::from(1);
                }
            };
            if interrupted {
                let mut prepared = prepared;
                return finish_early_interrupted(
                    &mut prepared.evidence,
                    "interrupted during session preparation",
                );
            }
            Some(prepared)
        }
        Commands::Run(_) => None,
    };
    let client_config = if prepared_session.is_some() {
        let loading_path = config_path.clone();
        let mut loading =
            tokio::task::spawn_blocking(move || load_client_config(loading_path.as_deref()));
        let (interrupted, loading_result) = tokio::select! {
            biased;
            _ = session_interrupt.as_mut().expect("session interrupt installed").interrupted() => (true, loading.await),
            result = &mut loading => (false, result),
        };
        let loaded = match loading_result {
            Ok(result) => result,
            Err(err) => {
                return finish_session_failure_elected(
                    prepared_session
                        .take()
                        .expect("session evidence prepared")
                        .evidence,
                    format!("client configuration worker failed: {err}"),
                    false,
                    session_interrupt
                        .as_mut()
                        .expect("session interrupt installed"),
                )
                .await;
            }
        };
        if interrupted {
            return finish_early_interrupted(
                &mut prepared_session
                    .as_mut()
                    .expect("session evidence prepared")
                    .evidence,
                "interrupted while loading client configuration",
            );
        }
        match loaded {
            Ok(config) => config,
            Err(err) => {
                return finish_session_failure_elected(
                    prepared_session
                        .take()
                        .expect("session evidence prepared")
                        .evidence,
                    format!("failed to load client configuration: {err}"),
                    false,
                    session_interrupt
                        .as_mut()
                        .expect("session interrupt installed"),
                )
                .await;
            }
        }
    } else {
        match load_client_config(config_path.as_deref()) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
    };
    let config_loaded = config_path.is_some();
    if let Some(interrupt) = session_interrupt.as_mut() {
        if interrupt.poll_pending().await {
            return finish_early_interrupted(
                &mut prepared_session
                    .as_mut()
                    .expect("session evidence prepared")
                    .evidence,
                "interrupted after client configuration",
            );
        }
    }

    let connection = client_config.connection.as_ref();
    if !resolve_connection_enabled(connection) {
        if let Some(interrupt) = session_interrupt.as_mut() {
            if interrupt.poll_pending().await {
                return finish_early_interrupted(
                    &mut prepared_session
                        .as_mut()
                        .expect("session evidence prepared")
                        .evidence,
                    "interrupted before session dispatch",
                );
            }
        }
        let message =
            format!("{OUTPUT_PREFIX} disabled (INDENTURED_SERVER_ENABLED/connection.enabled)");
        if let Some(prepared) = prepared_session.take() {
            return finish_session_failure_elected(
                prepared.evidence,
                message,
                true,
                session_interrupt
                    .as_mut()
                    .expect("session interrupt installed"),
            )
            .await;
        }
        eprintln!("{message}");
        return ExitCode::from(CONNECTION_FALLBACK_EXIT_CODE);
    }

    match cli.command {
        Commands::Run(args) => {
            run_command(
                args,
                cli.endpoint,
                cli.token_file,
                run_dir,
                repo_root,
                client_config,
                config_loaded,
            )
            .await
        }
        Commands::Session(args) => {
            session_command(
                args.command,
                prepared_session.expect("session evidence prepared"),
                SessionCommandContext {
                    interrupt: session_interrupt
                        .take()
                        .expect("session interrupt installed"),
                    endpoint_arg: cli.endpoint,
                    token_file_arg: cli.token_file,
                    invocation_dir: run_dir,
                    filesystem_root: repo_root,
                    client_config,
                    config_loaded,
                },
            )
            .await
        }
    }
}

async fn run_command(
    args: RunArgs,
    endpoint_arg: Option<String>,
    token_file_arg: Option<PathBuf>,
    invocation_dir: PathBuf,
    filesystem_root: PathBuf,
    client_config: ClientConfig,
    config_loaded: bool,
) -> ExitCode {
    let connection = client_config.connection.as_ref();
    let source_root = match find_jj_root(&invocation_dir) {
        Ok(Some(root)) => root,
        Ok(None) => match fs::canonicalize(&filesystem_root) {
            Ok(root) => root,
            Err(err) => {
                eprintln!("failed to resolve source root: {err}");
                return ExitCode::from(1);
            }
        },
        Err(err) => {
            eprintln!("failed to inspect source root: {err}");
            return ExitCode::from(1);
        }
    };
    let mut evidence = match RunEvidence::create(&source_root, args.result_root.as_deref()) {
        Ok(evidence) => evidence,
        Err(err) => {
            eprintln!("failed to create run results: {err}");
            return ExitCode::from(1);
        }
    };

    let source_patterns = match resolve_patterns(
        &client_config.sources,
        SOURCES_ENV,
        &args.source,
        SOURCES_EXCLUDE_ENV,
        &args.source_exclude,
    ) {
        Ok(patterns) => patterns,
        Err(err) => {
            let _ = evidence.error(err.to_string());
            let _ = evidence.finish("failed");
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = validate_patterns(&source_patterns, "sources") {
        let _ = evidence.error(err.to_string());
        let _ = evidence.finish("failed");
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    if let Some(path) = selected_token_path(token_file_arg.clone(), connection) {
        if path.exists() {
            if let Err(err) = reject_credential_overlap(&path, &source_root, &evidence.base) {
                let _ = evidence.error(err.to_string());
                let _ = evidence.finish("failed");
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
    }
    let endpoint = match resolve_endpoint(endpoint_arg, connection, config_loaded) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            let _ = evidence.error(err.to_string());
            let _ = evidence.finish("failed");
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let token = match resolve_token(token_file_arg, connection) {
        Ok(token) => token,
        Err(err) => {
            let _ = evidence.error(err.to_string());
            let _ = evidence.finish("failed");
            eprintln!("failed to load bearer credential: {err}");
            return ExitCode::from(1);
        }
    };
    let output_limits =
        match resolve_output_limits(client_config.output.as_ref(), &evidence.directory) {
            Ok(limits) => limits,
            Err(err) => {
                let _ = evidence.error(err.to_string());
                let _ = evidence.finish("failed");
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        };

    let patterns = FilesystemPatterns {
        include: source_patterns.include,
        exclude: source_patterns.exclude,
    };
    let cancellation = SourceCancellation::new();
    let (interrupt_tx, mut interrupt_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = interrupt_tx.send(()).await;
        } else {
            std::future::pending::<()>().await;
        }
    });
    // Give the listener one poll to install Tokio's process-wide signal handler
    // before any source discovery/subprocess work can begin.
    tokio::task::yield_now().await;
    let packaging_cancellation = cancellation.clone();
    let packaging_invocation = invocation_dir.clone();
    let packaging_root = filesystem_root.clone();
    let packaging_temp = evidence.directory.clone();
    let mut packaging = tokio::task::spawn_blocking(move || {
        package_source_cancellable(
            &packaging_invocation,
            &packaging_root,
            &patterns,
            &packaging_temp,
            &packaging_cancellation,
        )
    });
    let package = tokio::select! {
        result = &mut packaging => {
            match result {
                Ok(Ok(package)) => package,
                Ok(Err(err)) => {
                    let _ = evidence.error(err.to_string());
                    let _ = evidence.finish("failed");
                    eprintln!("failed to package sources: {err}");
                    return ExitCode::from(1);
                }
                Err(err) => {
                    let message = format!("source packaging worker failed: {err}");
                    let _ = evidence.error(&message);
                    let _ = evidence.finish("failed");
                    eprintln!("{message}");
                    return ExitCode::from(1);
                }
            }
        }
        _ = interrupt_rx.recv() => {
            cancellation.cancel();
            match tokio::time::timeout(Duration::from_secs(7), &mut packaging).await {
                Ok(Ok(Err(err))) if err.kind() != io::ErrorKind::Interrupted || err.to_string().contains("cleanup") => {
                    let _ = evidence.error(format!("source cleanup after interruption failed: {err}"));
                }
                Ok(Err(err)) => {
                    let _ = evidence.error(format!("source cleanup worker failed after interruption: {err}"));
                }
                Err(_) => {
                    packaging.abort();
                    let _ = evidence.error("source cleanup did not finish within 7 seconds after interruption");
                }
                _ => {}
            }
            let _ = evidence.finish("interrupted");
            eprintln!("{OUTPUT_PREFIX} interrupted during source preparation");
            return ExitCode::from(130);
        }
    };
    evidence.provenance.source = Some(package.identity.clone());
    if let Err(err) = evidence.write_manifest(&package.manifest) {
        let _ = evidence.error(err.to_string());
        let _ = evidence.finish("failed");
        eprintln!("failed to write source manifest: {err}");
        return ExitCode::from(1);
    }

    if interrupt_rx.try_recv().is_ok() {
        let _ = evidence.finish("interrupted");
        eprintln!("{OUTPUT_PREFIX} interrupted during source preparation");
        return ExitCode::from(130);
    }

    let request = Request {
        schema_version: REQUEST_SCHEMA_VERSION.to_string(),
        request_id: args
            .request_id
            .or_else(|| Some(evidence.provenance.run_id.clone())),
        task: args.task,
        source: SourceMetadata {
            format: SourceFormat::Zip,
        },
    };
    let _ = evidence.set_status("running");

    let result_directory = evidence.directory.clone();
    let outcome = {
        let remote = async {
            let build = run_build(
                &request,
                &package.archive,
                &endpoint,
                token.as_deref(),
                &output_limits,
            )
            .await?;
            let artifact_error = if let Some(archive) = &build.artifacts {
                download_and_extract(archive, &endpoint, token.as_deref(), &result_directory)
                    .await
                    .err()
                    .map(|err| err.to_string())
            } else {
                None
            };
            Ok::<_, BuildError>((build, artifact_error))
        };
        tokio::pin!(remote);
        tokio::select! {
            result = &mut remote => Some(result),
            _ = interrupt_rx.recv() => None,
        }
    };

    let Some(outcome) = outcome else {
        let _ = evidence.finish("interrupted");
        eprintln!("{OUTPUT_PREFIX} interrupted; remote request disconnected");
        return ExitCode::from(130);
    };
    let (build, artifact_error) = match outcome {
        Ok(value) => value,
        Err(err) => {
            let message = err.to_string();
            let _ = evidence.error(&message);
            let _ = evidence.finish("failed");
            eprintln!("build request failed: {message}");
            return match err {
                BuildError::ConnectionFailed(_) => ExitCode::from(connection_failure_exit_code(
                    connection.map(|c| c.local_fallback).unwrap_or(false),
                )),
                BuildError::TimedOut(_) => ExitCode::from(124),
                BuildError::Other(_) => ExitCode::from(1),
            };
        }
    };
    evidence.provenance.remote_build_id = build.build_id.clone();
    evidence.provenance.remote_exit_code = Some(build.exit_code);
    evidence.provenance.timed_out = Some(build.timed_out);
    evidence.provenance.failed_phase = build.failed_phase;
    evidence.provenance.phases = build.phases.clone();
    evidence.provenance.artifact_restrictions = build.artifact_restrictions.clone();
    if let Some(restrictions) = &build.artifact_restrictions {
        let _ = write_artifact_restrictions_notice(restrictions);
    }
    if let Some(message) = artifact_error {
        let _ = evidence.error(format!("artifact retrieval failed: {message}"));
        eprintln!("failed to fetch artifacts: {message}");
        if build.exit_code == 0 {
            let _ = evidence.finish("failed");
            return ExitCode::from(1);
        }
    }
    let status = if build.exit_code == 0 && !build.timed_out {
        "succeeded"
    } else {
        "failed"
    };
    let _ = evidence.finish(status);
    to_exit_code(build.exit_code, build.timed_out)
}

async fn session_command(
    command: SessionCommands,
    prepared: PreparedSession,
    context: SessionCommandContext,
) -> ExitCode {
    let PreparedSession {
        evidence,
        source_root,
    } = prepared;
    match command {
        SessionCommands::Start(args) => {
            session_start_command(
                args,
                evidence,
                source_root.expect("start source root prepared"),
                context,
            )
            .await
        }
        SessionCommands::Action(args) => session_action_command(args, evidence, context).await,
        SessionCommands::Stop(args) => session_stop_command(args, evidence, context).await,
    }
}

async fn session_start_command(
    args: SessionStartArgs,
    mut evidence: SessionEvidence,
    source_root: PathBuf,
    context: SessionCommandContext,
) -> ExitCode {
    let SessionCommandContext {
        mut interrupt,
        endpoint_arg,
        token_file_arg,
        invocation_dir,
        filesystem_root,
        client_config,
        config_loaded,
    } = context;
    if interrupt.poll_pending().await {
        return finish_early_interrupted(&mut evidence, "interrupted before source preparation");
    }
    let connection = client_config.connection.as_ref();
    let source_patterns = match resolve_patterns(
        &client_config.sources,
        SOURCES_ENV,
        &args.source,
        SOURCES_EXCLUDE_ENV,
        &args.source_exclude,
    ) {
        Ok(patterns) => patterns,
        Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
    };
    if let Err(err) = validate_patterns(&source_patterns, "sources") {
        return finish_session_failure(&mut evidence, err.to_string(), false);
    }
    if let Some(path) = selected_token_path(token_file_arg.clone(), connection) {
        if path.exists() {
            if let Err(err) = reject_credential_overlap(&path, &source_root, &evidence.base) {
                return finish_session_failure(&mut evidence, err.to_string(), false);
            }
        }
    }
    let endpoint = match resolve_endpoint(endpoint_arg, connection, config_loaded) {
        Ok(endpoint) => endpoint,
        Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
    };
    let token = match resolve_token(token_file_arg, connection) {
        Ok(token) => token,
        Err(err) => {
            return finish_session_failure(
                &mut evidence,
                format!("failed to load bearer credential: {err}"),
                false,
            )
        }
    };
    let output_limits =
        match resolve_output_limits(client_config.output.as_ref(), &evidence.directory) {
            Ok(limits) => limits,
            Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
        };
    if interrupt.poll_pending().await {
        return finish_early_interrupted(&mut evidence, "interrupted during source preparation");
    }
    let patterns = FilesystemPatterns {
        include: source_patterns.include,
        exclude: source_patterns.exclude,
    };
    let cancellation = SourceCancellation::new();
    let packaging_cancellation = cancellation.clone();
    let packaging_invocation = invocation_dir;
    let packaging_root = filesystem_root;
    let packaging_temp = evidence.directory.clone();
    let mut packaging = tokio::task::spawn_blocking(move || {
        package_source_cancellable(
            &packaging_invocation,
            &packaging_root,
            &patterns,
            &packaging_temp,
            &packaging_cancellation,
        )
    });
    let package = tokio::select! {
        biased;
        _ = interrupt.interrupted() => {
            cancellation.cancel();
            match tokio::time::timeout(Duration::from_secs(7), &mut packaging).await {
                Ok(Ok(Err(err))) if err.kind() != io::ErrorKind::Interrupted || err.to_string().contains("cleanup") => {
                    let _ = evidence.error(format!("source cleanup after interruption failed: {err}"));
                }
                Ok(Err(err)) => { let _ = evidence.error(format!("source cleanup worker failed after interruption: {err}")); }
                Err(_) => { packaging.abort(); let _ = evidence.error("source cleanup did not finish within 7 seconds after interruption"); }
                _ => {}
            }
            return finish_early_interrupted(
                &mut evidence,
                "interrupted during source preparation",
            );
        }
        result = &mut packaging => match result {
            Ok(Ok(package)) => package,
            Ok(Err(err)) => return finish_session_failure(&mut evidence, format!("failed to package sources: {err}"), false),
            Err(err) => return finish_session_failure(&mut evidence, format!("source packaging worker failed: {err}"), false),
        },
    };
    evidence.provenance.source = Some(package.identity.clone());
    if let Err(err) = evidence.write_manifest(&package.manifest) {
        return finish_session_failure(
            &mut evidence,
            format!("failed to write source manifest: {err}"),
            false,
        );
    }
    let request = SessionStartRequest {
        schema_version: SESSION_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: args
            .request_id
            .or_else(|| Some(evidence.provenance.invocation_id.clone())),
        task: args.task,
        source: SourceMetadata {
            format: SourceFormat::Zip,
        },
    };
    if let Err(err) = evidence.set_status("running") {
        return provenance_failure(&mut evidence, err);
    }
    let (observed_sender, mut observed_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut observed_session_id = None;
    let controlled = {
        let remote = run_session_start(
            &request,
            &package.archive,
            &endpoint,
            token.as_deref(),
            &output_limits,
            observed_sender,
        );
        tokio::pin!(remote);
        loop {
            let event = tokio::select! {
                biased;
                _ = interrupt.interrupted() => Controlled::Interrupted,
                Some(session_id) = observed_receiver.recv() => {
                    if observed_session_id.is_none() {
                        observed_session_id = Some(session_id.clone());
                        match evidence.set_session_id(&session_id) {
                            Ok(()) => continue,
                            Err(err) => Controlled::Provenance(err),
                        }
                    } else {
                        continue;
                    }
                }
                result = &mut remote => Controlled::Completed(result),
            };
            break event;
        }
    };
    let outcome = match controlled {
        Controlled::Completed(outcome) => {
            while let Ok(session_id) = observed_receiver.try_recv() {
                if observed_session_id.is_none() {
                    observed_session_id = Some(session_id.clone());
                    if let Err(err) = evidence.set_session_id(&session_id) {
                        let _ = record_best_effort_stop(
                            &mut evidence,
                            &session_id,
                            &endpoint,
                            token.as_deref(),
                        )
                        .await;
                        return provenance_failure(&mut evidence, err);
                    }
                }
            }
            outcome
        }
        Controlled::Interrupted => {
            while let Ok(session_id) = observed_receiver.try_recv() {
                if observed_session_id.is_none() {
                    observed_session_id = Some(session_id.clone());
                    let _ = evidence.set_session_id(&session_id);
                }
            }
            if let Some(session_id) = observed_session_id.as_deref() {
                return finish_interrupted_session(
                    &mut evidence,
                    session_id,
                    &endpoint,
                    token.as_deref(),
                    "interrupted during session initialization",
                )
                .await;
            }
            return finish_early_interrupted(
                &mut evidence,
                "interrupted; remote request disconnected",
            );
        }
        Controlled::Provenance(err) => {
            if let Some(session_id) = observed_session_id.as_deref() {
                let _ =
                    record_best_effort_stop(&mut evidence, session_id, &endpoint, token.as_deref())
                        .await;
            }
            return provenance_failure(&mut evidence, err);
        }
    };
    match outcome {
        Ok(result) => {
            evidence.provenance.remote_exit_code = Some(result.exit_code);
            evidence.provenance.timed_out = Some(result.timed_out);
            evidence.provenance.phases = result.phases;
            for error in result.errors {
                let _ = evidence.error(error);
            }
            if let Some(session_id) = result.session_id {
                if observed_session_id.as_deref() != Some(session_id.as_str()) {
                    let message = "Ready session identity was not durably observed".to_string();
                    let _ = record_best_effort_stop(
                        &mut evidence,
                        &session_id,
                        &endpoint,
                        token.as_deref(),
                    )
                    .await;
                    return finish_session_failure(&mut evidence, message, false);
                }
                if interrupt.poll_pending().await {
                    return finish_interrupted_session(
                        &mut evidence,
                        &session_id,
                        &endpoint,
                        token.as_deref(),
                        "interrupted before final Ready provenance",
                    )
                    .await;
                }
                match finish_evidence_controlled(evidence, "ready", &mut interrupt).await {
                    ControlledEvidence::Interrupted(returned) => {
                        evidence = returned;
                        return finish_interrupted_session(
                            &mut evidence,
                            &session_id,
                            &endpoint,
                            token.as_deref(),
                            "interrupted during final Ready provenance",
                        )
                        .await;
                    }
                    ControlledEvidence::Completed(returned, result) => {
                        evidence = returned;
                        if let Err(err) = result {
                            let _ = record_best_effort_stop(
                                &mut evidence,
                                &session_id,
                                &endpoint,
                                token.as_deref(),
                            )
                            .await;
                            return provenance_failure(&mut evidence, err);
                        }
                    }
                }
                if interrupt.poll_pending().await {
                    return finish_interrupted_session(
                        &mut evidence,
                        &session_id,
                        &endpoint,
                        token.as_deref(),
                        "interrupted before session ID output",
                    )
                    .await;
                }
                match emit_session_id_controlled(&session_id, &mut interrupt).await {
                    ControlledIo::Interrupted => {
                        return finish_interrupted_session(
                            &mut evidence,
                            &session_id,
                            &endpoint,
                            token.as_deref(),
                            "interrupted during session ID output",
                        )
                        .await;
                    }
                    ControlledIo::Completed(Ok(())) => {}
                    ControlledIo::Completed(Err(err)) => {
                        let _ = record_best_effort_stop(
                            &mut evidence,
                            &session_id,
                            &endpoint,
                            token.as_deref(),
                        )
                        .await;
                        return finish_session_failure(
                            &mut evidence,
                            format!("failed to emit session ID: {err}"),
                            false,
                        );
                    }
                }
                evidence_exit(&evidence, 0)
            } else {
                if let Some(session_id) = observed_session_id.as_deref() {
                    let _ = record_best_effort_stop(
                        &mut evidence,
                        session_id,
                        &endpoint,
                        token.as_deref(),
                    )
                    .await;
                }
                if let Err(err) = evidence.finish("failed") {
                    return provenance_failure(&mut evidence, err);
                }
                evidence_exit(
                    &evidence,
                    normalize_requested_exit(result.exit_code, result.timed_out),
                )
            }
        }
        Err(err) => {
            if let Some(session_id) = observed_session_id.as_deref() {
                let _ =
                    record_best_effort_stop(&mut evidence, session_id, &endpoint, token.as_deref())
                        .await;
            }
            finish_remote_session_error(&mut evidence, err, connection)
        }
    }
}

async fn session_action_command(
    args: SessionActionArgs,
    mut evidence: SessionEvidence,
    context: SessionCommandContext,
) -> ExitCode {
    let SessionCommandContext {
        mut interrupt,
        endpoint_arg,
        token_file_arg,
        client_config,
        config_loaded,
        ..
    } = context;
    if interrupt.poll_pending().await {
        return finish_early_interrupted(&mut evidence, "interrupted before action preparation");
    }
    if !valid_session_id(&args.session) {
        return finish_session_failure(&mut evidence, "invalid session ID".to_string(), false);
    }
    if !valid_task_id(&args.action) {
        return finish_session_failure(&mut evidence, "invalid action name".to_string(), false);
    }
    let connection = client_config.connection.as_ref();
    if let Some(path) = selected_token_path(token_file_arg.clone(), connection) {
        if path.exists() {
            if let Err(err) = reject_credential_result_overlap(&path, &evidence.base) {
                return finish_session_failure(&mut evidence, err.to_string(), false);
            }
        }
    }
    let endpoint = match resolve_endpoint(endpoint_arg, connection, config_loaded) {
        Ok(endpoint) => endpoint,
        Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
    };
    let token = match resolve_token(token_file_arg, connection) {
        Ok(token) => token,
        Err(err) => {
            return finish_session_failure(
                &mut evidence,
                format!("failed to load bearer credential: {err}"),
                false,
            )
        }
    };
    let output_limits =
        match resolve_output_limits(client_config.output.as_ref(), &evidence.directory) {
            Ok(limits) => limits,
            Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
        };
    if let Err(err) = evidence.set_status("reading_input") {
        return provenance_failure(&mut evidence, err);
    }
    let body = match read_action_input(&args.input, &mut interrupt).await {
        Ok(Some(body)) => body,
        Ok(None) => {
            return finish_interrupted_session(
                &mut evidence,
                &args.session,
                &endpoint,
                token.as_deref(),
                "interrupted while reading action input",
            )
            .await
        }
        Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
    };
    if let Err(err) = evidence.set_status("running") {
        return provenance_failure(&mut evidence, err);
    }
    let (observed_sender, mut observed_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut observed_action_id = None;
    let controlled = {
        let remote = run_session_action(
            &args.session,
            &args.action,
            body,
            &endpoint,
            token.as_deref(),
            &output_limits,
            observed_sender,
        );
        tokio::pin!(remote);
        loop {
            let event = tokio::select! {
                biased;
                _ = interrupt.interrupted() => Controlled::Interrupted,
                Some(action_id) = observed_receiver.recv() => {
                    if observed_action_id.is_none() {
                        observed_action_id = Some(action_id.clone());
                        match evidence.set_action_id(&action_id) {
                            Ok(()) => continue,
                            Err(err) => Controlled::Provenance(err),
                        }
                    } else {
                        continue;
                    }
                }
                result = &mut remote => Controlled::Completed(result),
            };
            break event;
        }
    };
    let outcome = match controlled {
        Controlled::Completed(outcome) => {
            while let Ok(action_id) = observed_receiver.try_recv() {
                if observed_action_id.is_none() {
                    observed_action_id = Some(action_id.clone());
                    if let Err(err) = evidence.set_action_id(&action_id) {
                        let _ = record_best_effort_stop(
                            &mut evidence,
                            &args.session,
                            &endpoint,
                            token.as_deref(),
                        )
                        .await;
                        return provenance_failure(&mut evidence, err);
                    }
                }
            }
            outcome
        }
        Controlled::Interrupted => {
            while let Ok(action_id) = observed_receiver.try_recv() {
                if observed_action_id.is_none() {
                    observed_action_id = Some(action_id.clone());
                    let _ = evidence.set_action_id(&action_id);
                }
            }
            return finish_interrupted_session(
                &mut evidence,
                &args.session,
                &endpoint,
                token.as_deref(),
                "interrupted during action execution",
            )
            .await;
        }
        Controlled::Provenance(err) => {
            let _ =
                record_best_effort_stop(&mut evidence, &args.session, &endpoint, token.as_deref())
                    .await;
            return provenance_failure(&mut evidence, err);
        }
    };
    let result = match outcome {
        Ok(result) => result,
        Err(err) => return finish_remote_session_error(&mut evidence, err, connection),
    };
    if observed_action_id.as_deref() != Some(result.action_id.as_str()) {
        return finish_session_failure(
            &mut evidence,
            "action result identity was not durably observed".to_string(),
            false,
        );
    }
    evidence.provenance.remote_exit_code = Some(result.exit_code);
    evidence.provenance.timed_out = Some(result.timed_out);
    evidence.provenance.artifact_restrictions = result.artifact_restrictions.clone();
    for error in &result.errors {
        let _ = evidence.error(error.clone());
    }
    if let Some(restrictions) = &result.artifact_restrictions {
        let _ = write_artifact_restrictions_notice(restrictions);
    }
    let artifact_error = if let Some(archive) = &result.artifacts {
        let evidence_directory = evidence.directory.clone();
        let downloaded = {
            let download =
                download_and_extract(archive, &endpoint, token.as_deref(), &evidence_directory);
            tokio::pin!(download);
            tokio::select! {
                biased;
                _ = interrupt.interrupted() => None,
                result = &mut download => Some(result),
            }
        };
        let Some(downloaded) = downloaded else {
            return finish_interrupted_session(
                &mut evidence,
                &args.session,
                &endpoint,
                token.as_deref(),
                "interrupted while downloading action artifacts",
            )
            .await;
        };
        downloaded.err().map(|err| err.to_string())
    } else {
        None
    };
    let artifact_failed_success = artifact_error.is_some() && result.exit_code == 0;
    if let Some(message) = artifact_error {
        let _ = evidence.error(format!("artifact retrieval failed: {message}"));
        eprintln!("failed to fetch action artifacts: {message}");
    }
    if interrupt.poll_pending().await {
        return finish_interrupted_session(
            &mut evidence,
            &args.session,
            &endpoint,
            token.as_deref(),
            "interrupted before final action provenance",
        )
        .await;
    }
    let status = if artifact_failed_success || result.exit_code != 0 || result.timed_out {
        "failed"
    } else {
        "succeeded"
    };
    match finish_evidence_controlled(evidence, status, &mut interrupt).await {
        ControlledEvidence::Interrupted(returned) => {
            evidence = returned;
            return finish_interrupted_session(
                &mut evidence,
                &args.session,
                &endpoint,
                token.as_deref(),
                "interrupted during final action provenance",
            )
            .await;
        }
        ControlledEvidence::Completed(returned, result) => {
            evidence = returned;
            if let Err(err) = result {
                let _ = record_best_effort_stop(
                    &mut evidence,
                    &args.session,
                    &endpoint,
                    token.as_deref(),
                )
                .await;
                return provenance_failure(&mut evidence, err);
            }
        }
    }
    if !interrupt.claim_completion().await {
        return finish_interrupted_session(
            &mut evidence,
            &args.session,
            &endpoint,
            token.as_deref(),
            "interrupted at action completion",
        )
        .await;
    }
    let requested = if artifact_failed_success {
        1
    } else {
        normalize_requested_exit(result.exit_code, result.timed_out)
    };
    evidence_exit(&evidence, requested)
}

async fn session_stop_command(
    args: SessionStopArgs,
    mut evidence: SessionEvidence,
    context: SessionCommandContext,
) -> ExitCode {
    let SessionCommandContext {
        mut interrupt,
        endpoint_arg,
        token_file_arg,
        client_config,
        config_loaded,
        ..
    } = context;
    if interrupt.poll_pending().await {
        return finish_early_interrupted(&mut evidence, "interrupted before stop preparation");
    }
    if !valid_session_id(&args.session) {
        return finish_session_failure(&mut evidence, "invalid session ID".to_string(), false);
    }
    let connection = client_config.connection.as_ref();
    if let Some(path) = selected_token_path(token_file_arg.clone(), connection) {
        if path.exists() {
            if let Err(err) = reject_credential_result_overlap(&path, &evidence.base) {
                return finish_session_failure(&mut evidence, err.to_string(), false);
            }
        }
    }
    let endpoint = match resolve_endpoint(endpoint_arg, connection, config_loaded) {
        Ok(endpoint) => endpoint,
        Err(err) => return finish_session_failure(&mut evidence, err.to_string(), false),
    };
    let token = match resolve_token(token_file_arg, connection) {
        Ok(token) => token,
        Err(err) => {
            return finish_session_failure(
                &mut evidence,
                format!("failed to load bearer credential: {err}"),
                false,
            )
        }
    };
    if let Err(err) = evidence.set_status("running") {
        return provenance_failure(&mut evidence, err);
    }
    let stopped = {
        let request = request_session_stop(&args.session, &endpoint, token.as_deref());
        tokio::pin!(request);
        tokio::select! {
            biased;
            _ = interrupt.interrupted() => None,
            response = &mut request => Some(response),
        }
    };
    let Some(stopped) = stopped else {
        return finish_interrupted_session(
            &mut evidence,
            &args.session,
            &endpoint,
            token.as_deref(),
            "interrupted during session stop",
        )
        .await;
    };
    let response = match stopped {
        Ok(response) => response,
        Err(err) => return finish_remote_session_error(&mut evidence, err, connection),
    };
    if response.session_id != args.session {
        return finish_session_failure(
            &mut evidence,
            "stop response had inconsistent session identity".to_string(),
            false,
        );
    }
    evidence.provenance.teardown = Some(response.teardown.clone());
    evidence.provenance.artifact_restrictions = response.artifact_restrictions.clone();
    if let Some(restrictions) = &response.artifact_restrictions {
        let _ = write_artifact_restrictions_notice(restrictions);
    }
    let artifact_error = if let Some(archive) = &response.artifacts {
        let evidence_directory = evidence.directory.clone();
        let downloaded = {
            let download =
                download_and_extract(archive, &endpoint, token.as_deref(), &evidence_directory);
            tokio::pin!(download);
            tokio::select! {
                biased;
                _ = interrupt.interrupted() => None,
                result = &mut download => Some(result),
            }
        };
        let Some(downloaded) = downloaded else {
            return finish_interrupted_session(
                &mut evidence,
                &args.session,
                &endpoint,
                token.as_deref(),
                "interrupted while downloading final artifacts",
            )
            .await;
        };
        downloaded.err().map(|err| err.to_string())
    } else {
        None
    };
    let code = response.teardown.exit_code.unwrap_or(1);
    evidence.provenance.remote_exit_code = response.teardown.exit_code;
    evidence.provenance.timed_out = Some(response.teardown.timed_out);
    let artifact_failed_success = artifact_error.is_some()
        && code == 0
        && !response.teardown.timed_out
        && response.teardown.error_code.is_none();
    if let Some(message) = artifact_error {
        let _ = evidence.error(format!("artifact retrieval failed: {message}"));
        eprintln!("failed to fetch final artifacts: {message}");
    }
    if let Some(error_code) = &response.teardown.error_code {
        let message = format!("teardown failed: {error_code}");
        let _ = evidence.error(&message);
        eprintln!("{message}");
    }
    eprintln!(
        "{OUTPUT_PREFIX} teardown finished in {:.3}s (exit_code={}, timed_out={})",
        response.teardown.duration_ms as f64 / 1000.0,
        response
            .teardown
            .exit_code
            .map_or_else(|| "none".to_string(), |code| code.to_string()),
        response.teardown.timed_out
    );
    let succeeded = code == 0
        && !response.teardown.timed_out
        && response.teardown.error_code.is_none()
        && !artifact_failed_success;
    if interrupt.poll_pending().await {
        return finish_interrupted_session(
            &mut evidence,
            &args.session,
            &endpoint,
            token.as_deref(),
            "interrupted before final stop provenance",
        )
        .await;
    }
    let status = if succeeded { "succeeded" } else { "failed" };
    match finish_evidence_controlled(evidence, status, &mut interrupt).await {
        ControlledEvidence::Interrupted(returned) => {
            evidence = returned;
            return finish_interrupted_session(
                &mut evidence,
                &args.session,
                &endpoint,
                token.as_deref(),
                "interrupted during final stop provenance",
            )
            .await;
        }
        ControlledEvidence::Completed(returned, result) => {
            evidence = returned;
            if let Err(err) = result {
                return provenance_failure(&mut evidence, err);
            }
        }
    }
    if !interrupt.claim_completion().await {
        return finish_interrupted_session(
            &mut evidence,
            &args.session,
            &endpoint,
            token.as_deref(),
            "interrupted at stop completion",
        )
        .await;
    }
    let requested = if response.teardown.error_code.is_some() || artifact_failed_success {
        1
    } else {
        normalize_requested_exit(code, response.teardown.timed_out)
    };
    evidence_exit(&evidence, requested)
}

async fn finish_session_failure_elected(
    evidence: SessionEvidence,
    message: String,
    connection_failure: bool,
    interrupt: &mut InterruptControl,
) -> ExitCode {
    let mut finalizing = tokio::task::spawn_blocking(move || {
        let mut evidence = evidence;
        let exit = finish_session_failure(&mut evidence, message, connection_failure);
        (evidence, exit)
    });
    tokio::select! {
        biased;
        _ = interrupt.interrupted() => match finalizing.await {
            Ok((mut evidence, _)) => finish_early_interrupted(
                &mut evidence,
                "interrupted while finalizing session failure",
            ),
            Err(err) => {
                eprintln!("session failure provenance worker failed: {err}");
                ExitCode::from(1)
            }
        },
        result = &mut finalizing => match result {
            Ok((_, exit)) => exit,
            Err(err) => {
                eprintln!("session failure provenance worker failed: {err}");
                ExitCode::from(1)
            }
        },
    }
}

fn finish_session_failure(
    evidence: &mut SessionEvidence,
    message: String,
    connection_failure: bool,
) -> ExitCode {
    let _ = evidence.error(&message);
    let _ = evidence.finish("failed");
    eprintln!("{message}");
    let code = if connection_failure {
        CONNECTION_FALLBACK_EXIT_CODE
    } else {
        1
    };
    evidence_exit(evidence, code)
}

fn evidence_exit(evidence: &SessionEvidence, requested: u8) -> ExitCode {
    if let Some(message) = &evidence.persistence_failure {
        eprintln!("{OUTPUT_PREFIX} {message}");
        ExitCode::from(1)
    } else {
        ExitCode::from(requested)
    }
}

fn provenance_failure(evidence: &mut SessionEvidence, err: io::Error) -> ExitCode {
    evidence
        .persistence_failure
        .get_or_insert_with(|| format!("provenance persistence failed: {err}"));
    evidence_exit(evidence, 1)
}

enum ControlledEvidence {
    Completed(SessionEvidence, io::Result<()>),
    Interrupted(SessionEvidence),
}

async fn finish_evidence_controlled(
    evidence: SessionEvidence,
    status: &str,
    interrupt: &mut InterruptControl,
) -> ControlledEvidence {
    let status = status.to_string();
    let mut writing = tokio::task::spawn_blocking(move || {
        let mut evidence = evidence;
        let result = evidence.finish(&status);
        (evidence, result)
    });
    tokio::select! {
        biased;
        _ = interrupt.interrupted() => {
            match writing.await {
                Ok((evidence, _)) => ControlledEvidence::Interrupted(evidence),
                Err(err) => panic!("final provenance worker failed: {err}"),
            }
        },
        result = &mut writing => match result {
            Ok((evidence, result)) => ControlledEvidence::Completed(evidence, result),
            Err(err) => panic!("final provenance worker failed: {err}"),
        },
    }
}

enum ControlledIo {
    Completed(io::Result<()>),
    Interrupted,
}

struct NonblockingStdout {
    file: fs::File,
    original_flags: i32,
}

impl NonblockingStdout {
    fn open() -> io::Result<Self> {
        let descriptor = unsafe { libc::dup(libc::STDOUT_FILENO) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { fs::File::from_raw_fd(descriptor) };
        let original_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if original_flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(descriptor, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            original_flags,
        })
    }

    fn is_writable(&self) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if result >= 0 {
                return Ok(result == 1);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    fn write_atomic(&self, bytes: &[u8]) -> io::Result<()> {
        let written = unsafe {
            libc::write(
                self.as_raw_fd(),
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
            )
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial session ID output",
            ));
        }
        Ok(())
    }
}

impl AsRawFd for NonblockingStdout {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for NonblockingStdout {
    fn drop(&mut self) {
        let _ = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, self.original_flags) };
    }
}

async fn emit_session_id_controlled(
    session_id: &str,
    interrupt: &mut InterruptControl,
) -> ControlledIo {
    let output = match NonblockingStdout::open() {
        Ok(output) => output,
        Err(err) => return ControlledIo::Completed(Err(err)),
    };
    let mut bytes = session_id.as_bytes().to_vec();
    bytes.push(b'\n');
    if interrupt.poll_pending().await {
        return ControlledIo::Interrupted;
    }
    match output.is_writable() {
        Ok(true) => {
            if !interrupt.claim_completion().await {
                return ControlledIo::Interrupted;
            }
            return ControlledIo::Completed(output.write_atomic(&bytes));
        }
        Ok(false) => {}
        Err(err) => return ControlledIo::Completed(Err(err)),
    }
    let output = match tokio::io::unix::AsyncFd::new(output) {
        Ok(output) => output,
        Err(err) => {
            if interrupt.poll_pending().await {
                return ControlledIo::Interrupted;
            }
            return ControlledIo::Completed(Err(err));
        }
    };
    loop {
        if interrupt.poll_pending().await {
            return ControlledIo::Interrupted;
        }
        match output.get_ref().is_writable() {
            Ok(true) => {
                if !interrupt.claim_completion().await {
                    return ControlledIo::Interrupted;
                }
                return ControlledIo::Completed(output.get_ref().write_atomic(&bytes));
            }
            Ok(false) => {}
            Err(err) => return ControlledIo::Completed(Err(err)),
        }
        let readiness = tokio::select! {
            biased;
            _ = interrupt.interrupted() => return ControlledIo::Interrupted,
            readiness = output.writable() => readiness,
        };
        match readiness {
            Ok(mut readiness) => readiness.clear_ready(),
            Err(err) => return ControlledIo::Completed(Err(err)),
        }
    }
}

fn finish_early_interrupted(evidence: &mut SessionEvidence, message: &str) -> ExitCode {
    if evidence.provenance.operation == "start" && evidence.provenance.session_id.is_none() {
        let _ = evidence.set_cleanup_status("not attempted: session ID unavailable".to_string());
    }
    let _ = evidence.error(message.to_string());
    let _ = evidence.finish("interrupted");
    eprintln!("{OUTPUT_PREFIX} {message}");
    evidence_exit(evidence, 130)
}

async fn record_best_effort_stop(
    evidence: &mut SessionEvidence,
    session_id: &str,
    endpoint: &Endpoint,
    token: Option<&str>,
) -> String {
    let cleanup = best_effort_stop(session_id, endpoint, token).await;
    let _ = evidence.set_cleanup_status(cleanup.clone());
    if cleanup.starts_with("failed:") {
        let _ = evidence.error(format!("best-effort stop {cleanup}"));
    }
    cleanup
}

async fn finish_interrupted_session(
    evidence: &mut SessionEvidence,
    session_id: &str,
    endpoint: &Endpoint,
    token: Option<&str>,
    message: &str,
) -> ExitCode {
    let cleanup = record_best_effort_stop(evidence, session_id, endpoint, token).await;
    let _ = evidence.finish("interrupted");
    eprintln!("{OUTPUT_PREFIX} {message}; best-effort stop: {cleanup}");
    evidence_exit(evidence, 130)
}

fn finish_remote_session_error(
    evidence: &mut SessionEvidence,
    err: BuildError,
    connection: Option<&ConnectionConfig>,
) -> ExitCode {
    let message = err.to_string();
    if matches!(&err, BuildError::TimedOut(_)) {
        evidence.provenance.timed_out = Some(true);
    }
    let _ = evidence.error(&message);
    let _ = evidence.finish("failed");
    eprintln!("session request failed: {message}");
    let code = match err {
        BuildError::ConnectionFailed(_) => connection_failure_exit_code(
            connection
                .map(|config| config.local_fallback)
                .unwrap_or(false),
        ),
        BuildError::TimedOut(_) => 124,
        BuildError::Other(_) => 1,
    };
    evidence_exit(evidence, code)
}

fn find_client_config_path(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(CLIENT_CONFIG_DIR).join(CLIENT_CONFIG_FILE);
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }

    None
}

fn load_client_config(path: Option<&Path>) -> io::Result<ClientConfig> {
    let Some(path) = path else {
        return Ok(ClientConfig::default());
    };

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client configuration must be a regular file",
        ));
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    toml::from_str(&raw).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn resolve_patterns(
    config: &PatternConfig,
    include_env: &str,
    include_args: &[String],
    exclude_env: &str,
    exclude_args: &[String],
) -> io::Result<PatternConfig> {
    Ok(PatternConfig {
        include: merge_pattern_values(&config.include, include_env, include_args)?,
        exclude: merge_pattern_values(&config.exclude, exclude_env, exclude_args)?,
    })
}

fn merge_pattern_values(
    config_values: &[String],
    env_name: &str,
    cli_values: &[String],
) -> io::Result<Vec<String>> {
    let mut values = config_values.to_vec();
    values.extend(parse_csv_env_values(env_name)?);
    values.extend(
        cli_values
            .iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    );
    Ok(values)
}

fn parse_csv_env_values(name: &str) -> io::Result<Vec<String>> {
    let raw = match env::var(name) {
        Ok(raw) => raw,
        Err(_) => return Ok(Vec::new()),
    };

    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn validate_patterns(patterns: &PatternConfig, label: &str) -> io::Result<()> {
    for pattern in &patterns.include {
        let field = format!("{label}.include");
        validate_relative_pattern(pattern, &field)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    }
    for pattern in &patterns.exclude {
        let field = format!("{label}.exclude");
        validate_relative_pattern(pattern, &field)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    }
    Ok(())
}

fn parse_endpoint(raw: &str) -> io::Result<Endpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "endpoint must not be empty",
        ));
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let scheme_pos = trimmed.find("://").unwrap_or(0);
        let after_scheme = &trimmed[scheme_pos + 3..];
        if after_scheme.is_empty() || after_scheme.chars().all(|c| c == '/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "http endpoint must include a host",
            ));
        }
        let base = trimmed.trim_end_matches('/').to_string();
        return Ok(Endpoint::Http { base });
    }

    if let Some(path_str) = trimmed.strip_prefix("unix://") {
        if path_str.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unix endpoint must include an absolute path",
            ));
        }
        let path = PathBuf::from(path_str);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unix endpoint path must be absolute",
            ));
        }
        return Ok(Endpoint::Unix { path });
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "endpoint must start with http://, https://, or unix://",
    ))
}

fn resolve_endpoint(
    explicit: Option<String>,
    config: Option<&ConnectionConfig>,
    config_loaded: bool,
) -> io::Result<Endpoint> {
    if let Some(endpoint) = explicit {
        if !endpoint.trim().is_empty() {
            return parse_endpoint(&endpoint);
        }
    }

    if let Ok(env_endpoint) = env::var(ENDPOINT_ENV) {
        if !env_endpoint.trim().is_empty() {
            return parse_endpoint(&env_endpoint);
        }
    }

    if let Some(connection) = config {
        if let Some(endpoint) = &connection.endpoint {
            if !endpoint.trim().is_empty() {
                return parse_endpoint(endpoint);
            }
        }
    }

    if config_loaded {
        let default_endpoint = format!("unix://{DEFAULT_SOCKET_PATH}");
        return parse_endpoint(&default_endpoint);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "endpoint must be provided via --endpoint, INDENTURED_SERVER_ENDPOINT, or client config",
    ))
}

fn selected_token_path(
    explicit: Option<PathBuf>,
    config: Option<&ConnectionConfig>,
) -> Option<PathBuf> {
    explicit
        .or_else(|| env::var_os(TOKEN_FILE_ENV).map(PathBuf::from))
        .or_else(|| config.and_then(|connection| connection.token_file.clone()))
}

fn resolve_token(
    explicit: Option<PathBuf>,
    config: Option<&ConnectionConfig>,
) -> io::Result<Option<String>> {
    let path = selected_token_path(explicit, config);
    let Some(path) = path else {
        return Ok(None);
    };
    let runtime_path = path.is_absolute()
        && (path.starts_with("/run")
            || path.starts_with("/var/run")
            || path.starts_with("/private/var/run"));
    if !runtime_path || path.starts_with("/nix/store") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential path must be an absolute runtime path outside the Nix store",
        ));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential file must be regular with no group/other permissions",
        ));
    }
    let mut raw =
        Vec::with_capacity((metadata.len() as usize).min(MAX_BEARER_TOKEN_FILE_BYTES + 1));
    std::io::Read::by_ref(&mut file)
        .take((MAX_BEARER_TOKEN_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_BEARER_TOKEN_FILE_BYTES {
        raw.fill(0);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential file exceeds 4096 bytes",
        ));
    }
    let token = match BearerToken::parse_file(&raw) {
        Ok(token) => token.as_str().to_owned(),
        Err(err) => {
            raw.fill(0);
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }
    };
    raw.fill(0);
    Ok(Some(token))
}

fn resolve_connection_enabled(config: Option<&ConnectionConfig>) -> bool {
    if let Ok(raw) = env::var(ENABLED_ENV) {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();
        let disabled = matches!(lower.as_str(), "" | "0" | "false" | "no" | "off");
        return !disabled;
    }

    config.map(|connection| connection.enabled).unwrap_or(true)
}

enum Controlled<T> {
    Completed(T),
    Interrupted,
    Provenance(io::Error),
}

struct SessionStartResult {
    session_id: Option<String>,
    exit_code: i32,
    timed_out: bool,
    phases: Vec<PhaseResult>,
    errors: Vec<String>,
}

struct SessionActionResult {
    action_id: String,
    exit_code: i32,
    timed_out: bool,
    artifacts: Option<ArtifactArchive>,
    artifact_restrictions: Option<ArtifactRestrictions>,
    errors: Vec<String>,
}

async fn read_action_input(
    path: &str,
    interrupt: &mut InterruptControl,
) -> io::Result<Option<Vec<u8>>> {
    let read = async {
        let bytes = if path == "-" {
            let file = duplicate_nonblocking_stdin()?;
            if file.metadata()?.file_type().is_file() {
                let mut bytes = Vec::new();
                let mut file = tokio::fs::File::from_std(file)
                    .take((MAX_SESSION_ACTION_BODY_BYTES + 1) as u64);
                file.read_to_end(&mut bytes).await?;
                bytes
            } else {
                read_nonblocking_descriptor(file, false).await?
            }
        } else {
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            if file.metadata()?.file_type().is_fifo() {
                read_nonblocking_descriptor(file, true).await?
            } else {
                let mut bytes = Vec::new();
                let mut file = tokio::fs::File::from_std(file)
                    .take((MAX_SESSION_ACTION_BODY_BYTES + 1) as u64);
                file.read_to_end(&mut bytes).await?;
                bytes
            }
        };
        encode_action_input(&bytes).map(Some)
    };
    tokio::pin!(read);
    tokio::select! {
        biased;
        _ = interrupt.interrupted() => Ok(None),
        result = &mut read => result,
    }
}

fn duplicate_nonblocking_stdin() -> io::Result<fs::File> {
    let descriptor = unsafe { libc::fcntl(io::stdin().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

async fn read_nonblocking_descriptor(
    file: fs::File,
    wait_on_initial_eof: bool,
) -> io::Result<Vec<u8>> {
    let descriptor = tokio::io::unix::AsyncFd::new(file)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let mut ready = descriptor.readable().await?;
        match ready.try_io(|inner| {
            let mut file = inner.get_ref();
            file.read(&mut chunk)
        }) {
            Ok(Ok(0)) if wait_on_initial_eof && bytes.is_empty() => {
                drop(ready);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() > MAX_SESSION_ACTION_BODY_BYTES {
                    break;
                }
            }
            Ok(Err(err)) => return Err(err),
            Err(_) => continue,
        }
    }
    Ok(bytes)
}

fn encode_action_input(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() > MAX_SESSION_ACTION_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("action input exceeds {MAX_SESSION_ACTION_BODY_BYTES} bytes"),
        ));
    }
    let input: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid action input JSON: {err}"),
        )
    })?;
    let input = input.as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "action input must be a JSON object",
        )
    })?;
    let request = SessionActionRequest {
        schema_version: SESSION_REQUEST_SCHEMA_VERSION.to_string(),
        input: input.clone(),
    };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    if body.len() > MAX_SESSION_ACTION_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("encoded action request exceeds {MAX_SESSION_ACTION_BODY_BYTES} bytes"),
        ));
    }
    Ok(body)
}

fn session_http_client(
    endpoint: &Endpoint,
    path: &str,
) -> Result<(Client, String, bool), BuildError> {
    match endpoint {
        Endpoint::Http { base } => Ok((
            Client::builder()
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?,
            format!("{base}{path}"),
            true,
        )),
        Endpoint::Unix { path: socket } => Ok((
            Client::builder()
                .unix_socket(socket.clone())
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?,
            format!("http://localhost{path}"),
            false,
        )),
    }
}

async fn session_http_error(response: reqwest::Response, operation: &str) -> BuildError {
    let status = response.status();
    let mut body = response.text().await.unwrap_or_default();
    truncate_utf8(&mut body, 4096);
    let detail = match status.as_u16() {
        401 | 403 => "authentication failed; verify the existing bearer credential".to_string(),
        404 if operation == "start" => {
            "server does not support managed sessions; upgrade indentured-server".to_string()
        }
        404 => "session is missing or expired".to_string(),
        408 => format!("{operation} timed out"),
        409 => {
            "session is busy or terminating; retry after the active operation completes".to_string()
        }
        503 if body.contains("busy") => {
            "server capacity is busy; stop an existing session or retry later".to_string()
        }
        503 => "managed sessions are unavailable on this server".to_string(),
        _ => format!("server returned {status}"),
    };
    let message = if body.is_empty() {
        detail
    } else {
        format!("{detail}: {body}")
    };
    if status.as_u16() == 408 {
        BuildError::TimedOut(message)
    } else {
        BuildError::Other(message)
    }
}

async fn run_session_start(
    request: &SessionStartRequest,
    source_archive: &NamedTempFile,
    endpoint: &Endpoint,
    token: Option<&str>,
    output_limits: &OutputLimits,
    observed_id: tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<SessionStartResult, BuildError> {
    let (client, url, send_auth) = session_http_client(endpoint, "/v1/sessions")?;
    let metadata = serde_json::to_string(request)
        .map_err(|err| BuildError::Other(format!("failed to serialize request: {err}")))?;
    let length = source_archive
        .as_file()
        .metadata()
        .map_err(|err| BuildError::Other(format!("failed to inspect source archive: {err}")))?
        .len();
    let file = tokio::fs::File::open(source_archive.path())
        .await
        .map_err(|err| BuildError::Other(format!("failed to read source archive: {err}")))?;
    let source =
        Part::stream_with_length(reqwest::Body::wrap_stream(ReaderStream::new(file)), length)
            .file_name("source.zip")
            .mime_str("application/zip")
            .expect("static MIME type");
    let form = Form::new()
        .part(
            "metadata",
            Part::text(metadata)
                .mime_str("application/json")
                .expect("static MIME type"),
        )
        .part("source", source);
    let mut builder = client.post(url).multipart(form);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }
    let response = match builder.send().await {
        Ok(response) => response,
        Err(err) if is_connection_failure(&err) => {
            return Err(BuildError::ConnectionFailed(format!(
                "cannot reach endpoint: {err}"
            )))
        }
        Err(err) => return Err(BuildError::Other(format!("session start failed: {err}"))),
    };
    if !response.status().is_success() {
        return Err(session_http_error(response, "start").await);
    }
    read_session_start_response(response, output_limits, observed_id).await
}

async fn read_session_start_response(
    mut response: reqwest::Response,
    output_limits: &OutputLimits,
    observed_id: tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<SessionStartResult, BuildError> {
    let mut pending = Vec::new();
    let mut output = OutputLimiter::new(output_limits);
    let mut logs = LogCaptureState::new(output_limits);
    let paths = logs
        .initialize("session")
        .map_err(|err| BuildError::Other(format!("failed to initialize result logs: {err}")))?
        .ok_or_else(|| BuildError::Other("result logs were not configured".to_string()))?;
    output.set_log_paths(&paths);
    let mut started_id: Option<String> = None;
    let mut stream_errors = Vec::new();
    let mut result = None;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| BuildError::Other(format!("failed to read session start response: {err}")))?
    {
        pending.extend_from_slice(&chunk);
        if pending.len() > 1024 * 1024 {
            return Err(BuildError::Other(
                "response line exceeded 1 MiB".to_string(),
            ));
        }
        while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=position).collect();
            let line = std::str::from_utf8(&line[..line.len() - 1])
                .map_err(|_| BuildError::Other("response was not UTF-8".to_string()))?
                .trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if result.is_some() {
                return Err(BuildError::Other(
                    "session start response contained an event after its final event".to_string(),
                ));
            }
            let event: SessionStartEvent = serde_json::from_str(line)
                .map_err(|err| BuildError::Other(format!("invalid session response: {err}")))?;
            match event {
                SessionStartEvent::Session {
                    id,
                    status,
                    phase,
                    duration_ms,
                    exit_code,
                    timed_out,
                } => {
                    if !valid_session_id(&id) {
                        return Err(BuildError::Other(
                            "server returned an invalid session ID".to_string(),
                        ));
                    }
                    if let Some(existing) = &started_id {
                        if existing != &id {
                            return Err(BuildError::Other(
                                "session identity changed during initialization".to_string(),
                            ));
                        }
                    } else {
                        started_id = Some(id.clone());
                        let _ = observed_id.send(id.clone());
                    }
                    match status {
                        SessionStartStatus::Started => {
                            eprintln!("{OUTPUT_PREFIX} session {id} started")
                        }
                        SessionStartStatus::PhaseStarted => {
                            if let Some(phase) = phase {
                                eprintln!("{OUTPUT_PREFIX} {} phase started", phase.as_str());
                            }
                        }
                        SessionStartStatus::PhaseFinished => {
                            if let (Some(phase), Some(duration), Some(code), Some(timeout)) =
                                (phase, duration_ms, exit_code, timed_out)
                            {
                                eprintln!(
                                    "{OUTPUT_PREFIX} {} phase finished in {:.3}s (exit_code={code}, timed_out={timeout})",
                                    phase.as_str(),
                                    duration as f64 / 1000.0
                                );
                            }
                        }
                    }
                }
                SessionStartEvent::Stdout { data } => logs
                    .process_event_routed(BufferedStreamEvent::Stdout(data), &mut output, true)
                    .map_err(|err| BuildError::Other(format!("failed to write stdout: {err}")))?,
                SessionStartEvent::Stderr { data } => logs
                    .process_event(BufferedStreamEvent::Stderr(data), &mut output)
                    .map_err(|err| BuildError::Other(format!("failed to write stderr: {err}")))?,
                SessionStartEvent::Error { code, message, .. } => {
                    let message = message
                        .map_or_else(|| code.clone(), |message| format!("{code}: {message}"));
                    eprintln!("{message}");
                    stream_errors.push(message);
                }
                SessionStartEvent::Ready { session_id, phases } => {
                    if !valid_session_id(&session_id)
                        || started_id.as_deref() != Some(session_id.as_str())
                    {
                        return Err(BuildError::Other(
                            "ready event had inconsistent session identity".to_string(),
                        ));
                    }
                    result = Some(SessionStartResult {
                        session_id: Some(session_id),
                        exit_code: 0,
                        timed_out: false,
                        phases,
                        errors: std::mem::take(&mut stream_errors),
                    });
                }
                SessionStartEvent::Exit {
                    code,
                    timed_out,
                    phases,
                    ..
                } => {
                    result = Some(SessionStartResult {
                        session_id: None,
                        exit_code: code,
                        timed_out,
                        phases,
                        errors: std::mem::take(&mut stream_errors),
                    });
                }
            }
        }
        if result.is_some() {
            if !pending.is_empty() {
                return Err(BuildError::Other(
                    "session start response contained data after its final event".to_string(),
                ));
            }
            loop {
                match response.chunk().await.map_err(|err| {
                    BuildError::Other(format!("failed to finish Ready delivery: {err}"))
                })? {
                    None => break,
                    Some(extra) if extra.is_empty() => continue,
                    Some(_) => {
                        return Err(BuildError::Other(
                            "session start response contained events after its final event"
                                .to_string(),
                        ))
                    }
                }
            }
            break;
        }
    }
    output
        .finish_routed(true)
        .map_err(|err| BuildError::Other(format!("failed to flush output: {err}")))?;
    logs.write_completion_notice().map_err(|err| {
        BuildError::Other(format!("failed to write log completion notice: {err}"))
    })?;
    result.ok_or_else(|| BuildError::Other("missing ready or exit event".to_string()))
}

async fn run_session_action(
    session_id: &str,
    action: &str,
    body: Vec<u8>,
    endpoint: &Endpoint,
    token: Option<&str>,
    output_limits: &OutputLimits,
    observed_action_id: tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<SessionActionResult, BuildError> {
    let path = format!("/v1/sessions/{session_id}/actions/{action}");
    let (client, url, send_auth) = session_http_client(endpoint, &path)?;
    let mut builder = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }
    let response = match builder.send().await {
        Ok(response) => response,
        Err(err) if is_connection_failure(&err) => {
            return Err(BuildError::ConnectionFailed(format!(
                "cannot reach endpoint: {err}"
            )))
        }
        Err(err) => return Err(BuildError::Other(format!("session action failed: {err}"))),
    };
    if !response.status().is_success() {
        return Err(session_http_error(response, "action").await);
    }
    read_session_action_response(
        response,
        output_limits,
        session_id,
        action,
        observed_action_id,
    )
    .await
}

async fn read_session_action_response(
    mut response: reqwest::Response,
    output_limits: &OutputLimits,
    expected_session: &str,
    expected_action: &str,
    observed_action_id: tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<SessionActionResult, BuildError> {
    let mut pending = Vec::new();
    let mut output = OutputLimiter::new(output_limits);
    let mut logs = LogCaptureState::new(output_limits);
    let paths = logs
        .initialize("action")
        .map_err(|err| BuildError::Other(format!("failed to initialize result logs: {err}")))?
        .ok_or_else(|| BuildError::Other("result logs were not configured".to_string()))?;
    output.set_log_paths(&paths);
    let mut started_id: Option<String> = None;
    let mut stream_errors = Vec::new();
    let mut result = None;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| BuildError::Other(format!("failed to read action response: {err}")))?
    {
        pending.extend_from_slice(&chunk);
        if pending.len() > 1024 * 1024 {
            return Err(BuildError::Other(
                "response line exceeded 1 MiB".to_string(),
            ));
        }
        while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=position).collect();
            let line = std::str::from_utf8(&line[..line.len() - 1])
                .map_err(|_| BuildError::Other("response was not UTF-8".to_string()))?
                .trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if result.is_some() {
                return Err(BuildError::Other(
                    "action response contained an event after the exit event".to_string(),
                ));
            }
            let event: SessionActionEvent = serde_json::from_str(line)
                .map_err(|err| BuildError::Other(format!("invalid action response: {err}")))?;
            match event {
                SessionActionEvent::Action {
                    session_id,
                    action_id,
                    action,
                    status,
                } => {
                    if session_id != expected_session
                        || action != expected_action
                        || !valid_action_id(&action_id)
                    {
                        return Err(BuildError::Other(
                            "action stream identity was inconsistent".to_string(),
                        ));
                    }
                    if let Some(existing) = &started_id {
                        if existing != &action_id {
                            return Err(BuildError::Other(
                                "action identity changed during execution".to_string(),
                            ));
                        }
                    } else {
                        started_id = Some(action_id.clone());
                        let _ = observed_action_id.send(action_id.clone());
                    }
                    match status {
                        SessionActionStatus::Started => {
                            eprintln!("{OUTPUT_PREFIX} action {action} started ({action_id})")
                        }
                        SessionActionStatus::Snapshotting => {
                            eprintln!("{OUTPUT_PREFIX} action {action} snapshotting artifacts")
                        }
                    }
                }
                SessionActionEvent::Stdout { data } => logs
                    .process_event(BufferedStreamEvent::Stdout(data), &mut output)
                    .map_err(|err| BuildError::Other(format!("failed to write stdout: {err}")))?,
                SessionActionEvent::Stderr { data } => logs
                    .process_event(BufferedStreamEvent::Stderr(data), &mut output)
                    .map_err(|err| BuildError::Other(format!("failed to write stderr: {err}")))?,
                SessionActionEvent::Error { code, message } => {
                    let message = message
                        .map_or_else(|| code.clone(), |message| format!("{code}: {message}"));
                    eprintln!("{message}");
                    stream_errors.push(message);
                }
                SessionActionEvent::Exit {
                    session_id,
                    action_id,
                    action,
                    code,
                    timed_out,
                    artifacts,
                    artifact_restrictions,
                } => {
                    if session_id != expected_session
                        || action != expected_action
                        || !valid_action_id(&action_id)
                        || started_id.as_deref() != Some(action_id.as_str())
                    {
                        return Err(BuildError::Other(
                            "action exit identity was inconsistent".to_string(),
                        ));
                    }
                    result = Some(SessionActionResult {
                        action_id,
                        exit_code: code,
                        timed_out,
                        artifacts,
                        artifact_restrictions,
                        errors: std::mem::take(&mut stream_errors),
                    });
                }
            }
        }
        if result.is_some() {
            if !pending.is_empty() {
                return Err(BuildError::Other(
                    "action response contained data after the exit event".to_string(),
                ));
            }
            loop {
                match response.chunk().await.map_err(|err| {
                    BuildError::Other(format!("failed to acknowledge action exit: {err}"))
                })? {
                    None => break,
                    Some(extra) if extra.is_empty() => continue,
                    Some(_) => {
                        return Err(BuildError::Other(
                            "action response contained events after exit".to_string(),
                        ))
                    }
                }
            }
            break;
        }
    }
    output
        .finish()
        .map_err(|err| BuildError::Other(format!("failed to flush output: {err}")))?;
    logs.write_completion_notice().map_err(|err| {
        BuildError::Other(format!("failed to write log completion notice: {err}"))
    })?;
    result.ok_or_else(|| BuildError::Other("missing action exit event".to_string()))
}

async fn request_session_stop(
    session_id: &str,
    endpoint: &Endpoint,
    token: Option<&str>,
) -> Result<SessionStopResponse, BuildError> {
    let path = format!("/v1/sessions/{session_id}");
    let (client, url, send_auth) = session_http_client(endpoint, &path)?;
    let mut builder = client.delete(url);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }
    let response = match builder.send().await {
        Ok(response) => response,
        Err(err) if is_connection_failure(&err) => {
            return Err(BuildError::ConnectionFailed(format!(
                "cannot reach endpoint: {err}"
            )))
        }
        Err(err) => return Err(BuildError::Other(format!("session stop failed: {err}"))),
    };
    if !response.status().is_success() {
        return Err(session_http_error(response, "stop").await);
    }
    response
        .json::<SessionStopResponse>()
        .await
        .map_err(|err| BuildError::Other(format!("invalid stop response: {err}")))
}

async fn best_effort_stop(session_id: &str, endpoint: &Endpoint, token: Option<&str>) -> String {
    match tokio::time::timeout(
        Duration::from_secs(10),
        request_session_stop(session_id, endpoint, token),
    )
    .await
    {
        Ok(Ok(response)) if response.session_id != session_id => format!(
            "failed: stop response session identity mismatch (expected {session_id}, got {})",
            response.session_id
        ),
        Ok(Ok(response)) if response.teardown.timed_out => "failed: teardown timed out".to_string(),
        Ok(Ok(response)) if response.teardown.error_code.is_some() => format!(
            "failed: teardown {}",
            response.teardown.error_code.as_deref().unwrap_or("failed")
        ),
        Ok(Ok(response)) if response.teardown.exit_code != Some(0) => format!(
            "failed: teardown exit code {}",
            response
                .teardown
                .exit_code
                .map_or_else(|| "missing".to_string(), |code| code.to_string())
        ),
        Ok(Ok(_)) => "succeeded".to_string(),
        Ok(Err(err)) => format!("failed: {err}"),
        Err(_) => "failed: stop request timed out".to_string(),
    }
}

struct BuildResult {
    build_id: Option<String>,
    exit_code: i32,
    timed_out: bool,
    artifacts: Option<ArtifactArchive>,
    artifact_restrictions: Option<ArtifactRestrictions>,
    failed_phase: Option<BuildPhase>,
    phases: Vec<PhaseResult>,
}

async fn run_build(
    request: &Request,
    source_archive: &NamedTempFile,
    endpoint: &Endpoint,
    token: Option<&str>,
    output_limits: &OutputLimits,
) -> Result<BuildResult, BuildError> {
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            Client::builder()
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?,
            format!("{base}/v1/builds"),
            true,
        ),
        Endpoint::Unix { path } => (
            Client::builder()
                .unix_socket(path.clone())
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?,
            "http://localhost/v1/builds".to_string(),
            false,
        ),
    };
    let metadata = serde_json::to_string(request)
        .map_err(|err| BuildError::Other(format!("failed to serialize request: {err}")))?;
    let length = source_archive
        .as_file()
        .metadata()
        .map_err(|err| BuildError::Other(format!("failed to inspect source archive: {err}")))?
        .len();
    let file = tokio::fs::File::open(source_archive.path())
        .await
        .map_err(|err| BuildError::Other(format!("failed to read source archive: {err}")))?;
    let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
    let source_part = Part::stream_with_length(body, length)
        .file_name("source.zip")
        .mime_str("application/zip")
        .unwrap();
    let form = Form::new()
        .part(
            "metadata",
            Part::text(metadata).mime_str("application/json").unwrap(),
        )
        .part("source", source_part);
    let mut builder = client.post(url).multipart(form);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }
    let response = match builder.send().await {
        Ok(response) => response,
        Err(err) if is_connection_failure(&err) => {
            return Err(BuildError::ConnectionFailed(format!(
                "cannot reach endpoint: {err}"
            )))
        }
        Err(err) => return Err(BuildError::Other(format!("request failed: {err}"))),
    };
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(BuildError::Other(format!(
            "server returned {status}: {body}"
        )));
    }
    read_responses(response, output_limits).await
}

async fn read_responses(
    mut response: reqwest::Response,
    output_limits: &OutputLimits,
) -> Result<BuildResult, BuildError> {
    let mut pending = Vec::new();
    let mut output = OutputLimiter::new(output_limits);
    let mut log_capture = LogCaptureState::new(output_limits);
    let paths = log_capture
        .initialize("local")
        .map_err(|err| BuildError::Other(format!("failed to initialize result logs: {err}")))?
        .ok_or_else(|| BuildError::Other("result logs were not configured".to_string()))?;
    output.set_log_paths(&paths);
    let mut build_id = None;
    let mut result = None;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| BuildError::Other(format!("failed to read response: {err}")))?
    {
        pending.extend_from_slice(&chunk);
        if pending.len() > 1024 * 1024 {
            return Err(BuildError::Other(
                "response line exceeded 1 MiB".to_string(),
            ));
        }
        while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=position).collect();
            let line = std::str::from_utf8(&line[..line.len() - 1])
                .map_err(|_| BuildError::Other("response was not UTF-8".to_string()))?
                .trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let event: ResponseEvent = serde_json::from_str(line)
                .map_err(|err| BuildError::Other(format!("invalid response format: {err}")))?;
            match event {
                ResponseEvent::Stdout { data } => log_capture
                    .process_event(BufferedStreamEvent::Stdout(data), &mut output)
                    .map_err(|err| BuildError::Other(format!("failed to write stdout: {err}")))?,
                ResponseEvent::Stderr { data } => log_capture
                    .process_event(BufferedStreamEvent::Stderr(data), &mut output)
                    .map_err(|err| BuildError::Other(format!("failed to write stderr: {err}")))?,
                ResponseEvent::Error {
                    message: Some(message),
                    ..
                } => {
                    eprintln!("{message}");
                }
                ResponseEvent::Error { .. } => {}
                ResponseEvent::Build {
                    id,
                    status,
                    phase,
                    duration_ms,
                    exit_code,
                    timed_out,
                } => {
                    validate_build_id(&id).map_err(|err| BuildError::Other(err.to_string()))?;
                    build_id = Some(id);
                    if let Some(phase) = phase {
                        match status.as_str() {
                            "phase_started" => {
                                eprintln!("{OUTPUT_PREFIX} {} phase started", phase.as_str());
                            }
                            "phase_finished" => {
                                if let (Some(duration_ms), Some(exit_code), Some(timed_out)) =
                                    (duration_ms, exit_code, timed_out)
                                {
                                    eprintln!(
                                        "{OUTPUT_PREFIX} {} phase finished in {:.3}s (exit_code={exit_code}, timed_out={timed_out})",
                                        phase.as_str(),
                                        duration_ms as f64 / 1000.0
                                    );
                                } else {
                                    eprintln!(
                                        "{OUTPUT_PREFIX} {} phase finished without complete timing metadata",
                                        phase.as_str()
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
                ResponseEvent::Exit {
                    code,
                    timed_out,
                    artifacts,
                    artifact_restrictions,
                    failed_phase,
                    phases,
                } => {
                    result = Some(BuildResult {
                        build_id: build_id.clone(),
                        exit_code: code,
                        timed_out,
                        artifacts,
                        artifact_restrictions,
                        failed_phase,
                        phases,
                    });
                }
            }
        }
        if result.is_some() {
            break;
        }
    }
    output
        .finish()
        .map_err(|err| BuildError::Other(format!("failed to flush output: {err}")))?;
    log_capture.write_completion_notice().map_err(|err| {
        BuildError::Other(format!("failed to write log completion notice: {err}"))
    })?;
    result.ok_or_else(|| BuildError::Other("missing exit event".to_string()))
}

fn write_artifact_restrictions_notice(restrictions: &ArtifactRestrictions) -> io::Result<()> {
    let mut stderr = io::stderr();
    writeln!(stderr, "{}", artifact_restrictions_notice(restrictions))
}

fn artifact_restrictions_notice(restrictions: &ArtifactRestrictions) -> String {
    let file_label = if restrictions.omitted_count == 1 {
        "file was"
    } else {
        "files were"
    };
    if restrictions.matched_patterns.is_empty() {
        format!(
            "{OUTPUT_PREFIX} {} requested artifact {file_label} omitted by server artifact restrictions",
            restrictions.omitted_count
        )
    } else {
        format!(
            "{OUTPUT_PREFIX} {} requested artifact {file_label} omitted by server artifact restrictions: {}",
            restrictions.omitted_count,
            restrictions.matched_patterns.join(", ")
        )
    }
}

async fn download_and_extract(
    archive: &ArtifactArchive,
    endpoint: &Endpoint,
    token: Option<&str>,
    run_directory: &Path,
) -> io::Result<()> {
    const MAX_ARTIFACT_BYTES: u64 = 536_870_912;
    if archive.size > MAX_ARTIFACT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "advertised artifact exceeds client transfer limit",
        ));
    }
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            Client::builder().build().map_err(io::Error::other)?,
            build_artifact_url(base, &archive.path),
            true,
        ),
        Endpoint::Unix { path } => (
            Client::builder()
                .unix_socket(path.clone())
                .build()
                .map_err(io::Error::other)?,
            build_artifact_url("http://localhost", &archive.path),
            false,
        ),
    };
    let mut builder = client.get(url);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }
    let mut response = builder.send().await.map_err(io::Error::other)?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(io::Error::other(format!(
            "artifact download failed {status}: {body}"
        )));
    }
    let temp = tempfile::Builder::new()
        .prefix(".artifacts-download-")
        .suffix(".zip")
        .tempfile_in(run_directory)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut temp_file = tokio::fs::File::from_std(temp.reopen()?);
    let mut received = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        received = received.saturating_add(chunk.len() as u64);
        if received > MAX_ARTIFACT_BYTES || received > archive.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact transfer exceeded advertised or client size limit",
            ));
        }
        temp_file.write_all(&chunk).await?;
    }
    if received != archive.size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact size did not match server advertisement",
        ));
    }
    temp_file.sync_all().await?;
    drop(temp_file);
    let run_directory = run_directory.to_path_buf();
    tokio::task::spawn_blocking(move || extract_zip_atomic(temp.path(), &run_directory))
        .await
        .map_err(|err| io::Error::other(format!("artifact extraction worker failed: {err}")))?
}

fn build_artifact_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }

    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn extract_zip_atomic(zip_path: &Path, run_directory: &Path) -> io::Result<()> {
    const MAX_FILES: usize = 10_000;
    const MAX_BYTES: u64 = 2_147_483_648;
    const MAX_DEPTH: usize = 64;
    let destination = run_directory.join("artifacts");
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "artifacts directory already exists",
        ));
    }
    reject_duplicate_zip_entries(zip_path)?;
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if archive.len() > MAX_FILES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact entry count exceeded client limit",
        ));
    }
    let mut exact = HashSet::new();
    let mut folded = HashSet::new();
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    let mut declared = 0u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let name = entry.name().trim_end_matches('/').to_string();
        validate_zip_entry_path(&name)?;
        if name.split('/').count() > MAX_DEPTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact path exceeded client depth limit",
            ));
        }
        validate_artifact_zip_type(entry.unix_mode(), entry.is_dir())?;
        let lower = name.to_ascii_lowercase();
        if !exact.insert(name.clone()) || !folded.insert(lower.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact archive contains duplicate or case-colliding paths",
            ));
        }
        let components: Vec<_> = name.split('/').collect();
        let mut ancestor = String::new();
        for component in &components[..components.len().saturating_sub(1)] {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            if files.contains(&ancestor.to_ascii_lowercase()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact archive contains a file/directory collision",
                ));
            }
            directories.insert(ancestor.to_ascii_lowercase());
        }
        if entry.is_dir() {
            if files.contains(&lower) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact archive contains a file/directory collision",
                ));
            }
            directories.insert(lower);
        } else {
            if directories.contains(&lower) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact archive contains a file/directory collision",
                ));
            }
            files.insert(lower);
            declared = declared.saturating_add(entry.size());
        }
        if declared > MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact uncompressed bytes exceeded client limit",
            ));
        }
    }
    let staging_name = format!(".artifacts-{}", uuid::Uuid::new_v4().simple());
    let staging = run_directory.join(&staging_name);
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let result = (|| {
        let file = fs::File::open(zip_path)?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut actual = 0u64;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            let name = entry.name().trim_end_matches('/');
            let output = staging.join(name);
            if entry.is_dir() {
                fs::create_dir_all(&output)?;
                continue;
            }
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&output)?;
            let copied = io::copy(&mut entry, &mut file)?;
            actual = actual.saturating_add(copied);
            if actual > MAX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact extracted bytes exceeded client limit",
                ));
            }
            if let Some(mode) = entry.unix_mode() {
                fs::set_permissions(&output, fs::Permissions::from_mode(mode & 0o777))?;
            }
        }
        fs::rename(&staging, &destination)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn validate_artifact_zip_type(mode: Option<u32>, is_dir: bool) -> io::Result<()> {
    let Some(mode) = mode else {
        // Portable ZIP producers may omit Unix attributes. Directory spelling
        // remains authoritative for those archives, preserving compatibility.
        return Ok(());
    };
    let kind = mode & 0o170000;
    let expected = if is_dir { 0o040000 } else { 0o100000 };
    // Some non-Unix ZIP producers expose permissions with a zero type field.
    // Accept that portable form, but reject every explicit non-file/non-directory
    // Unix kind rather than relying on zip::ZipFile::is_file().
    if kind != 0 && kind != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact archive contains a special file",
        ));
    }
    Ok(())
}

fn reject_duplicate_zip_entries(zip_path: &Path) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};

    let mut file = fs::File::open(zip_path)?;
    let length = file.metadata()?.len();
    let tail_length = length.min(65_557) as usize;
    file.seek(SeekFrom::End(-(tail_length as i64)))?;
    let mut tail = vec![0u8; tail_length];
    file.read_exact(&mut tail)?;
    let signature = 0x0605_4b50u32.to_le_bytes();
    let eocd = (0..=tail.len().saturating_sub(22))
        .rev()
        .find(|&index| {
            tail[index..].starts_with(&signature)
                && index + 22 + u16::from_le_bytes([tail[index + 20], tail[index + 21]]) as usize
                    == tail.len()
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "zip end record missing"))?;
    let u16_at = |offset: usize| u16::from_le_bytes([tail[eocd + offset], tail[eocd + offset + 1]]);
    let u32_at = |offset: usize| {
        u32::from_le_bytes([
            tail[eocd + offset],
            tail[eocd + offset + 1],
            tail[eocd + offset + 2],
            tail[eocd + offset + 3],
        ])
    };
    let disk = u16_at(4);
    let central_disk = u16_at(6);
    let disk_entries = u16_at(8);
    let entries = u16_at(10);
    let central_size = u32_at(12);
    let central_offset = u32_at(16);
    if disk != 0 || central_disk != 0 || disk_entries != entries {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multi-disk artifact ZIP is unsupported",
        ));
    }
    if entries == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ZIP64 artifact archives are unsupported",
        ));
    }
    let eocd_absolute = length - tail_length as u64 + eocd as u64;
    if u64::from(central_offset).saturating_add(u64::from(central_size)) > eocd_absolute {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact ZIP central directory is out of bounds",
        ));
    }
    file.seek(SeekFrom::Start(u64::from(central_offset)))?;
    let mut names = HashSet::new();
    for _ in 0..entries {
        let mut header = [0u8; 46];
        file.read_exact(&mut header)?;
        if header[..4] != 0x0201_4b50u32.to_le_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact ZIP central entry is invalid",
            ));
        }
        let name_length = u16::from_le_bytes([header[28], header[29]]) as usize;
        let extra_length = u16::from_le_bytes([header[30], header[31]]) as i64;
        let comment_length = u16::from_le_bytes([header[32], header[33]]) as i64;
        if name_length == 0 || name_length > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact ZIP entry name is empty or too long",
            ));
        }
        let mut name = vec![0u8; name_length];
        file.read_exact(&mut name)?;
        if !names.insert(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact archive contains duplicate paths",
            ));
        }
        file.seek(SeekFrom::Current(extra_length + comment_length))?;
    }
    Ok(())
}

fn validate_zip_entry_path(name: &str) -> io::Result<()> {
    if name.is_empty()
        || !name.is_ascii()
        || name.contains(['\\', '\0'])
        || name
            .split('/')
            .any(|component| component.is_empty() || component == ".")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zip entry had invalid path",
        ));
    }

    let path = Path::new(name);
    if path.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zip entry had invalid path",
        ));
    }

    Ok(())
}

fn to_exit_code(code: i32, timed_out: bool) -> ExitCode {
    ExitCode::from(normalize_requested_exit(code, timed_out))
}

fn normalize_requested_exit(code: i32, timed_out: bool) -> u8 {
    if timed_out {
        124
    } else {
        normalize_exit_code(code)
    }
}

fn normalize_exit_code(code: i32) -> u8 {
    if code < 0 {
        return 1;
    }
    if code > u8::MAX as i32 {
        return u8::MAX;
    }
    code as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions as FileOptions;
    use zip::ZipWriter;

    #[test]
    fn provenance_error_truncation_preserves_utf8() {
        let mut message = "a".repeat(4095);
        message.push('é');
        truncate_utf8(&mut message, 4096);
        assert_eq!(message.len(), 4095);
        assert!(message.is_char_boundary(message.len()));
    }

    #[test]
    fn cli_accepts_only_task_request_identity_and_source_selection() {
        let cli = Cli::try_parse_from([
            "indentured",
            "--endpoint",
            "http://localhost:8080",
            "run",
            "--request-id",
            "req.1",
            "--source",
            "src/**",
            "build",
        ])
        .expect("parse");
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.task, "build");
                assert_eq!(args.request_id.as_deref(), Some("req.1"));
                assert_eq!(args.source, vec!["src/**"]);
            }
            Commands::Session(_) => panic!("expected run command"),
        }
    }

    #[test]
    fn cli_accepts_only_the_three_explicit_session_operations() {
        let start = Cli::try_parse_from([
            "indentured",
            "session",
            "start",
            "--source",
            "src/**",
            "build",
        ])
        .unwrap();
        assert!(matches!(
            start.command,
            Commands::Session(SessionArgs {
                command: SessionCommands::Start(SessionStartArgs { task, .. })
            }) if task == "build"
        ));
        let action = Cli::try_parse_from([
            "indentured",
            "session",
            "action",
            "ses_1",
            "observe",
            "--input",
            "-",
        ])
        .unwrap();
        assert!(matches!(
            action.command,
            Commands::Session(SessionArgs {
                command: SessionCommands::Action(SessionActionArgs { session, action, input, .. })
            }) if session == "ses_1" && action == "observe" && input == "-"
        ));
        let stop = Cli::try_parse_from(["indentured", "session", "stop", "ses_1"]).unwrap();
        assert!(matches!(
            stop.command,
            Commands::Session(SessionArgs {
                command: SessionCommands::Stop(SessionStopArgs { session, .. })
            }) if session == "ses_1"
        ));
        for unsupported in [
            vec!["indentured", "session", "list"],
            vec!["indentured", "session", "reset", "ses_1"],
            vec!["indentured", "session", "action", "ses_1", "observe"],
            vec![
                "indentured",
                "session",
                "action",
                "ses_1",
                "observe",
                "--input-json",
                "{}",
            ],
            vec!["indentured", "session", "start", "--cwd", "/tmp", "build"],
        ] {
            assert!(Cli::try_parse_from(unsupported).is_err());
        }
    }

    #[test]
    fn action_input_is_an_object_wrapped_in_the_bounded_fixed_envelope() {
        let body = encode_action_input(br#"{"operator_data":true,"argv":["data"]}"#).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema_version"], SESSION_REQUEST_SCHEMA_VERSION);
        assert_eq!(value["input"]["operator_data"], true);
        assert_eq!(value["input"]["argv"][0], "data");
        assert_eq!(value.as_object().unwrap().len(), 2);

        assert!(encode_action_input(b"[]").is_err());
        assert!(encode_action_input(&vec![b'x'; MAX_SESSION_ACTION_BODY_BYTES + 1]).is_err());

        let empty_request = serde_json::to_vec(&SessionActionRequest {
            schema_version: SESSION_REQUEST_SCHEMA_VERSION.to_string(),
            input: serde_json::from_value(serde_json::json!({"data":""})).unwrap(),
        })
        .unwrap();
        let exact_input = format!(
            "{{\"data\":\"{}\"}}",
            "x".repeat(MAX_SESSION_ACTION_BODY_BYTES - empty_request.len())
        );
        assert_eq!(
            encode_action_input(exact_input.as_bytes()).unwrap().len(),
            MAX_SESSION_ACTION_BODY_BYTES
        );

        let prefix = br#"{"data":""#;
        let suffix = br#""}"#;
        let mut largest = Vec::new();
        largest.extend_from_slice(prefix);
        largest.extend(std::iter::repeat_n(
            b'x',
            MAX_SESSION_ACTION_BODY_BYTES - prefix.len() - suffix.len(),
        ));
        largest.extend_from_slice(suffix);
        let error = encode_action_input(&largest).unwrap_err();
        assert!(error.to_string().contains("encoded action request exceeds"));
    }

    #[test]
    fn session_evidence_is_private_atomic_and_records_lifecycle_fields() {
        let root = tempdir().unwrap();
        let mut evidence = SessionEvidence::create(
            "action",
            Some("ses_1"),
            Some("observe"),
            Some(root.path()),
            None,
        )
        .unwrap();
        evidence.provenance.action_id = Some("act_1".to_string());
        evidence.provenance.remote_exit_code = Some(7);
        evidence.provenance.timed_out = Some(false);
        evidence.provenance.cleanup_status = Some("not-needed".to_string());
        evidence.finish("failed").unwrap();
        assert_eq!(
            fs::metadata(&evidence.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence.directory.join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(value["session_id"], "ses_1");
        assert_eq!(value["action_id"], "act_1");
        assert_eq!(value["remote_exit_code"], 7);
        assert!(fs::read_dir(&evidence.directory)
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".provenance-")));
    }

    #[test]
    fn cli_rejects_every_legacy_authority_surface() {
        for args in [
            vec!["indentured", "run", "--timeout", "10", "build"],
            vec!["indentured", "run", "--cwd", "subdir", "build"],
            vec!["indentured", "run", "--env", "A=B", "build"],
            vec!["indentured", "run", "--artifact", "out/**", "build"],
            vec!["indentured", "run", "--workspace-id", "x", "build"],
            vec!["indentured", "run", "build", "--", "arbitrary"],
            vec!["indentured", "workspace", "reset", "--workspace-id", "x"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn raw_bearer_token_surfaces_are_rejected_and_token_file_is_loaded() {
        assert!(Cli::try_parse_from(["indentured", "--token", "secret", "run", "build",]).is_err());
        assert!(toml::from_str::<ClientConfig>("[connection]\ntoken = \"secret\"\n").is_err());
        let runtime_root = PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
        let temp = tempfile::tempdir_in(runtime_root).unwrap();
        let path = temp.path().join("token");
        let write_token = |contents: &[u8]| {
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };

        let mut max_with_lf = vec![b'x'; 4095];
        max_with_lf.push(b'\n');
        for (contents, expected) in [
            (b"A".to_vec(), "A".to_string()),
            (b"azAZ09-._~+/===\n".to_vec(), "azAZ09-._~+/===".to_string()),
            (vec![b'x'; 4096], "x".repeat(4096)),
            (max_with_lf, "x".repeat(4095)),
        ] {
            write_token(&contents);
            assert_eq!(
                resolve_token(Some(path.clone()), None).unwrap(),
                Some(expected)
            );
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
            let error = resolve_token(Some(path.clone()), None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }

        write_token(b"sentinel-secret:");
        let error = resolve_token(Some(path), None).unwrap_err();
        assert!(!error.to_string().contains("sentinel-secret"));
    }

    #[test]
    fn request_wire_shape_has_no_execution_authority() {
        let request = Request {
            schema_version: REQUEST_SCHEMA_VERSION.to_string(),
            request_id: Some("req.1".to_string()),
            task: "build".to_string(),
            source: SourceMetadata {
                format: SourceFormat::Zip,
            },
        };
        let value = serde_json::to_value(request).unwrap();
        let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["request_id", "schema_version", "source", "task"]);
    }

    #[test]
    fn endpoint_parser_requires_supported_scheme_and_absolute_socket_path() {
        assert!(parse_endpoint("example.com").is_err());
        assert!(parse_endpoint("unix://relative.sock").is_err());
        assert!(matches!(
            parse_endpoint("unix:///tmp/server.sock").unwrap(),
            Endpoint::Unix { .. }
        ));
    }

    #[test]
    fn artifact_restriction_notice_is_stable() {
        let notice = artifact_restrictions_notice(&ArtifactRestrictions {
            omitted_count: 2,
            matched_patterns: vec!["**/*.key".to_string()],
        });
        assert!(notice.contains("2 requested artifact files were omitted"));
        assert!(notice.contains("**/*.key"));
    }

    #[test]
    fn result_roots_must_not_overlap_source_in_either_direction() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let inside = source.join("results");
        assert!(reject_overlap(&source, &inside).is_err());
        assert!(
            !inside.exists(),
            "overlap validation must not create source paths"
        );
        assert!(reject_overlap(&source, root.path()).is_err());
        let separate = tempdir().unwrap();
        assert!(reject_overlap(&source, separate.path()).is_ok());
        let alias_parent = tempdir().unwrap();
        let alias = alias_parent.path().join("source-alias");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(reject_overlap(&source, &alias.join("results")).is_err());
        assert!(resolve_result_root(Some(Path::new("relative"))).is_err());
    }

    #[test]
    fn credential_must_not_overlap_source_or_configured_result_base() {
        let source = tempdir().unwrap();
        let results = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let source_token = source.path().join("token");
        let result_token = results.path().join("token");
        let child_token = results.path().join("future-run/token");
        let outside_token = outside.path().join("token");
        fs::write(&source_token, "secret").unwrap();
        fs::write(&result_token, "secret").unwrap();
        fs::create_dir(results.path().join("future-run")).unwrap();
        fs::write(&child_token, "secret").unwrap();
        fs::write(&outside_token, "secret").unwrap();
        assert!(reject_credential_overlap(&source_token, source.path(), results.path()).is_err());
        assert!(reject_credential_overlap(&result_token, source.path(), results.path()).is_err());
        assert!(reject_credential_overlap(&child_token, source.path(), results.path()).is_err());
        assert!(reject_credential_overlap(&outside_token, source.path(), results.path()).is_ok());

        let aliases = tempdir().unwrap();
        let alias = aliases.path().join("results-alias");
        std::os::unix::fs::symlink(results.path(), &alias).unwrap();
        assert!(reject_credential_overlap(&result_token, source.path(), &alias).is_err());
    }

    #[test]
    fn result_root_uses_home_fallback_and_requires_home_when_xdg_is_missing() {
        let home = tempdir().unwrap();
        assert_eq!(
            resolve_result_root_from(None, None, Some(home.path().as_os_str().to_os_string()))
                .unwrap(),
            home.path().join(".local/state/indentured/runs")
        );
        assert_eq!(
            resolve_result_root_from(None, None, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn artifact_preflight_rejects_duplicates_collisions_and_special_files() {
        fn raw_unix_archive(entries: &[(&str, u32)]) -> NamedTempFile {
            let mut bytes = Vec::new();
            let mut offsets = Vec::new();
            for (name, _) in entries {
                offsets.push(bytes.len() as u32);
                bytes.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
                bytes.extend_from_slice(&20u16.to_le_bytes());
                bytes.extend_from_slice(&[0; 20]);
                bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.extend_from_slice(name.as_bytes());
            }
            let central_start = bytes.len() as u32;
            for ((name, mode), offset) in entries.iter().zip(offsets) {
                bytes.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
                bytes.extend_from_slice(&0x0314u16.to_le_bytes());
                bytes.extend_from_slice(&20u16.to_le_bytes());
                bytes.extend_from_slice(&[0; 20]);
                bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&[0; 8]);
                bytes.extend_from_slice(&(mode << 16).to_le_bytes());
                bytes.extend_from_slice(&offset.to_le_bytes());
                bytes.extend_from_slice(name.as_bytes());
            }
            let central_size = bytes.len() as u32 - central_start;
            bytes.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&[0; 4]);
            bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&central_size.to_le_bytes());
            bytes.extend_from_slice(&central_start.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            let mut file = NamedTempFile::new().unwrap();
            file.write_all(&bytes).unwrap();
            file
        }
        fn archive(entries: &[(&str, bool)]) -> NamedTempFile {
            let file = NamedTempFile::new().unwrap();
            let mut zip = ZipWriter::new(file.reopen().unwrap());
            for (name, symlink) in entries {
                if *symlink {
                    zip.add_symlink(*name, "target", FileOptions::default())
                        .unwrap();
                } else {
                    zip.start_file(*name, FileOptions::default()).unwrap();
                    zip.write_all(b"x").unwrap();
                }
            }
            zip.finish().unwrap();
            file
        }
        fn assert_rejected_without_staging(zip: &NamedTempFile) -> io::Error {
            let run = tempdir().unwrap();
            let error = extract_zip_atomic(zip.path(), run.path()).unwrap_err();
            assert!(!run.path().join("artifacts").exists());
            assert!(fs::read_dir(run.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".artifacts-")));
            error
        }

        let _ = assert_rejected_without_staging(&raw_unix_archive(&[
            ("same", 0o100644),
            ("same", 0o100644),
        ]));
        for entries in [
            vec![("Name", false), ("name", false)],
            vec![("Foo/bar", false), ("foo", false)],
            vec![("foo", false), ("Foo/bar", false)],
            vec![("link", true)],
        ] {
            let _ = assert_rejected_without_staging(&archive(&entries));
        }
        for (name, kind) in [
            ("fifo", libc::S_IFIFO),
            ("socket", libc::S_IFSOCK),
            ("block-device", libc::S_IFBLK),
            ("character-device", libc::S_IFCHR),
        ] {
            let error = assert_rejected_without_staging(&raw_unix_archive(&[(name, kind | 0o644)]));
            assert!(
                error.to_string().contains("special file"),
                "{name}: {error}"
            );
        }

        let portable = raw_unix_archive(&[("portable", 0o644)]);
        let run = tempdir().unwrap();
        extract_zip_atomic(portable.path(), run.path()).unwrap();
        assert!(run.path().join("artifacts/portable").is_file());
    }

    #[test]
    fn artifact_extraction_is_atomic_and_cannot_overwrite_evidence() {
        let run = tempdir().unwrap();
        fs::write(run.path().join("provenance.json"), "evidence").unwrap();
        let unsafe_zip = NamedTempFile::new().unwrap();
        let mut zip = ZipWriter::new(unsafe_zip.reopen().unwrap());
        zip.start_file("../provenance.json", FileOptions::default())
            .unwrap();
        zip.write_all(b"overwrite").unwrap();
        zip.finish().unwrap();
        assert!(extract_zip_atomic(unsafe_zip.path(), run.path()).is_err());
        assert_eq!(
            fs::read_to_string(run.path().join("provenance.json")).unwrap(),
            "evidence"
        );
        assert!(!run.path().join("artifacts").exists());

        let safe_zip = NamedTempFile::new().unwrap();
        let mut zip = ZipWriter::new(safe_zip.reopen().unwrap());
        zip.start_file("provenance.json", FileOptions::default())
            .unwrap();
        zip.write_all(b"artifact evidence").unwrap();
        zip.finish().unwrap();
        extract_zip_atomic(safe_zip.path(), run.path()).unwrap();
        assert_eq!(
            fs::read_to_string(run.path().join("provenance.json")).unwrap(),
            "evidence"
        );
        assert_eq!(
            fs::read_to_string(run.path().join("artifacts/provenance.json")).unwrap(),
            "artifact evidence"
        );
        assert!(extract_zip_atomic(safe_zip.path(), run.path()).is_err());
    }
}
