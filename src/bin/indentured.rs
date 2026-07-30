use std::collections::{HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufWriter, Read as _, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgAction, Parser, Subcommand};
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_util::io::ReaderStream;

use indentured_server::bearer_token::{BearerToken, MAX_BEARER_TOKEN_FILE_BYTES};
use indentured_server::client_source::{
    find_jj_root, package_source_cancellable, FilesystemPatterns, SourceCancellation,
    SourceIdentity, SourceManifest,
};
use indentured_server::protocol::{
    ArtifactArchive, ArtifactRestrictions, BuildPhase, PhaseResult, Request, ResponseEvent,
    SourceFormat, SourceMetadata, REQUEST_SCHEMA_VERSION,
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
    Other(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::ConnectionFailed(msg) | BuildError::Other(msg) => write!(f, "{msg}"),
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

    fn write_stderr(&mut self, data: &str) -> io::Result<()> {
        let mut stderr = io::stderr();
        self.stderr.write_chunk(data, &mut stderr)
    }

    fn finish(&mut self) -> io::Result<()> {
        self.stdout.finish();
        self.stderr.finish();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        self.stdout.write_summary(&mut stdout, "stdout")?;
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

        write_event_to_terminal(event, output)
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

fn write_new_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
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

    let config_path = find_client_config_path(&run_dir);
    let repo_root = config_path
        .as_ref()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| run_dir.clone());
    let client_config = match load_client_config(config_path.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let config_loaded = config_path.is_some();

    let connection = client_config.connection.as_ref();
    if !resolve_connection_enabled(connection) {
        eprintln!("{OUTPUT_PREFIX} disabled (INDENTURED_SERVER_ENABLED/connection.enabled)");
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

    let raw = fs::read_to_string(path)?;
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
    let mut temp = tempfile::Builder::new()
        .prefix(".artifacts-download-")
        .suffix(".zip")
        .tempfile_in(run_directory)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut received = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        received = received.saturating_add(chunk.len() as u64);
        if received > MAX_ARTIFACT_BYTES || received > archive.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact transfer exceeded advertised or client size limit",
            ));
        }
        temp.write_all(&chunk)?;
    }
    if received != archive.size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact size did not match server advertisement",
        ));
    }
    temp.as_file().sync_all()?;
    extract_zip_atomic(temp.path(), run_directory)
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
    if timed_out {
        return ExitCode::from(124);
    }
    ExitCode::from(normalize_exit_code(code))
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
        }
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
