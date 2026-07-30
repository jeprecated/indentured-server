use std::collections::HashMap;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logging::LoggingSettings;
use crate::protocol::valid_task_id;
use crate::validation::{validate_relative_path, validate_relative_pattern};

const DEFAULT_CONFIG_PATH: &str = "/etc/indentured-server/config.toml";
pub const CONFIG_SCHEMA_VERSION: &str = "7";
pub(crate) const SCRIPT_SHELL: &str = "/bin/sh";
const MAX_TASK_SCRIPT_BYTES: usize = 64 * 1024;
const DEFAULT_SOURCE_TRANSFER_BYTES: u64 = 134_217_728;
const DEFAULT_SOURCE_UNCOMPRESSED_BYTES: u64 = DEFAULT_SOURCE_TRANSFER_BYTES * 10;
const DEFAULT_SOURCE_MAX_FILES: usize = 50_000;
const DEFAULT_SOURCE_MAX_DEPTH: usize = 64;
const DEFAULT_SOURCE_UPLOAD_TIMEOUT_SEC: u64 = 120;
const MAX_SOURCE_UPLOAD_TIMEOUT_SEC: u64 = 3_600;
const DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_ARTIFACT_TRANSFER_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_ARTIFACT_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_ARTIFACT_MAX_FILES: usize = 10_000;
const DEFAULT_ARTIFACT_MAX_DEPTH: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config {path}{location}", location = format_parse_location(*.line, *.column))]
    ParseToml {
        path: PathBuf,
        line: Option<usize>,
        column: Option<usize>,
    },

    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathKind {
    Explicit,
    Env,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: String,

    #[serde(default)]
    pub service: ServiceConfig,

    #[serde(default)]
    pub build: BuildConfig,

    pub tasks: HashMap<String, TaskConfig>,

    #[serde(default)]
    pub sources: SourcesConfig,

    #[serde(default)]
    pub artifacts: ArtifactsConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load_from_sources(cli_path: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, _kind) = Self::resolve_path(cli_path);
        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;

        let mut config: Config = toml::from_str(&raw).map_err(|source| {
            let (line, column) = parse_error_location(&raw, source.span().map(|span| span.start));
            ConfigError::ParseToml {
                path: path.clone(),
                line,
                column,
            }
        })?;

        config.apply_env_overrides();
        config.validate()?;

        Ok(config)
    }

    pub fn resolve_path(cli_path: Option<&Path>) -> (PathBuf, ConfigPathKind) {
        if let Some(p) = cli_path {
            (p.to_path_buf(), ConfigPathKind::Explicit)
        } else if let Ok(env_path) = env::var("INDENTURED_SERVER_CONFIG") {
            (PathBuf::from(env_path), ConfigPathKind::Env)
        } else {
            (PathBuf::from(DEFAULT_CONFIG_PATH), ConfigPathKind::Default)
        }
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(level) = env::var("INDENTURED_SERVER_LOG_LEVEL") {
            if !level.trim().is_empty() {
                self.logging.level = level;
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported schema_version {}, expected {}",
                self.schema_version, CONFIG_SCHEMA_VERSION
            )));
        }

        if !self.service.socket.enabled && !self.service.http.enabled {
            return Err(ConfigError::Invalid(
                "at least one of service.socket.enabled or service.http.enabled must be true"
                    .to_string(),
            ));
        }

        if self.service.socket.enabled {
            if let Some(group) = &self.service.socket.group {
                if group.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "service.socket.group must not be empty when set".to_string(),
                    ));
                }
            }

            if !self.service.socket.path.is_absolute() {
                return Err(ConfigError::Invalid(
                    "service.socket.path must be an absolute path".to_string(),
                ));
            }
            let parent = self.service.socket.path.parent();
            if matches!(
                parent,
                Some(path) if path == Path::new("/run")
                    || path == Path::new("/var/run")
                    || path == Path::new("/private/var/run")
            ) {
                return Err(ConfigError::Invalid(
                    "service.socket.path must use a dedicated protected runtime directory"
                        .to_string(),
                ));
            }

            self.service
                .socket
                .parse_mode()
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        }

        if self.service.http.enabled {
            if self.service.http.listen_addr.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "service.http.listen_addr must not be empty".to_string(),
                ));
            }

            if self.service.http.auth.required && self.service.http.auth.token_files.is_empty() {
                return Err(ConfigError::Invalid(
                    "service.http.auth.token_files must not be empty when auth is required"
                        .to_string(),
                ));
            }
            for path in &self.service.http.auth.token_files {
                if !path.is_absolute() {
                    return Err(ConfigError::Invalid(
                        "service.http.auth.token_files entries must be absolute paths".to_string(),
                    ));
                }
                let runtime_path = path.starts_with("/run")
                    || path.starts_with("/var/run")
                    || path.starts_with("/private/var/run");
                if path.starts_with("/nix/store") || !runtime_path {
                    return Err(ConfigError::Invalid(
                        "service.http.auth.token_files must reference /run, /var/run, or /private/var/run and never the Nix store"
                            .to_string(),
                    ));
                }
            }

            if self.service.http.auth.auth_type != "bearer" {
                return Err(ConfigError::Invalid(
                    "service.http.auth.type must be 'bearer'".to_string(),
                ));
            }

            if self.service.http.tls.enabled {
                for (field, path) in [
                    ("cert_path", self.service.http.tls.cert_path.as_deref()),
                    ("key_path", self.service.http.tls.key_path.as_deref()),
                ] {
                    let Some(path) = path else {
                        return Err(ConfigError::Invalid(format!(
                            "service.http.tls.{field} must be set when built-in TLS is enabled"
                        )));
                    };
                    if !path.is_absolute() {
                        return Err(ConfigError::Invalid(format!(
                            "service.http.tls.{field} must be an absolute path"
                        )));
                    }
                }
            }
        }

        if !self.build.workspace_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "build.workspace_root must be an absolute path".to_string(),
            ));
        }

        if self.service.max_concurrent_builds == 0 {
            return Err(ConfigError::Invalid(
                "service.max_concurrent_builds must be greater than zero".to_string(),
            ));
        }

        if self.build.max_timeout_sec == 0 {
            return Err(ConfigError::Invalid(
                "build.max_timeout_sec must be greater than zero".to_string(),
            ));
        }
        if self.build.max_output_bytes == 0 {
            return Err(ConfigError::Invalid(
                "build.max_output_bytes must be greater than zero".to_string(),
            ));
        }

        if self.sources.max_transfer_bytes == 0 {
            return Err(ConfigError::Invalid(
                "sources.max_transfer_bytes must be greater than zero".to_string(),
            ));
        }

        if self.sources.max_uncompressed_bytes == 0 {
            return Err(ConfigError::Invalid(
                "sources.max_uncompressed_bytes must be greater than zero".to_string(),
            ));
        }
        if self.sources.max_files == 0 || self.sources.max_depth == 0 {
            return Err(ConfigError::Invalid(
                "sources.max_files and sources.max_depth must be greater than zero".to_string(),
            ));
        }
        if self.sources.upload_timeout_sec == 0
            || self.sources.upload_timeout_sec > MAX_SOURCE_UPLOAD_TIMEOUT_SEC
        {
            return Err(ConfigError::Invalid(format!(
                "sources.upload_timeout_sec must be between 1 and {MAX_SOURCE_UPLOAD_TIMEOUT_SEC}"
            )));
        }

        if self.tasks.is_empty() {
            return Err(ConfigError::Invalid(
                "tasks must include at least one named task".to_string(),
            ));
        }

        let mut has_script_task = false;
        for (name, task) in &self.tasks {
            task.validate(name, self.build.max_timeout_sec)?;
            has_script_task |= task.script.is_some()
                || task
                    .setup
                    .as_ref()
                    .is_some_and(|setup| setup.script.is_some());
        }
        if has_script_task {
            validate_executable_file(Path::new(SCRIPT_SHELL), "script shell")?;
        }

        if let Some(user) = &self.build.run_as_user {
            if user.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.run_as_user must not be empty".to_string(),
                ));
            }
        }

        if let Some(group) = &self.build.run_as_group {
            if group.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.run_as_group must not be empty".to_string(),
                ));
            }
        }

        if self.service.socket.enabled {
            if self.build.run_as_user.is_none() {
                return Err(ConfigError::Invalid(
                    "enabled unauthenticated service.socket requires a dedicated build.run_as_user"
                        .to_string(),
                ));
            }
            let mode = self
                .service
                .socket
                .parse_mode()
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
            if mode & 0o077 != 0 || self.service.socket.group.is_some() {
                return Err(ConfigError::Invalid(
                    "service.socket must use no group and mode 0600 or stricter so the task identity cannot access it"
                        .to_string(),
                ));
            }
        }

        self.artifacts.validate()?;

        if let Err(err) = LoggingSettings::from_config(&self.logging) {
            return Err(ConfigError::Invalid(format!("{err}")));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    #[serde(default)]
    pub socket: SocketConfig,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default = "default_max_concurrent_builds")]
    pub max_concurrent_builds: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            socket: SocketConfig::default(),
            http: HttpConfig::default(),
            max_concurrent_builds: default_max_concurrent_builds(),
        }
    }
}

fn default_max_concurrent_builds() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketConfig {
    #[serde(default = "default_socket_enabled")]
    pub enabled: bool,

    #[serde(default = "default_socket_path")]
    pub path: PathBuf,

    #[serde(default)]
    pub group: Option<String>,

    #[serde(default = "default_socket_mode")]
    pub mode: String,
}

impl SocketConfig {
    pub fn parse_mode(&self) -> Result<u32, SocketModeError> {
        parse_socket_mode(&self.mode)
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            enabled: default_socket_enabled(),
            path: default_socket_path(),
            group: None,
            mode: default_socket_mode(),
        }
    }
}

fn default_socket_enabled() -> bool {
    false
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/indentured-server/control/server.sock")
}

fn default_socket_mode() -> String {
    "0600".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    #[serde(default = "default_http_enabled")]
    pub enabled: bool,

    #[serde(default = "default_http_listen")]
    pub listen_addr: String,

    #[serde(default)]
    pub auth: HttpAuthConfig,

    #[serde(default)]
    pub tls: HttpTlsConfig,
}

fn default_http_enabled() -> bool {
    false
}

fn default_http_listen() -> String {
    "127.0.0.1:8080".to_string()
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: default_http_enabled(),
            listen_addr: default_http_listen(),
            auth: HttpAuthConfig::default(),
            tls: HttpTlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpAuthConfig {
    #[serde(default = "default_http_auth_type", rename = "type")]
    pub auth_type: String,

    #[serde(default)]
    pub required: bool,

    #[serde(default)]
    pub token_files: Vec<PathBuf>,
}

fn default_http_auth_type() -> String {
    "bearer".to_string()
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            auth_type: default_http_auth_type(),
            required: false,
            token_files: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HttpTlsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    #[serde(default = "default_workspace_root")]
    pub workspace_root: PathBuf,

    #[serde(default = "default_max_timeout_sec")]
    pub max_timeout_sec: u64,

    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: u64,

    #[serde(default)]
    pub run_as_user: Option<String>,

    #[serde(default)]
    pub run_as_group: Option<String>,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            workspace_root: default_workspace_root(),
            max_timeout_sec: default_max_timeout_sec(),
            max_output_bytes: default_max_output_bytes(),
            run_as_user: None,
            run_as_group: None,
        }
    }
}

fn default_workspace_root() -> PathBuf {
    PathBuf::from("/var/lib/indentured-server/workspaces")
}

fn default_max_timeout_sec() -> u64 {
    1800
}

fn default_max_output_bytes() -> u64 {
    DEFAULT_OUTPUT_BYTES
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScriptText(String);

impl ScriptText {
    #[cfg(test)]
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ScriptText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScriptText(<redacted>)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskConfig {
    #[serde(default)]
    pub script: Option<ScriptText>,
    #[serde(default)]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub setup: Option<TaskSetupConfig>,
    pub cwd: String,
    pub timeout_sec: u64,
    pub environment: HashMap<String, String>,
    pub artifacts: ArtifactSpec,
    pub workspace: WorkspacePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSetupConfig {
    #[serde(default)]
    pub script: Option<ScriptText>,
    #[serde(default)]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspacePolicy {
    Fresh,
}

pub(crate) enum TaskExecution<'a> {
    Script(&'a str),
    Executable { path: &'a Path, args: &'a [String] },
}

impl TaskSetupConfig {
    pub(crate) fn execution(&self) -> TaskExecution<'_> {
        execution(&self.script, &self.executable, &self.args)
    }
}

impl TaskConfig {
    pub(crate) fn execution(&self) -> TaskExecution<'_> {
        execution(&self.script, &self.executable, &self.args)
    }

    fn validate(&self, name: &str, max_timeout_sec: u64) -> Result<(), ConfigError> {
        if !valid_task_id(name) {
            return Err(ConfigError::Invalid(format!(
                "task name {name:?} must match [A-Za-z0-9_-]+ and be at most 64 bytes"
            )));
        }
        validate_execution(
            &self.script,
            &self.executable,
            &self.args,
            &format!("tasks.{name}"),
            &self.environment,
        )?;
        validate_relative_path(&self.cwd, &format!("tasks.{name}.cwd"))
            .map_err(|err| ConfigError::Invalid(err.to_string()))?;
        if self.timeout_sec == 0 {
            return Err(ConfigError::Invalid(format!(
                "tasks.{name}.timeout_sec must be greater than zero"
            )));
        }
        let total_timeout = if let Some(setup) = &self.setup {
            validate_execution(
                &setup.script,
                &setup.executable,
                &setup.args,
                &format!("tasks.{name}.setup"),
                &self.environment,
            )?;
            if setup.timeout_sec == 0 {
                return Err(ConfigError::Invalid(format!(
                    "tasks.{name}.setup.timeout_sec must be greater than zero"
                )));
            }
            setup
                .timeout_sec
                .checked_add(self.timeout_sec)
                .ok_or_else(|| {
                    ConfigError::Invalid(format!("tasks.{name} phase timeouts overflow"))
                })?
        } else {
            self.timeout_sec
        };
        if total_timeout > max_timeout_sec {
            let message = if self.setup.is_some() {
                format!(
                    "tasks.{name} setup and run timeouts must total no more than build.max_timeout_sec ({max_timeout_sec})"
                )
            } else {
                format!(
                    "tasks.{name}.timeout_sec must be between 1 and build.max_timeout_sec ({max_timeout_sec})"
                )
            };
            return Err(ConfigError::Invalid(message));
        }
        for arg in &self.args {
            if arg.contains('\0') {
                return Err(ConfigError::Invalid(format!(
                    "tasks.{name}.args must not contain NUL"
                )));
            }
        }
        if let Some(setup) = &self.setup {
            for arg in &setup.args {
                if arg.contains('\0') {
                    return Err(ConfigError::Invalid(format!(
                        "tasks.{name}.setup.args must not contain NUL"
                    )));
                }
            }
        }
        for (key, value) in &self.environment {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                return Err(ConfigError::Invalid(format!(
                    "tasks.{name}.environment contains an invalid key or value"
                )));
            }
        }
        for (field, patterns) in [
            ("include", &self.artifacts.include),
            ("exclude", &self.artifacts.exclude),
        ] {
            for pattern in patterns {
                validate_relative_pattern(pattern, &format!("tasks.{name}.artifacts.{field}"))
                    .map_err(|err| ConfigError::Invalid(err.to_string()))?;
                glob::Pattern::new(pattern).map_err(|err| {
                    ConfigError::Invalid(format!(
                        "invalid glob in tasks.{name}.artifacts.{field} {pattern:?}: {err}"
                    ))
                })?;
            }
        }
        Ok(())
    }
}

fn execution<'a>(
    script: &'a Option<ScriptText>,
    executable: &'a Option<PathBuf>,
    args: &'a [String],
) -> TaskExecution<'a> {
    match (script, executable) {
        (Some(script), None) if args.is_empty() => TaskExecution::Script(script.as_str()),
        (None, Some(path)) => TaskExecution::Executable { path, args },
        _ => unreachable!("task execution shape must be validated at startup"),
    }
}

fn validate_execution(
    script: &Option<ScriptText>,
    executable: &Option<PathBuf>,
    args: &[String],
    field: &str,
    environment: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    match (script, executable) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(ConfigError::Invalid(format!(
                "{field} must define exactly one of script or executable"
            )));
        }
        (Some(script), None) => {
            if !args.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "{field}.args must be empty when script is set"
                )));
            }
            validate_script(script, field, environment)?;
        }
        (None, Some(executable)) => {
            validate_executable_file(executable, &format!("{field}.executable"))?
        }
    }
    Ok(())
}

fn validate_script(
    script: &ScriptText,
    field: &str,
    environment: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    let value = script.as_str();
    if value.is_empty() || value.len() > MAX_TASK_SCRIPT_BYTES || value.trim().is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{field}.script must contain 1 to {MAX_TASK_SCRIPT_BYTES} bytes of non-whitespace text"
        )));
    }
    if value.contains('\0') {
        return Err(ConfigError::Invalid(format!(
            "{field}.script must not contain NUL"
        )));
    }
    let environment_field = field.strip_suffix(".setup").unwrap_or(field);
    let path = environment.get("PATH").ok_or_else(|| {
        ConfigError::Invalid(format!(
            "{environment_field}.environment.PATH is required for script tasks"
        ))
    })?;
    if path.is_empty()
        || path
            .split(':')
            .any(|component| component.is_empty() || !Path::new(component).is_absolute())
    {
        return Err(ConfigError::Invalid(format!(
            "{environment_field}.environment.PATH must contain only nonempty absolute components"
        )));
    }
    Ok(())
}

fn validate_executable_file(path: &Path, field: &str) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::Invalid(format!(
            "{field} must be an absolute path"
        )));
    }
    let metadata = std::fs::metadata(path).map_err(|err| {
        ConfigError::Invalid(format!("{field} is not accessible at {path:?}: {err}"))
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be an executable regular file"
        )));
    }
    Ok(())
}

fn parse_error_location(raw: &str, offset: Option<usize>) -> (Option<usize>, Option<usize>) {
    let Some(offset) = offset.filter(|offset| *offset <= raw.len()) else {
        return (None, None);
    };
    let prefix = &raw[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let column = raw[line_start..offset].chars().count() + 1;
    (Some(line), Some(column))
}

fn format_parse_location(line: Option<usize>, column: Option<usize>) -> String {
    match (line, column) {
        (Some(line), Some(column)) => format!(" at line {line}, column {column}"),
        _ => String::new(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactsConfig {
    #[serde(default)]
    pub storage_root: PathBuf,

    #[serde(default)]
    pub ttl_sec: Option<u64>,

    #[serde(default)]
    pub gc_interval_sec: Option<u64>,

    #[serde(default)]
    pub max_bytes: Option<u64>,

    #[serde(default = "default_artifact_transfer_bytes")]
    pub max_transfer_bytes: u64,

    #[serde(default = "default_artifact_uncompressed_bytes")]
    pub max_uncompressed_bytes: u64,

    #[serde(default = "default_artifact_max_files")]
    pub max_files: usize,

    #[serde(default = "default_artifact_max_depth")]
    pub max_depth: usize,

    #[serde(default)]
    pub restricted_patterns: Vec<String>,
}

impl Default for ArtifactsConfig {
    fn default() -> Self {
        Self {
            storage_root: PathBuf::new(),
            ttl_sec: None,
            gc_interval_sec: None,
            max_bytes: None,
            max_transfer_bytes: default_artifact_transfer_bytes(),
            max_uncompressed_bytes: default_artifact_uncompressed_bytes(),
            max_files: default_artifact_max_files(),
            max_depth: default_artifact_max_depth(),
            restricted_patterns: Vec::new(),
        }
    }
}

impl ArtifactsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.storage_root.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "artifacts.storage_root must not be empty".to_string(),
            ));
        }

        if !self.storage_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "artifacts.storage_root must be an absolute path".to_string(),
            ));
        }

        if let Some(ttl) = self.ttl_sec {
            if ttl == 0 {
                return Err(ConfigError::Invalid(
                    "artifacts.ttl_sec must be greater than zero".to_string(),
                ));
            }
        }

        if let Some(interval) = self.gc_interval_sec {
            if interval == 0 {
                return Err(ConfigError::Invalid(
                    "artifacts.gc_interval_sec must be greater than zero".to_string(),
                ));
            }
        }

        if let Some(max_bytes) = self.max_bytes {
            if max_bytes == 0 {
                return Err(ConfigError::Invalid(
                    "artifacts.max_bytes must be greater than zero".to_string(),
                ));
            }
        }

        if self.max_transfer_bytes == 0
            || self.max_uncompressed_bytes == 0
            || self.max_files == 0
            || self.max_depth == 0
        {
            return Err(ConfigError::Invalid(
                "artifact transfer, uncompressed, file-count, and depth limits must be greater than zero"
                    .to_string(),
            ));
        }

        for pattern in &self.restricted_patterns {
            validate_relative_pattern(pattern, "artifacts.restricted_patterns")
                .map_err(|err| ConfigError::Invalid(err.to_string()))?;
            glob::Pattern::new(pattern).map_err(|err| {
                ConfigError::Invalid(format!(
                    "invalid glob pattern in artifacts.restricted_patterns {pattern:?}: {err}"
                ))
            })?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub directory: Option<PathBuf>,

    #[serde(default = "default_logging_level")]
    pub level: String,

    #[serde(default = "default_logging_max_bytes")]
    pub max_bytes: u64,

    #[serde(default = "default_logging_max_files")]
    pub max_files: usize,

    #[serde(default = "default_logging_console")]
    pub console: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesConfig {
    #[serde(default = "default_source_transfer_bytes")]
    pub max_transfer_bytes: u64,

    #[serde(default = "default_source_uncompressed_bytes")]
    pub max_uncompressed_bytes: u64,

    #[serde(default = "default_source_max_files")]
    pub max_files: usize,

    #[serde(default = "default_source_max_depth")]
    pub max_depth: usize,

    #[serde(default = "default_source_upload_timeout_sec")]
    pub upload_timeout_sec: u64,
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self {
            max_transfer_bytes: default_source_transfer_bytes(),
            max_uncompressed_bytes: default_source_uncompressed_bytes(),
            max_files: default_source_max_files(),
            max_depth: default_source_max_depth(),
            upload_timeout_sec: default_source_upload_timeout_sec(),
        }
    }
}

fn default_source_transfer_bytes() -> u64 {
    DEFAULT_SOURCE_TRANSFER_BYTES
}

fn default_source_uncompressed_bytes() -> u64 {
    DEFAULT_SOURCE_UNCOMPRESSED_BYTES
}

fn default_source_max_files() -> usize {
    DEFAULT_SOURCE_MAX_FILES
}

fn default_source_max_depth() -> usize {
    DEFAULT_SOURCE_MAX_DEPTH
}

fn default_source_upload_timeout_sec() -> u64 {
    DEFAULT_SOURCE_UPLOAD_TIMEOUT_SEC
}

fn default_artifact_transfer_bytes() -> u64 {
    DEFAULT_ARTIFACT_TRANSFER_BYTES
}

fn default_artifact_uncompressed_bytes() -> u64 {
    DEFAULT_ARTIFACT_UNCOMPRESSED_BYTES
}

fn default_artifact_max_files() -> usize {
    DEFAULT_ARTIFACT_MAX_FILES
}

fn default_artifact_max_depth() -> usize {
    DEFAULT_ARTIFACT_MAX_DEPTH
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            directory: None,
            level: default_logging_level(),
            max_bytes: default_logging_max_bytes(),
            max_files: default_logging_max_files(),
            console: default_logging_console(),
        }
    }
}

fn default_logging_level() -> String {
    "info".to_string()
}

fn default_logging_max_bytes() -> u64 {
    104_857_600
}

fn default_logging_max_files() -> usize {
    5
}

fn default_logging_console() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum SocketModeError {
    #[error("socket mode must be a 4-digit octal string")]
    InvalidLength,

    #[error("socket mode must be octal digits")]
    InvalidDigit,
}

fn parse_socket_mode(mode: &str) -> Result<u32, SocketModeError> {
    let value = mode.trim();
    if value.len() != 4 {
        return Err(SocketModeError::InvalidLength);
    }

    let digits = value.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }

    let parsed = u32::from_str_radix(digits, 8).map_err(|_| SocketModeError::InvalidDigit)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(executable: PathBuf) -> TaskConfig {
        TaskConfig {
            script: None,
            executable: Some(executable),
            args: vec!["fixed".to_string()],
            setup: None,
            cwd: ".".to_string(),
            timeout_sec: 30,
            environment: HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]),
            artifacts: ArtifactSpec {
                include: vec!["out/**".to_string()],
                exclude: Vec::new(),
            },
            workspace: WorkspacePolicy::Fresh,
        }
    }

    fn valid_config(temp: &Path) -> Config {
        let artifacts = ArtifactsConfig {
            storage_root: temp.join("artifacts"),
            ..ArtifactsConfig::default()
        };
        let mut service = ServiceConfig::default();
        service.http.enabled = true;
        Config {
            schema_version: CONFIG_SCHEMA_VERSION.to_string(),
            service,
            build: BuildConfig {
                workspace_root: temp.join("workspaces"),
                ..BuildConfig::default()
            },
            tasks: HashMap::from([(
                "build".to_string(),
                task(std::env::current_exe().expect("current executable")),
            )]),
            sources: SourcesConfig::default(),
            artifacts,
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn parse_socket_mode_accepts_octal() {
        assert_eq!(parse_socket_mode("0660").unwrap(), 0o660);
    }

    #[test]
    fn strict_config_rejects_legacy_authority_sections() {
        let raw = r#"
schema_version = "7"
tasks = {}
[build]
commands = { make = "/usr/bin/make" }
"#;
        assert!(toml::from_str::<Config>(raw).is_err());
    }

    #[test]
    fn strict_config_rejects_inline_tokens_and_enforces_hardening_defaults() {
        let raw = r#"
schema_version = "7"
tasks = {}
[service.http]
enabled = true
[service.http.auth]
required = true
tokens = ["secret"]
"#;
        assert!(toml::from_str::<Config>(raw).is_err());
        let service = ServiceConfig::default();
        assert!(!service.socket.enabled);
        assert_eq!(service.http.listen_addr, "127.0.0.1:8080");
        assert_eq!(service.max_concurrent_builds, 1);
        assert!(ArtifactsConfig::default().max_transfer_bytes > 0);
        assert!(ArtifactsConfig::default().max_files > 0);
        assert_eq!(SourcesConfig::default().upload_timeout_sec, 120);

        let temp = tempfile::tempdir().unwrap();
        let mut config = valid_config(temp.path());
        config.service.socket.enabled = false;
        config.service.http.enabled = true;
        config.service.http.auth.required = true;
        config.service.http.auth.token_files = vec![temp.path().join("repo-token")];
        assert!(config.validate().unwrap_err().to_string().contains("/run"));
    }

    #[test]
    fn validates_complete_named_task_policy() {
        let temp = tempfile::tempdir().expect("tempdir");
        valid_config(temp.path()).validate().expect("valid config");
    }

    #[test]
    fn rejects_relative_executable_invalid_cwd_timeout_env_and_glob() {
        let temp = tempfile::tempdir().expect("tempdir");
        type TaskMutation = Box<dyn Fn(&mut TaskConfig)>;
        let cases: Vec<TaskMutation> = vec![
            Box::new(|task| task.executable = Some(PathBuf::from("bin/build"))),
            Box::new(|task| task.cwd = "../outside".to_string()),
            Box::new(|task| task.timeout_sec = 0),
            Box::new(|task| {
                task.environment
                    .insert("BAD=KEY".to_string(), "x".to_string());
            }),
            Box::new(|task| task.artifacts.include = vec!["../secret".to_string()]),
        ];
        for mutate in cases {
            let mut config = valid_config(temp.path());
            mutate(config.tasks.get_mut("build").unwrap());
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn every_enabled_uds_requires_an_isolated_task_identity_and_owner_only_mode() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = valid_config(temp.path());
        config.service.socket.enabled = true;
        config.build.run_as_user = None;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("dedicated build.run_as_user"));

        config.build.run_as_user = Some("dedicated-task".to_string());
        config.service.socket.group = Some("task-group".to_string());
        config.service.socket.mode = "0660".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mode 0600"));

        config.service.socket.group = None;
        config.service.socket.mode = "0601".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_task_timeout_over_server_maximum() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = valid_config(temp.path());
        config.build.max_timeout_sec = 10;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("timeout_sec"));
    }

    #[test]
    fn setup_and_run_timeouts_share_the_server_maximum() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = valid_config(temp.path());
        config.build.max_timeout_sec = 40;
        config.tasks.get_mut("build").unwrap().setup = Some(TaskSetupConfig {
            script: Some(ScriptText::new("printf setup")),
            executable: None,
            args: Vec::new(),
            timeout_sec: 10,
        });
        config.validate().expect("10 + 30 fits the maximum");

        config
            .tasks
            .get_mut("build")
            .unwrap()
            .setup
            .as_mut()
            .unwrap()
            .timeout_sec = 11;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("must total no more"));
    }

    #[test]
    fn rejects_invalid_upload_deadlines_and_legacy_tls_ca_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        for value in [0, MAX_SOURCE_UPLOAD_TIMEOUT_SEC + 1] {
            let mut config = valid_config(temp.path());
            config.sources.upload_timeout_sec = value;
            assert!(config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("sources.upload_timeout_sec"));
        }

        let legacy = r#"
schema_version = "7"
tasks = {}
[service.http]
enabled = true
[service.http.tls]
enabled = false
ca_path = "/etc/indentured-server/client-ca.pem"
"#;
        assert!(toml::from_str::<Config>(legacy).is_err());
    }

    #[test]
    fn built_in_tls_requires_absolute_server_certificate_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = valid_config(temp.path());
        config.service.http.tls.enabled = true;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cert_path"));
        config.service.http.tls.cert_path = Some(PathBuf::from("relative-cert.pem"));
        config.service.http.tls.key_path = Some(PathBuf::from("/run/server-key.pem"));
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("absolute"));
        config.service.http.tls.cert_path = Some(PathBuf::from("/run/server-cert.pem"));
        config.validate().expect("absolute server TLS paths");
    }

    fn script_task(value: impl Into<String>) -> TaskConfig {
        TaskConfig {
            script: Some(ScriptText::new(value)),
            executable: None,
            args: Vec::new(),
            setup: None,
            cwd: ".".to_string(),
            timeout_sec: 30,
            environment: HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]),
            artifacts: ArtifactSpec::default(),
            workspace: WorkspacePolicy::Fresh,
        }
    }

    #[test]
    fn schema_seven_deserializes_multiline_scripts_and_both_legal_shapes() {
        let current_exe = std::env::current_exe().unwrap();
        let raw = format!(
            r#"schema_version = "7"
[service.http]
enabled = true
[build]
workspace_root = "/tmp/workspaces"
[tasks.script]
script = '''
printf 'one\n'
printf 'two\n'
'''
cwd = "."
timeout_sec = 30
workspace = "fresh"
[tasks.script.environment]
PATH = "/usr/bin:/bin"
[tasks.script.artifacts]
include = []
exclude = []
[tasks.script.setup]
script = "printf setup"
timeout_sec = 10
[tasks.compat]
executable = "{}"
args = ["fixed"]
cwd = "."
timeout_sec = 30
workspace = "fresh"
[tasks.compat.environment]
[tasks.compat.artifacts]
include = []
exclude = []
[artifacts]
storage_root = "/tmp/artifacts"
"#,
            current_exe.display()
        );
        let config: Config = toml::from_str(&raw).unwrap();
        assert!(matches!(
            config.tasks["script"].execution(),
            TaskExecution::Script(script) if script.contains("printf 'two")
        ));
        assert!(matches!(
            config.tasks["script"].setup.as_ref().unwrap().execution(),
            TaskExecution::Script("printf setup")
        ));
        assert!(matches!(
            config.tasks["compat"].execution(),
            TaskExecution::Executable { .. }
        ));
        config.validate().unwrap();
    }

    #[test]
    fn old_and_future_schema_versions_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        for version in ["6", "8"] {
            let mut config = valid_config(temp.path());
            config.schema_version = version.to_string();
            assert!(config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("schema_version"));
        }
    }

    #[test]
    fn execution_shapes_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let cases = [
            TaskConfig {
                script: None,
                executable: None,
                args: Vec::new(),
                ..script_task("true")
            },
            TaskConfig {
                executable: Some(executable),
                ..script_task("true")
            },
            TaskConfig {
                args: vec!["not-allowed".to_string()],
                ..script_task("true")
            },
            TaskConfig {
                script: None,
                executable: None,
                args: vec!["orphan".to_string()],
                ..script_task("true")
            },
        ];
        for invalid in cases {
            let mut config = valid_config(temp.path());
            config.tasks.insert("build".to_string(), invalid);
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn script_content_bounds_and_path_are_strict() {
        let temp = tempfile::tempdir().unwrap();
        for invalid in [
            "".to_string(),
            " \n\t".to_string(),
            "a\0b".to_string(),
            "x".repeat(MAX_TASK_SCRIPT_BYTES + 1),
        ] {
            let mut config = valid_config(temp.path());
            config
                .tasks
                .insert("build".to_string(), script_task(invalid));
            assert!(config.validate().is_err());
        }

        let mut config = valid_config(temp.path());
        config.tasks.insert(
            "build".to_string(),
            script_task("x".repeat(MAX_TASK_SCRIPT_BYTES)),
        );
        config.validate().unwrap();

        for path in [
            None,
            Some(""),
            Some(":/bin"),
            Some("/bin:"),
            Some("."),
            Some("bin:/usr/bin"),
        ] {
            let mut config = valid_config(temp.path());
            let mut task = script_task("true");
            match path {
                Some(value) => {
                    task.environment
                        .insert("PATH".to_string(), value.to_string());
                }
                None => {
                    task.environment.remove("PATH");
                }
            }
            config.tasks.insert("build".to_string(), task);
            assert!(config.validate().is_err(), "PATH case {path:?}");
        }
    }

    #[test]
    fn shared_executable_validation_accepts_script_shell_and_rejects_nonexecutables() {
        validate_executable_file(Path::new(SCRIPT_SHELL), "script shell").unwrap();
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut permissions = temp.as_file().metadata().unwrap().permissions();
        permissions.set_mode(0o600);
        temp.as_file().set_permissions(permissions).unwrap();
        assert!(validate_executable_file(temp.path(), "test executable").is_err());
    }

    #[test]
    fn script_and_config_debug_are_redacted() {
        let temp = tempfile::tempdir().unwrap();
        let marker = "unique-script-debug-secret";
        let task = script_task(format!("printf {marker}"));
        assert!(!format!("{task:?}").contains(marker));
        let mut config = valid_config(temp.path());
        config.tasks.insert("build".to_string(), task);
        assert!(!format!("{config:?}").contains(marker));
        assert_eq!(
            format!("{:?}", ScriptText::new(marker)),
            "ScriptText(<redacted>)"
        );
    }

    #[test]
    fn malformed_toml_errors_do_not_reproduce_source_values() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret-config.toml");
        let marker = "unique-malformed-script-secret";
        std::fs::write(
            &path,
            format!("schema_version = \"6\"\nscript = \"{marker}\" unexpected\n"),
        )
        .unwrap();
        let error = Config::load_from_sources(Some(&path)).unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("line"));
        assert!(!display.contains(marker), "{display}");
        assert!(!debug.contains(marker), "{debug}");
    }
}
