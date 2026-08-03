use serde::{Deserialize, Serialize};

pub const REQUEST_SCHEMA_VERSION: &str = "1";
pub const SESSION_REQUEST_SCHEMA_VERSION: &str = "1";
pub const MAX_REQUEST_ID_LEN: usize = 128;
pub const MAX_TASK_ID_LEN: usize = 64;
pub const MAX_SESSION_ID_LEN: usize = 128;
pub const MAX_ACTION_ID_LEN: usize = 128;
pub const MAX_SESSION_ACTION_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub task: String,
    pub source: SourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMetadata {
    pub format: SourceFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStartRequest {
    pub schema_version: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub task: String,
    pub source: SourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionActionRequest {
    pub schema_version: String,
    pub input: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Zip,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("metadata must be a JSON object")]
    NotObject,
    #[error("missing schema_version")]
    MissingSchemaVersion,
    #[error("schema_version must be a string")]
    InvalidSchemaVersionType,
    #[error("unsupported schema_version {0}")]
    UnsupportedSchemaVersion(String),
    #[error("invalid metadata json: {0}")]
    InvalidJson(String),
    #[error("task must be 1..={MAX_TASK_ID_LEN} ASCII letters, digits, '_' or '-'")]
    InvalidTask,
    #[error("request_id must be 1..={MAX_REQUEST_ID_LEN} ASCII letters, digits, '_', '-' or '.'")]
    InvalidRequestId,
}

pub fn parse_request_metadata(data: &[u8]) -> Result<Request, RequestError> {
    let value: serde_json::Value =
        serde_json::from_slice(data).map_err(|err| RequestError::InvalidJson(err.to_string()))?;
    let object = value.as_object().ok_or(RequestError::NotObject)?;
    let version = object
        .get("schema_version")
        .ok_or(RequestError::MissingSchemaVersion)?
        .as_str()
        .ok_or(RequestError::InvalidSchemaVersionType)?;
    if version != REQUEST_SCHEMA_VERSION {
        return Err(RequestError::UnsupportedSchemaVersion(version.to_string()));
    }

    let request: Request =
        serde_json::from_value(value).map_err(|err| RequestError::InvalidJson(err.to_string()))?;
    validate_identifier(&request.task, MAX_TASK_ID_LEN, false)
        .map_err(|_| RequestError::InvalidTask)?;
    if let Some(request_id) = &request.request_id {
        validate_identifier(request_id, MAX_REQUEST_ID_LEN, true)
            .map_err(|_| RequestError::InvalidRequestId)?;
    }
    Ok(request)
}

pub fn parse_session_start_metadata(data: &[u8]) -> Result<SessionStartRequest, RequestError> {
    let value: serde_json::Value =
        serde_json::from_slice(data).map_err(|err| RequestError::InvalidJson(err.to_string()))?;
    let object = value.as_object().ok_or(RequestError::NotObject)?;
    let version = object
        .get("schema_version")
        .ok_or(RequestError::MissingSchemaVersion)?
        .as_str()
        .ok_or(RequestError::InvalidSchemaVersionType)?;
    if version != SESSION_REQUEST_SCHEMA_VERSION {
        return Err(RequestError::UnsupportedSchemaVersion(version.to_string()));
    }

    let request: SessionStartRequest =
        serde_json::from_value(value).map_err(|err| RequestError::InvalidJson(err.to_string()))?;
    validate_identifier(&request.task, MAX_TASK_ID_LEN, false)
        .map_err(|_| RequestError::InvalidTask)?;
    if let Some(request_id) = &request.request_id {
        validate_identifier(request_id, MAX_REQUEST_ID_LEN, true)
            .map_err(|_| RequestError::InvalidRequestId)?;
    }
    Ok(request)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionActionRequestError {
    #[error("action body exceeds {MAX_SESSION_ACTION_BODY_BYTES} bytes")]
    TooLarge,
    #[error("action body must be a JSON object")]
    NotObject,
    #[error("missing schema_version")]
    MissingSchemaVersion,
    #[error("schema_version must be a string")]
    InvalidSchemaVersionType,
    #[error("unsupported schema_version {0}")]
    UnsupportedSchemaVersion(String),
    #[error("missing input")]
    MissingInput,
    #[error("input must be a JSON object")]
    InputNotObject,
    #[error("invalid action json: {0}")]
    InvalidJson(String),
}

pub fn parse_session_action_request(
    data: &[u8],
) -> Result<SessionActionRequest, SessionActionRequestError> {
    if data.len() > MAX_SESSION_ACTION_BODY_BYTES {
        return Err(SessionActionRequestError::TooLarge);
    }
    let value: serde_json::Value = serde_json::from_slice(data)
        .map_err(|err| SessionActionRequestError::InvalidJson(err.to_string()))?;
    let object = value
        .as_object()
        .ok_or(SessionActionRequestError::NotObject)?;
    let version = object
        .get("schema_version")
        .ok_or(SessionActionRequestError::MissingSchemaVersion)?
        .as_str()
        .ok_or(SessionActionRequestError::InvalidSchemaVersionType)?;
    if version != SESSION_REQUEST_SCHEMA_VERSION {
        return Err(SessionActionRequestError::UnsupportedSchemaVersion(
            version.to_string(),
        ));
    }
    let input = object
        .get("input")
        .ok_or(SessionActionRequestError::MissingInput)?;
    if !input.is_object() {
        return Err(SessionActionRequestError::InputNotObject);
    }
    serde_json::from_value(value)
        .map_err(|err| SessionActionRequestError::InvalidJson(err.to_string()))
}

pub fn valid_task_id(value: &str) -> bool {
    validate_identifier(value, MAX_TASK_ID_LEN, false).is_ok()
}

pub fn valid_session_id(value: &str) -> bool {
    validate_identifier(value, MAX_SESSION_ID_LEN, false).is_ok()
}

pub fn valid_action_id(value: &str) -> bool {
    validate_identifier(value, MAX_ACTION_ID_LEN, false).is_ok()
}

fn validate_identifier(value: &str, max_len: usize, allow_dot: bool) -> Result<(), ()> {
    if value.is_empty() || value.len() > max_len {
        return Err(());
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || (allow_dot && byte == b'.')
    }) {
        Ok(())
    } else {
        Err(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactArchive {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildPhase {
    Setup,
    Run,
}

impl BuildPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Run => "run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseResult {
    pub phase: BuildPhase,
    pub duration_ms: u64,
    pub exit_code: i32,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRestrictions {
    pub omitted_count: usize,
    pub matched_patterns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStartStatus {
    Started,
    PhaseStarted,
    PhaseFinished,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionStartEvent {
    Session {
        id: String,
        status: SessionStartStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<BuildPhase>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timed_out: Option<bool>,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<BuildPhase>,
    },
    Ready {
        session_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        phases: Vec<PhaseResult>,
    },
    Exit {
        code: i32,
        timed_out: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        failed_phase: Option<BuildPhase>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        phases: Vec<PhaseResult>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionActionStatus {
    Started,
    Snapshotting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionActionEvent {
    Action {
        session_id: String,
        action_id: String,
        action: String,
        status: SessionActionStatus,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    Exit {
        session_id: String,
        action_id: String,
        action: String,
        code: i32,
        timed_out: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifacts: Option<ArtifactArchive>,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact_restrictions: Option<ArtifactRestrictions>,
    },
}

pub(crate) struct SessionActionStreamItem {
    pub(crate) event: SessionActionEvent,
    pub(crate) final_ack: Option<std::sync::mpsc::SyncSender<bool>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTeardownResult {
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStopResponse {
    pub session_id: String,
    pub teardown: SessionTeardownResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<ArtifactArchive>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_restrictions: Option<ArtifactRestrictions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResponseEvent {
    Build {
        id: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<BuildPhase>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timed_out: Option<bool>,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<BuildPhase>,
    },
    Exit {
        code: i32,
        timed_out: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifacts: Option<ArtifactArchive>,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact_restrictions: Option<ArtifactRestrictions>,
        #[serde(skip_serializing_if = "Option::is_none")]
        failed_phase: Option<BuildPhase>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        phases: Vec<PhaseResult>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": "1",
            "request_id": "req.1",
            "task": "build",
            "source": { "format": "zip" }
        })
    }

    #[test]
    fn strict_v1_request_parses() {
        let request = parse_request_metadata(&serde_json::to_vec(&valid_json()).unwrap()).unwrap();
        assert_eq!(request.task, "build");
        assert_eq!(request.source.format, SourceFormat::Zip);
    }

    #[test]
    fn missing_legacy_and_future_versions_fail_closed() {
        let mut missing = valid_json();
        missing.as_object_mut().unwrap().remove("schema_version");
        assert_eq!(
            parse_request_metadata(&serde_json::to_vec(&missing).unwrap()).unwrap_err(),
            RequestError::MissingSchemaVersion
        );

        for version in ["3", "2", "999"] {
            let mut value = valid_json();
            value["schema_version"] = serde_json::Value::String(version.to_string());
            assert!(matches!(
                parse_request_metadata(&serde_json::to_vec(&value).unwrap()),
                Err(RequestError::UnsupportedSchemaVersion(found)) if found == version
            ));
        }
    }

    #[test]
    fn every_legacy_authority_field_is_rejected() {
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
            let mut value = valid_json();
            value[field] = serde_json::json!("override");
            let err = parse_request_metadata(&serde_json::to_vec(&value).unwrap()).unwrap_err();
            assert!(
                matches!(err, RequestError::InvalidJson(_)),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn unknown_source_fields_and_invalid_identifiers_are_rejected() {
        let mut nested = valid_json();
        nested["source"]["path"] = serde_json::json!("/tmp/override");
        assert!(matches!(
            parse_request_metadata(&serde_json::to_vec(&nested).unwrap()),
            Err(RequestError::InvalidJson(_))
        ));

        for task in ["", "../build", "bad task"] {
            let mut value = valid_json();
            value["task"] = serde_json::json!(task);
            assert_eq!(
                parse_request_metadata(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
                RequestError::InvalidTask
            );
        }
    }

    #[test]
    fn response_event_serialization() {
        let event = ResponseEvent::Stdout {
            data: "hello".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert_eq!(json, "{\"type\":\"stdout\",\"data\":\"hello\"}");
    }

    #[test]
    fn phase_fields_are_additive_to_existing_response_events() {
        let old_exit: ResponseEvent =
            serde_json::from_str(r#"{"type":"exit","code":0,"timed_out":false}"#).unwrap();
        assert!(matches!(
            old_exit,
            ResponseEvent::Exit {
                failed_phase: None,
                phases,
                ..
            } if phases.is_empty()
        ));

        let event = ResponseEvent::Build {
            id: "bld_123".to_string(),
            status: "phase_finished".to_string(),
            phase: Some(BuildPhase::Setup),
            duration_ms: Some(42),
            exit_code: Some(0),
            timed_out: Some(false),
        };
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["type"], "build");
        assert_eq!(value["phase"], "setup");
        assert_eq!(value["duration_ms"], 42);
    }

    #[test]
    fn one_shot_request_wire_shape_is_unchanged() {
        let request = Request {
            schema_version: REQUEST_SCHEMA_VERSION.to_string(),
            request_id: Some("req.1".to_string()),
            task: "build".to_string(),
            source: SourceMetadata {
                format: SourceFormat::Zip,
            },
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"schema_version":"1","request_id":"req.1","task":"build","source":{"format":"zip"}}"#
        );
        let exit = ResponseEvent::Exit {
            code: 0,
            timed_out: false,
            artifacts: None,
            artifact_restrictions: None,
            failed_phase: None,
            phases: Vec::new(),
        };
        assert_eq!(
            serde_json::to_string(&exit).unwrap(),
            r#"{"type":"exit","code":0,"timed_out":false}"#
        );
    }

    #[test]
    fn strict_session_start_metadata_is_separate_from_build_request() {
        let value = serde_json::json!({
            "schema_version": SESSION_REQUEST_SCHEMA_VERSION,
            "request_id": "session.1",
            "task": "build",
            "source": { "format": "zip" }
        });
        let request =
            parse_session_start_metadata(&serde_json::to_vec(&value).unwrap()).expect("valid");
        assert_eq!(request.task, "build");

        for field in [
            "argv",
            "environment",
            "cwd",
            "timeout_sec",
            "artifacts",
            "path",
        ] {
            let mut invalid = value.clone();
            invalid[field] = serde_json::json!("override");
            assert!(matches!(
                parse_session_start_metadata(&serde_json::to_vec(&invalid).unwrap()),
                Err(RequestError::InvalidJson(_))
            ));
        }

        let mut future = value;
        future["schema_version"] = serde_json::json!("2");
        assert!(matches!(
            parse_session_start_metadata(&serde_json::to_vec(&future).unwrap()),
            Err(RequestError::UnsupportedSchemaVersion(version)) if version == "2"
        ));
    }

    fn action_body_with_size(size: usize) -> Vec<u8> {
        let prefix = br#"{"schema_version":"1","input":{"data":""#;
        let suffix = br#""}}"#;
        assert!(size >= prefix.len() + suffix.len());
        let mut body = Vec::with_capacity(size);
        body.extend_from_slice(prefix);
        body.extend(std::iter::repeat_n(
            b'x',
            size - prefix.len() - suffix.len(),
        ));
        body.extend_from_slice(suffix);
        body
    }

    #[test]
    fn session_action_body_is_strict_and_bounded() {
        let maximum = action_body_with_size(MAX_SESSION_ACTION_BODY_BYTES);
        let parsed = parse_session_action_request(&maximum).expect("exact maximum is accepted");
        assert_eq!(
            parsed.input["data"].as_str().unwrap().len(),
            MAX_SESSION_ACTION_BODY_BYTES
                - br#"{"schema_version":"1","input":{"data":""#.len()
                - br#""}}"#.len()
        );
        assert_eq!(
            parse_session_action_request(&action_body_with_size(MAX_SESSION_ACTION_BODY_BYTES + 1))
                .unwrap_err(),
            SessionActionRequestError::TooLarge
        );

        for body in ["[]", r#"{"schema_version":"1","input":[]}"#] {
            assert!(parse_session_action_request(body.as_bytes()).is_err());
        }
        for field in [
            "argv",
            "environment",
            "cwd",
            "timeout_sec",
            "artifacts",
            "path",
            "unknown",
        ] {
            let mut value = serde_json::json!({
                "schema_version": SESSION_REQUEST_SCHEMA_VERSION,
                "input": {"operator_data": true}
            });
            value[field] = serde_json::json!("override");
            assert!(matches!(
                parse_session_action_request(&serde_json::to_vec(&value).unwrap()),
                Err(SessionActionRequestError::InvalidJson(_))
            ));
        }

        let input_authority_words_are_data =
            br#"{"schema_version":"1","input":{"argv":["data"],"timeout_sec":1}}"#;
        assert!(parse_session_action_request(input_authority_words_are_data).is_ok());
    }

    #[test]
    fn opaque_session_and_action_identifiers_are_bounded() {
        assert!(valid_session_id("ses_123"));
        assert!(valid_action_id("act-123"));
        assert!(valid_session_id(&"s".repeat(MAX_SESSION_ID_LEN)));
        assert!(valid_action_id(&"a".repeat(MAX_ACTION_ID_LEN)));
        for invalid in ["", "../session", "session.id", "bad session"] {
            assert!(!valid_session_id(invalid));
            assert!(!valid_action_id(invalid));
        }
        assert!(!valid_session_id(&"s".repeat(MAX_SESSION_ID_LEN + 1)));
        assert!(!valid_action_id(&"a".repeat(MAX_ACTION_ID_LEN + 1)));
    }

    #[test]
    fn session_events_and_stop_response_have_stable_identity_and_outcomes() {
        let action = SessionActionEvent::Action {
            session_id: "ses_1".to_string(),
            action_id: "act_1".to_string(),
            action: "observe".to_string(),
            status: SessionActionStatus::Started,
        };
        assert_eq!(
            serde_json::to_string(&action).unwrap(),
            r#"{"type":"action","session_id":"ses_1","action_id":"act_1","action":"observe","status":"started"}"#
        );

        let stop = SessionStopResponse {
            session_id: "ses_1".to_string(),
            teardown: SessionTeardownResult {
                duration_ms: 25,
                exit_code: Some(7),
                timed_out: false,
                error_code: None,
            },
            artifacts: None,
            artifact_restrictions: None,
        };
        assert_eq!(
            serde_json::to_value(stop).unwrap(),
            serde_json::json!({
                "session_id": "ses_1",
                "teardown": {"duration_ms": 25, "exit_code": 7, "timed_out": false}
            })
        );
    }
}
