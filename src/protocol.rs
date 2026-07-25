use serde::{Deserialize, Serialize};

pub const REQUEST_SCHEMA_VERSION: &str = "1";
pub const MAX_REQUEST_ID_LEN: usize = 128;
pub const MAX_TASK_ID_LEN: usize = 64;

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

pub fn valid_task_id(value: &str) -> bool {
    validate_identifier(value, MAX_TASK_ID_LEN, false).is_ok()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactArchive {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRestrictions {
    pub omitted_count: usize,
    pub matched_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResponseEvent {
    Build {
        id: String,
        status: String,
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
    },
    Exit {
        code: i32,
        timed_out: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifacts: Option<ArtifactArchive>,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact_restrictions: Option<ArtifactRestrictions>,
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
}
