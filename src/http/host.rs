use super::*;
use crate::host_observation::{self, ObservationResponse};
use std::os::unix::fs::DirBuilderExt;

fn disabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "host_observation_disabled".into(),
        }),
    )
        .into_response()
}

pub(super) async fn observe(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }
    if !state.config.host_observation.enabled {
        return disabled();
    }
    let permit = match Arc::clone(&state.host_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return busy_response(),
    };
    let bytes = match tokio::time::timeout(Duration::from_secs(5), to_bytes(body, 4096)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return bad_request("host request exceeds 4096 bytes or body is invalid"),
        Err(_) => {
            return (
                StatusCode::REQUEST_TIMEOUT,
                Json(ErrorResponse {
                    error: "host request body timed out".into(),
                }),
            )
                .into_response()
        }
    };
    let request = match host_observation::parse_request(&bytes) {
        Ok(request) => request,
        Err(error) => return bad_request(&error),
    };
    let result = tokio::task::spawn_blocking(move || {
        // Cancellation of the HTTP future cannot release admission while the
        // bounded blocking broker transfer is still running.
        let _permit = permit;
        let config = &state.config;
        let policy = &config.host_observation;
        let scratch = tempfile::Builder::new()
            .prefix("indentured-host-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|e| e.to_string())?;
        let scratch_path = scratch.path().canonicalize().map_err(|e| e.to_string())?;
        let manifest = host_observation::observe(
            policy
                .socket
                .as_deref()
                .ok_or("host socket is not configured")?,
            policy.peer_uid.ok_or("host peer UID is not configured")?,
            &request,
            &scratch_path,
        )?;
        // Fresh daemon-issued identity, same storage, restrictions, limits and
        // GC as all other artifacts. No build/task/session is synthesized.
        let destination = config.artifacts.storage_root.join(&manifest.observation_id);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&destination)
            .map_err(|e| e.to_string())?;
        let collected = crate::artifacts::collect_artifacts_zip(
            &scratch_path,
            &crate::config::ArtifactSpec {
                include: vec!["observations/**".into()],
                exclude: vec![],
            },
            &config.artifacts,
            &manifest.observation_id,
        );
        let mut collection = match collected {
            Ok(collection) => collection,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&destination);
                return Err(error.to_string());
            }
        };
        if collection.archive.is_none() {
            let _ = std::fs::remove_dir_all(&destination);
        }
        if let Some(archive) = collection.archive.as_mut() {
            archive.path = format!(
                "/v1/host/observations/{}/artifacts.zip",
                manifest.observation_id
            );
        }
        Ok::<_, String>(ObservationResponse {
            manifest,
            artifacts: collection.archive,
            artifact_restrictions: collection.restrictions,
        })
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error }),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "host observation worker failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "host observation worker failed".into(),
                }),
            )
                .into_response()
        }
    }
}

pub(super) async fn artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Some(response) = authorize(&headers, &state.auth, state.auth_required) {
        return response;
    }
    if !state.config.host_observation.enabled {
        return disabled();
    }
    if !host_observation::valid_observation_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    read_artifact(&state, &id).await
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
