use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc::Sender, Notify, OwnedSemaphorePermit};
use tokio::task::AbortHandle;
use tracing::{error, info, warn};
use uuid::Uuid;

#[cfg(test)]
use crate::artifacts::ArtifactSnapshotCheckpoint;
use crate::artifacts::{collect_artifacts_zip, collect_artifacts_zip_controlled, ArtifactError};
#[cfg(test)]
use crate::build::InitializationCheckpoint;
use crate::build::{
    initialize_session, run_session_action, run_session_teardown, send_action_response,
    CancellationFlag, ValidatedRequest,
};
use crate::config::{
    Config, SessionActionConfig, SourceUpdatesConfig, TaskConfig, TaskSessionConfig,
    MAX_SESSION_LIFETIME_SEC,
};
use crate::protocol::{
    SessionActionDispatchInput, SessionActionEvent, SessionActionStatus, SessionActionStreamItem,
    SessionStartEvent, SessionStartStatus, SessionStopResponse, SessionTeardownResult,
    SessionUpdateResponse, SESSION_ACTION_DISPATCH_SCHEMA_VERSION,
};
use crate::services::{DurableServiceProcess, RunningService};
use crate::source_updates::{
    apply_update, PreparedUpdate, UpdateError as SourceUpdateError, UpdateErrorKind,
};

const METADATA_VERSION: u8 = 3;
const METADATA_DIRECTORY: &str = ".sessions";

#[derive(Clone)]
pub(crate) struct SessionManager {
    inner: Arc<SessionManagerInner>,
}

struct SessionManagerInner {
    config: Arc<Config>,
    metadata_root: PathBuf,
    sessions: Mutex<HashMap<String, Arc<SessionEntry>>>,
    #[cfg(test)]
    hooks: Mutex<LifecycleHooks>,
}

pub(crate) struct SessionReservation {
    entry: Arc<SessionEntry>,
}

pub(crate) struct SessionActionReservation {
    entry: Arc<SessionEntry>,
    action_id: String,
    action_name: String,
    action: SessionActionConfig,
    mode: SessionActionMode,
    workspace_revision: String,
    cancellation: CancellationFlag,
}

pub(crate) struct SessionUpdateReservation {
    entry: Arc<SessionEntry>,
    update_id: String,
    request_id: String,
    request_digest: [u8; 32],
    base_revision: u64,
    cancellation: CancellationFlag,
}

pub(crate) enum SessionUpdateAdmission {
    Start(SessionUpdateReservation),
    Retry(SessionUpdateResponse),
}

#[derive(Clone)]
pub(crate) struct SessionUpdateUploadContext {
    pub(crate) policy: SourceUpdatesConfig,
    pub(crate) remaining_lifetime: Duration,
}

#[derive(Clone, Copy)]
enum SessionActionMode {
    Named,
    Dispatcher,
}

impl SessionActionReservation {
    pub(crate) fn session_id(&self) -> &str {
        &self.entry.id
    }

    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    pub(crate) fn encode_input(
        &self,
        input: &serde_json::Map<String, serde_json::Value>,
    ) -> Vec<u8> {
        let encoded = match self.mode {
            SessionActionMode::Named => serde_json::to_vec(input),
            SessionActionMode::Dispatcher => serde_json::to_vec(&SessionActionDispatchInput {
                schema_version: SESSION_ACTION_DISPATCH_SCHEMA_VERSION,
                action: &self.action_name,
                input,
            }),
        };
        encoded.expect("JSON value serialization cannot fail")
    }
}

impl SessionReservation {
    pub(crate) fn id(&self) -> &str {
        &self.entry.id
    }

    pub(crate) fn remaining_lifetime(&self) -> Duration {
        self.entry
            .deadline
            .saturating_duration_since(Instant::now())
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            if self.entry.initialization_cancellation.is_cancelled() {
                return;
            }
            let notified = self.entry.cancellation_notify.notified();
            if self.entry.initialization_cancellation.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

struct SessionEntry {
    id: String,
    request_id: Option<String>,
    task_id: String,
    task: TaskConfig,
    workspace: PathBuf,
    deadline: Instant,
    state: Mutex<SessionState>,
    completion: Condvar,
    initialization_cancellation: CancellationFlag,
    cancellation_notify: Notify,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    timers: Mutex<Vec<AbortHandle>>,
    update_data: Mutex<SessionUpdateData>,
    services: Mutex<Vec<RunningService>>,
    retaining_service_output: Arc<std::sync::atomic::AtomicBool>,
}

struct SessionUpdateData {
    revision: u64,
    last_success: Option<SuccessfulUpdate>,
}

struct SuccessfulUpdate {
    request_id: String,
    request_digest: [u8; 32],
    response: SessionUpdateResponse,
}

#[derive(Clone)]
enum SessionState {
    Initializing {
        worker_started: bool,
    },
    Ready {
        last_activity: Instant,
    },
    Action {
        action_id: String,
        cancellation: CancellationFlag,
    },
    Updating {
        update_id: String,
        cancellation: CancellationFlag,
    },
    Terminating(Termination),
    Terminated(SessionStopResponse),
}

#[derive(Clone, Copy)]
struct Termination {
    explicit: bool,
    owner: CleanupOwner,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupOwner {
    Initializer,
    Action,
    Update,
    Requester,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableSessionMetadata {
    version: u8,
    session_id: String,
    task_id: String,
    workspace_revision: u64,
    #[serde(default, skip_serializing_if = "DurableSessionState::is_ready")]
    state: DurableSessionState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    services: Vec<DurableServiceProcess>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableSessionState {
    StartingServices,
    #[default]
    Ready,
}

impl DurableSessionState {
    fn is_ready(&self) -> bool {
        *self == Self::Ready
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StopError {
    #[error("session not found")]
    NotFound,
    #[error("session operation already in progress")]
    Conflict,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ActionError {
    #[error("session not found or expired")]
    NotFound,
    #[error("unknown configured action")]
    UnknownAction,
    #[error("session operation already in progress")]
    Conflict,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpdateAdmissionError {
    #[error("session not found, expired, or does not support source updates")]
    NotFound,
    #[error("session operation already in progress")]
    OperationConflict,
    #[error("base revision does not match")]
    RevisionConflict { current_revision: String },
    #[error("request_id was already used with different content")]
    RequestConflict,
}

#[cfg(test)]
#[derive(Default)]
struct LifecycleHooks {
    initialization_checkpoint: Option<(InitializationCheckpoint, BarrierHook)>,
    before_commit: Option<BarrierHook>,
    commit_election: Option<BarrierHook>,
    after_commit: Option<BarrierHook>,
    explicit_cleanup: Option<BarrierHook>,
    automatic_cleanup: Option<BarrierHook>,
    artifact_snapshot: Option<(ArtifactSnapshotCheckpoint, BarrierHook)>,
    final_enqueued: Option<BarrierHook>,
    update_apply: Option<BarrierHook>,
    panic_update_worker: bool,
    force_action_setup_failure: bool,
}

#[cfg(test)]
#[derive(Clone)]
struct BarrierHook {
    arrived: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

impl SessionManager {
    pub(crate) fn new(config: Arc<Config>) -> io::Result<Self> {
        let manager = Self::new_disabled(config);
        manager.reconcile_stale_sessions()?;
        Ok(manager)
    }

    pub(crate) fn new_disabled(config: Arc<Config>) -> Self {
        Self {
            inner: Arc::new(SessionManagerInner {
                metadata_root: config.build.workspace_root.join(METADATA_DIRECTORY),
                config,
                sessions: Mutex::new(HashMap::new()),
                #[cfg(test)]
                hooks: Mutex::new(LifecycleHooks::default()),
            }),
        }
    }

    pub(crate) fn reserve(
        &self,
        validated: ValidatedRequest,
        permit: OwnedSemaphorePermit,
    ) -> SessionReservation {
        let session_id = format!("ses_{}", Uuid::new_v4().simple());
        let lifetime_sec = validated
            .task
            .session
            .as_ref()
            .expect("validated session task")
            .max_lifetime_sec;
        assert!(
            lifetime_sec <= MAX_SESSION_LIFETIME_SEC,
            "session task must pass configuration validation"
        );
        let lifetime = Duration::from_secs(lifetime_sec);
        let now = Instant::now();
        let deadline = now
            .checked_add(lifetime)
            .expect("validated session lifetime must fit Instant");
        let entry = Arc::new(SessionEntry {
            workspace: self.session_workspace(&session_id),
            id: session_id.clone(),
            request_id: validated.request_id,
            task_id: validated.task_id,
            task: validated.task,
            deadline,
            state: Mutex::new(SessionState::Initializing {
                worker_started: false,
            }),
            completion: Condvar::new(),
            initialization_cancellation: CancellationFlag::default(),
            cancellation_notify: Notify::new(),
            permit: Mutex::new(Some(permit)),
            timers: Mutex::new(Vec::new()),
            update_data: Mutex::new(SessionUpdateData {
                revision: 0,
                last_success: None,
            }),
            services: Mutex::new(Vec::new()),
            retaining_service_output: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        #[cfg(test)]
        if let Some((checkpoint, hook)) = self
            .inner
            .hooks
            .lock()
            .unwrap()
            .initialization_checkpoint
            .take()
        {
            entry
                .initialization_cancellation
                .install_initialization_checkpoint_hook(checkpoint, hook.arrived, hook.release);
        }
        self.inner
            .sessions
            .lock()
            .expect("session registry lock")
            .insert(session_id, Arc::clone(&entry));
        self.spawn_lifetime_timer(&entry);
        SessionReservation { entry }
    }

    pub(crate) fn begin_initialization(&self, reservation: &SessionReservation) -> bool {
        let entry = &reservation.entry;
        let mut state = entry.state.lock().expect("session state lock");
        match &mut *state {
            SessionState::Initializing { worker_started }
                if !*worker_started
                    && !entry.initialization_cancellation.is_cancelled()
                    && Instant::now() < entry.deadline =>
            {
                *worker_started = true;
                true
            }
            SessionState::Initializing { worker_started } if !*worker_started => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                drop(state);
                self.cleanup_entry(entry, false);
                false
            }
            _ => false,
        }
    }

    pub(crate) fn cancel_upload(&self, reservation: &SessionReservation) {
        let entry = &reservation.entry;
        let mut state = entry.state.lock().expect("session state lock");
        if matches!(
            *state,
            SessionState::Initializing {
                worker_started: false
            }
        ) {
            entry.initialization_cancellation.cancel();
            entry.cancellation_notify.notify_waiters();
            *state = SessionState::Terminating(Termination {
                explicit: false,
                owner: CleanupOwner::Requester,
            });
            entry.completion.notify_all();
            drop(state);
            self.cleanup_entry(entry, false);
        }
    }

    pub(crate) fn initialize(
        &self,
        reservation: SessionReservation,
        source_archive: tempfile::TempPath,
        sender: Sender<SessionStartEvent>,
    ) {
        let entry = reservation.entry;
        let validated = ValidatedRequest {
            request_id: entry.request_id.clone(),
            task_id: entry.task_id.clone(),
            task: entry.task.clone(),
        };
        let initialization = initialize_session(
            &validated,
            &self.inner.config,
            &source_archive,
            &entry.workspace,
            &entry.id,
            &sender,
            &entry.initialization_cancellation,
            entry.deadline,
        );

        let outcome = match initialization {
            Ok(outcome) => outcome,
            Err(err) => {
                send_best_effort(
                    &sender,
                    SessionStartEvent::Error {
                        code: err.code.to_string(),
                        message: Some(err.message),
                        phase: err.phase,
                    },
                );
                send_best_effort(
                    &sender,
                    SessionStartEvent::Exit {
                        code: 1,
                        timed_out: false,
                        failed_phase: err.phase,
                        phases: err.phases,
                    },
                );
                self.initializer_cleanup(&entry, false);
                return;
            }
        };

        if outcome.exit_code != 0 || outcome.timed_out {
            send_best_effort(
                &sender,
                SessionStartEvent::Exit {
                    code: outcome.exit_code,
                    timed_out: outcome.timed_out,
                    failed_phase: outcome.failed_phase,
                    phases: outcome.phases,
                },
            );
            self.initializer_cleanup(&entry, false);
            return;
        }

        if let Err(err) = self.start_configured_services(&entry, &sender) {
            send_best_effort(
                &sender,
                SessionStartEvent::Error {
                    code: err.code.to_string(),
                    message: Some(err.message),
                    phase: None,
                },
            );
            send_best_effort(
                &sender,
                SessionStartEvent::Exit {
                    code: 1,
                    timed_out: Instant::now() >= entry.deadline,
                    failed_phase: None,
                    phases: outcome.phases,
                },
            );
            self.initializer_cleanup(&entry, false);
            return;
        }

        #[cfg(test)]
        self.wait_at_hook(HookKind::BeforeCommit);

        {
            let mut state = entry.state.lock().expect("session state lock");
            if !matches!(*state, SessionState::Initializing { .. })
                || entry.initialization_cancellation.is_cancelled()
                || Instant::now() >= entry.deadline
            {
                if matches!(*state, SessionState::Initializing { .. }) {
                    *state = SessionState::Terminating(Termination {
                        explicit: false,
                        owner: CleanupOwner::Initializer,
                    });
                }
                drop(state);
                self.initializer_cleanup(&entry, false);
                return;
            }
        }

        let metadata = DurableSessionMetadata {
            version: self.metadata_version(&entry),
            session_id: entry.id.clone(),
            task_id: entry.task_id.clone(),
            workspace_revision: 0,
            state: DurableSessionState::Ready,
            services: self.durable_services(&entry),
        };
        if let Err(err) = self.write_metadata(&metadata) {
            error!(
                "failed to commit session metadata session_id={}: {err}",
                entry.id
            );
            let mut state = entry.state.lock().expect("session state lock");
            if matches!(*state, SessionState::Initializing { .. }) {
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Initializer,
                });
            }
            drop(state);
            send_best_effort(
                &sender,
                SessionStartEvent::Error {
                    code: "session_commit_failed".to_string(),
                    message: Some("failed to commit session metadata".to_string()),
                    phase: None,
                },
            );
            send_best_effort(
                &sender,
                SessionStartEvent::Exit {
                    code: 1,
                    timed_out: false,
                    failed_phase: None,
                    phases: outcome.phases,
                },
            );
            self.initializer_cleanup(&entry, false);
            return;
        }

        #[cfg(test)]
        self.wait_at_hook(HookKind::CommitElection);

        // Durable metadata exists, but Initializing -> Ready and every
        // termination trigger contend on this one state lock. Whichever changes
        // Initializing first owns the outcome; there is no separately observable
        // commit flag.
        let mut state = entry.state.lock().expect("session state lock");
        if matches!(*state, SessionState::Initializing { .. })
            && !entry.initialization_cancellation.is_cancelled()
            && Instant::now() < entry.deadline
        {
            *state = SessionState::Ready {
                last_activity: Instant::now(),
            };
            entry
                .retaining_service_output
                .store(true, std::sync::atomic::Ordering::SeqCst);
            for service in entry.services.lock().expect("session services lock").iter() {
                service.retain_output();
            }
            self.spawn_idle_timer(&entry);
            send_best_effort(
                &sender,
                SessionStartEvent::Ready {
                    session_id: entry.id.clone(),
                    workspace_revision: "rev_0".to_string(),
                    phases: outcome.phases,
                },
            );
            drop(state);
            info!("managed session ready session_id={}", entry.id);

            #[cfg(test)]
            self.wait_at_hook(HookKind::AfterCommit);
            return;
        }
        if matches!(*state, SessionState::Initializing { .. }) {
            *state = SessionState::Terminating(Termination {
                explicit: false,
                owner: CleanupOwner::Initializer,
            });
        }
        drop(state);
        self.remove_metadata(&entry.id);
        send_best_effort(
            &sender,
            SessionStartEvent::Exit {
                code: 1,
                timed_out: Instant::now() >= entry.deadline,
                failed_phase: None,
                phases: outcome.phases,
            },
        );
        self.initializer_cleanup(&entry, false);
    }

    fn start_configured_services(
        &self,
        entry: &Arc<SessionEntry>,
        sender: &Sender<SessionStartEvent>,
    ) -> Result<(), crate::build::BuildError> {
        let Some(session) = entry.task.session.as_ref() else {
            return Ok(());
        };
        if session.services.is_empty() {
            return Ok(());
        }

        send_best_effort(
            sender,
            SessionStartEvent::Session {
                id: entry.id.clone(),
                status: SessionStartStatus::StartingServices,
                phase: None,
                duration_ms: None,
                exit_code: None,
                timed_out: None,
            },
        );
        self.write_metadata(&DurableSessionMetadata {
            version: METADATA_VERSION,
            session_id: entry.id.clone(),
            task_id: entry.task_id.clone(),
            workspace_revision: 0,
            state: DurableSessionState::StartingServices,
            services: Vec::new(),
        })
        .map_err(|err| {
            crate::build::BuildError::new(
                "session_commit_failed",
                format!("failed to record service startup: {err}"),
            )
        })?;

        for name in sorted_service_names(session) {
            if entry.initialization_cancellation.is_cancelled() || Instant::now() >= entry.deadline
            {
                return Err(crate::build::BuildError::new(
                    "service_start_cancelled",
                    "service startup was cancelled",
                ));
            }
            let service = session
                .services
                .get(&name)
                .expect("name collected from service map");
            let startup_deadline = (Instant::now()
                + Duration::from_secs(service.startup_timeout_sec))
            .min(entry.deadline);
            let manager = self.clone();
            let callback_entry = Arc::clone(entry);
            let callback = Arc::new(move |detail: String| {
                manager.service_failed(&callback_entry, &detail);
            });
            let running = crate::services::spawn_service(
                &name,
                service,
                &entry.task,
                &self.inner.config,
                &entry.workspace,
                sender,
                &entry.initialization_cancellation,
                startup_deadline,
                entry.deadline,
                Arc::clone(&entry.retaining_service_output),
                callback,
            )?;
            entry
                .services
                .lock()
                .expect("session services lock")
                .push(running);

            self.write_metadata(&DurableSessionMetadata {
                version: METADATA_VERSION,
                session_id: entry.id.clone(),
                task_id: entry.task_id.clone(),
                workspace_revision: 0,
                state: DurableSessionState::StartingServices,
                services: self.durable_services(entry),
            })
            .map_err(|err| {
                crate::build::BuildError::new(
                    "session_commit_failed",
                    format!("failed to record spawned service: {err}"),
                )
            })?;

            entry
                .services
                .lock()
                .expect("session services lock")
                .last_mut()
                .expect("service just inserted")
                .wait_ready(
                    startup_deadline,
                    entry.deadline,
                    &entry.initialization_cancellation,
                )?;
        }
        Ok(())
    }

    fn metadata_version(&self, entry: &SessionEntry) -> u8 {
        if entry
            .task
            .session
            .as_ref()
            .is_some_and(|session| !session.services.is_empty())
        {
            METADATA_VERSION
        } else {
            2
        }
    }

    fn durable_services(&self, entry: &SessionEntry) -> Vec<DurableServiceProcess> {
        entry
            .services
            .lock()
            .expect("session services lock")
            .iter()
            .map(|service| service.process.clone())
            .collect()
    }

    fn service_failed(&self, entry: &Arc<SessionEntry>, detail: &str) {
        warn!(
            "managed session service failed session_id={} detail={detail}",
            entry.id
        );
        let mut state = entry.state.lock().expect("session state lock");
        let cleanup = match &*state {
            SessionState::Initializing { .. } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Initializer,
                });
                entry.completion.notify_all();
                false
            }
            SessionState::Ready { .. } => {
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                true
            }
            SessionState::Action { cancellation, .. } => {
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Action,
                });
                entry.completion.notify_all();
                false
            }
            SessionState::Updating { cancellation, .. } => {
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Update,
                });
                entry.completion.notify_all();
                false
            }
            SessionState::Terminating(_) | SessionState::Terminated(_) => false,
        };
        drop(state);
        if cleanup {
            self.cleanup_entry(entry, false);
        }
    }

    pub(crate) fn disconnect(&self, session_id: &str) {
        let Some(entry) = self.lookup(session_id) else {
            return;
        };
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Initializing {
                worker_started: true,
            } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Initializer,
                });
                entry.completion.notify_all();
            }
            SessionState::Initializing {
                worker_started: false,
            } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                drop(state);
                self.cleanup_entry(&entry, false);
            }
            SessionState::Ready { .. }
            | SessionState::Action { .. }
            | SessionState::Updating { .. }
            | SessionState::Terminating(_)
            | SessionState::Terminated(_) => {}
        }
    }

    pub(crate) fn update_upload_context(
        &self,
        session_id: &str,
    ) -> Result<SessionUpdateUploadContext, UpdateAdmissionError> {
        let entry = self
            .lookup(session_id)
            .ok_or(UpdateAdmissionError::NotFound)?;
        let policy = entry
            .task
            .session
            .as_ref()
            .and_then(|session| session.source_updates.clone())
            .ok_or(UpdateAdmissionError::NotFound)?;
        let state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Ready { .. }
            | SessionState::Action { .. }
            | SessionState::Updating { .. }
                if Instant::now() < entry.deadline =>
            {
                Ok(SessionUpdateUploadContext {
                    policy,
                    remaining_lifetime: entry.deadline.saturating_duration_since(Instant::now()),
                })
            }
            _ => Err(UpdateAdmissionError::NotFound),
        }
    }

    pub(crate) fn start_update(
        &self,
        session_id: &str,
        request_id: String,
        request_digest: [u8; 32],
        base_revision: u64,
    ) -> Result<SessionUpdateAdmission, UpdateAdmissionError> {
        let entry = self
            .lookup(session_id)
            .ok_or(UpdateAdmissionError::NotFound)?;
        if entry
            .task
            .session
            .as_ref()
            .and_then(|session| session.source_updates.as_ref())
            .is_none()
        {
            return Err(UpdateAdmissionError::NotFound);
        }
        let update_id = format!("upd_{}", Uuid::new_v4().simple());
        let cancellation = CancellationFlag::default();
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Ready { .. } if Instant::now() < entry.deadline => {
                let update_data = entry.update_data.lock().expect("session update data lock");
                if let Some(last) = &update_data.last_success {
                    if last.request_id == request_id {
                        if last.request_digest == request_digest {
                            return Ok(SessionUpdateAdmission::Retry(last.response.clone()));
                        }
                        return Err(UpdateAdmissionError::RequestConflict);
                    }
                }
                if update_data.revision != base_revision {
                    return Err(UpdateAdmissionError::RevisionConflict {
                        current_revision: format!("rev_{}", update_data.revision),
                    });
                }
                drop(update_data);
                *state = SessionState::Updating {
                    update_id: update_id.clone(),
                    cancellation: cancellation.clone(),
                };
                entry.completion.notify_all();
                drop(state);
                Ok(SessionUpdateAdmission::Start(SessionUpdateReservation {
                    entry,
                    update_id,
                    request_id,
                    request_digest,
                    base_revision,
                    cancellation,
                }))
            }
            SessionState::Ready { .. }
            | SessionState::Terminating(_)
            | SessionState::Terminated(_) => Err(UpdateAdmissionError::NotFound),
            SessionState::Initializing { .. }
            | SessionState::Action { .. }
            | SessionState::Updating { .. } => Err(UpdateAdmissionError::OperationConflict),
        }
    }

    pub(crate) fn execute_update(
        &self,
        reservation: SessionUpdateReservation,
        prepared: PreparedUpdate,
    ) -> Result<SessionUpdateResponse, SourceUpdateError> {
        let entry = reservation.entry;
        let next_revision = match reservation.base_revision.checked_add(1) {
            Some(revision) => revision,
            None => {
                let err = SourceUpdateError {
                    kind: UpdateErrorKind::Internal,
                    message: "workspace revision overflow".to_string(),
                    rollback_proven: false,
                };
                self.finish_update_error(&entry, &reservation.update_id, &err);
                return Err(err);
            }
        };
        let identity = match crate::build::resolved_run_as_identity(&self.inner.config) {
            Ok(identity) => identity,
            Err(identity_error) => {
                let err = SourceUpdateError {
                    kind: UpdateErrorKind::Internal,
                    message: identity_error.message,
                    rollback_proven: false,
                };
                self.finish_update_error(&entry, &reservation.update_id, &err);
                return Err(err);
            }
        };
        #[cfg(test)]
        let identity = identity.unwrap_or_else(|| {
            (
                unsafe { libc::geteuid() },
                "test-task".to_string(),
                unsafe { libc::getegid() },
            )
        });
        #[cfg(not(test))]
        let identity = match identity {
            Some(identity) => identity,
            None => {
                let err = SourceUpdateError {
                    kind: UpdateErrorKind::Internal,
                    message: "managed source updates require a task identity".to_string(),
                    rollback_proven: false,
                };
                self.finish_update_error(&entry, &reservation.update_id, &err);
                return Err(err);
            }
        };
        let metadata = DurableSessionMetadata {
            version: self.metadata_version(&entry),
            session_id: entry.id.clone(),
            task_id: entry.task_id.clone(),
            workspace_revision: next_revision,
            state: DurableSessionState::Ready,
            services: self.durable_services(&entry),
        };
        #[cfg(test)]
        {
            let hook = self
                .inner
                .hooks
                .lock()
                .expect("lifecycle hooks lock")
                .update_apply
                .take();
            if let Some(hook) = hook {
                hook.arrived.wait();
                hook.release.wait();
            }
            if std::mem::take(
                &mut self
                    .inner
                    .hooks
                    .lock()
                    .expect("lifecycle hooks lock")
                    .panic_update_worker,
            ) {
                panic!("forced source update worker panic");
            }
        }
        let result = apply_update(
            prepared,
            &entry.workspace,
            identity.0,
            identity.2,
            &reservation.cancellation,
            || self.write_metadata(&metadata),
        );
        match result {
            Ok(evidence) => {
                let response = SessionUpdateResponse {
                    session_id: entry.id.clone(),
                    update_id: reservation.update_id.clone(),
                    request_id: reservation.request_id.clone(),
                    base_revision: format!("rev_{}", reservation.base_revision),
                    workspace_revision: format!("rev_{next_revision}"),
                    changed: evidence.changed,
                    deleted: evidence.deleted,
                };
                let mut state = entry.state.lock().expect("session state lock");
                match &*state {
                    SessionState::Updating {
                        update_id,
                        cancellation,
                    } if update_id == &reservation.update_id
                        && !cancellation.is_cancelled()
                        && Instant::now() < entry.deadline =>
                    {
                        let mut update_data =
                            entry.update_data.lock().expect("session update data lock");
                        update_data.revision = next_revision;
                        update_data.last_success = Some(SuccessfulUpdate {
                            request_id: reservation.request_id,
                            request_digest: reservation.request_digest,
                            response: response.clone(),
                        });
                        *state = SessionState::Ready {
                            last_activity: Instant::now(),
                        };
                        entry.completion.notify_all();
                        drop(update_data);
                        drop(state);
                        self.spawn_idle_timer(&entry);
                        Ok(response)
                    }
                    SessionState::Updating { .. } => {
                        *state = SessionState::Terminating(Termination {
                            explicit: false,
                            owner: CleanupOwner::Update,
                        });
                        entry.completion.notify_all();
                        drop(state);
                        self.cleanup_entry(&entry, false);
                        Err(SourceUpdateError {
                            kind: UpdateErrorKind::Cancelled,
                            message: "update exceeded session lifetime".to_string(),
                            rollback_proven: true,
                        })
                    }
                    SessionState::Terminating(termination)
                        if termination.owner == CleanupOwner::Update =>
                    {
                        let explicit = termination.explicit;
                        drop(state);
                        self.cleanup_entry(&entry, explicit);
                        Err(SourceUpdateError {
                            kind: UpdateErrorKind::Cancelled,
                            message: "update cancelled".to_string(),
                            rollback_proven: true,
                        })
                    }
                    _ => Err(SourceUpdateError {
                        kind: UpdateErrorKind::Internal,
                        message: "update lost session ownership".to_string(),
                        rollback_proven: false,
                    }),
                }
            }
            Err(err) => {
                self.finish_update_error(&entry, &reservation.update_id, &err);
                Err(err)
            }
        }
    }

    fn finish_update_error(
        &self,
        entry: &Arc<SessionEntry>,
        update_id: &str,
        err: &SourceUpdateError,
    ) {
        let mut state = entry.state.lock().expect("session state lock");
        let (cleanup, ready) = match &*state {
            SessionState::Terminating(termination) if termination.owner == CleanupOwner::Update => {
                (Some(termination.explicit), false)
            }
            SessionState::Updating {
                update_id: active, ..
            } if active == update_id && !err.rollback_proven => {
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Update,
                });
                entry.completion.notify_all();
                (Some(false), false)
            }
            SessionState::Updating {
                update_id: active, ..
            } if active == update_id => {
                *state = SessionState::Ready {
                    last_activity: Instant::now(),
                };
                entry.completion.notify_all();
                (None, true)
            }
            _ => (None, false),
        };
        drop(state);
        if let Some(explicit) = cleanup {
            self.cleanup_entry(entry, explicit);
        } else if ready {
            self.spawn_idle_timer(entry);
        }
    }

    pub(crate) fn update_worker_panicked(&self, session_id: &str) {
        let Some(entry) = self.lookup(session_id) else {
            return;
        };
        let mut state = entry.state.lock().expect("session state lock");
        let explicit = match &*state {
            SessionState::Updating { cancellation, .. } => {
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                Some(false)
            }
            SessionState::Terminating(termination) if termination.owner == CleanupOwner::Update => {
                Some(termination.explicit)
            }
            _ => None,
        };
        drop(state);
        if let Some(explicit) = explicit {
            self.cleanup_entry(&entry, explicit);
        }
    }

    pub(crate) fn start_action(
        &self,
        session_id: &str,
        action_name: &str,
    ) -> Result<SessionActionReservation, ActionError> {
        let entry = self.lookup(session_id).ok_or(ActionError::NotFound)?;
        let session = entry.task.session.as_ref().ok_or(ActionError::NotFound)?;
        let (action, mode) = if let Some(action) = session.actions.get(action_name) {
            (action.clone(), SessionActionMode::Named)
        } else if let Some(dispatcher) = &session.action_dispatcher {
            (
                dispatcher
                    .resolve(action_name)
                    .ok_or(ActionError::UnknownAction)?,
                SessionActionMode::Dispatcher,
            )
        } else {
            return Err(ActionError::UnknownAction);
        };
        let cancellation = CancellationFlag::default();
        #[cfg(test)]
        {
            let mut hooks = self.inner.hooks.lock().unwrap();
            if hooks.force_action_setup_failure {
                hooks.force_action_setup_failure = false;
                cancellation.force_post_spawn_setup_failure();
            }
        }
        let action_id = format!("act_{}", Uuid::new_v4().simple());
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Ready { .. } if Instant::now() < entry.deadline => {
                let workspace_revision = format!(
                    "rev_{}",
                    entry
                        .update_data
                        .lock()
                        .expect("session update data lock")
                        .revision
                );
                *state = SessionState::Action {
                    action_id: action_id.clone(),
                    cancellation: cancellation.clone(),
                };
                entry.completion.notify_all();
                drop(state);
                Ok(SessionActionReservation {
                    entry,
                    action_id,
                    action_name: action_name.to_string(),
                    action,
                    mode,
                    workspace_revision,
                    cancellation,
                })
            }
            SessionState::Ready { .. }
            | SessionState::Terminating(_)
            | SessionState::Terminated(_) => Err(ActionError::NotFound),
            SessionState::Initializing { .. }
            | SessionState::Action { .. }
            | SessionState::Updating { .. } => Err(ActionError::Conflict),
        }
    }

    pub(crate) fn execute_action(
        &self,
        reservation: SessionActionReservation,
        input: Vec<u8>,
        sender: Sender<SessionActionStreamItem>,
    ) {
        let entry = reservation.entry;
        let action_id = reservation.action_id;
        let action_name = reservation.action_name;
        let action = reservation.action;
        let workspace_revision = reservation.workspace_revision;
        let cancellation = reservation.cancellation;
        let outcome = run_session_action(
            &entry.task_id,
            &entry.task,
            &action,
            &self.inner.config,
            &entry.workspace,
            &entry.id,
            &action_id,
            &action_name,
            &workspace_revision,
            &input,
            &sender,
            &cancellation,
        );

        let outcome = match outcome {
            Ok(outcome) if !outcome.timed_out => outcome,
            Ok(outcome) => {
                send_action_best_effort(
                    &sender,
                    SessionActionEvent::Exit {
                        session_id: entry.id.clone(),
                        action_id: action_id.clone(),
                        action: action_name.clone(),
                        workspace_revision: workspace_revision.clone(),
                        code: outcome.code,
                        timed_out: true,
                        artifacts: None,
                        artifact_restrictions: None,
                    },
                );
                self.finish_action(&entry, &action_id, false);
                return;
            }
            Err(err) => {
                if err.code != "stream_closed" {
                    send_action_best_effort(
                        &sender,
                        SessionActionEvent::Error {
                            code: err.code.to_string(),
                            message: Some(err.message),
                        },
                    );
                    send_action_best_effort(
                        &sender,
                        SessionActionEvent::Exit {
                            session_id: entry.id.clone(),
                            action_id: action_id.clone(),
                            action: action_name.clone(),
                            workspace_revision: workspace_revision.clone(),
                            code: 1,
                            timed_out: false,
                            artifacts: None,
                            artifact_restrictions: None,
                        },
                    );
                }
                self.finish_action(&entry, &action_id, false);
                return;
            }
        };

        if send_action_response(
            &sender,
            SessionActionEvent::Action {
                session_id: entry.id.clone(),
                action_id: action_id.clone(),
                action: action_name.clone(),
                workspace_revision: workspace_revision.clone(),
                status: SessionActionStatus::Snapshotting,
            },
            &cancellation,
        )
        .is_err()
        {
            self.finish_action(&entry, &action_id, false);
            return;
        }

        let archive_id = format!("bld_{}", Uuid::new_v4().simple());
        let checkpoint = |checkpoint| {
            #[cfg(test)]
            self.wait_at_hook(HookKind::ArtifactSnapshot(checkpoint));
            #[cfg(not(test))]
            let _ = checkpoint;
        };
        let collection = collect_artifacts_zip_controlled(
            &entry.workspace,
            &action.artifacts,
            &self.inner.config.artifacts,
            &archive_id,
            &|| cancellation.is_cancelled(),
            &checkpoint,
        );
        let collection = match collection {
            Ok(collection) => collection,
            Err(err) => {
                let _ =
                    fs::remove_dir_all(self.inner.config.artifacts.storage_root.join(&archive_id));
                if !matches!(err, ArtifactError::Cancelled) && !cancellation.is_cancelled() {
                    send_action_best_effort(
                        &sender,
                        SessionActionEvent::Error {
                            code: "artifact_collection_failed".to_string(),
                            message: Some(err.to_string()),
                        },
                    );
                    send_action_best_effort(
                        &sender,
                        SessionActionEvent::Exit {
                            session_id: entry.id.clone(),
                            action_id: action_id.clone(),
                            action: action_name.clone(),
                            workspace_revision: workspace_revision.clone(),
                            code: if outcome.code == 0 { 1 } else { outcome.code },
                            timed_out: false,
                            artifacts: None,
                            artifact_restrictions: None,
                        },
                    );
                }
                self.finish_action(&entry, &action_id, false);
                return;
            }
        };

        let archive_root = self.inner.config.artifacts.storage_root.join(&archive_id);
        if !self.action_can_publish(&entry, &action_id) {
            let _ = fs::remove_dir_all(&archive_root);
            self.finish_action(&entry, &action_id, false);
            return;
        }
        let final_event = SessionActionEvent::Exit {
            session_id: entry.id.clone(),
            action_id: action_id.clone(),
            action: action_name,
            workspace_revision,
            code: outcome.code,
            timed_out: false,
            artifacts: collection.archive,
            artifact_restrictions: collection.restrictions,
        };
        if !self.deliver_final_action_event(&entry, &action_id, &sender, final_event, &cancellation)
        {
            let _ = fs::remove_dir_all(&archive_root);
            self.finish_action(&entry, &action_id, false);
        }
    }

    fn action_can_publish(&self, entry: &Arc<SessionEntry>, action_id: &str) -> bool {
        let state = entry.state.lock().expect("session state lock");
        matches!(
            &*state,
            SessionState::Action {
                action_id: active,
                cancellation,
                ..
            } if active == action_id
                && !cancellation.is_cancelled()
                && Instant::now() < entry.deadline
        )
    }

    fn deliver_final_action_event(
        &self,
        entry: &Arc<SessionEntry>,
        action_id: &str,
        sender: &Sender<SessionActionStreamItem>,
        event: SessionActionEvent,
        cancellation: &CancellationFlag,
    ) -> bool {
        let (ack_sender, ack_receiver) = std::sync::mpsc::sync_channel(1);
        let mut pending = SessionActionStreamItem {
            event,
            final_ack: Some(ack_sender),
        };
        let enqueue_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if cancellation.is_cancelled() || !self.action_can_publish(entry, action_id) {
                return false;
            }
            match sender.try_send(pending) {
                Ok(()) => break,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
                Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => {
                    pending = item;
                    if Instant::now() >= enqueue_deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        #[cfg(test)]
        self.wait_at_hook(HookKind::FinalEnqueued);
        let acknowledgement_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if cancellation.is_cancelled() {
                return false;
            }
            match ack_receiver.try_recv() {
                Ok(accepted) => return accepted,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if Instant::now() >= acknowledgement_deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn finish_action(&self, entry: &Arc<SessionEntry>, action_id: &str, reusable: bool) {
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Action {
                action_id: active, ..
            } if active == action_id && reusable => {
                *state = SessionState::Ready {
                    last_activity: Instant::now(),
                };
                entry.completion.notify_all();
                drop(state);
                self.spawn_idle_timer(entry);
            }
            SessionState::Action {
                action_id: active, ..
            } if active == action_id => {
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Action,
                });
                entry.completion.notify_all();
                drop(state);
                self.cleanup_entry(entry, false);
            }
            SessionState::Terminating(termination) if termination.owner == CleanupOwner::Action => {
                let explicit = termination.explicit;
                drop(state);
                self.cleanup_entry(entry, explicit);
            }
            _ => {}
        }
    }

    pub(crate) fn acknowledge_action_delivery(&self, session_id: &str, action_id: &str) -> bool {
        let Some(entry) = self.lookup(session_id) else {
            return false;
        };
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Action {
                action_id: active,
                cancellation,
            } if active == action_id
                && !cancellation.is_cancelled()
                && Instant::now() < entry.deadline =>
            {
                *state = SessionState::Ready {
                    last_activity: Instant::now(),
                };
                entry.completion.notify_all();
                drop(state);
                self.spawn_idle_timer(&entry);
                true
            }
            SessionState::Action {
                action_id: active,
                cancellation,
            } if active == action_id => {
                let cancellation = cancellation.clone();
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Action,
                });
                entry.completion.notify_all();
                false
            }
            _ => false,
        }
    }

    pub(crate) fn disconnect_action(&self, session_id: &str, action_id: &str) {
        let Some(entry) = self.lookup(session_id) else {
            return;
        };
        let mut state = entry.state.lock().expect("session state lock");
        if let SessionState::Action {
            action_id: active,
            cancellation,
        } = &*state
        {
            if active == action_id {
                let cancellation = cancellation.clone();
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Action,
                });
                entry.completion.notify_all();
            }
        }
    }

    pub(crate) fn stop(&self, session_id: &str) -> Result<SessionStopResponse, StopError> {
        let entry = self.lookup(session_id).ok_or(StopError::NotFound)?;
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Initializing {
                worker_started: true,
            } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: true,
                    owner: CleanupOwner::Initializer,
                });
                entry.completion.notify_all();
                loop {
                    state = entry.completion.wait(state).expect("session state lock");
                    if let SessionState::Terminated(response) = &*state {
                        return Ok(response.clone());
                    }
                }
            }
            SessionState::Action { cancellation, .. } => {
                let cancellation = cancellation.clone();
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: true,
                    owner: CleanupOwner::Action,
                });
                entry.completion.notify_all();
                loop {
                    state = entry.completion.wait(state).expect("session state lock");
                    if let SessionState::Terminated(response) = &*state {
                        return Ok(response.clone());
                    }
                }
            }
            SessionState::Updating { cancellation, .. } => {
                let cancellation = cancellation.clone();
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: true,
                    owner: CleanupOwner::Update,
                });
                entry.completion.notify_all();
                loop {
                    state = entry.completion.wait(state).expect("session state lock");
                    if let SessionState::Terminated(response) = &*state {
                        return Ok(response.clone());
                    }
                }
            }
            SessionState::Initializing {
                worker_started: false,
            }
            | SessionState::Ready { .. } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: true,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                drop(state);
                #[cfg(test)]
                self.wait_at_hook(HookKind::ExplicitCleanup);
                Ok(self.cleanup_entry(&entry, true))
            }
            SessionState::Terminating(_) => Err(StopError::Conflict),
            SessionState::Terminated(_) => Err(StopError::Conflict),
        }
    }

    fn initializer_cleanup(&self, entry: &Arc<SessionEntry>, default_explicit: bool) {
        let explicit = {
            let mut state = entry.state.lock().expect("session state lock");
            match &*state {
                SessionState::Initializing { .. } => {
                    *state = SessionState::Terminating(Termination {
                        explicit: default_explicit,
                        owner: CleanupOwner::Initializer,
                    });
                    default_explicit
                }
                SessionState::Terminating(termination)
                    if termination.owner == CleanupOwner::Initializer =>
                {
                    termination.explicit
                }
                SessionState::Terminating(_)
                | SessionState::Ready { .. }
                | SessionState::Action { .. }
                | SessionState::Updating { .. } => return,
                SessionState::Terminated(_) => return,
            }
        };
        self.cleanup_entry(entry, explicit);
    }

    fn cleanup_entry(&self, entry: &Arc<SessionEntry>, explicit: bool) -> SessionStopResponse {
        self.abort_timers(entry);
        entry
            .retaining_service_output
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let services = std::mem::take(&mut *entry.services.lock().expect("session services lock"));
        let mut service_cleanup_failed = false;
        let mut service_identity_cleanup_unproven = false;
        for service in services.into_iter().rev() {
            if let Err(err) = service.stop() {
                service_cleanup_failed = true;
                service_identity_cleanup_unproven |= err.cleanup_unproven();
                warn!(
                    "retained service cleanup was not proven session_id={}: {err}",
                    entry.id
                );
            }
        }
        let mut teardown = if entry.workspace.is_dir() {
            run_session_teardown(
                &entry.task_id,
                &entry.task,
                &self.inner.config,
                &entry.workspace,
                &entry.id,
            )
        } else {
            SessionTeardownResult {
                duration_ms: 0,
                exit_code: None,
                timed_out: false,
                error_code: Some("workspace_missing".to_string()),
            }
        };
        if service_cleanup_failed && teardown.error_code.is_none() {
            teardown.error_code = Some("service_cleanup_failed".to_string());
        }
        let (artifacts, artifact_restrictions) = if explicit && entry.workspace.is_dir() {
            let archive_id = format!("bld_{}", Uuid::new_v4().simple());
            match collect_artifacts_zip(
                &entry.workspace,
                &entry.task.artifacts,
                &self.inner.config.artifacts,
                &archive_id,
            ) {
                Ok(collection) => (collection.archive, collection.restrictions),
                Err(err) => {
                    warn!(
                        "final session artifact collection failed session_id={}: {err}",
                        entry.id
                    );
                    if teardown.error_code.is_none() {
                        teardown.error_code = Some("artifact_collection_failed".to_string());
                    }
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
        let response = SessionStopResponse {
            session_id: entry.id.clone(),
            teardown,
            artifacts,
            artifact_restrictions,
        };

        remove_path(&entry.workspace);
        if service_identity_cleanup_unproven {
            warn!(
                "preserving protected session metadata for fail-closed stale reconciliation session_id={}",
                entry.id
            );
        } else {
            self.remove_metadata(&entry.id);
        }
        self.inner
            .sessions
            .lock()
            .expect("session registry lock")
            .remove(&entry.id);
        entry.permit.lock().expect("session permit lock").take();
        let mut state = entry.state.lock().expect("session state lock");
        *state = SessionState::Terminated(response.clone());
        entry.completion.notify_all();
        drop(state);
        info!(
            "managed session removed session_id={} explicit={explicit}",
            entry.id
        );
        response
    }

    fn spawn_lifetime_timer(&self, entry: &Arc<SessionEntry>) {
        let manager = self.clone();
        let id = entry.id.clone();
        let deadline = entry.deadline;
        let handle = tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            let manager_for_cleanup = manager.clone();
            let _ = tokio::task::spawn_blocking(move || {
                manager_for_cleanup.expire_lifetime(&id);
            })
            .await;
        });
        entry
            .timers
            .lock()
            .expect("session timer lock")
            .push(handle.abort_handle());
    }

    fn spawn_idle_timer(&self, entry: &Arc<SessionEntry>) {
        let idle = Duration::from_secs(
            entry
                .task
                .session
                .as_ref()
                .expect("validated session task")
                .idle_timeout_sec,
        );
        let manager = self.clone();
        let id = entry.id.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Some(remaining) = manager.idle_remaining(&id, idle) else {
                    return;
                };
                if remaining.is_zero() {
                    let manager_for_cleanup = manager.clone();
                    let cleanup_id = id.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        manager_for_cleanup.expire_idle(&cleanup_id, idle);
                    })
                    .await;
                    return;
                }
                tokio::time::sleep(remaining).await;
            }
        });
        entry
            .timers
            .lock()
            .expect("session timer lock")
            .push(handle.abort_handle());
    }

    fn expire_lifetime(&self, session_id: &str) {
        let Some(entry) = self.lookup(session_id) else {
            return;
        };
        let mut state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Initializing {
                worker_started: true,
            } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Initializer,
                });
                entry.completion.notify_all();
            }
            SessionState::Action { cancellation, .. } => {
                let cancellation = cancellation.clone();
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Action,
                });
                entry.completion.notify_all();
            }
            SessionState::Updating { cancellation, .. } => {
                let cancellation = cancellation.clone();
                cancellation.cancel();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Update,
                });
                entry.completion.notify_all();
            }
            SessionState::Initializing {
                worker_started: false,
            }
            | SessionState::Ready { .. } => {
                entry.initialization_cancellation.cancel();
                entry.cancellation_notify.notify_waiters();
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                drop(state);
                #[cfg(test)]
                self.wait_at_hook(HookKind::AutomaticCleanup);
                self.cleanup_entry(&entry, false);
            }
            SessionState::Terminating(_) | SessionState::Terminated(_) => {}
        }
    }

    fn expire_idle(&self, session_id: &str, idle: Duration) {
        let Some(entry) = self.lookup(session_id) else {
            return;
        };
        let mut state = entry.state.lock().expect("session state lock");
        if let SessionState::Ready { last_activity } = &*state {
            if last_activity.elapsed() >= idle {
                *state = SessionState::Terminating(Termination {
                    explicit: false,
                    owner: CleanupOwner::Requester,
                });
                entry.completion.notify_all();
                drop(state);
                #[cfg(test)]
                self.wait_at_hook(HookKind::AutomaticCleanup);
                self.cleanup_entry(&entry, false);
            }
        }
    }

    fn idle_remaining(&self, session_id: &str, idle: Duration) -> Option<Duration> {
        let entry = self.lookup(session_id)?;
        let state = entry.state.lock().expect("session state lock");
        match &*state {
            SessionState::Ready { last_activity } => {
                Some(idle.saturating_sub(last_activity.elapsed()))
            }
            _ => None,
        }
    }

    fn abort_timers(&self, entry: &SessionEntry) {
        for timer in entry.timers.lock().expect("session timer lock").drain(..) {
            timer.abort();
        }
    }

    fn lookup(&self, session_id: &str) -> Option<Arc<SessionEntry>> {
        self.inner
            .sessions
            .lock()
            .expect("session registry lock")
            .get(session_id)
            .cloned()
    }

    fn reconcile_stale_sessions(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.inner.metadata_root) {
            Ok(_) => {
                validate_protected_directory(&self.inner.metadata_root)?;
                for entry in fs::read_dir(&self.inner.metadata_root)? {
                    let entry = entry?;
                    let path = entry.path();
                    let Some(session_id) = path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .filter(|_| {
                            path.extension().and_then(|value| value.to_str()) == Some("json")
                        })
                        .map(str::to_string)
                    else {
                        warn!("removing unrecognized stale session metadata {path:?}");
                        remove_path(&path);
                        continue;
                    };
                    let workspace = self.session_workspace(&session_id);
                    let metadata = read_metadata(&path).ok().filter(|metadata| {
                        (metadata.version == 2 || metadata.version == METADATA_VERSION)
                            && metadata.session_id == session_id
                    });
                    if let Some(metadata) = metadata {
                        self.await_stale_service_shutdown(&metadata)?;
                        if let Some(task) = self
                            .inner
                            .config
                            .tasks
                            .get(&metadata.task_id)
                            .filter(|task| task.session.is_some())
                        {
                            if workspace.is_dir() {
                                let _ = run_session_teardown(
                                    &metadata.task_id,
                                    task,
                                    &self.inner.config,
                                    &workspace,
                                    &session_id,
                                );
                            }
                        } else {
                            warn!(
                            "stale session configuration unavailable; performing root cleanup session_id={session_id}"
                        );
                        }
                    } else {
                        warn!("invalid stale session metadata; performing root cleanup session_id={session_id}");
                    }
                    self.remove_session_files(&session_id, &workspace);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        if self.inner.config.build.workspace_root.exists() {
            for entry in fs::read_dir(&self.inner.config.build.workspace_root)? {
                let entry = entry?;
                let name = entry.file_name();
                if name
                    .to_str()
                    .is_some_and(|name| name.starts_with("session-ses_"))
                {
                    warn!(
                        "removing orphaned uncommitted session workspace {:?}",
                        entry.path()
                    );
                    remove_path(&entry.path());
                }
            }
        }
        Ok(())
    }

    fn await_stale_service_shutdown(&self, metadata: &DurableSessionMetadata) -> io::Result<()> {
        for service in metadata.services.iter().rev() {
            let deadline = Instant::now()
                + Duration::from_secs(service.shutdown_timeout_sec)
                + Duration::from_secs(6);
            while process_exists(service.supervisor_pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
            if process_exists(service.supervisor_pid) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "recorded service supervisor {} is still live; refusing unsafe stale cleanup",
                        service.supervisor_pid
                    ),
                ));
            }
            let group_live =
                crate::build::process_group_exists(service.service_pgid).unwrap_or(true);
            if process_exists(service.service_pid) || group_live {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "recorded service {} survived its supervisor; refusing PID-reuse-unsafe stale cleanup",
                        service.name
                    ),
                ));
            }
        }
        Ok(())
    }

    fn write_metadata(&self, metadata: &DurableSessionMetadata) -> io::Result<()> {
        prepare_protected_directory(&self.inner.metadata_root)?;
        let final_path = self.metadata_path(&metadata.session_id);
        let temp_path = self
            .inner
            .metadata_root
            .join(format!(".{}.tmp", metadata.session_id));
        let result = (|| {
            let bytes = serde_json::to_vec(metadata).map_err(io::Error::other)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp_path, &final_path)?;
            OpenOptions::new()
                .read(true)
                .open(&self.inner.metadata_root)?
                .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            match fs::remove_file(&temp_path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    warn!("failed to remove session metadata temp file {temp_path:?}: {err}")
                }
            }
        }
        result
    }

    fn remove_metadata(&self, session_id: &str) {
        let metadata = self.metadata_path(session_id);
        if let Err(err) = fs::remove_file(&metadata) {
            if err.kind() != io::ErrorKind::NotFound {
                warn!("failed to remove session metadata {metadata:?}: {err}");
            }
        }
    }

    fn remove_session_files(&self, session_id: &str, workspace: &Path) {
        remove_path(workspace);
        self.remove_metadata(session_id);
    }

    fn session_workspace(&self, session_id: &str) -> PathBuf {
        self.inner
            .config
            .build
            .workspace_root
            .join(format!("session-{session_id}"))
    }

    fn metadata_path(&self, session_id: &str) -> PathBuf {
        self.inner.metadata_root.join(format!("{session_id}.json"))
    }

    #[cfg(test)]
    pub(crate) fn active_count(&self) -> usize {
        self.inner.sessions.lock().unwrap().len()
    }

    pub(crate) fn metadata_root(&self) -> &Path {
        &self.inner.metadata_root
    }

    #[cfg(test)]
    pub(crate) fn wait_for_terminating_for_test(&self, session_id: &str) {
        let entry = self.lookup(session_id).expect("test session");
        let mut state = entry.state.lock().unwrap();
        while !matches!(
            *state,
            SessionState::Terminating(_) | SessionState::Terminated(_)
        ) {
            state = entry.completion.wait(state).unwrap();
        }
    }

    #[cfg(test)]
    pub(crate) fn wait_for_terminated_for_test(&self, session_id: &str) -> SessionStopResponse {
        let entry = self.lookup(session_id).expect("test session");
        let mut state = entry.state.lock().unwrap();
        loop {
            if let SessionState::Terminated(response) = &*state {
                return response.clone();
            }
            state = entry.completion.wait(state).unwrap();
        }
    }

    #[cfg(test)]
    pub(crate) fn install_update_apply_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().update_apply = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn panic_next_update_worker(&self) {
        self.inner.hooks.lock().unwrap().panic_update_worker = true;
    }

    #[cfg(test)]
    pub(crate) fn force_lifetime_for_test(&self, session_id: &str) {
        self.expire_lifetime(session_id);
    }

    #[cfg(test)]
    pub(crate) fn force_idle_for_test(&self, session_id: &str) {
        self.expire_idle(session_id, Duration::ZERO);
    }

    #[cfg(test)]
    pub(crate) fn workspace_revision_for_test(&self, session_id: &str) -> u64 {
        self.lookup(session_id)
            .expect("test session")
            .update_data
            .lock()
            .unwrap()
            .revision
    }

    #[cfg(test)]
    pub(crate) fn timer_handles_for_test(&self, session_id: &str) -> Vec<AbortHandle> {
        self.lookup(session_id)
            .expect("test session")
            .timers
            .lock()
            .unwrap()
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn install_initialization_checkpoint_hook(
        &self,
        checkpoint: InitializationCheckpoint,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().initialization_checkpoint =
            Some((checkpoint, BarrierHook { arrived, release }));
    }

    #[cfg(test)]
    pub(crate) fn install_before_commit_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().before_commit = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn install_commit_election_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().commit_election = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn install_after_commit_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().after_commit = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn install_explicit_cleanup_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().explicit_cleanup = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn install_automatic_cleanup_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().automatic_cleanup = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn install_action_snapshot_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.install_artifact_checkpoint_hook(
            ArtifactSnapshotCheckpoint::Traversal,
            arrived,
            release,
        );
    }

    #[cfg(test)]
    pub(crate) fn install_artifact_checkpoint_hook(
        &self,
        checkpoint: ArtifactSnapshotCheckpoint,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().artifact_snapshot =
            Some((checkpoint, BarrierHook { arrived, release }));
    }

    #[cfg(test)]
    pub(crate) fn install_final_enqueued_hook(
        &self,
        arrived: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.hooks.lock().unwrap().final_enqueued = Some(BarrierHook { arrived, release });
    }

    #[cfg(test)]
    pub(crate) fn force_next_action_setup_failure(&self) {
        self.inner.hooks.lock().unwrap().force_action_setup_failure = true;
    }

    #[cfg(test)]
    fn wait_at_hook(&self, kind: HookKind) {
        let hook = {
            let mut hooks = self.inner.hooks.lock().unwrap();
            match kind {
                HookKind::BeforeCommit => hooks.before_commit.take(),
                HookKind::CommitElection => hooks.commit_election.take(),
                HookKind::AfterCommit => hooks.after_commit.take(),
                HookKind::ExplicitCleanup => hooks.explicit_cleanup.take(),
                HookKind::AutomaticCleanup => hooks.automatic_cleanup.take(),
                HookKind::ArtifactSnapshot(checkpoint) => {
                    if hooks
                        .artifact_snapshot
                        .as_ref()
                        .is_some_and(|(installed, _)| *installed == checkpoint)
                    {
                        hooks.artifact_snapshot.take().map(|(_, hook)| hook)
                    } else {
                        None
                    }
                }
                HookKind::FinalEnqueued => hooks.final_enqueued.take(),
            }
        };
        if let Some(hook) = hook {
            hook.arrived.wait();
            hook.release.wait();
        }
    }
}

fn sorted_service_names(session: &TaskSessionConfig) -> Vec<String> {
    let mut names: Vec<_> = session.services.keys().cloned().collect();
    names.sort();
    names
}

fn send_best_effort(sender: &Sender<SessionStartEvent>, event: SessionStartEvent) {
    if let Err(err) = sender.try_send(event) {
        warn!("dropping undeliverable session event: {err}");
    }
}

fn send_action_best_effort(sender: &Sender<SessionActionStreamItem>, event: SessionActionEvent) {
    if let Err(err) = sender.try_send(SessionActionStreamItem {
        event,
        final_ack: None,
    }) {
        warn!("dropping undeliverable session action event: {err}");
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum HookKind {
    BeforeCommit,
    CommitElection,
    AfterCommit,
    ExplicitCleanup,
    AutomaticCleanup,
    ArtifactSnapshot(ArtifactSnapshotCheckpoint),
    FinalEnqueued,
}

fn prepare_protected_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    validate_protected_directory(path)
}

fn validate_protected_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "session metadata root must be a daemon-owned mode-0700 real directory",
        ));
    }
    Ok(())
}

fn read_metadata(path: &Path) -> io::Result<DurableSessionMetadata> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unprotected session metadata",
        ));
    }
    serde_json::from_reader(file).map_err(io::Error::other)
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
}

fn remove_path(path: &Path) {
    let result = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)
        }
        Ok(_) => fs::remove_file(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return,
        Err(err) => Err(err),
    };
    if let Err(err) = result {
        warn!("failed to remove stale session path {path:?}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ArtifactSpec, ArtifactsConfig, BuildConfig, LoggingConfig, ServiceConfig,
        SessionActionConfig, SessionActionDispatcherConfig, SessionActionPolicyOverride,
        SessionServiceConfig, SessionTeardownConfig, SourcesConfig, TaskSessionConfig,
        WorkspacePolicy, CONFIG_SCHEMA_VERSION,
    };
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use tempfile::tempdir;

    fn test_config(root: &Path, executable: &Path) -> Config {
        let task = TaskConfig {
            script: None,
            executable: Some(executable.to_path_buf()),
            args: vec!["initialize".to_string()],
            setup: None,
            session: Some(TaskSessionConfig {
                idle_timeout_sec: 1,
                max_lifetime_sec: 2,
                teardown: SessionTeardownConfig {
                    script: None,
                    executable: Some(executable.to_path_buf()),
                    args: vec!["teardown".to_string()],
                    timeout_sec: 1,
                },
                services: HashMap::new(),
                actions: HashMap::from([(
                    "observe".to_string(),
                    SessionActionConfig {
                        script: None,
                        executable: Some(executable.to_path_buf()),
                        args: vec!["observe".to_string()],
                        timeout_sec: 1,
                        artifacts: ArtifactSpec::default(),
                    },
                )]),
                action_dispatcher: None,
                source_updates: None,
            }),
            cwd: ".".to_string(),
            timeout_sec: 1,
            environment: HashMap::new(),
            artifacts: ArtifactSpec::default(),
            workspace: WorkspacePolicy::Fresh,
        };
        Config {
            schema_version: CONFIG_SCHEMA_VERSION.to_string(),
            service: ServiceConfig::default(),
            build: BuildConfig {
                workspace_root: root.join("workspaces"),
                max_timeout_sec: 10,
                max_output_bytes: 1024 * 1024,
                run_as_user: None,
                run_as_group: None,
            },
            tasks: HashMap::from([("managed".to_string(), task)]),
            sources: SourcesConfig::default(),
            artifacts: ArtifactsConfig {
                storage_root: root.join("artifacts"),
                ..ArtifactsConfig::default()
            },
            logging: LoggingConfig::default(),
        }
    }

    #[tokio::test]
    async fn unexpected_service_exit_elects_ready_action_and_update_termination() {
        let temp = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let config = Arc::new(test_config(temp.path(), &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new_disabled(Arc::clone(&config));

        let reserve = || async {
            let permit = Arc::new(tokio::sync::Semaphore::new(1))
                .acquire_owned()
                .await
                .unwrap();
            manager.reserve(
                ValidatedRequest {
                    request_id: None,
                    task_id: "managed".to_string(),
                    task: config.tasks["managed"].clone(),
                },
                permit,
            )
        };

        let ready = reserve().await;
        *ready.entry.state.lock().unwrap() = SessionState::Ready {
            last_activity: Instant::now(),
        };
        manager.service_failed(&ready.entry, "ready exit");
        assert_eq!(manager.active_count(), 0);

        let action = reserve().await;
        let action_cancel = CancellationFlag::default();
        *action.entry.state.lock().unwrap() = SessionState::Action {
            action_id: "act_test".to_string(),
            cancellation: action_cancel.clone(),
        };
        manager.service_failed(&action.entry, "action exit");
        assert!(action_cancel.is_cancelled());
        assert!(matches!(
            *action.entry.state.lock().unwrap(),
            SessionState::Terminating(Termination {
                owner: CleanupOwner::Action,
                ..
            })
        ));
        manager.cleanup_entry(&action.entry, false);

        let update = reserve().await;
        let update_cancel = CancellationFlag::default();
        *update.entry.state.lock().unwrap() = SessionState::Updating {
            update_id: "upd_test".to_string(),
            cancellation: update_cancel.clone(),
        };
        manager.service_failed(&update.entry, "update exit");
        assert!(update_cancel.is_cancelled());
        assert!(matches!(
            *update.entry.state.lock().unwrap(),
            SessionState::Terminating(Termination {
                owner: CleanupOwner::Update,
                ..
            })
        ));
        manager.cleanup_entry(&update.entry, false);
    }

    #[test]
    fn no_services_metadata_keeps_legacy_shape() {
        let metadata = DurableSessionMetadata {
            version: 2,
            session_id: "ses_legacy".to_string(),
            task_id: "managed".to_string(),
            workspace_revision: 0,
            state: DurableSessionState::Ready,
            services: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(metadata).unwrap(),
            serde_json::json!({
                "version": 2,
                "session_id": "ses_legacy",
                "task_id": "managed",
                "workspace_revision": 0
            })
        );
    }

    #[tokio::test]
    async fn pathological_service_cleanup_is_bounded_and_releases_permit() {
        let temp = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let config = Arc::new(test_config(temp.path(), &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new_disabled(Arc::clone(&config));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&slots).acquire_owned().await.unwrap();
        let reservation = manager.reserve(
            ValidatedRequest {
                request_id: None,
                task_id: "managed".to_string(),
                task: config.tasks["managed"].clone(),
            },
            permit,
        );
        fs::create_dir(&reservation.entry.workspace).unwrap();
        *reservation.entry.state.lock().unwrap() = SessionState::Ready {
            last_activity: Instant::now(),
        };
        reservation
            .entry
            .services
            .lock()
            .unwrap()
            .push(RunningService::pathological_for_test("pathological"));
        manager
            .write_metadata(&DurableSessionMetadata {
                version: METADATA_VERSION,
                session_id: reservation.entry.id.clone(),
                task_id: reservation.entry.task_id.clone(),
                workspace_revision: 0,
                state: DurableSessionState::Ready,
                services: manager.durable_services(&reservation.entry),
            })
            .unwrap();

        let started = Instant::now();
        manager.service_failed(&reservation.entry, "forced failure");
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(manager.active_count(), 0);
        assert_eq!(slots.available_permits(), 1);
        assert!(!reservation.entry.workspace.exists());
        assert!(manager.metadata_path(&reservation.entry.id).is_file());
        let response = match &*reservation.entry.state.lock().unwrap() {
            SessionState::Terminated(response) => response.clone(),
            _ => panic!("session cleanup did not terminate"),
        };
        assert_eq!(
            response.teardown.error_code.as_deref(),
            Some("service_cleanup_failed")
        );
    }

    #[test]
    fn retained_service_start_order_is_name_sorted() {
        let executable = std::env::current_exe().unwrap();
        let service = || SessionServiceConfig {
            script: None,
            executable: Some(executable.clone()),
            args: Vec::new(),
            startup_timeout_sec: 1,
            shutdown_timeout_sec: 1,
            diagnostic_tail_bytes: 1,
        };
        let mut session = test_config(Path::new("/tmp"), &executable).tasks["managed"]
            .session
            .clone()
            .unwrap();
        session.services.insert("zeta".to_string(), service());
        session.services.insert("alpha".to_string(), service());
        session.services.insert("middle".to_string(), service());
        assert_eq!(sorted_service_names(&session), ["alpha", "middle", "zeta"]);
    }

    #[test]
    fn startup_reconciliation_tears_down_known_sessions_and_root_cleans_drift() {
        let temp = tempdir().unwrap();
        let executable = temp.path().join("task.sh");
        let teardown_log = temp.path().join("teardown.log");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\n[ \"${{1:-}}\" = teardown ] && echo teardown >> '{}'\n",
                teardown_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let config = Arc::new(test_config(temp.path(), &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new(Arc::clone(&config)).unwrap();
        prepare_protected_directory(manager.metadata_root()).unwrap();

        for (id, task) in [("ses_known", "managed"), ("ses_drift", "removed")] {
            let workspace = manager.session_workspace(id);
            fs::create_dir(&workspace).unwrap();
            fs::write(workspace.join("state"), "x").unwrap();
            manager
                .write_metadata(&DurableSessionMetadata {
                    version: METADATA_VERSION,
                    session_id: id.to_string(),
                    task_id: task.to_string(),
                    workspace_revision: 0,
                    state: DurableSessionState::Ready,
                    services: Vec::new(),
                })
                .unwrap();
        }
        let orphan = manager.session_workspace("ses_orphan");
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("partial"), "x").unwrap();
        drop(manager);

        let reconciled = SessionManager::new(config).unwrap();
        assert_eq!(reconciled.active_count(), 0);
        assert!(!reconciled.session_workspace("ses_known").exists());
        assert!(!reconciled.session_workspace("ses_drift").exists());
        assert!(!reconciled.session_workspace("ses_orphan").exists());
        assert_eq!(fs::read_to_string(teardown_log).unwrap().lines().count(), 1);
    }

    #[tokio::test]
    async fn maximum_validated_lifetime_reservation_does_not_overflow_instant() {
        let temp = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut config = test_config(temp.path(), &executable);
        config.service.http.enabled = true;
        let session = config
            .tasks
            .get_mut("managed")
            .unwrap()
            .session
            .as_mut()
            .unwrap();
        session.idle_timeout_sec = MAX_SESSION_LIFETIME_SEC - 1;
        session.max_lifetime_sec = MAX_SESSION_LIFETIME_SEC;
        config.validate().expect("maximum session lifetime");
        let config = Arc::new(config);
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new(Arc::clone(&config)).unwrap();
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .unwrap();
        let task = config.tasks.get("managed").unwrap().clone();
        let reservation = manager.reserve(
            ValidatedRequest {
                request_id: None,
                task_id: "managed".to_string(),
                task,
            },
            permit,
        );
        assert!(reservation.remaining_lifetime() > Duration::from_secs(1));
        manager.cancel_upload(&reservation);
    }

    #[tokio::test]
    async fn dispatcher_reservation_retains_fixed_action_and_encodes_name_as_data() {
        let temp = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut config = test_config(temp.path(), &executable);
        config.service.http.enabled = true;
        let session = config
            .tasks
            .get_mut("managed")
            .unwrap()
            .session
            .as_mut()
            .unwrap();
        let action = session.actions.remove("observe").unwrap();
        session.action_dispatcher = Some(SessionActionDispatcherConfig {
            script: action.script,
            executable: action.executable,
            args: action.args,
            timeout_sec: action.timeout_sec,
            artifacts: action.artifacts,
            allow_unlisted: true,
            actions: HashMap::new(),
        });
        config.validate().unwrap();
        let config = Arc::new(config);
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new(Arc::clone(&config)).unwrap();
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .unwrap();
        let reservation = manager.reserve(
            ValidatedRequest {
                request_id: None,
                task_id: "managed".to_string(),
                task: config.tasks["managed"].clone(),
            },
            permit,
        );
        *reservation.entry.state.lock().unwrap() = SessionState::Ready {
            last_activity: Instant::now(),
        };

        let action = manager
            .start_action(reservation.id(), "observe-later")
            .unwrap();
        assert_eq!(action.action.args, vec!["observe".to_string()]);
        assert_eq!(action.action.timeout_sec, 1);
        let input = serde_json::Map::from_iter([("count".to_string(), serde_json::Value::from(2))]);
        assert_eq!(
            action.encode_input(&input),
            br#"{"schema_version":"1","action":"observe-later","input":{"count":2}}"#
        );
    }

    #[tokio::test]
    async fn dispatcher_reservation_freezes_overrides_and_closed_allowlist_rejects_before_spawn() {
        let temp = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut config = test_config(temp.path(), &executable);
        config.service.http.enabled = true;
        let session = config
            .tasks
            .get_mut("managed")
            .unwrap()
            .session
            .as_mut()
            .unwrap();
        let action = session.actions.remove("observe").unwrap();
        session.action_dispatcher = Some(SessionActionDispatcherConfig {
            script: action.script,
            executable: action.executable,
            args: action.args,
            timeout_sec: 1,
            artifacts: ArtifactSpec {
                include: vec!["default/**".to_string()],
                exclude: Vec::new(),
            },
            allow_unlisted: false,
            actions: HashMap::from([(
                "allowed".to_string(),
                SessionActionPolicyOverride {
                    timeout_sec: Some(2),
                    artifacts: Some(ArtifactSpec::default()),
                },
            )]),
        });
        config.validate().unwrap();
        let config = Arc::new(config);
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new(Arc::clone(&config)).unwrap();
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .unwrap();
        let reservation = manager.reserve(
            ValidatedRequest {
                request_id: None,
                task_id: "managed".to_string(),
                task: config.tasks["managed"].clone(),
            },
            permit,
        );
        *reservation.entry.state.lock().unwrap() = SessionState::Ready {
            last_activity: Instant::now(),
        };

        assert!(matches!(
            manager.start_action(reservation.id(), "denied"),
            Err(ActionError::UnknownAction)
        ));
        assert!(matches!(
            *reservation.entry.state.lock().unwrap(),
            SessionState::Ready { .. }
        ));

        let action = manager.start_action(reservation.id(), "allowed").unwrap();
        assert_eq!(action.action.timeout_sec, 2);
        assert!(action.action.artifacts.include.is_empty());
        assert!(action.action.artifacts.exclude.is_empty());
    }

    #[test]
    fn stale_reconciliation_refuses_a_service_that_survived_its_supervisor() {
        let temp = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let config = Arc::new(test_config(temp.path(), &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let manager = SessionManager::new_disabled(Arc::clone(&config));
        prepare_protected_directory(manager.metadata_root()).unwrap();
        let workspace = manager.session_workspace("ses_survivor");
        fs::create_dir(&workspace).unwrap();

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do :; done"]);
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut service = command.spawn().unwrap();
        let pid = service.id();
        manager
            .write_metadata(&DurableSessionMetadata {
                version: METADATA_VERSION,
                session_id: "ses_survivor".to_string(),
                task_id: "managed".to_string(),
                workspace_revision: 0,
                state: DurableSessionState::StartingServices,
                services: vec![DurableServiceProcess {
                    name: "survivor".to_string(),
                    supervisor_pid: u32::MAX,
                    service_pid: pid,
                    service_pgid: pid as i32,
                    shutdown_timeout_sec: 1,
                }],
            })
            .unwrap();
        drop(manager);

        let error = SessionManager::new(config)
            .err()
            .expect("unsafe cleanup refused");
        assert!(error.to_string().contains("survived its supervisor"));
        assert!(workspace.exists());
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, 0);

        unsafe { libc::killpg(pid as i32, libc::SIGKILL) };
        service.wait().unwrap();
    }

    #[test]
    fn protected_metadata_rejects_permissive_directory_actual_and_dangling_symlinks() {
        let temp = tempdir().unwrap();
        let executable = temp.path().join("task.sh");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        let permissive = temp.path().join("permissive");
        let config = Arc::new(test_config(&permissive, &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let metadata_root = config.build.workspace_root.join(METADATA_DIRECTORY);
        fs::create_dir(&metadata_root).unwrap();
        fs::set_permissions(&metadata_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SessionManager::new(config).is_err());

        let linked = temp.path().join("linked");
        let config = Arc::new(test_config(&linked, &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        let target = linked.join("metadata-target");
        fs::create_dir_all(&target).unwrap();
        symlink(
            &target,
            config.build.workspace_root.join(METADATA_DIRECTORY),
        )
        .unwrap();
        assert!(SessionManager::new(config).is_err());

        let dangling = temp.path().join("dangling");
        let config = Arc::new(test_config(&dangling, &executable));
        fs::create_dir_all(&config.build.workspace_root).unwrap();
        symlink(
            dangling.join("missing-target"),
            config.build.workspace_root.join(METADATA_DIRECTORY),
        )
        .unwrap();
        assert!(SessionManager::new(config).is_err());
    }
}
