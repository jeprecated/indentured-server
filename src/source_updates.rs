use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::build::CancellationFlag;
use crate::config::SourceUpdatesConfig;
use crate::protocol::{SessionUpdateChange, SessionUpdateEvidence, SessionUpdateRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateErrorKind {
    BadRequest,
    Limit,
    Internal,
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct UpdateError {
    pub(crate) kind: UpdateErrorKind,
    pub(crate) message: String,
    pub(crate) rollback_proven: bool,
}

impl UpdateError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            kind: UpdateErrorKind::BadRequest,
            message: message.into(),
            rollback_proven: true,
        }
    }

    fn limit(message: impl Into<String>) -> Self {
        Self {
            kind: UpdateErrorKind::Limit,
            message: message.into(),
            rollback_proven: true,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: UpdateErrorKind::Internal,
            message: message.into(),
            rollback_proven: true,
        }
    }

    pub(crate) fn worker_panicked() -> Self {
        Self {
            kind: UpdateErrorKind::Internal,
            message: "source update worker panicked".to_string(),
            rollback_proven: false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreparedUpdate {
    root: PathBuf,
    changes: Vec<PreparedChange>,
}

impl Drop for PreparedUpdate {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct PreparedChange {
    path: String,
    kind: PreparedKind,
}

#[derive(Debug)]
enum PreparedKind {
    File { staged: PathBuf, sha256: String },
    Delete,
}

struct Backup {
    path: String,
    staged: Option<PathBuf>,
    original: Option<FileIdentity>,
    uid: u32,
    gid: u32,
    mode: u32,
    sha256: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct AppliedEvidence {
    pub(crate) changed: Vec<SessionUpdateEvidence>,
    pub(crate) deleted: Vec<SessionUpdateEvidence>,
}

pub(crate) fn prepare_update(
    archive_path: &Path,
    metadata_root: &Path,
    session_id: &str,
    request: &SessionUpdateRequest,
    policy: &SourceUpdatesConfig,
) -> Result<PreparedUpdate, UpdateError> {
    let includes = compile_patterns(&policy.include)?;
    let excludes = compile_patterns(&policy.exclude)?;
    for change in &request.changes {
        let path = Path::new(change.path());
        if !includes.iter().any(|pattern| pattern.matches_path(path))
            || excludes.iter().any(|pattern| pattern.matches_path(path))
        {
            return Err(UpdateError::bad(format!(
                "change path {:?} is outside the configured source update allowlist",
                change.path()
            )));
        }
    }

    let root = metadata_root.join(format!(".{session_id}.update-{}", Uuid::new_v4().simple()));
    fs::create_dir(&root)
        .and_then(|()| fs::set_permissions(&root, fs::Permissions::from_mode(0o700)))
        .map_err(|err| UpdateError::internal(format!("failed to create update staging: {err}")))?;

    let result = prepare_archive(archive_path, &root, request, policy);
    match result {
        Ok(changes) => Ok(PreparedUpdate { root, changes }),
        Err(err) => {
            let _ = fs::remove_dir_all(&root);
            Err(err)
        }
    }
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<glob::Pattern>, UpdateError> {
    patterns
        .iter()
        .map(|pattern| {
            glob::Pattern::new(pattern).map_err(|err| {
                UpdateError::internal(format!("configured source update glob is invalid: {err}"))
            })
        })
        .collect()
}

fn prepare_archive(
    archive_path: &Path,
    root: &Path,
    request: &SessionUpdateRequest,
    policy: &SourceUpdatesConfig,
) -> Result<Vec<PreparedChange>, UpdateError> {
    let declared_files: HashMap<&str, &str> = request
        .changes
        .iter()
        .filter_map(|change| match change {
            SessionUpdateChange::File { path, sha256 } => Some((path.as_str(), sha256.as_str())),
            SessionUpdateChange::Delete { .. } => None,
        })
        .collect();
    let file = File::open(archive_path)
        .map_err(|err| UpdateError::internal(format!("failed to open update archive: {err}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|err| UpdateError::bad(format!("invalid update zip archive: {err}")))?;
    if archive.len() > policy.max_files {
        return Err(UpdateError::limit(format!(
            "update archive exceeds max_files ({})",
            policy.max_files
        )));
    }
    if archive.len() != declared_files.len() {
        return Err(UpdateError::bad(
            "update archive must contain exactly the declared file entries",
        ));
    }

    let mut seen = HashSet::new();
    let mut folded = HashSet::new();
    let mut staged_by_path = HashMap::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| UpdateError::bad(format!("failed to read update zip entry: {err}")))?;
        let name = entry.name().to_string();
        if !seen.insert(name.clone()) || !folded.insert(name.to_ascii_lowercase()) {
            return Err(UpdateError::bad(
                "update archive contains duplicate or case-colliding paths",
            ));
        }
        let Some(expected_hash) = declared_files.get(name.as_str()) else {
            return Err(UpdateError::bad(
                "update archive contains an undeclared file entry",
            ));
        };
        if entry.is_dir() || entry.is_symlink() {
            return Err(UpdateError::bad(
                "update archive entries must be regular non-executable files",
            ));
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            if (kind != 0 && kind != 0o100000) || mode & 0o111 != 0 {
                return Err(UpdateError::bad(
                    "update archive entries must be regular non-executable files",
                ));
            }
        }
        total = total.saturating_add(entry.size());
        if total > policy.max_uncompressed_bytes {
            return Err(UpdateError::limit(format!(
                "update archive exceeds max_uncompressed_bytes ({})",
                policy.max_uncompressed_bytes
            )));
        }

        let staged = root.join(format!("file-{index}"));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged)
            .map_err(|err| UpdateError::internal(format!("failed to stage update file: {err}")))?;
        let mut hasher = Sha256::new();
        let mut actual = 0u64;
        loop {
            let bytes = entry
                .read(&mut buffer)
                .map_err(|err| UpdateError::bad(format!("failed to read update entry: {err}")))?;
            if bytes == 0 {
                break;
            }
            actual = actual.saturating_add(bytes as u64);
            if total.saturating_sub(entry.size()).saturating_add(actual)
                > policy.max_uncompressed_bytes
            {
                return Err(UpdateError::limit(format!(
                    "update archive exceeds max_uncompressed_bytes ({})",
                    policy.max_uncompressed_bytes
                )));
            }
            hasher.update(&buffer[..bytes]);
            output.write_all(&buffer[..bytes]).map_err(|err| {
                UpdateError::internal(format!("failed to write staged update file: {err}"))
            })?;
        }
        output
            .sync_all()
            .map_err(|err| UpdateError::internal(format!("failed to sync staged file: {err}")))?;
        let actual_hash = format!("{:x}", hasher.finalize());
        if actual_hash != **expected_hash {
            return Err(UpdateError::bad(format!(
                "content sha256 mismatch for {name:?}"
            )));
        }
        staged_by_path.insert(name, (staged, actual_hash));
    }

    let mut changes = Vec::with_capacity(request.changes.len());
    for change in &request.changes {
        let kind = match change {
            SessionUpdateChange::File { path, .. } => {
                let (staged, sha256) = staged_by_path
                    .remove(path)
                    .expect("archive and declarations were matched");
                PreparedKind::File { staged, sha256 }
            }
            SessionUpdateChange::Delete { .. } => PreparedKind::Delete,
        };
        changes.push(PreparedChange {
            path: change.path().to_string(),
            kind,
        });
    }
    Ok(changes)
}

pub(crate) fn apply_update(
    prepared: PreparedUpdate,
    workspace: &Path,
    task_uid: u32,
    task_gid: u32,
    cancellation: &CancellationFlag,
    commit_metadata: impl FnOnce() -> io::Result<()>,
) -> Result<AppliedEvidence, UpdateError> {
    apply_update_inner(
        &prepared,
        workspace,
        task_uid,
        task_gid,
        cancellation,
        commit_metadata,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdateCheckpoint {
    AfterMutation(usize),
}

fn apply_update_inner(
    prepared: &PreparedUpdate,
    workspace: &Path,
    task_uid: u32,
    task_gid: u32,
    cancellation: &CancellationFlag,
    commit_metadata: impl FnOnce() -> io::Result<()>,
) -> Result<AppliedEvidence, UpdateError> {
    apply_update_inner_controlled(
        prepared,
        workspace,
        task_uid,
        task_gid,
        cancellation,
        commit_metadata,
        |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_update_inner_controlled(
    prepared: &PreparedUpdate,
    workspace: &Path,
    task_uid: u32,
    task_gid: u32,
    cancellation: &CancellationFlag,
    commit_metadata: impl FnOnce() -> io::Result<()>,
    checkpoint: impl Fn(UpdateCheckpoint),
) -> Result<AppliedEvidence, UpdateError> {
    if cancellation.is_cancelled() {
        return Err(UpdateError {
            kind: UpdateErrorKind::Cancelled,
            message: "update cancelled".into(),
            rollback_proven: true,
        });
    }
    let root_fd = open_workspace_root(workspace)?;
    let backups_root = prepared.root.join("backups");
    fs::create_dir(&backups_root)
        .and_then(|()| fs::set_permissions(&backups_root, fs::Permissions::from_mode(0o700)))
        .map_err(|err| UpdateError::internal(format!("failed to create update backups: {err}")))?;

    for change in &prepared.changes {
        if let PreparedKind::File { staged, .. } = &change.kind {
            prepare_staged_file(staged, task_uid, task_gid).map_err(|err| {
                UpdateError::internal(format!("failed to prepare staged file: {err}"))
            })?;
        }
    }

    let mut backups = Vec::with_capacity(prepared.changes.len());
    for (index, change) in prepared.changes.iter().enumerate() {
        let (parent, name) = open_workspace_parent(root_fd.as_raw_fd(), &change.path)
            .map_err(|err| UpdateError::bad(format!("invalid update ancestor: {err}")))?;
        let metadata = inspect_target(parent.as_raw_fd(), &name).map_err(|err| {
            UpdateError::internal(format!(
                "failed to inspect update target {:?}: {err}",
                change.path
            ))
        })?;
        if let Some(metadata) = metadata {
            if !is_regular_mode(metadata.mode) {
                return Err(UpdateError::bad(format!(
                    "update target {:?} is not a regular file",
                    change.path
                )));
            }
            if metadata.mode & 0o111 != 0 {
                return Err(UpdateError::bad(format!(
                    "update target {:?} is executable",
                    change.path
                )));
            }
        }
        if matches!(change.kind, PreparedKind::Delete) && metadata.is_none() {
            return Err(UpdateError::bad(format!(
                "delete target {:?} does not exist",
                change.path
            )));
        }
        let backup_path = metadata.map(|_| backups_root.join(format!("backup-{index}")));
        let sha256 = if let Some(backup_path) = &backup_path {
            let mut source = open_regular_at(parent.as_raw_fd(), &name, metadata.expect("present"))
                .map_err(|err| {
                    UpdateError::bad(format!(
                        "update target {:?} changed during backup: {err}",
                        change.path
                    ))
                })?;
            Some(
                copy_open_file_and_hash(&mut source, backup_path).map_err(|err| {
                    UpdateError::internal(format!("failed to back up update target: {err}"))
                })?,
            )
        } else {
            None
        };
        backups.push(Backup {
            path: change.path.clone(),
            staged: backup_path,
            original: metadata.map(|metadata| metadata.identity),
            uid: metadata.map_or(task_uid, |metadata| metadata.uid),
            gid: metadata.map_or(task_gid, |metadata| metadata.gid),
            mode: metadata.map_or(0o644, |metadata| metadata.mode & 0o777),
            sha256,
        });
    }

    let mut mutation_parents = Vec::with_capacity(prepared.changes.len());
    let mutation = (|| {
        for (index, change) in prepared.changes.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(UpdateError {
                    kind: UpdateErrorKind::Cancelled,
                    message: "update cancelled".into(),
                    rollback_proven: true,
                });
            }
            let (parent, name) = open_workspace_parent(root_fd.as_raw_fd(), &change.path)
                .map_err(|err| UpdateError::bad(format!("invalid update ancestor: {err}")))?;
            validate_target_at(parent.as_raw_fd(), &name, &backups[index])?;
            mutation_parents.push(parent);
            let parent_fd = mutation_parents
                .last()
                .expect("just pushed mutation parent")
                .as_raw_fd();
            match &change.kind {
                PreparedKind::File { staged, .. } => {
                    atomic_copy_at(staged, parent_fd, &name, task_uid, task_gid, 0o644).map_err(
                        |err| {
                            UpdateError::internal(format!("failed to install update file: {err}"))
                        },
                    )?;
                }
                PreparedKind::Delete => {
                    unlink_file_at(parent_fd, &name).map_err(|err| {
                        UpdateError::internal(format!("failed to delete update target: {err}"))
                    })?;
                }
            }
            checkpoint(UpdateCheckpoint::AfterMutation(index));
        }
        for (change, parent) in prepared.changes.iter().zip(&mutation_parents) {
            verify_parent_still_beneath(root_fd.as_raw_fd(), &change.path, parent.as_raw_fd())?;
        }
        if cancellation.is_cancelled() {
            return Err(UpdateError {
                kind: UpdateErrorKind::Cancelled,
                message: "update cancelled".into(),
                rollback_proven: true,
            });
        }
        commit_metadata().map_err(|err| UpdateError {
            kind: UpdateErrorKind::Internal,
            message: format!("failed to commit workspace revision: {err}"),
            rollback_proven: false,
        })?;
        Ok(())
    })();

    if let Err(mut err) = mutation {
        if let Err(rollback) = rollback(&backups[..mutation_parents.len()], &mutation_parents) {
            err.rollback_proven = false;
            err.message = format!("{}; rollback failed: {rollback}", err.message);
        }
        return Err(err);
    }

    let mut changed = Vec::new();
    let mut deleted = Vec::new();
    for (change, backup) in prepared.changes.iter().zip(&backups) {
        match &change.kind {
            PreparedKind::File { sha256, .. } => changed.push(SessionUpdateEvidence {
                path: change.path.clone(),
                sha256: sha256.clone(),
            }),
            PreparedKind::Delete => deleted.push(SessionUpdateEvidence {
                path: change.path.clone(),
                sha256: backup
                    .sha256
                    .clone()
                    .expect("delete target required an existing backup"),
            }),
        }
    }
    Ok(AppliedEvidence { changed, deleted })
}

#[derive(Clone, Copy)]
struct TargetMetadata {
    identity: FileIdentity,
    uid: u32,
    gid: u32,
    mode: u32,
}

fn open_workspace_root(workspace: &Path) -> Result<OwnedFd, UpdateError> {
    let workspace = CString::new(workspace.as_os_str().as_bytes())
        .map_err(|_| UpdateError::bad("session workspace path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            workspace.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        )
    };
    if fd < 0 {
        Err(UpdateError::internal(format!(
            "failed to open session workspace: {}",
            io::Error::last_os_error()
        )))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn open_workspace_parent(root_fd: RawFd, relative: &str) -> io::Result<(OwnedFd, CString)> {
    let components: Vec<&str> = relative.split('/').collect();
    let final_name = CString::new(
        *components
            .last()
            .ok_or_else(|| io::Error::other("empty path"))?,
    )
    .map_err(|_| io::Error::other("path contains NUL"))?;
    let duplicated = unsafe { libc::fcntl(root_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut parent = unsafe { OwnedFd::from_raw_fd(duplicated) };
    for component in &components[..components.len().saturating_sub(1)] {
        let component = CString::new(*component)
            .map_err(|_| io::Error::other("path component contains NUL"))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        parent = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok((parent, final_name))
}

fn inspect_target(parent_fd: RawFd, name: &CString) -> io::Result<Option<TargetMetadata>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    let stat = unsafe { stat.assume_init() };
    Ok(Some(TargetMetadata {
        identity: stat_identity(&stat),
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat_mode(&stat),
    }))
}

fn open_regular_at(parent_fd: RawFd, name: &CString, expected: TargetMetadata) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || fd_identity(file.as_raw_fd())? != expected.identity {
        return Err(io::Error::other("target identity changed"));
    }
    Ok(file)
}

fn validate_target_at(
    parent_fd: RawFd,
    name: &CString,
    backup: &Backup,
) -> Result<(), UpdateError> {
    let current = inspect_target(parent_fd, name)
        .map_err(|err| UpdateError::internal(format!("failed to recheck update target: {err}")))?;
    match (backup.original, current) {
        (Some(expected), Some(current))
            if current.identity == expected && is_regular_mode(current.mode) =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(UpdateError::bad(format!(
            "update target {:?} changed before mutation",
            backup.path
        ))),
    }
}

fn verify_parent_still_beneath(
    root_fd: RawFd,
    relative: &str,
    held_parent_fd: RawFd,
) -> Result<(), UpdateError> {
    let (current, _) = open_workspace_parent(root_fd, relative)
        .map_err(|err| UpdateError::bad(format!("update ancestor changed: {err}")))?;
    let held = fd_identity(held_parent_fd)
        .map_err(|err| UpdateError::internal(format!("failed to inspect held parent: {err}")))?;
    let current = fd_identity(current.as_raw_fd())
        .map_err(|err| UpdateError::internal(format!("failed to inspect current parent: {err}")))?;
    if held == current {
        Ok(())
    } else {
        Err(UpdateError::bad("update ancestor changed during mutation"))
    }
}

fn fd_identity(fd: RawFd) -> io::Result<FileIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    Ok(stat_identity(&stat))
}

#[allow(clippy::unnecessary_cast)]
fn stat_identity(stat: &libc::stat) -> FileIdentity {
    // libc uses platform-specific dev_t/ino_t widths and signedness.
    FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    }
}

#[allow(clippy::unnecessary_cast)]
fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode as u32
}

#[allow(clippy::unnecessary_cast)]
fn is_regular_mode(mode: u32) -> bool {
    mode & (libc::S_IFMT as u32) == libc::S_IFREG as u32
}

fn rollback(backups: &[Backup], parents: &[OwnedFd]) -> io::Result<()> {
    for (backup, parent) in backups.iter().zip(parents).rev() {
        let name = CString::new(
            backup
                .path
                .rsplit('/')
                .next()
                .ok_or_else(|| io::Error::other("empty rollback path"))?,
        )
        .map_err(|_| io::Error::other("rollback path contains NUL"))?;
        if let Some(staged) = &backup.staged {
            if inspect_target(parent.as_raw_fd(), &name)?
                .is_some_and(|metadata| !is_regular_mode(metadata.mode))
            {
                return Err(io::Error::other("rollback target is not a regular file"));
            }
            atomic_copy_at(
                staged,
                parent.as_raw_fd(),
                &name,
                backup.uid,
                backup.gid,
                backup.mode,
            )?;
        } else {
            match inspect_target(parent.as_raw_fd(), &name)? {
                Some(metadata) if is_regular_mode(metadata.mode) => {
                    unlink_file_at(parent.as_raw_fd(), &name)?;
                }
                None => {}
                Some(_) => {
                    return Err(io::Error::other("rollback target is not a regular file"));
                }
            }
        }
    }
    Ok(())
}

fn copy_open_file_and_hash(source: &mut File, destination: &Path) -> io::Result<String> {
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes = source.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
        destination.write_all(&buffer[..bytes])?;
    }
    destination.sync_all()?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn prepare_staged_file(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("staged update is not a regular file"));
    }
    set_fd_owner_mode(file.as_raw_fd(), uid, gid, 0o644)
}

fn atomic_copy_at(
    source: &Path,
    parent_fd: RawFd,
    target_name: &CString,
    uid: u32,
    gid: u32,
    mode: u32,
) -> io::Result<()> {
    let temp_name = CString::new(format!(
        ".indentured-update-{}.tmp",
        Uuid::new_v4().simple()
    ))
    .expect("generated update temp name contains no NUL");
    let result = (|| {
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)?;
        if !source.metadata()?.is_file() {
            return Err(io::Error::other("atomic source is not a regular file"));
        }
        let fd = unsafe {
            libc::openat(
                parent_fd,
                temp_name.as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut output = unsafe { File::from_raw_fd(fd) };
        io::copy(&mut source, &mut output)?;
        output.sync_all()?;
        set_fd_owner_mode(output.as_raw_fd(), uid, gid, mode)?;
        output.sync_all()?;
        if unsafe {
            libc::renameat(
                parent_fd,
                temp_name.as_ptr(),
                parent_fd,
                target_name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        sync_fd(parent_fd)
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent_fd, temp_name.as_ptr(), 0);
        }
    }
    result
}

fn unlink_file_at(parent_fd: RawFd, name: &CString) -> io::Result<()> {
    if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    sync_fd(parent_fd)
}

fn set_fd_owner_mode(fd: RawFd, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    if unsafe { libc::fchown(fd, uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sync_fd(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use tempfile::{tempdir, NamedTempFile};
    use zip::write::SimpleFileOptions;

    fn request(path: &str, contents: &[u8]) -> SessionUpdateRequest {
        SessionUpdateRequest {
            schema_version: "1".into(),
            request_id: "req-1".into(),
            base_revision: "rev_0".into(),
            source: crate::protocol::SourceMetadata {
                format: crate::protocol::SourceFormat::Zip,
            },
            changes: vec![SessionUpdateChange::File {
                path: path.into(),
                sha256: format!("{:x}", Sha256::digest(contents)),
            }],
        }
    }

    fn policy() -> SourceUpdatesConfig {
        SourceUpdatesConfig {
            timeout_sec: 10,
            max_transfer_bytes: 1024 * 1024,
            max_uncompressed_bytes: 1024 * 1024,
            max_files: 10,
            max_depth: 10,
            include: vec!["src/**".into()],
            exclude: vec!["src/private/**".into()],
        }
    }

    fn archive(entries: &[(&str, &[u8], u32)]) -> NamedTempFile {
        let temp = NamedTempFile::new().unwrap();
        let mut zip = zip::ZipWriter::new(temp.reopen().unwrap());
        for (path, contents, mode) in entries {
            zip.start_file(*path, SimpleFileOptions::default().unix_permissions(*mode))
                .unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();
        temp
    }

    #[test]
    fn live_ancestor_symlink_swap_cannot_touch_outside_and_rolls_back() {
        let temp = tempdir().unwrap();
        let metadata = temp.path().join("metadata");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir(&metadata).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("src")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(workspace.join("src/one"), b"old-one").unwrap();
        fs::write(workspace.join("src/two"), b"old-two").unwrap();
        fs::write(outside.join("one"), b"outside-one").unwrap();
        fs::write(outside.join("two"), b"outside-two").unwrap();
        let zip = archive(&[
            ("src/one", b"new-one", 0o644),
            ("src/two", b"new-two", 0o644),
        ]);
        let request = SessionUpdateRequest {
            schema_version: "1".into(),
            request_id: "req-swap".into(),
            base_revision: "rev_0".into(),
            source: crate::protocol::SourceMetadata {
                format: crate::protocol::SourceFormat::Zip,
            },
            changes: vec![
                SessionUpdateChange::File {
                    path: "src/one".into(),
                    sha256: format!("{:x}", Sha256::digest(b"new-one")),
                },
                SessionUpdateChange::File {
                    path: "src/two".into(),
                    sha256: format!("{:x}", Sha256::digest(b"new-two")),
                },
            ],
        };
        let prepared =
            prepare_update(zip.path(), &metadata, "ses_test", &request, &policy()).unwrap();
        let arrived = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_workspace = workspace.clone();
        let worker_arrived = Arc::clone(&arrived);
        let worker_release = Arc::clone(&release);
        let worker_committed = Arc::clone(&committed);
        let worker = std::thread::spawn(move || {
            apply_update_inner_controlled(
                &prepared,
                &worker_workspace,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                &CancellationFlag::default(),
                || {
                    worker_committed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
                |checkpoint| {
                    if checkpoint == UpdateCheckpoint::AfterMutation(0) {
                        worker_arrived.wait();
                        worker_release.wait();
                    }
                },
            )
        });
        arrived.wait();
        fs::rename(workspace.join("src"), workspace.join("moved")).unwrap();
        symlink(&outside, workspace.join("src")).unwrap();
        release.wait();
        let err = worker.join().unwrap().unwrap_err();
        assert!(err.rollback_proven, "{err}");
        assert!(!committed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(fs::read(workspace.join("moved/one")).unwrap(), b"old-one");
        assert_eq!(fs::read(workspace.join("moved/two")).unwrap(), b"old-two");
        assert_eq!(fs::read(outside.join("one")).unwrap(), b"outside-one");
        assert_eq!(fs::read(outside.join("two")).unwrap(), b"outside-two");
    }

    #[test]
    fn file_and_delete_update_commits_hash_evidence() {
        let temp = tempdir().unwrap();
        let metadata = temp.path().join("metadata");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&metadata).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("src")).unwrap();
        fs::write(workspace.join("src/old"), b"old").unwrap();
        let zip = archive(&[("src/new", b"new", 0o644)]);
        let request = SessionUpdateRequest {
            schema_version: "1".into(),
            request_id: "req-commit".into(),
            base_revision: "rev_0".into(),
            source: crate::protocol::SourceMetadata {
                format: crate::protocol::SourceFormat::Zip,
            },
            changes: vec![
                SessionUpdateChange::File {
                    path: "src/new".into(),
                    sha256: format!("{:x}", Sha256::digest(b"new")),
                },
                SessionUpdateChange::Delete {
                    path: "src/old".into(),
                },
            ],
        };
        let prepared =
            prepare_update(zip.path(), &metadata, "ses_test", &request, &policy()).unwrap();
        let evidence = apply_update(
            prepared,
            &workspace,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            &CancellationFlag::default(),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(fs::read(workspace.join("src/new")).unwrap(), b"new");
        assert!(!workspace.join("src/old").exists());
        assert_eq!(
            evidence.changed[0].sha256,
            format!("{:x}", Sha256::digest(b"new"))
        );
        assert_eq!(
            evidence.deleted[0].sha256,
            format!("{:x}", Sha256::digest(b"old"))
        );
    }

    #[test]
    fn verified_update_applies_and_metadata_failure_rolls_back() {
        let temp = tempdir().unwrap();
        let metadata = temp.path().join("metadata");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&metadata).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("src")).unwrap();
        fs::write(workspace.join("src/file"), b"old").unwrap();
        let zip = archive(&[("src/file", b"new", 0o644)]);
        let prepared = prepare_update(
            zip.path(),
            &metadata,
            "ses_test",
            &request("src/file", b"new"),
            &policy(),
        )
        .unwrap();
        let metadata_before = fs::read(workspace.join("src/file")).unwrap();
        let err = apply_update(
            prepared,
            &workspace,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            &CancellationFlag::default(),
            || Err(io::Error::other("forced")),
        )
        .unwrap_err();
        assert_eq!(err.kind, UpdateErrorKind::Internal);
        assert!(!err.rollback_proven);
        assert_eq!(
            fs::read(workspace.join("src/file")).unwrap(),
            metadata_before
        );
    }

    #[test]
    fn archive_directories_symlinks_special_files_allowlists_and_limits_fail_closed() {
        let temp = tempdir().unwrap();
        let metadata = temp.path().join("metadata");
        fs::create_dir(&metadata).unwrap();

        let directory = NamedTempFile::new().unwrap();
        let mut zip = zip::ZipWriter::new(directory.reopen().unwrap());
        zip.add_directory(
            "src/file/",
            SimpleFileOptions::default().unix_permissions(0o755),
        )
        .unwrap();
        zip.finish().unwrap();
        assert!(prepare_update(
            directory.path(),
            &metadata,
            "ses_test",
            &request("src/file", b""),
            &policy()
        )
        .is_err());

        let symlink = NamedTempFile::new().unwrap();
        let mut zip = zip::ZipWriter::new(symlink.reopen().unwrap());
        zip.add_symlink(
            "src/file",
            "target",
            SimpleFileOptions::default().unix_permissions(0o777),
        )
        .unwrap();
        zip.finish().unwrap();
        assert!(prepare_update(
            symlink.path(),
            &metadata,
            "ses_test",
            &request("src/file", b"target"),
            &policy()
        )
        .is_err());

        let special = archive(&[("src/file", b"x", 0o644)]);
        let mut bytes = fs::read(special.path()).unwrap();
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        bytes[central + 38..central + 42].copy_from_slice(&(0o020666u32 << 16).to_le_bytes());
        fs::write(special.path(), bytes).unwrap();
        assert!(prepare_update(
            special.path(),
            &metadata,
            "ses_test",
            &request("src/file", b"x"),
            &policy()
        )
        .is_err());

        let private = archive(&[("src/private/file", b"x", 0o644)]);
        assert!(prepare_update(
            private.path(),
            &metadata,
            "ses_test",
            &request("src/private/file", b"x"),
            &policy()
        )
        .is_err());

        let large = archive(&[("src/file", b"large", 0o644)]);
        let mut small_policy = policy();
        small_policy.max_uncompressed_bytes = 2;
        assert_eq!(
            prepare_update(
                large.path(),
                &metadata,
                "ses_test",
                &request("src/file", b"large"),
                &small_policy
            )
            .unwrap_err()
            .kind,
            UpdateErrorKind::Limit
        );
    }

    #[test]
    fn archive_policy_hash_type_and_ancestor_fail_closed() {
        let temp = tempdir().unwrap();
        let metadata = temp.path().join("metadata");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&metadata).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("src")).unwrap();

        let executable = archive(&[("src/file", b"new", 0o755)]);
        assert_eq!(
            prepare_update(
                executable.path(),
                &metadata,
                "ses_test",
                &request("src/file", b"new"),
                &policy()
            )
            .unwrap_err()
            .kind,
            UpdateErrorKind::BadRequest
        );
        let undeclared = archive(&[("src/other", b"new", 0o644)]);
        assert!(prepare_update(
            undeclared.path(),
            &metadata,
            "ses_test",
            &request("src/file", b"new"),
            &policy()
        )
        .is_err());
        let wrong_hash = archive(&[("src/file", b"wrong", 0o644)]);
        assert!(prepare_update(
            wrong_hash.path(),
            &metadata,
            "ses_test",
            &request("src/file", b"new"),
            &policy()
        )
        .is_err());

        let valid = archive(&[("src/file", b"new", 0o644)]);
        let prepared = prepare_update(
            valid.path(),
            &metadata,
            "ses_test",
            &request("src/file", b"new"),
            &policy(),
        )
        .unwrap();
        fs::remove_dir(workspace.join("src")).unwrap();
        symlink(temp.path(), workspace.join("src")).unwrap();
        assert_eq!(
            apply_update(
                prepared,
                &workspace,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                &CancellationFlag::default(),
                || Ok(())
            )
            .unwrap_err()
            .kind,
            UpdateErrorKind::BadRequest
        );
    }
}
