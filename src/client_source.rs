use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MAX_FILES: usize = 50_000;
const MAX_DEPTH: usize = 64;
const MAX_UNCOMPRESSED_BYTES: u64 = 1_342_177_280;
const MAX_JJ_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_JJ_STDERR: usize = 8192;
const JJ_POLL_INTERVAL: Duration = Duration::from_millis(20);
const JJ_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const JJ_MANIFEST_TEMPLATE: &str = "\"{\\\"path\\\":\" ++ json(path) ++ \",\\\"type\\\":\" ++ file_type.escape_json() ++ \",\\\"executable\\\":\" ++ executable ++ \",\\\"conflict\\\":\" ++ conflict ++ \"}\\n\"";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: EntryKind,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceManifest {
    pub schema_version: u32,
    pub entries: Vec<SourceEntry>,
    pub entry_count: usize,
    pub uncompressed_bytes: u64,
    pub aggregate_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub mode: String,
    pub root: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jj_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jj_commit_id: Option<String>,
    pub initial_snapshot_atomicity: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
}

pub struct SourcePackage {
    pub archive: NamedTempFile,
    pub manifest: SourceManifest,
    pub identity: SourceIdentity,
}

#[derive(Clone)]
pub struct SourceCancellation {
    cancelled: Arc<AtomicBool>,
    program: Arc<std::ffi::OsString>,
    prefix_args: Arc<Vec<std::ffi::OsString>>,
}

impl Default for SourceCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            program: Arc::new(std::ffi::OsString::from("jj")),
            prefix_args: Arc::new(Vec::new()),
        }
    }
}

impl SourceCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_program(program: impl Into<std::ffi::OsString>) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            program: Arc::new(std::ffi::OsString::from("/bin/sh")),
            prefix_args: Arc::new(vec![program.into()]),
        }
    }

    fn cleanup_context(&self) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            program: Arc::clone(&self.program),
            prefix_args: Arc::clone(&self.prefix_args),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn check(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "source packaging interrupted",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilesystemPatterns {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JjEntry {
    path: String,
    #[serde(rename = "type")]
    file_type: String,
    executable: bool,
    conflict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedEntry {
    path: String,
    kind: EntryKind,
    executable: bool,
    symlink_target: Option<String>,
}

struct PackageContext<'a> {
    root: &'a Path,
    mode: &'a str,
    jj_version: Option<String>,
    jj_commit_id: Option<String>,
}

pub fn find_jj_root(start: &Path) -> io::Result<Option<PathBuf>> {
    let mut cursor = fs::canonicalize(start)?;
    loop {
        let marker = cursor.join(".jj");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("refusing symlinked Jujutsu marker {}", marker.display()),
                    ));
                }
                return Ok(Some(cursor));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        if !cursor.pop() {
            return Ok(None);
        }
    }
}

pub fn package_source(
    invocation_dir: &Path,
    filesystem_root: &Path,
    patterns: &FilesystemPatterns,
    temporary_root: &Path,
) -> io::Result<SourcePackage> {
    package_source_cancellable(
        invocation_dir,
        filesystem_root,
        patterns,
        temporary_root,
        &SourceCancellation::new(),
    )
}

pub fn package_source_cancellable(
    invocation_dir: &Path,
    filesystem_root: &Path,
    patterns: &FilesystemPatterns,
    temporary_root: &Path,
    cancellation: &SourceCancellation,
) -> io::Result<SourcePackage> {
    cancellation.check()?;
    if let Some(root) = find_jj_root(invocation_dir)? {
        if !patterns.include.is_empty() || !patterns.exclude.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--source/--source-exclude and sources config are not allowed in a Jujutsu repository; the complete pinned @ tree is submitted",
            ));
        }
        package_jj(&root, invocation_dir, temporary_root, cancellation)
    } else {
        package_filesystem_cancellable(filesystem_root, patterns, temporary_root, cancellation)
    }
}

fn package_jj(
    root: &Path,
    invocation_dir: &Path,
    temporary_root: &Path,
    cancellation: &SourceCancellation,
) -> io::Result<SourcePackage> {
    let version = run_jj_bounded(root, &["--version"], true, cancellation, None)?;
    let version = one_line(&version, 256, "jj version")?;
    let pin = run_jj_bounded(
        invocation_dir,
        &[
            "--no-pager",
            "log",
            "--no-graph",
            "-r",
            "@",
            "-T",
            "commit_id ++ \"\\n\"",
        ],
        true,
        cancellation,
        None,
    )?;
    let pin = one_line(&pin, 128, "Jujutsu commit id")?;
    if pin.len() < 40 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Jujutsu did not return one full hexadecimal commit id",
        ));
    }

    let listing = run_jj_bounded(
        root,
        &[
            "--ignore-working-copy",
            "--no-pager",
            "file",
            "list",
            "-r",
            &pin,
            "-T",
            JJ_MANIFEST_TEMPLATE,
        ],
        true,
        cancellation,
        None,
    )?;
    if listing.len() > MAX_JJ_OUTPUT {
        return Err(limit("Jujutsu manifest output exceeded the client limit"));
    }
    let mut planned = Vec::new();
    for line in listing.lines() {
        if line.is_empty() {
            continue;
        }
        let entry: JjEntry = serde_json::from_str(line).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid jj manifest JSON: {err}"),
            )
        })?;
        if entry.conflict || entry.file_type == "conflict" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Jujutsu tree contains a conflict at {:?}", entry.path),
            ));
        }
        let kind = match entry.file_type.as_str() {
            "file" => EntryKind::File,
            "symlink" => EntryKind::Symlink,
            "git-submodule" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Jujutsu tree contains unsupported git submodule {:?}",
                        entry.path
                    ),
                ))
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Jujutsu tree contains unsupported {other} entry {:?}",
                        entry.path
                    ),
                ))
            }
        };
        validate_archive_path(&entry.path)?;
        planned.push(PlannedEntry {
            path: entry.path,
            kind,
            executable: entry.executable,
            symlink_target: None,
        });
    }
    validate_planned_entries(&mut planned)?;
    populate_jj_symlink_targets(root, &pin, &mut planned, temporary_root, cancellation)?;

    let temp = tempfile::Builder::new()
        .prefix(".source-")
        .suffix(".zip")
        .tempfile_in(temporary_root)?;
    let mut writer = ZipWriter::new(temp.reopen()?);
    let mut manifest_entries = Vec::with_capacity(planned.len());
    let mut total = 0u64;
    let mut aggregate = Sha256::new();

    for entry in &planned {
        cancellation.check()?;
        match entry.kind {
            EntryKind::File => {
                let options = regular_options(entry.executable);
                writer
                    .start_file(&entry.path, options)
                    .map_err(io::Error::other)?;
                let fileset = format!("root-file:{}", serde_json::to_string(&entry.path).unwrap());
                let (size, digest) =
                    stream_jj_file(root, &pin, &fileset, &mut writer, &mut total, cancellation)?;
                update_aggregate(&mut aggregate, &entry.path, &EntryKind::File, size, &digest);
                manifest_entries.push(SourceEntry {
                    path: entry.path.clone(),
                    kind: EntryKind::File,
                    mode: if entry.executable { 0o100755 } else { 0o100644 },
                    size,
                    sha256: hex(&digest),
                });
            }
            EntryKind::Symlink => {
                let target = entry.symlink_target.as_deref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing Jujutsu symlink target")
                })?;
                let bytes = target.as_bytes();
                add_total(&mut total, bytes.len() as u64)?;
                let digest: [u8; 32] = Sha256::digest(bytes).into();
                writer
                    .add_symlink(&entry.path, target, fixed_options().unix_permissions(0o777))
                    .map_err(io::Error::other)?;
                update_aggregate(
                    &mut aggregate,
                    &entry.path,
                    &EntryKind::Symlink,
                    bytes.len() as u64,
                    &digest,
                );
                manifest_entries.push(SourceEntry {
                    path: entry.path.clone(),
                    kind: EntryKind::Symlink,
                    mode: 0o120777,
                    size: bytes.len() as u64,
                    sha256: hex(&digest),
                });
            }
        }
    }
    writer.finish().map_err(io::Error::other)?;
    finish_package(
        temp,
        manifest_entries,
        total,
        aggregate,
        PackageContext {
            root,
            mode: "jujutsu",
            jj_version: Some(version),
            jj_commit_id: Some(pin),
        },
    )
}

fn populate_jj_symlink_targets(
    root: &Path,
    pin: &str,
    entries: &mut [PlannedEntry],
    temporary_root: &Path,
    cancellation: &SourceCancellation,
) -> io::Result<()> {
    if !entries.iter().any(|entry| entry.kind == EntryKind::Symlink) {
        return Ok(());
    }
    let parent = tempfile::Builder::new()
        .prefix(".jj-workspace-")
        .tempdir_in(temporary_root)?;
    let workspace = parent.path().join("tree");
    let name = format!("indentured-export-{}", Uuid::new_v4().simple());
    let path = workspace.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary workspace path is not UTF-8",
        )
    })?;

    // Arm cleanup before attempting the mutating command: a command can register
    // the workspace and still report failure or be interrupted before returning.
    let mut cleanup =
        WorkspaceCleanupGuard::new(root, name.clone(), cancellation.cleanup_context());
    let add = run_jj_bounded(
        root,
        &[
            "--no-pager",
            "workspace",
            "add",
            "--name",
            &name,
            "--sparse-patterns",
            "full",
            "--revision",
            pin,
            path,
        ],
        true,
        cancellation,
        None,
    )
    .map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("jj workspace add failed while materializing symlinks: {err}"),
        )
    });
    if let Err(err) = add {
        return cleanup.finish(Err(err));
    }

    let result = (|| {
        for entry in entries
            .iter_mut()
            .filter(|entry| entry.kind == EntryKind::Symlink)
        {
            cancellation.check()?;
            let link = workspace.join(&entry.path);
            let metadata = fs::symlink_metadata(&link)?;
            if !metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Jujutsu workspace did not materialize {:?} as a symlink",
                        entry.path
                    ),
                ));
            }
            let target = fs::read_link(&link)?;
            let target = target.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8")
            })?;
            validate_symlink_target(&entry.path, target)?;
            entry.symlink_target = Some(target.to_string());
        }
        Ok(())
    })();
    cleanup.finish(result)
}

struct WorkspaceCleanupGuard {
    root: PathBuf,
    name: String,
    cleanup_context: SourceCancellation,
    armed: bool,
}

impl WorkspaceCleanupGuard {
    fn new(root: &Path, name: String, cleanup_context: SourceCancellation) -> Self {
        Self {
            root: root.to_path_buf(),
            name,
            cleanup_context,
            armed: true,
        }
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        run_jj_bounded(
            &self.root,
            &["--no-pager", "workspace", "forget", &self.name],
            true,
            &self.cleanup_context,
            Some(JJ_CLEANUP_TIMEOUT),
        )
        .map(|_| ())
    }

    fn finish<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        let cleanup = self.cleanup();
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(err), Ok(())) => Err(err),
            (Ok(_), Err(cleanup_err)) => Err(io::Error::other(format!(
                "jj workspace cleanup failed ({cleanup_err}); run `jj workspace forget {}` before retrying",
                self.name
            ))),
            (Err(export_err), Err(cleanup_err)) => Err(io::Error::new(
                export_err.kind(),
                format!(
                    "{export_err}; jj workspace cleanup also failed ({cleanup_err}); run `jj workspace forget {}` before retrying",
                    self.name
                ),
            )),
        }
    }
}

impl Drop for WorkspaceCleanupGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn stream_jj_file(
    root: &Path,
    pin: &str,
    fileset: &str,
    writer: &mut impl Write,
    total: &mut u64,
    cancellation: &SourceCancellation,
) -> io::Result<(u64, [u8; 32])> {
    cancellation.check()?;
    let mut command = Command::new(cancellation.program.as_os_str());
    let mut child = command
        .args(cancellation.prefix_args.iter())
        .current_dir(root)
        .args([
            "--ignore-working-copy",
            "--no-pager",
            "file",
            "show",
            "-r",
            pin,
            "-T",
            "",
            fileset,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (stdout_tx, stdout_rx) = mpsc::sync_channel(4);
    let stdout_handle = thread::spawn(move || {
        let mut stdout = stdout;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    let _ = stdout_tx.send(Ok(None));
                    break;
                }
                Ok(read) => {
                    if stdout_tx.send(Ok(Some(buffer[..read].to_vec()))).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = stdout_tx.send(Err(err));
                    break;
                }
            }
        }
    });
    let stderr_failed = Arc::new(AtomicBool::new(false));
    let stderr_failed_reader = Arc::clone(&stderr_failed);
    let stderr_handle = thread::spawn(move || {
        let result = read_and_drain_bounded(stderr, MAX_JJ_STDERR);
        if result.is_err() {
            stderr_failed_reader.store(true, Ordering::SeqCst);
        }
        result
    });

    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let stream_result = loop {
        if let Err(err) = cancellation.check() {
            break Err(err);
        }
        if stderr_failed.load(Ordering::SeqCst) {
            break Err(io::Error::other("jj stderr reader failed"));
        }
        match stdout_rx.recv_timeout(JJ_POLL_INTERVAL) {
            Ok(Ok(Some(bytes))) => {
                size = size.saturating_add(bytes.len() as u64);
                if let Err(err) =
                    add_total(total, bytes.len() as u64).and_then(|()| writer.write_all(&bytes))
                {
                    break Err(err);
                }
                hasher.update(&bytes);
            }
            Ok(Ok(None)) => break Ok(()),
            Ok(Err(err)) => break Err(err),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(io::Error::other("jj stdout reader disconnected"));
            }
        }
    };

    drop(stdout_rx);
    let status = match stream_result {
        Ok(()) => wait_child(
            &mut child,
            cancellation,
            None,
            None,
            Some(stderr_failed.as_ref()),
        ),
        Err(err) => {
            terminate_and_reap(&mut child);
            Err(err)
        }
    };
    let _ = stdout_handle.join();
    let stderr = stderr_handle
        .join()
        .map_err(|_| io::Error::other("jj stderr reader panicked"))??
        .0;
    let status = status?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "jj file show failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    Ok((size, hasher.finalize().into()))
}

#[cfg(test)]
fn package_filesystem(
    root: &Path,
    patterns: &FilesystemPatterns,
    temporary_root: &Path,
) -> io::Result<SourcePackage> {
    package_filesystem_cancellable(root, patterns, temporary_root, &SourceCancellation::new())
}

fn package_filesystem_cancellable(
    root: &Path,
    patterns: &FilesystemPatterns,
    temporary_root: &Path,
    cancellation: &SourceCancellation,
) -> io::Result<SourcePackage> {
    package_filesystem_with_hooks(
        root,
        patterns,
        temporary_root,
        cancellation,
        &mut FilesystemHooks::default(),
    )
}

#[derive(Default)]
struct FilesystemHooks<'a> {
    after_manifest: Option<&'a mut dyn FnMut()>,
    after_file_open: Option<&'a mut dyn FnMut(&Path)>,
}

fn package_filesystem_with_hooks(
    root: &Path,
    patterns: &FilesystemPatterns,
    temporary_root: &Path,
    cancellation: &SourceCancellation,
    hooks: &mut FilesystemHooks<'_>,
) -> io::Result<SourcePackage> {
    cancellation.check()?;
    let root = fs::canonicalize(root)?;
    let mut first = enumerate_filesystem(&root, patterns, cancellation)?;
    if let Some(hook) = hooks.after_manifest.as_deref_mut() {
        hook();
    }
    validate_planned_entries(&mut first)?;
    let temp = tempfile::Builder::new()
        .prefix(".source-")
        .suffix(".zip")
        .tempfile_in(temporary_root)?;
    let mut writer = ZipWriter::new(temp.reopen()?);
    let mut manifest_entries = Vec::with_capacity(first.len());
    let mut total = 0u64;
    let mut aggregate = Sha256::new();

    for entry in &first {
        cancellation.check()?;
        let source = root.join(&entry.path);
        match entry.kind {
            EntryKind::File => {
                let before = fs::symlink_metadata(&source)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&source)?;
                let opened = file.metadata()?;
                if before.dev() != opened.dev() || before.ino() != opened.ino() || !opened.is_file()
                {
                    return Err(io::Error::other(
                        "source changed while it was being packaged",
                    ));
                }
                if let Some(hook) = hooks.after_file_open.as_deref_mut() {
                    hook(&source);
                }
                writer
                    .start_file(&entry.path, regular_options(entry.executable))
                    .map_err(io::Error::other)?;
                let mut hasher = Sha256::new();
                let mut size = 0u64;
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    cancellation.check()?;
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    add_total(&mut total, read as u64)?;
                    size += read as u64;
                    hasher.update(&buffer[..read]);
                    writer.write_all(&buffer[..read])?;
                }
                let after = file.metadata()?;
                if opened.len() != after.len()
                    || opened.mtime() != after.mtime()
                    || opened.mtime_nsec() != after.mtime_nsec()
                {
                    return Err(io::Error::other(
                        "source changed while it was being packaged",
                    ));
                }
                let digest: [u8; 32] = hasher.finalize().into();
                update_aggregate(&mut aggregate, &entry.path, &EntryKind::File, size, &digest);
                manifest_entries.push(SourceEntry {
                    path: entry.path.clone(),
                    kind: EntryKind::File,
                    mode: if entry.executable { 0o100755 } else { 0o100644 },
                    size,
                    sha256: hex(&digest),
                });
            }
            EntryKind::Symlink => {
                let target = fs::read_link(&source)?;
                let target = target.to_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8")
                })?;
                if entry.symlink_target.as_deref() != Some(target) {
                    return Err(io::Error::other(
                        "source symlink changed while it was being packaged",
                    ));
                }
                validate_symlink_target(&entry.path, target)?;
                let bytes = target.as_bytes();
                add_total(&mut total, bytes.len() as u64)?;
                let digest: [u8; 32] = Sha256::digest(bytes).into();
                writer
                    .add_symlink(&entry.path, target, fixed_options().unix_permissions(0o777))
                    .map_err(io::Error::other)?;
                update_aggregate(
                    &mut aggregate,
                    &entry.path,
                    &EntryKind::Symlink,
                    bytes.len() as u64,
                    &digest,
                );
                manifest_entries.push(SourceEntry {
                    path: entry.path.clone(),
                    kind: EntryKind::Symlink,
                    mode: 0o120777,
                    size: bytes.len() as u64,
                    sha256: hex(&digest),
                });
            }
        }
    }
    writer.finish().map_err(io::Error::other)?;
    cancellation.check()?;
    let second = enumerate_filesystem(&root, patterns, cancellation)?;
    if first != second {
        return Err(io::Error::other(
            "filesystem source manifest changed concurrently; retry after writers are quiescent",
        ));
    }
    finish_package(
        temp,
        manifest_entries,
        total,
        aggregate,
        PackageContext {
            root: &root,
            mode: "filesystem",
            jj_version: None,
            jj_commit_id: None,
        },
    )
}

fn enumerate_filesystem(
    root: &Path,
    patterns: &FilesystemPatterns,
    cancellation: &SourceCancellation,
) -> io::Result<Vec<PlannedEntry>> {
    let includes = compile_globs(&patterns.include)?;
    let excludes = compile_globs(&patterns.exclude)?;
    let mut entries = Vec::new();
    if includes.is_empty() {
        return Ok(entries);
    }
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .filter_entry(|entry| {
            !(entry.file_type().is_dir()
                && (entry.file_name().eq_ignore_ascii_case(".git")
                    || entry.file_name().eq_ignore_ascii_case(".jj")))
        });
    for item in walker {
        cancellation.check()?;
        let item = item.map_err(io::Error::other)?;
        let relative = item.path().strip_prefix(root).map_err(io::Error::other)?;
        let path = relative
            .to_str()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "filesystem path is not UTF-8")
            })?
            .replace('\\', "/");
        if path.split('/').any(|part| matches!(part, ".git" | ".jj")) {
            continue;
        }
        let selected = includes.iter().any(|pattern| pattern.matches(&path));
        if !selected || excludes.iter().any(|pattern| pattern.matches(&path)) {
            continue;
        }
        let metadata = fs::symlink_metadata(item.path())?;
        let kind = if metadata.file_type().is_file() {
            EntryKind::File
        } else if metadata.file_type().is_symlink() {
            EntryKind::Symlink
        } else if metadata.file_type().is_dir() {
            continue;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported special source file {path:?}"),
            ));
        };
        validate_archive_path(&path)?;
        let symlink_target = if kind == EntryKind::Symlink {
            let target = fs::read_link(item.path())?;
            let target = target.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8")
            })?;
            validate_symlink_target(&path, target)?;
            Some(target.to_string())
        } else {
            None
        };
        entries.push(PlannedEntry {
            path,
            kind,
            executable: metadata.permissions().mode() & 0o111 != 0,
            symlink_target,
        });
    }
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(entries)
}

fn compile_globs(values: &[String]) -> io::Result<Vec<glob::Pattern>> {
    values
        .iter()
        .map(|value| {
            glob::Pattern::new(value)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        })
        .collect()
}

fn validate_planned_entries(entries: &mut [PlannedEntry]) -> io::Result<()> {
    if entries.len() > MAX_FILES {
        return Err(limit("source entry count exceeds the client limit"));
    }
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut exact = HashSet::new();
    let mut folded = HashSet::new();
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    for entry in entries.iter() {
        validate_archive_path(&entry.path)?;
        let lower = entry.path.to_ascii_lowercase();
        if !exact.insert(entry.path.clone()) || !folded.insert(lower.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source contains duplicate or case-colliding paths",
            ));
        }
        let mut ancestor = String::new();
        let components: Vec<_> = entry.path.split('/').collect();
        for component in &components[..components.len().saturating_sub(1)] {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            let folded_ancestor = ancestor.to_ascii_lowercase();
            if files.contains(&folded_ancestor) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "source contains a file/directory path collision",
                ));
            }
            directories.insert(folded_ancestor);
        }
        if directories.contains(&lower) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source contains a file/directory path collision",
            ));
        }
        files.insert(lower);
    }
    Ok(())
}

pub fn validate_archive_path(path: &str) -> io::Result<()> {
    if path.is_empty() || path.len() > 4096 || !path.is_ascii() || path.contains(['\\', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source path is not a portable ASCII relative path",
        ));
    }
    let components: Vec<_> = path.split('/').collect();
    if components.len() > MAX_DEPTH
        || components.iter().any(|component| {
            component.is_empty()
                || matches!(*component, "." | "..")
                || component.eq_ignore_ascii_case(".git")
                || component.eq_ignore_ascii_case(".jj")
        })
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source path is unsafe or exceeds the client depth limit",
        ));
    }
    Ok(())
}

pub fn validate_symlink_target(link_path: &str, target: &str) -> io::Result<()> {
    if target.is_empty()
        || target.len() > 4096
        || target.contains(['\\', '\0'])
        || Path::new(target).is_absolute()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsafe symlink target for {link_path:?}"),
        ));
    }
    let mut depth = link_path.split('/').count().saturating_sub(1) as isize;
    for component in Path::new(target).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) if value != OsStr::new("") => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("symlink target escapes source root: {link_path:?} -> {target:?}"),
                ))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsafe symlink target for {link_path:?}"),
                ))
            }
        }
    }
    Ok(())
}

fn finish_package(
    mut temp: NamedTempFile,
    entries: Vec<SourceEntry>,
    total: u64,
    aggregate: Sha256,
    context: PackageContext<'_>,
) -> io::Result<SourcePackage> {
    temp.as_file_mut().flush()?;
    temp.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut archive_hasher = Sha256::new();
    io::copy(
        &mut temp.as_file_mut(),
        &mut HashWriter(&mut archive_hasher),
    )?;
    let archive_bytes = temp.as_file().metadata()?.len();
    let manifest = SourceManifest {
        schema_version: 1,
        entry_count: entries.len(),
        uncompressed_bytes: total,
        aggregate_sha256: hex(&aggregate.finalize().into()),
        entries,
    };
    Ok(SourcePackage {
        archive: temp,
        manifest,
        identity: SourceIdentity {
            mode: context.mode.to_string(),
            root: context.root.to_path_buf(),
            jj_version: context.jj_version,
            jj_commit_id: context.jj_commit_id,
            initial_snapshot_atomicity: "not-guaranteed".to_string(),
            archive_sha256: hex(&archive_hasher.finalize().into()),
            archive_bytes,
        },
    })
}

struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fixed_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
}
fn regular_options(executable: bool) -> SimpleFileOptions {
    fixed_options().unix_permissions(if executable { 0o755 } else { 0o644 })
}
fn add_total(total: &mut u64, amount: u64) -> io::Result<()> {
    *total = total.saturating_add(amount);
    if *total > MAX_UNCOMPRESSED_BYTES {
        Err(limit("source bytes exceed the client limit"))
    } else {
        Ok(())
    }
}
fn update_aggregate(
    hasher: &mut Sha256,
    path: &str,
    kind: &EntryKind,
    size: u64,
    digest: &[u8; 32],
) {
    hasher.update((path.len() as u64).to_le_bytes());
    hasher.update(path.as_bytes());
    hasher.update([match kind {
        EntryKind::File => 0,
        EntryKind::Symlink => 1,
    }]);
    hasher.update(size.to_le_bytes());
    hasher.update(digest);
}
fn run_jj_bounded(
    cwd: &Path,
    args: &[&str],
    require_success: bool,
    cancellation: &SourceCancellation,
    timeout: Option<Duration>,
) -> io::Result<String> {
    cancellation.check()?;
    let mut command = Command::new(cancellation.program.as_os_str());
    let mut child = command
        .args(cancellation.prefix_args.iter())
        .current_dir(cwd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to execute jj in detected Jujutsu repository: {err}"),
            )
        })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let reader_failed = Arc::new(AtomicBool::new(false));
    let stdout_overflow_reader = Arc::clone(&stdout_overflow);
    let stdout_failed = Arc::clone(&reader_failed);
    let stdout_handle = thread::spawn(move || {
        let result =
            read_and_drain_bounded_signaled(stdout, MAX_JJ_OUTPUT, &stdout_overflow_reader);
        if result.is_err() {
            stdout_failed.store(true, Ordering::SeqCst);
        }
        result
    });
    let stderr_failed = Arc::clone(&reader_failed);
    let stderr_handle = thread::spawn(move || {
        let result = read_and_drain_bounded(stderr, MAX_JJ_STDERR);
        if result.is_err() {
            stderr_failed.store(true, Ordering::SeqCst);
        }
        result
    });
    let status = wait_child(
        &mut child,
        cancellation,
        timeout,
        Some(stdout_overflow.as_ref()),
        Some(reader_failed.as_ref()),
    );
    let stdout = stdout_handle
        .join()
        .map_err(|_| io::Error::other("jj stdout reader panicked"))?;
    let stderr = stderr_handle
        .join()
        .map_err(|_| io::Error::other("jj stderr reader panicked"))?;
    let status = status?;
    let (stdout, stdout_overflow) = stdout?;
    let (stderr, _) = stderr?;
    if stdout_overflow {
        return Err(limit("Jujutsu output exceeded the client limit"));
    }
    if require_success && !status.success() {
        return Err(io::Error::other(format!(
            "jj command failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    String::from_utf8(stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "jj output was not UTF-8"))
}

fn wait_child(
    child: &mut Child,
    cancellation: &SourceCancellation,
    timeout: Option<Duration>,
    output_overflow: Option<&AtomicBool>,
    reader_failed: Option<&AtomicBool>,
) -> io::Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if output_overflow.is_some_and(|overflow| overflow.load(Ordering::SeqCst)) {
            terminate_and_reap(child);
            return Err(limit("Jujutsu output exceeded the client limit"));
        }
        if reader_failed.is_some_and(|failed| failed.load(Ordering::SeqCst)) {
            terminate_and_reap(child);
            return Err(io::Error::other("jj pipe reader failed"));
        }
        if cancellation.check().is_err() {
            terminate_and_reap(child);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "source packaging interrupted while jj was running",
            ));
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            terminate_and_reap(child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "jj cleanup command exceeded its time limit",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => thread::sleep(JJ_POLL_INTERVAL),
            Err(err) => {
                terminate_and_reap(child);
                return Err(err);
            }
        }
    }
}

fn terminate_and_reap(child: &mut Child) {
    let pid = child.id() as i32;
    // Each jj subprocess is its own process-group leader, so helper descendants
    // cannot outlive cancellation or an archive/stream failure.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_and_drain_bounded(reader: impl Read, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    read_and_drain_bounded_inner(reader, limit, None)
}

fn read_and_drain_bounded_signaled(
    reader: impl Read,
    limit: usize,
    overflow_signal: &AtomicBool,
) -> io::Result<(Vec<u8>, bool)> {
    read_and_drain_bounded_inner(reader, limit, Some(overflow_signal))
}

fn read_and_drain_bounded_inner(
    mut reader: impl Read,
    limit: usize,
    overflow_signal: Option<&AtomicBool>,
) -> io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::with_capacity(limit.min(8192));
    let mut overflow = false;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(kept.len());
        let keep = remaining.min(read);
        kept.extend_from_slice(&buffer[..keep]);
        overflow |= keep < read;
        if overflow {
            if let Some(signal) = overflow_signal {
                signal.store(true, Ordering::SeqCst);
            }
        }
    }
    Ok((kept, overflow))
}
fn one_line(value: &str, max: usize, label: &str) -> io::Result<String> {
    let trimmed = value.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.len() > max || trimmed.contains(['\r', '\n', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {label}"),
        ));
    }
    Ok(trimmed.to_string())
}
fn limit(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn safe_and_unsafe_symlink_targets() {
        assert!(validate_symlink_target("dir/link", "../target").is_ok());
        assert!(validate_symlink_target("link", "../target").is_err());
        assert!(validate_symlink_target("link", "/etc/passwd").is_err());
        assert!(validate_symlink_target("link", "target").is_ok());
    }

    #[test]
    fn filesystem_mode_preserves_files_executability_and_safe_links() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(root.path().join("src/a"), b"a").unwrap();
        fs::write(root.path().join("src/run"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(
            root.path().join("src/run"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("a", root.path().join("src/link")).unwrap();
        let output = tempdir().unwrap();
        let package = package_filesystem(
            root.path(),
            &FilesystemPatterns {
                include: vec!["src/**".into()],
                exclude: vec![],
            },
            output.path(),
        )
        .unwrap();
        assert_eq!(package.manifest.entry_count, 3);
        assert_eq!(
            package
                .manifest
                .entries
                .iter()
                .find(|entry| entry.path == "src/run")
                .unwrap()
                .mode,
            0o100755
        );
        let mut zip = zip::ZipArchive::new(package.archive.reopen().unwrap()).unwrap();
        assert!(zip.by_name("src/link").unwrap().is_symlink());
    }

    #[test]
    fn filesystem_mode_rejects_escaping_symlink() {
        let root = tempdir().unwrap();
        std::os::unix::fs::symlink("../escape", root.path().join("bad")).unwrap();
        let output = tempdir().unwrap();
        let err = package_filesystem(
            root.path(),
            &FilesystemPatterns {
                include: vec!["**".into()],
                exclude: vec![],
            },
            output.path(),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("escapes"));
    }

    #[test]
    fn real_jj_tree_exports_new_deleted_executable_ignored_and_symlink_entries() {
        let jj = Command::new("jj")
            .arg("--version")
            .output()
            .expect("jj is a required test prerequisite");
        assert!(jj.status.success(), "jj is a required test prerequisite");
        let root = tempdir().unwrap();
        assert!(Command::new("jj")
            .current_dir(root.path())
            .args(["git", "init", "."])
            .status()
            .unwrap()
            .success());
        fs::write(root.path().join(".gitignore"), "cache/\n*.secret\n").unwrap();
        fs::create_dir(root.path().join("dir")).unwrap();
        fs::create_dir(root.path().join("cache")).unwrap();
        fs::write(root.path().join("keep"), "old\n").unwrap();
        fs::write(root.path().join("deleted"), "gone\n").unwrap();
        fs::write(root.path().join("dir/target"), "target\n").unwrap();
        fs::write(root.path().join("run.sh"), "#!/bin/sh\n").unwrap();
        fs::write(
            root.path().join("api-token-example.txt"),
            "intentional source\n",
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(Command::new("jj")
            .current_dir(root.path())
            .args(["commit", "-m", "base"])
            .status()
            .unwrap()
            .success());
        fs::remove_file(root.path().join("deleted")).unwrap();
        fs::write(root.path().join("keep"), "changed\n").unwrap();
        fs::write(root.path().join("new"), "new\n").unwrap();
        fs::write(root.path().join("line\nname"), "tricky\n").unwrap();
        fs::write(root.path().join("cache/object"), "ignored").unwrap();
        fs::write(root.path().join("credential.secret"), "ignored").unwrap();
        std::os::unix::fs::symlink("dir/target", root.path().join("safe-link")).unwrap();

        let output = tempdir().unwrap();
        let package = package_jj(
            root.path(),
            root.path(),
            output.path(),
            &SourceCancellation::new(),
        )
        .unwrap();
        let names: Vec<_> = package
            .manifest
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        assert!(names.contains(&"new"));
        assert!(names.contains(&"keep"));
        assert!(names.contains(&"run.sh"));
        assert!(names.contains(&"safe-link"));
        assert!(names.contains(&"line\nname"));
        assert!(names.contains(&"api-token-example.txt"));
        assert!(!names.contains(&"deleted"));
        assert!(!names.contains(&"cache/object"));
        assert!(!names.contains(&"credential.secret"));
        assert_eq!(
            package
                .manifest
                .entries
                .iter()
                .find(|entry| entry.path == "run.sh")
                .unwrap()
                .mode,
            0o100755
        );
        let pinned = package.identity.jj_commit_id.clone().unwrap();
        fs::write(root.path().join("keep"), "after pin\n").unwrap();
        let mut zip = zip::ZipArchive::new(package.archive.reopen().unwrap()).unwrap();
        let mut bytes = String::new();
        zip.by_name("keep")
            .unwrap()
            .read_to_string(&mut bytes)
            .unwrap();
        assert_eq!(bytes, "changed\n");
        assert_eq!(
            package.identity.jj_commit_id.as_deref(),
            Some(pinned.as_str())
        );
        assert!(zip.by_name("safe-link").unwrap().is_symlink());
        let workspaces = run_jj_bounded(
            root.path(),
            &["workspace", "list"],
            true,
            &SourceCancellation::new(),
            None,
        )
        .unwrap();
        assert!(!workspaces.contains("indentured-export-"));
    }

    fn write_script(directory: &Path, body: &str) -> PathBuf {
        let path = directory.join("fake-jj");
        let mut temporary = tempfile::Builder::new()
            .prefix(".fake-jj-")
            .tempfile_in(directory)
            .unwrap();
        temporary
            .write_all(format!("#!/bin/sh\nset -u\n{body}\n").as_bytes())
            .unwrap();
        temporary.as_file_mut().flush().unwrap();
        temporary.as_file().sync_all().unwrap();
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))
            .unwrap();
        let published = temporary.persist_noclobber(&path).unwrap();
        published.sync_all().unwrap();
        drop(published);
        path
    }

    fn planned(path: &str) -> PlannedEntry {
        PlannedEntry {
            path: path.to_string(),
            kind: EntryKind::File,
            executable: false,
            symlink_target: None,
        }
    }

    #[test]
    fn rejects_case_folded_file_directory_collisions_in_both_orders_and_modes() {
        for mut entries in [
            vec![planned("Foo/bar"), planned("foo")],
            vec![planned("foo"), planned("Foo/bar")],
        ] {
            assert!(validate_planned_entries(&mut entries).is_err());
        }

        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("Foo")).unwrap();
        fs::write(root.path().join("Foo/bar"), "nested").unwrap();
        fs::write(root.path().join("foo"), "file").unwrap();
        let output = tempdir().unwrap();
        assert!(package_filesystem(
            root.path(),
            &FilesystemPatterns {
                include: vec!["**".into()],
                exclude: vec![],
            },
            output.path(),
        )
        .is_err());

        for listing in [
            "{\"path\":\"Foo/bar\",\"type\":\"file\",\"executable\":false,\"conflict\":false}\n{\"path\":\"foo\",\"type\":\"file\",\"executable\":false,\"conflict\":false}\n",
            "{\"path\":\"foo\",\"type\":\"file\",\"executable\":false,\"conflict\":false}\n{\"path\":\"Foo/bar\",\"type\":\"file\",\"executable\":false,\"conflict\":false}\n",
        ] {
            let fake = tempdir().unwrap();
            let script = write_script(
                fake.path(),
                &format!(
                    "case \"$*\" in\n  *--version*) echo 'jj 99.0.0' ;;\n  *' log '*) printf '%064d\\n' 0 ;;\n  *' file list '*) printf '%s' '{}' ;;\n  *) exit 2 ;;\nesac",
                    listing.replace('\\', "\\\\").replace('\'', "'\\''")
                ),
            );
            let repo = tempdir().unwrap();
            fs::create_dir(repo.path().join(".jj")).unwrap();
            let out = tempdir().unwrap();
            let err = package_jj(
                repo.path(),
                repo.path(),
                out.path(),
                &SourceCancellation::with_program(script.into_os_string()),
            )
            .err()
            .unwrap();
            assert!(err.to_string().contains("file/directory"));
        }
    }

    #[test]
    fn filesystem_detects_injected_manifest_and_content_changes() {
        let patterns = FilesystemPatterns {
            include: vec!["**".into()],
            exclude: vec![],
        };

        let root = tempdir().unwrap();
        fs::write(root.path().join("a"), "a").unwrap();
        let out = tempdir().unwrap();
        let root_path = root.path().to_path_buf();
        let mut add_file = move || fs::write(root_path.join("new"), "new").unwrap();
        let err = package_filesystem_with_hooks(
            root.path(),
            &patterns,
            out.path(),
            &SourceCancellation::new(),
            &mut FilesystemHooks {
                after_manifest: Some(&mut add_file),
                after_file_open: None,
            },
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("manifest changed concurrently"));

        let root = tempdir().unwrap();
        fs::write(root.path().join("a"), "a").unwrap();
        let out = tempdir().unwrap();
        let mut change_content = |path: &Path| fs::write(path, "longer content").unwrap();
        let err = package_filesystem_with_hooks(
            root.path(),
            &patterns,
            out.path(),
            &SourceCancellation::new(),
            &mut FilesystemHooks {
                after_manifest: None,
                after_file_open: Some(&mut change_content),
            },
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("source changed"));
    }

    #[test]
    fn file_show_drains_noisy_stderr_and_reaps_on_stream_and_writer_errors() {
        let fake = tempdir().unwrap();
        let script = write_script(
            fake.path(),
            "i=0; while [ $i -lt 20000 ]; do printf 'noisy-stderr-line-%05d\\n' \"$i\" >&2; i=$((i+1)); done; printf payload; exit 9",
        );
        let cancellation = SourceCancellation::with_program(script.into_os_string());
        let mut sink = Vec::new();
        let err = stream_jj_file(
            fake.path(),
            &"0".repeat(64),
            "root-file:\"a\"",
            &mut sink,
            &mut 0,
            &cancellation,
        )
        .err()
        .unwrap();
        assert!(
            err.to_string().contains("jj file show failed"),
            "unexpected error: {err}"
        );
        assert!(err.to_string().len() < MAX_JJ_STDERR + 128);

        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "injected ZIP failure",
                ))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let fake = tempdir().unwrap();
        let pid_file = fake.path().join("pid");
        let script = write_script(
            fake.path(),
            &format!(
                "echo $$ > '{}'; while :; do printf payload; sleep 0.01; done",
                pid_file.display()
            ),
        );
        let err = stream_jj_file(
            fake.path(),
            &"0".repeat(64),
            "root-file:\"a\"",
            &mut FailingWriter,
            &mut 0,
            &SourceCancellation::with_program(script.into_os_string()),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("injected ZIP failure"));
        let pid: i32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "jj child was not reaped");
    }

    #[test]
    fn bounded_jj_output_overflow_kills_and_reaps_the_process_group() {
        let fake = tempdir().unwrap();
        let pid_file = fake.path().join("pid");
        let payload = "x".repeat(4096);
        let script = write_script(
            fake.path(),
            &format!(
                "echo $$ > '{}'; while :; do printf '{}'; done",
                pid_file.display(),
                payload
            ),
        );
        let err = run_jj_bounded(
            fake.path(),
            &["file", "list"],
            true,
            &SourceCancellation::with_program(script.into_os_string()),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("output exceeded"));
        let pid: i32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "jj child was not reaped");
    }

    #[test]
    fn workspace_guard_cleans_success_partial_add_later_error_and_reports_cleanup_failure() {
        for (scenario, add_body, forget_status, expect_error) in [
            (
                "success",
                "mkdir -p \"$last\"; ln -s target \"$last/link\"; exit 0",
                0,
                false,
            ),
            ("partial", "mkdir -p \"$last\"; exit 7", 0, true),
            (
                "later",
                "mkdir -p \"$last\"; : > \"$last/link\"; exit 0",
                0,
                true,
            ),
            (
                "cleanup",
                "mkdir -p \"$last\"; ln -s target \"$last/link\"; exit 0",
                8,
                true,
            ),
        ] {
            let fake = tempdir().unwrap();
            let cleanup_log = fake.path().join("cleanup");
            let script = write_script(
                fake.path(),
                &format!(
                    "last=''; for arg in \"$@\"; do last=$arg; done\ncase \"$*\" in\n  *'workspace add'*) {} ;;\n  *'workspace forget'*) echo \"$*\" >> '{}'; exit {} ;;\n  *) exit 2 ;;\nesac",
                    add_body,
                    cleanup_log.display(),
                    forget_status
                ),
            );
            let root = tempdir().unwrap();
            let output = tempdir().unwrap();
            let mut entries = vec![PlannedEntry {
                path: "link".into(),
                kind: EntryKind::Symlink,
                executable: false,
                symlink_target: None,
            }];
            let result = populate_jj_symlink_targets(
                root.path(),
                &"0".repeat(64),
                &mut entries,
                output.path(),
                &SourceCancellation::with_program(script.into_os_string()),
            );
            assert_eq!(result.is_err(), expect_error, "scenario {scenario}");
            assert!(cleanup_log.exists(), "cleanup not attempted for {scenario}");
            if scenario == "cleanup" {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("workspace forget"));
                assert!(error.contains("before retrying"));
            }
        }
    }

    #[test]
    fn real_jj_mutation_after_pin_does_not_change_export_and_commands_stay_local() {
        let real_jj = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("jj"))
            .find(|candidate| candidate.is_file())
            .expect("jj is a required test prerequisite");
        let root = tempdir().unwrap();
        assert!(Command::new(&real_jj)
            .current_dir(root.path())
            .args(["git", "init", "."])
            .status()
            .unwrap()
            .success());
        fs::write(root.path().join("keep"), "base\n").unwrap();
        assert!(Command::new(&real_jj)
            .current_dir(root.path())
            .args(["commit", "-m", "base"])
            .status()
            .unwrap()
            .success());
        fs::write(root.path().join("keep"), "pinned\n").unwrap();

        let fake = tempdir().unwrap();
        let command_log = fake.path().join("commands");
        let wrapper = write_script(
            fake.path(),
            &format!(
                "echo \"$*\" >> '{}'\ncase \"$*\" in\n  *' log '*) output=$(\"{}\" \"$@\") || exit $?; printf 'after-pin\\n' > '{}'; printf '%s\\n' \"$output\" ;;\n  *) exec \"{}\" \"$@\" ;;\nesac",
                command_log.display(),
                real_jj.display(),
                root.path().join("keep").display(),
                real_jj.display()
            ),
        );
        let output = tempdir().unwrap();
        let package = package_jj(
            root.path(),
            root.path(),
            output.path(),
            &SourceCancellation::with_program(wrapper.into_os_string()),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("keep")).unwrap(),
            "after-pin\n"
        );
        let mut zip = zip::ZipArchive::new(package.archive.reopen().unwrap()).unwrap();
        let mut bytes = String::new();
        zip.by_name("keep")
            .unwrap()
            .read_to_string(&mut bytes)
            .unwrap();
        assert_eq!(bytes, "pinned\n");
        let commands = fs::read_to_string(command_log).unwrap();
        for forbidden in [
            " archive ",
            " git ",
            " fetch ",
            " push ",
            " remote ",
            " publish",
        ] {
            assert!(
                !commands.contains(forbidden),
                "forbidden jj command: {forbidden}"
            );
        }
        assert_eq!(commands.matches(" -r @ ").count(), 1);
    }

    #[test]
    fn fake_jj_proves_file_show_bytes_and_allowed_command_surface() {
        let fake = tempdir().unwrap();
        let command_log = fake.path().join("commands");
        let script = write_script(
            fake.path(),
            &format!(
                "echo \"$*\" >> '{}'\nlast=''; for arg in \"$@\"; do last=$arg; done\ncase \"$*\" in\n  *--version*) echo 'jj 99.0.0' ;;\n  *' log '*) printf '%064d\\n' 0 ;;\n  *' file list '*) printf '%s\\n' '{{\"path\":\"eol.txt\",\"type\":\"file\",\"executable\":false,\"conflict\":false}}' '{{\"path\":\"link\",\"type\":\"symlink\",\"executable\":false,\"conflict\":false}}' ;;\n  *' file show '*) printf 'committed\\r\\n' ;;\n  *'workspace add'*) mkdir -p \"$last\"; printf 'checkout-converted\\n' > \"$last/eol.txt\"; ln -s eol.txt \"$last/link\" ;;\n  *'workspace forget'*) : ;;\n  *) exit 2 ;;\nesac",
                command_log.display()
            ),
        );
        let repo = tempdir().unwrap();
        fs::create_dir(repo.path().join(".jj")).unwrap();
        let output = tempdir().unwrap();
        let package = package_jj(
            repo.path(),
            repo.path(),
            output.path(),
            &SourceCancellation::with_program(script.into_os_string()),
        )
        .unwrap();
        let mut zip = zip::ZipArchive::new(package.archive.reopen().unwrap()).unwrap();
        let mut bytes = Vec::new();
        zip.by_name("eol.txt")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"committed\r\n");
        let commands = fs::read_to_string(command_log).unwrap();
        for forbidden in [
            " archive ",
            " git ",
            " fetch ",
            " push ",
            " remote ",
            " publish",
        ] {
            assert!(
                !commands.contains(forbidden),
                "forbidden jj command: {forbidden}"
            );
        }
        assert_eq!(commands.matches(" -r @ ").count(), 1);
    }
}
