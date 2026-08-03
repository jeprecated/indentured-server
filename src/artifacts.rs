use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use tracing::{info, warn};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions as FileOptions;
use zip::ZipWriter;

use crate::config::{ArtifactSpec, ArtifactsConfig};
use crate::protocol::{ArtifactArchive, ArtifactRestrictions};
use crate::validation::validate_relative_pattern;

const DEFAULT_GC_INTERVAL_SECS: u64 = 3600;
const INTERNAL_EXCLUDE_PATTERN: &str = ".indentured-server/**";
const TRANSFER_LIMIT_SENTINEL: &str = "artifacts.max_transfer_bytes exceeded";

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact pattern {pattern} matched nothing")]
    GlobMiss { pattern: String },

    #[error("invalid artifact glob pattern {pattern}: {source}")]
    GlobPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },

    #[error("artifact path {path:?} is outside build root")]
    OutsideRoot { path: PathBuf },

    #[error("artifact io error ({context}): {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("failed to zip artifacts: {source}")]
    Zip {
        #[source]
        source: zip::result::ZipError,
    },

    #[error("invalid artifact pattern: {message}")]
    InvalidPattern { message: String },

    #[error("artifact archive exceeds artifacts.max_transfer_bytes ({max_bytes} bytes)")]
    TransferTooLarge { max_bytes: u64 },

    #[error("artifact contents exceed artifacts.max_uncompressed_bytes ({max_bytes} bytes)")]
    UncompressedTooLarge { max_bytes: u64 },

    #[error("artifact file count exceeds artifacts.max_files ({max_files})")]
    TooManyFiles { max_files: usize },

    #[error("artifact path depth exceeds artifacts.max_depth ({max_depth})")]
    TooDeep { max_depth: usize },

    #[error("artifact snapshot cancelled")]
    Cancelled,

    #[error("artifact path {path:?} is a symlink or unsupported special file")]
    UnsupportedFile { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct ArtifactCollection {
    pub archive: Option<ArtifactArchive>,
    pub restrictions: Option<ArtifactRestrictions>,
}

pub fn collect_artifacts_zip(
    build_root: &Path,
    spec: &ArtifactSpec,
    config: &ArtifactsConfig,
    build_id: &str,
) -> Result<ArtifactCollection, ArtifactError> {
    collect_artifacts_zip_cancellable(build_root, spec, config, build_id, &|| false)
}

pub(crate) fn collect_artifacts_zip_cancellable(
    build_root: &Path,
    spec: &ArtifactSpec,
    config: &ArtifactsConfig,
    build_id: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<ArtifactCollection, ArtifactError> {
    collect_artifacts_zip_controlled(build_root, spec, config, build_id, cancelled, &|_| {})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactSnapshotCheckpoint {
    Traversal,
    ArchiveWrite,
    Published,
}

pub(crate) fn collect_artifacts_zip_controlled(
    build_root: &Path,
    spec: &ArtifactSpec,
    config: &ArtifactsConfig,
    build_id: &str,
    cancelled: &dyn Fn() -> bool,
    checkpoint: &dyn Fn(ArtifactSnapshotCheckpoint),
) -> Result<ArtifactCollection, ArtifactError> {
    check_cancelled(cancelled)?;
    if spec.include.is_empty() {
        return Ok(ArtifactCollection {
            archive: None,
            restrictions: None,
        });
    }

    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(build_root)
        .map_err(|source| ArtifactError::Io {
            context: "open artifact root",
            source,
        })?;
    checkpoint(ArtifactSnapshotCheckpoint::Traversal);
    check_cancelled(cancelled)?;

    let mut excludes = spec.exclude.clone();
    excludes.push(INTERNAL_EXCLUDE_PATTERN.to_string());
    let exclude_patterns = compile_patterns(&excludes, "artifacts.exclude")?;
    let include_patterns = compile_patterns(&spec.include, "artifacts.include")?;
    let mut matched_files: HashMap<PathBuf, FileIdentity> = HashMap::new();
    let mut traversal = TraversalLimits::new(config.max_files, config.max_depth);

    // Walk once and apply every server-owned pattern to each candidate. This keeps
    // file-count/depth enforcement in front of recursive descent and accumulation;
    // no glob implementation performs an independent unbounded recursive walk.
    for entry in WalkDir::new(build_root).follow_links(false) {
        check_cancelled(cancelled)?;
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "walk artifact root",
            source: io::Error::other(source.to_string()),
        })?;
        let rel =
            entry
                .path()
                .strip_prefix(build_root)
                .map_err(|_| ArtifactError::OutsideRoot {
                    path: entry.path().to_path_buf(),
                })?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        traversal.observe(rel)?;
        if entry.file_type().is_dir() {
            continue;
        }
        if is_excluded(rel, &exclude_patterns) || !is_included(rel, &include_patterns) {
            continue;
        }
        let metadata = require_regular_file(entry.path())?;
        matched_files
            .entry(rel.to_path_buf())
            .or_insert(FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
    }

    let restrictions = apply_restricted_patterns(
        &mut matched_files,
        &config.restricted_patterns,
        "artifacts.restricted_patterns",
        cancelled,
    )?;

    // If no files matched any patterns, return None
    if matched_files.is_empty() {
        info!("no artifacts matched any patterns");
        return Ok(ArtifactCollection {
            archive: None,
            restrictions,
        });
    }

    validate_artifact_count_and_depth(&matched_files, config.max_files, config.max_depth)?;
    let mut opened = open_matched_artifacts(&root, &matched_files, cancelled)?;
    let total_uncompressed_bytes = opened
        .iter()
        .fold(0u64, |total, artifact| total.saturating_add(artifact.size));
    if total_uncompressed_bytes > config.max_uncompressed_bytes {
        return Err(ArtifactError::UncompressedTooLarge {
            max_bytes: config.max_uncompressed_bytes,
        });
    }

    let dest_dir = config.storage_root.join(build_id);
    fs::create_dir_all(&dest_dir).map_err(|source| ArtifactError::Io {
        context: "create artifact directory",
        source,
    })?;
    fs::set_permissions(&dest_dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ArtifactError::Io {
            context: "protect artifact directory",
            source,
        }
    })?;

    let dest = dest_dir.join("artifacts.zip");
    let temp_dest = dest_dir.join(".artifacts.zip.tmp");
    let publish = (|| {
        checkpoint(ArtifactSnapshotCheckpoint::ArchiveWrite);
        check_cancelled(cancelled)?;
        let size = write_artifacts_zip(
            &temp_dest,
            &mut opened,
            config.max_transfer_bytes,
            config.max_uncompressed_bytes,
            cancelled,
        )?;
        fs::set_permissions(&temp_dest, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ArtifactError::Io {
                context: "protect artifact archive",
                source,
            }
        })?;
        check_cancelled(cancelled)?;
        fs::rename(&temp_dest, &dest).map_err(|source| ArtifactError::Io {
            context: "publish artifact archive",
            source,
        })?;
        checkpoint(ArtifactSnapshotCheckpoint::Published);
        check_cancelled(cancelled)?;
        Ok::<u64, ArtifactError>(size)
    })();
    let size = match publish {
        Ok(size) => size,
        Err(err) => {
            let _ = fs::remove_dir_all(&dest_dir);
            return Err(err);
        }
    };

    Ok(ArtifactCollection {
        archive: Some(ArtifactArchive {
            path: format!("/v1/builds/{build_id}/artifacts.zip"),
            size,
        }),
        restrictions,
    })
}

fn require_regular_file(path: &Path) -> Result<fs::Metadata, ArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ArtifactError::Io {
        context: "inspect artifact path",
        source,
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink()
        || !file_type.is_file()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(ArtifactError::UnsupportedFile {
            path: path.to_path_buf(),
        });
    }
    Ok(metadata)
}

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct OpenedArtifact {
    file: File,
    relative: PathBuf,
    mode: u32,
    size: u64,
}

struct TraversalLimits {
    observed: HashSet<PathBuf>,
    max_files: usize,
    max_depth: usize,
}

impl TraversalLimits {
    fn new(max_files: usize, max_depth: usize) -> Self {
        Self {
            observed: HashSet::new(),
            max_files,
            max_depth,
        }
    }

    fn observe(&mut self, relative: &Path) -> Result<(), ArtifactError> {
        if relative.components().count() > self.max_depth {
            return Err(ArtifactError::TooDeep {
                max_depth: self.max_depth,
            });
        }
        if !self.observed.contains(relative) {
            if self.observed.len() >= self.max_files {
                return Err(ArtifactError::TooManyFiles {
                    max_files: self.max_files,
                });
            }
            self.observed.insert(relative.to_path_buf());
        }
        Ok(())
    }
}

fn validate_artifact_count_and_depth(
    matched_files: &HashMap<PathBuf, FileIdentity>,
    max_files: usize,
    max_depth: usize,
) -> Result<(), ArtifactError> {
    if matched_files.len() > max_files {
        return Err(ArtifactError::TooManyFiles { max_files });
    }
    if matched_files
        .keys()
        .any(|path| path.components().count() > max_depth)
    {
        return Err(ArtifactError::TooDeep { max_depth });
    }
    let mut folded = HashSet::new();
    for rel in matched_files.keys() {
        let key = rel.to_string_lossy().to_ascii_lowercase();
        if !folded.insert(key) {
            return Err(ArtifactError::UnsupportedFile { path: rel.clone() });
        }
    }
    Ok(())
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), ArtifactError> {
    if cancelled() {
        Err(ArtifactError::Cancelled)
    } else {
        Ok(())
    }
}

fn open_matched_artifacts(
    root: &File,
    matched_files: &HashMap<PathBuf, FileIdentity>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<OpenedArtifact>, ArtifactError> {
    let mut relative_paths: Vec<_> = matched_files.keys().cloned().collect();
    relative_paths.sort();
    let mut opened = Vec::with_capacity(relative_paths.len());
    for relative in relative_paths {
        check_cancelled(cancelled)?;
        let mut file = open_file_beneath(root.as_raw_fd(), &relative)?;
        let metadata = file.metadata().map_err(|source| ArtifactError::Io {
            context: "inspect opened artifact",
            source,
        })?;
        let expected = matched_files
            .get(&relative)
            .expect("matched artifact identity");
        if !metadata.is_file()
            || metadata.dev() != expected.device
            || metadata.ino() != expected.inode
        {
            return Err(ArtifactError::UnsupportedFile { path: relative });
        }
        file.rewind().map_err(|source| ArtifactError::Io {
            context: "rewind opened artifact",
            source,
        })?;
        opened.push(OpenedArtifact {
            file,
            relative,
            mode: metadata.permissions().mode(),
            size: metadata.len(),
        });
    }
    Ok(opened)
}

fn open_file_beneath(root_fd: RawFd, relative: &Path) -> Result<File, ArtifactError> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ArtifactError::UnsupportedFile {
            path: relative.to_path_buf(),
        });
    }
    let mut parent: Option<File> = None;
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            unreachable!("validated normal component")
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            ArtifactError::UnsupportedFile {
                path: relative.to_path_buf(),
            }
        })?;
        let directory = index + 1 != components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if directory { libc::O_DIRECTORY } else { 0 };
        let current_fd = parent.as_ref().map_or(root_fd, AsRawFd::as_raw_fd);
        let fd = unsafe { libc::openat(current_fd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(ArtifactError::Io {
                context: "open artifact beneath root",
                source: io::Error::last_os_error(),
            });
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        if directory {
            let metadata = opened.metadata().map_err(|source| ArtifactError::Io {
                context: "inspect artifact directory",
                source,
            })?;
            if !metadata.is_dir() {
                return Err(ArtifactError::UnsupportedFile {
                    path: relative.to_path_buf(),
                });
            }
            parent = Some(opened);
        } else {
            return Ok(opened);
        }
    }
    unreachable!("nonempty path has final component")
}

fn compile_patterns(patterns: &[String], field: &str) -> Result<Vec<glob::Pattern>, ArtifactError> {
    let mut compiled = Vec::new();
    for pattern in patterns {
        validate_relative_pattern(pattern, field).map_err(|err| ArtifactError::InvalidPattern {
            message: err.to_string(),
        })?;
        let glob = glob::Pattern::new(pattern).map_err(|source| ArtifactError::GlobPattern {
            pattern: pattern.to_string(),
            source,
        })?;
        compiled.push(glob);
    }
    Ok(compiled)
}

fn apply_restricted_patterns(
    matched_files: &mut HashMap<PathBuf, FileIdentity>,
    restricted_patterns: &[String],
    field: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<ArtifactRestrictions>, ArtifactError> {
    if restricted_patterns.is_empty() || matched_files.is_empty() {
        return Ok(None);
    }

    let compiled = compile_patterns(restricted_patterns, field)?;
    let mut restricted_paths = HashSet::new();
    let mut matched_pattern_indexes = HashSet::new();

    for rel in matched_files.keys() {
        check_cancelled(cancelled)?;
        let rel_str = rel.to_string_lossy();
        let mut restricted = false;
        for (index, pattern) in compiled.iter().enumerate() {
            if pattern.matches(&rel_str) {
                restricted = true;
                matched_pattern_indexes.insert(index);
            }
        }
        if restricted {
            restricted_paths.insert(rel.clone());
        }
    }

    if restricted_paths.is_empty() {
        return Ok(None);
    }

    let omitted_count = restricted_paths.len();
    for path in restricted_paths {
        matched_files.remove(&path);
    }

    let matched_patterns = restricted_patterns
        .iter()
        .enumerate()
        .filter(|(index, _pattern)| matched_pattern_indexes.contains(index))
        .map(|(_index, pattern)| pattern.clone())
        .collect();

    Ok(Some(ArtifactRestrictions {
        omitted_count,
        matched_patterns,
    }))
}

fn is_excluded(path: &Path, patterns: &[glob::Pattern]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let path_str = path.to_string_lossy();
    patterns.iter().any(|pattern| pattern.matches(&path_str))
}

fn is_included(path: &Path, patterns: &[glob::Pattern]) -> bool {
    patterns.iter().any(|pattern| {
        path.ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty())
            .any(|candidate| pattern.matches(&candidate.to_string_lossy()))
    })
}

fn write_artifacts_zip(
    dest: &Path,
    opened_artifacts: &mut [OpenedArtifact],
    max_transfer_bytes: u64,
    max_uncompressed_bytes: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<u64, ArtifactError> {
    let result = (|| {
        let file = File::create(dest).map_err(|source| ArtifactError::Io {
            context: "create artifacts.zip",
            source,
        })?;
        let transfer_limit = Rc::new(Cell::new(Some(max_transfer_bytes)));
        let mut zip = ZipWriter::new(LimitedWriter::new(file, Rc::clone(&transfer_limit)));

        opened_artifacts.sort_by(|a, b| a.relative.cmp(&b.relative));

        let mut uncompressed_bytes = 0u64;
        let mut buffer = [0u8; 8192];

        for artifact in opened_artifacts {
            check_cancelled(cancelled)?;
            let name = artifact.relative.to_string_lossy().replace('\\', "/");
            let mode = artifact.mode;

            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(mode);

            if let Err(source) = zip.start_file(name, options) {
                if is_transfer_limit_zip_error(&source) {
                    transfer_limit.set(None);
                    return Err(ArtifactError::TransferTooLarge {
                        max_bytes: max_transfer_bytes,
                    });
                }
                return Err(ArtifactError::Zip { source });
            }

            artifact.file.rewind().map_err(|source| ArtifactError::Io {
                context: "rewind artifact",
                source,
            })?;

            loop {
                check_cancelled(cancelled)?;
                let bytes =
                    artifact
                        .file
                        .read(&mut buffer)
                        .map_err(|source| ArtifactError::Io {
                            context: "read artifact",
                            source,
                        })?;
                if bytes == 0 {
                    break;
                }

                uncompressed_bytes = uncompressed_bytes.saturating_add(bytes as u64);
                if uncompressed_bytes > max_uncompressed_bytes {
                    return Err(ArtifactError::UncompressedTooLarge {
                        max_bytes: max_uncompressed_bytes,
                    });
                }

                if let Err(source) = zip.write_all(&buffer[..bytes]) {
                    if is_transfer_limit_error(&source) {
                        transfer_limit.set(None);
                        return Err(ArtifactError::TransferTooLarge {
                            max_bytes: max_transfer_bytes,
                        });
                    }
                    return Err(ArtifactError::Io {
                        context: "write artifact",
                        source,
                    });
                }
            }
        }

        let mut writer = match zip.finish() {
            Ok(writer) => writer,
            Err(source) => {
                if is_transfer_limit_zip_error(&source) {
                    transfer_limit.set(None);
                    return Err(ArtifactError::TransferTooLarge {
                        max_bytes: max_transfer_bytes,
                    });
                }
                return Err(ArtifactError::Zip { source });
            }
        };
        writer.flush().map_err(|source| ArtifactError::Io {
            context: "flush artifact archive",
            source,
        })?;
        drop(writer);
        fs::metadata(dest)
            .map(|metadata| metadata.len())
            .map_err(|source| ArtifactError::Io {
                context: "stat artifact archive",
                source,
            })
    })();

    if result.is_err() {
        let _ = fs::remove_file(dest);
    }

    result
}

fn is_transfer_limit_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Other && err.to_string() == TRANSFER_LIMIT_SENTINEL
}

fn is_transfer_limit_zip_error(err: &zip::result::ZipError) -> bool {
    matches!(err, zip::result::ZipError::Io(source) if is_transfer_limit_error(source))
}

struct LimitedWriter<W> {
    inner: W,
    bytes_written: u64,
    max_bytes: Rc<Cell<Option<u64>>>,
}

impl<W> LimitedWriter<W> {
    fn new(inner: W, max_bytes: Rc<Cell<Option<u64>>>) -> Self {
        Self {
            inner,
            bytes_written: 0,
            max_bytes,
        }
    }
}

impl<W: io::Write> io::Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(max_bytes) = self.max_bytes.get() {
            if self.bytes_written.saturating_add(buf.len() as u64) > max_bytes {
                return Err(io::Error::other(TRANSFER_LIMIT_SENTINEL));
            }
        }

        let written = self.inner.write(buf)?;
        self.bytes_written = self.bytes_written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: io::Seek> io::Seek for LimitedWriter<W> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub fn prepare_artifact_storage_root(root: &Path) -> Result<(), ArtifactError> {
    fs::create_dir_all(root).map_err(|source| ArtifactError::Io {
        context: "create artifacts root",
        source,
    })?;
    let metadata = fs::symlink_metadata(root).map_err(|source| ArtifactError::Io {
        context: "inspect artifacts root",
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(ArtifactError::Io {
            context: "validate artifacts root ownership",
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "artifact storage root must be a daemon-owned real directory",
            ),
        });
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ArtifactError::Io {
            context: "protect artifacts root",
            source,
        }
    })
}

fn validate_gc_root(root: &Path) -> Result<(), ArtifactError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| ArtifactError::Io {
        context: "inspect artifact gc root",
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ArtifactError::Io {
            context: "validate artifact gc root protection",
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "artifact gc root must be a daemon-owned, mode-0700 real directory",
            ),
        });
    }
    Ok(())
}

pub fn spawn_gc_task(config: crate::config::Config) -> Result<(), ArtifactError> {
    validate_gc_root(&config.artifacts.storage_root)?;
    if config.artifacts.ttl_sec.is_none() && config.artifacts.max_bytes.is_none() {
        return Ok(());
    }

    let artifacts = config.artifacts.clone();
    let interval = artifacts
        .gc_interval_sec
        .unwrap_or(DEFAULT_GC_INTERVAL_SECS);

    std::thread::spawn(move || loop {
        if let Err(err) = gc_artifacts(&artifacts) {
            warn!("artifact gc failed: {err}");
        }
        std::thread::sleep(Duration::from_secs(interval));
    });
    Ok(())
}

fn gc_artifacts(config: &ArtifactsConfig) -> Result<(), ArtifactError> {
    validate_gc_root(&config.storage_root)?;
    let mut entries = scan_artifact_entries(&config.storage_root)?;
    if entries.is_empty() {
        return Ok(());
    }

    if let Some(ttl_sec) = config.ttl_sec {
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(ttl_sec))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        entries.retain(|entry| {
            if entry.modified < cutoff {
                if let Err(err) = fs::remove_dir_all(&entry.path) {
                    warn!("failed to remove expired artifacts {:?}: {err}", entry.path);
                    return true;
                }
                info!("removed expired artifacts {:?}", entry.path);
                return false;
            }
            true
        });
    }

    if let Some(max_bytes) = config.max_bytes {
        let mut total: u64 = entries.iter().map(|entry| entry.size).sum();
        if total > max_bytes {
            entries.sort_by_key(|entry| entry.modified);
            for entry in entries {
                if total <= max_bytes {
                    break;
                }
                if let Err(err) = fs::remove_dir_all(&entry.path) {
                    warn!("failed to remove artifacts {:?}: {err}", entry.path);
                    continue;
                }
                info!("removed artifacts {:?} to enforce max_bytes", entry.path);
                total = total.saturating_sub(entry.size);
            }
        }
    }

    Ok(())
}

struct ArtifactEntry {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

fn scan_artifact_entries(root: &Path) -> Result<Vec<ArtifactEntry>, ArtifactError> {
    let mut entries = Vec::new();
    let read_dir = match fs::read_dir(root) {
        Ok(read_dir) => read_dir,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(entries);
            }
            return Err(ArtifactError::Io {
                context: "read artifacts root",
                source: err,
            });
        }
    };

    for entry in read_dir {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "read artifacts entry",
            source,
        })?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|source| ArtifactError::Io {
            context: "stat artifacts entry",
            source,
        })?;
        if !meta.is_dir() {
            continue;
        }

        let (size, modified) = scan_entry(&path)?;
        entries.push(ArtifactEntry {
            path,
            size,
            modified,
        });
    }

    Ok(entries)
}

fn scan_entry(path: &Path) -> Result<(u64, SystemTime), ArtifactError> {
    let mut total = 0u64;
    let mut newest = SystemTime::UNIX_EPOCH;

    for entry in WalkDir::new(path) {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "walk artifacts",
            source: io::Error::other(source.to_string()),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = entry.metadata().map_err(|source| ArtifactError::Io {
            context: "stat artifacts",
            source: io::Error::other(source.to_string()),
        })?;
        total = total.saturating_add(meta.len());
        if let Ok(modified) = meta.modified() {
            if modified > newest {
                newest = modified;
            }
        }
    }

    Ok((total, newest))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;
    use zip::ZipArchive;

    fn artifacts_config(root: &Path) -> ArtifactsConfig {
        ArtifactsConfig {
            storage_root: root.join("artifacts"),
            ..ArtifactsConfig::default()
        }
    }

    fn zip_entry_names(path: &Path) -> Vec<String> {
        let file = File::open(path).expect("open zip");
        let mut archive = ZipArchive::new(file).expect("read zip");
        let mut names = Vec::new();
        for index in 0..archive.len() {
            names.push(
                archive
                    .by_index(index)
                    .expect("zip entry")
                    .name()
                    .to_string(),
            );
        }
        names
    }

    #[test]
    fn collect_artifacts_no_match_returns_none() {
        let root = tempdir().expect("tempdir");
        let config = artifacts_config(root.path());
        let spec = ArtifactSpec {
            include: vec!["out/*.bin".to_string()],
            exclude: vec![],
        };

        // Glob miss no longer fails - just returns None if no files matched
        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap();
        assert!(
            result.archive.is_none(),
            "expected None when no files match"
        );
        assert!(result.restrictions.is_none());
    }

    #[test]
    fn collect_artifacts_creates_zip() {
        let root = tempdir().expect("tempdir");
        let config = artifacts_config(root.path());
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app"), "bin").expect("write");
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let archive = collect_artifacts_zip(root.path(), &spec, &config, "bld")
            .expect("collect")
            .archive
            .expect("archive");
        assert!(archive.path.ends_with("artifacts.zip"));
        let zip_path = config.storage_root.join("bld").join("artifacts.zip");
        assert!(zip_path.exists());
        assert_eq!(archive.size, std::fs::metadata(zip_path).unwrap().len());
    }

    #[test]
    fn collect_artifacts_omits_restricted_files_and_reports_patterns() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.bin"), "bin").expect("write app");
        std::fs::write(root.path().join("foo.cpp"), "source").expect("write source");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["foo.*".to_string(), "*.cpp".to_string()];
        let spec = ArtifactSpec {
            include: vec!["**".to_string(), "foo.cpp".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        let restrictions = result.restrictions.expect("restrictions");
        assert_eq!(restrictions.omitted_count, 1);
        assert_eq!(restrictions.matched_patterns, vec!["foo.*", "*.cpp"]);

        let archive = result.archive.expect("archive");
        assert!(archive.path.ends_with("artifacts.zip"));
        let names = zip_entry_names(&config.storage_root.join("bld").join("artifacts.zip"));
        assert_eq!(names, vec!["out/app.bin"]);
    }

    #[test]
    fn collect_artifacts_all_restricted_returns_no_archive_with_summary() {
        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("foo.cpp"), "source").expect("write source");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["*.cpp".to_string()];
        let spec = ArtifactSpec {
            include: vec!["*.cpp".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_none());
        let restrictions = result.restrictions.expect("restrictions");
        assert_eq!(restrictions.omitted_count, 1);
        assert_eq!(restrictions.matched_patterns, vec!["*.cpp"]);
        assert!(!config
            .storage_root
            .join("bld")
            .join("artifacts.zip")
            .exists());
    }

    #[test]
    fn collect_artifacts_absent_restriction_match_returns_no_summary() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.bin"), "bin").expect("write app");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["*.cpp".to_string()];
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_some());
        assert!(result.restrictions.is_none());
    }

    #[test]
    fn collect_artifacts_restricted_files_do_not_count_toward_size_limits() {
        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("large.h"), "artifact payload").expect("write source");

        let mut config = artifacts_config(root.path());
        config.max_uncompressed_bytes = 1;
        config.restricted_patterns = vec!["*.h".to_string()];
        let spec = ArtifactSpec {
            include: vec!["*.h".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_none());
        let restrictions = result.restrictions.expect("restrictions");
        assert_eq!(restrictions.omitted_count, 1);
        assert_eq!(restrictions.matched_patterns, vec!["*.h"]);
    }

    #[test]
    fn collect_artifacts_internal_excludes_are_not_reported_as_restrictions() {
        let root = tempdir().expect("tempdir");
        let internal = root.path().join(".indentured-server");
        let output = root.path().join("out");
        std::fs::create_dir_all(&internal).expect("mkdir internal");
        std::fs::create_dir_all(&output).expect("mkdir out");
        std::fs::write(internal.join("generated.h"), "internal").expect("write internal");
        std::fs::write(output.join("app.bin"), "bin").expect("write app");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["**/*.h".to_string()];
        let spec = ArtifactSpec {
            include: vec!["**".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_some());
        assert!(result.restrictions.is_none());
        let names = zip_entry_names(&config.storage_root.join("bld").join("artifacts.zip"));
        assert_eq!(names, vec!["out/app.bin"]);
    }

    #[cfg(unix)]
    #[test]
    fn collect_artifacts_rejects_symlink_outside_root() {
        let root = tempdir().expect("tempdir");
        let outside = tempdir().expect("tempdir");
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").expect("write");

        let link_path = root.path().join("link.txt");
        symlink(&outside_file, &link_path).expect("symlink");

        let config = artifacts_config(root.path());
        let spec = ArtifactSpec {
            include: vec!["link.txt".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        assert!(matches!(err, ArtifactError::UnsupportedFile { .. }));
    }

    #[test]
    fn descriptor_relative_open_rejects_file_and_ancestor_symlink_swaps() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let output = root.path().join("out");
        fs::create_dir(&output).unwrap();
        let file = output.join("evidence.txt");
        fs::write(&file, "safe").unwrap();
        let metadata = fs::symlink_metadata(&file).unwrap();
        let matched = HashMap::from([(
            PathBuf::from("out/evidence.txt"),
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )]);
        let root_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root.path())
            .unwrap();

        fs::remove_file(&file).unwrap();
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, "secret").unwrap();
        symlink(&outside_file, &file).unwrap();
        assert!(open_matched_artifacts(&root_fd, &matched, &|| false).is_err());

        fs::remove_file(&file).unwrap();
        fs::write(&file, "safe-again").unwrap();
        let metadata = fs::symlink_metadata(&file).unwrap();
        let matched = HashMap::from([(
            PathBuf::from("out/evidence.txt"),
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )]);
        fs::rename(&output, root.path().join("old-out")).unwrap();
        symlink(outside.path(), &output).unwrap();
        assert!(open_matched_artifacts(&root_fd, &matched, &|| false).is_err());
    }

    #[test]
    fn cancellation_at_each_snapshot_stage_removes_temporary_and_published_archives() {
        for checkpoint in [
            ArtifactSnapshotCheckpoint::Traversal,
            ArtifactSnapshotCheckpoint::ArchiveWrite,
            ArtifactSnapshotCheckpoint::Published,
        ] {
            let root = tempdir().unwrap();
            fs::write(root.path().join("evidence.txt"), vec![b'x'; 32 * 1024]).unwrap();
            let config = artifacts_config(root.path());
            let spec = ArtifactSpec {
                include: vec!["evidence.txt".to_string()],
                exclude: vec![],
            };
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            let result = collect_artifacts_zip_controlled(
                root.path(),
                &spec,
                &config,
                "bld_cancelled",
                &|| cancelled.load(std::sync::atomic::Ordering::SeqCst),
                &|reached| {
                    if reached == checkpoint {
                        cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                },
            );
            assert!(matches!(result, Err(ArtifactError::Cancelled)));
            assert!(!config.storage_root.join("bld_cancelled").exists());
        }
    }

    #[test]
    fn collect_artifacts_rejects_special_files() {
        let root = tempdir().expect("tempdir");
        let socket_path = root.path().join("control.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let config = artifacts_config(root.path());
        let spec = ArtifactSpec {
            include: vec!["control.sock".to_string()],
            exclude: vec![],
        };
        assert!(matches!(
            collect_artifacts_zip(root.path(), &spec, &config, "bld"),
            Err(ArtifactError::UnsupportedFile { .. })
        ));
    }

    #[test]
    fn artifact_gc_independently_rejects_symlinked_or_unprotected_roots() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("artifacts");
        prepare_artifact_storage_root(&root).unwrap();
        assert!(validate_gc_root(&root).is_ok());

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_gc_root(&root).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let link = temp.path().join("artifacts-link");
        symlink(&root, &link).unwrap();
        assert!(validate_gc_root(&link).is_err());
        let mut config = artifacts_config(temp.path());
        config.storage_root = link;
        assert!(gc_artifacts(&config).is_err());
    }

    #[test]
    fn traversal_limits_abort_before_accumulating_over_limit() {
        let mut limits = TraversalLimits::new(1, 2);
        limits.observe(Path::new("out/a")).unwrap();
        assert!(matches!(
            limits.observe(Path::new("out/b")),
            Err(ArtifactError::TooManyFiles { max_files: 1 })
        ));
        assert_eq!(limits.observed.len(), 1);

        let mut limits = TraversalLimits::new(10, 2);
        assert!(matches!(
            limits.observe(Path::new("out/deep/file")),
            Err(ArtifactError::TooDeep { max_depth: 2 })
        ));
        assert!(limits.observed.is_empty());
    }

    #[test]
    fn collect_artifacts_enforces_file_count_and_depth() {
        let root = tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("out/deep")).unwrap();
        std::fs::write(root.path().join("out/a"), "a").unwrap();
        std::fs::write(root.path().join("out/deep/b"), "b").unwrap();
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };
        let mut config = artifacts_config(root.path());
        config.max_files = 1;
        assert!(matches!(
            collect_artifacts_zip(root.path(), &spec, &config, "bld"),
            Err(ArtifactError::TooManyFiles { .. })
        ));
        config.max_files = 10;
        config.max_depth = 2;
        assert!(matches!(
            collect_artifacts_zip(root.path(), &spec, &config, "bld"),
            Err(ArtifactError::TooDeep { .. })
        ));
    }

    #[test]
    fn collect_artifacts_enforces_max_uncompressed_bytes() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.txt"), "artifact payload").expect("write");
        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            max_uncompressed_bytes: 8,
            ..ArtifactsConfig::default()
        };
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::UncompressedTooLarge { max_bytes: 8 }
        ));
        assert!(
            !config
                .storage_root
                .join("bld")
                .join("artifacts.zip")
                .exists(),
            "oversized archives should be removed"
        );
    }

    #[test]
    fn collect_artifacts_enforces_max_transfer_bytes() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.txt"), "artifact payload").expect("write");
        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            max_transfer_bytes: 1,
            ..ArtifactsConfig::default()
        };
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::TransferTooLarge { max_bytes: 1 }
        ));
        assert!(
            !config
                .storage_root
                .join("bld")
                .join("artifacts.zip")
                .exists(),
            "oversized archives should be removed"
        );
    }
}
