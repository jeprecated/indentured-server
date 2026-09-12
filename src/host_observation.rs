//! Read-only, explicitly authorized desktop observation. The GUI broker deliberately owns no
//! task execution authority: clients can select identities, never commands or paths.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

mod native;
mod socket_access;

pub type Result<T> = std::result::Result<T, String>;
const MAX_REQUEST: usize = 4096;
const MAX_ARCHIVE: usize = 64 * 1024 * 1024;
const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_IMAGES: usize = 32;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Desktop {},
    Application { pid: u32 },
    Window { pid: u32, window_id: u32 },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    List {},
    Capture { target: Target },
}

/// Bounded, identity-only request shared by the host API and GUI broker.
pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    if bytes.len() > MAX_REQUEST {
        return Err("host request exceeds 4096 bytes".into());
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    validate_request(&request)?;
    Ok(request)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationResponse {
    pub manifest: Manifest,
    pub artifacts: Option<crate::protocol::ArtifactArchive>,
    pub artifact_restrictions: Option<crate::protocol::ArtifactRestrictions>,
}

pub fn valid_observation_id(value: &str) -> bool {
    value
        .strip_prefix("host-")
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .is_some_and(|id| value == format!("host-{id}"))
}

fn validate_request(request: &Request) -> Result<()> {
    if let Request::Capture { target } = request {
        let (pid, window) = match target {
            Target::Desktop {} => return Ok(()),
            Target::Application { pid } => (*pid, None),
            Target::Window { pid, window_id } => (*pid, Some(*window_id)),
        };
        if pid == 0 || pid > i32::MAX as u32 || window == Some(0) {
            return Err(
                "pid must be a positive signed 32-bit process ID; window_id must be nonzero".into(),
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub pid: u32,
    pub name: String,
    pub bundle_id: Option<String>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub window_id: u32,
    pub pid: u32,
    pub title: String,
    pub on_screen: bool,
    pub layer: i32,
    pub bounds: Bounds,
    /// Eligibility, not a promise: protected/closing windows can still fail capture.
    pub capturable: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    pub display_id: u32,
    /// CoreGraphics global screen points (top-left origin, y increases downward).
    pub bounds: Bounds,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub applications: Vec<Application>,
    pub windows: Vec<Window>,
    pub displays: Vec<Display>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: String,
    pub observation_id: String,
    pub captured_at: String,
    pub status: String,
    pub inventory: Option<Inventory>,
    pub images: Vec<Image>,
    pub errors: Vec<String>,
}

impl Manifest {
    fn new() -> Self {
        Self {
            schema_version: "1".into(),
            observation_id: format!("host-{}", uuid::Uuid::new_v4()),
            captured_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("current UTC timestamp is representable"),
            status: "succeeded".into(),
            inventory: None,
            images: vec![],
            errors: vec![],
        }
    }
    fn fail(&mut self, error: String) {
        self.status = "failed".into();
        self.errors.push(error);
    }
}

#[derive(Debug, Clone)]
pub enum Capture {
    Window { pid: u32, window_id: u32 },
    Display { display_id: u32, bounds: Bounds },
}

/// Implementations must honor the deadline and only write a new regular PNG at
/// the supplied private path. This narrow seam also permits offline native fakes.
pub trait Backend {
    fn inventory(&self, deadline: Instant) -> Result<Inventory>;
    fn capture(&self, capture: &Capture, path: &Path, deadline: Instant) -> Result<()>;
}

fn select(inventory: &Inventory, target: &Target) -> Result<Vec<Capture>> {
    let selected = match target {
        Target::Desktop {} => inventory
            .displays
            .iter()
            .map(|d| Capture::Display {
                display_id: d.display_id,
                bounds: d.bounds.clone(),
            })
            .collect::<Vec<_>>(),
        Target::Application { pid } => {
            if !inventory.applications.iter().any(|app| app.pid == *pid) {
                return Err(format!(
                    "application PID {pid} is no longer running; list again"
                ));
            }
            inventory
                .windows
                .iter()
                .filter(|w| w.pid == *pid && w.capturable)
                .map(|w| Capture::Window {
                    pid: *pid,
                    window_id: w.window_id,
                })
                .collect()
        }
        Target::Window { pid, window_id } => {
            let window = inventory
                .windows
                .iter()
                .find(|w| w.window_id == *window_id)
                .ok_or_else(|| "window is stale or unavailable; list again".to_string())?;
            if window.pid != *pid {
                return Err("window owner changed; refusing capture; list again".into());
            }
            if !window.capturable {
                return Err("window is hidden, minimized, off-screen, on a nonzero layer, or not capturable; no desktop fallback".into());
            }
            vec![Capture::Window {
                pid: *pid,
                window_id: *window_id,
            }]
        }
    };
    if selected.is_empty() {
        return Err("no capturable windows/displays; ensure the user is logged in, unlocked, and the app has visible windows".into());
    }
    if selected.len() > MAX_IMAGES {
        return Err(format!(
            "capture exceeds {MAX_IMAGES} image limit; select individual windows instead"
        ));
    }
    Ok(selected)
}

fn check_display_topology(expected: &Inventory, mut current: Inventory) -> Result<()> {
    current.displays.sort_by_key(|d| d.display_id);
    if current.displays != expected.displays {
        return Err("display topology changed; list again".into());
    }
    Ok(())
}

fn build_observation(backend: &dyn Backend, request: &Request) -> Result<Vec<u8>> {
    validate_request(request)?;
    let mut manifest = Manifest::new();
    let mut images = Vec::new();
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let result = (|| {
        let mut inventory = backend.inventory(deadline)?;
        inventory.applications.sort_by_key(|a| a.pid);
        inventory.windows.sort_by_key(|w| w.window_id);
        inventory.displays.sort_by_key(|d| d.display_id);
        manifest.inventory = Some(inventory.clone());
        if let Request::Capture { target } = request {
            let captures = select(&inventory, target)?;
            let directory = private_temp()?;
            let mut total = 0;
            for (index, capture) in captures.into_iter().enumerate() {
                if Instant::now() >= deadline {
                    return Err("host observation exceeded 45 second deadline".into());
                }
                let name = format!("image-{index:04}.png");
                let path = directory.path().join(&name);
                // Recheck owner/visibility immediately before each native capture.
                let current = backend.inventory(deadline)?;
                match &capture {
                    Capture::Window { pid, window_id } => {
                        select(
                            &current,
                            &Target::Window {
                                pid: *pid,
                                window_id: *window_id,
                            },
                        )?;
                    }
                    Capture::Display { .. } => check_display_topology(&inventory, current)?,
                }
                backend.capture(&capture, &path, deadline)?;
                // A moved/added/removed display invalidates the whole observation,
                // including images captured earlier. Never relabel a rectangle.
                if matches!(capture, Capture::Display { .. }) {
                    check_display_topology(&inventory, backend.inventory(deadline)?)?;
                }
                if Instant::now() >= deadline {
                    return Err("host observation exceeded 45 second deadline".into());
                }
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|e| format!("capture did not produce an image: {e}"))?;
                if !metadata.is_file() || metadata.len() > MAX_ARCHIVE as u64 {
                    return Err("capture is not a bounded regular PNG".into());
                }
                let bytes = fs::read(&path).map_err(|e| e.to_string())?;
                validate_png(&bytes)?;
                total += bytes.len();
                if total > MAX_ARCHIVE - MAX_MANIFEST {
                    return Err("capture images exceed 63 MiB transfer budget".into());
                }
                let (pid, window_id, display_id) = match capture {
                    Capture::Window { pid, window_id } => (Some(pid), Some(window_id), None),
                    Capture::Display { display_id, .. } => (None, None, Some(display_id)),
                };
                manifest.images.push(Image {
                    path: name.clone(),
                    pid,
                    window_id,
                    display_id,
                });
                images.push((name, bytes));
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        manifest.fail(error);
        // A partial capture is never presented as a complete observation.
        manifest.images.clear();
        images.clear();
    }
    encode_archive(&manifest, &images)
}

fn encode_archive(manifest: &Manifest, images: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(manifest).map_err(|e| e.to_string())?;
    if json.len() > MAX_MANIFEST {
        return Err("observation inventory exceeds 1 MiB manifest limit".into());
    }
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o600);
    zip.start_file("manifest.json", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(&json).map_err(|e| e.to_string())?;
    for (name, bytes) in images {
        zip.start_file(name, options).map_err(|e| e.to_string())?;
        zip.write_all(bytes).map_err(|e| e.to_string())?;
    }
    let bytes = zip.finish().map_err(|e| e.to_string())?.into_inner();
    if bytes.len() > MAX_ARCHIVE {
        return Err("observation archive exceeds 64 MiB".into());
    }
    Ok(bytes)
}

fn error_archive(error: String) -> Result<Vec<u8>> {
    let mut manifest = Manifest::new();
    manifest.fail(error);
    encode_archive(&manifest, &[])
}

/// Check PNG framing, dimensions, critical chunk ordering and CRCs. The actual
/// image codec belongs to the OS; no decoding of untrusted pixels occurs here.
pub fn validate_png(bytes: &[u8]) -> Result<()> {
    let invalid = || "capture is not a valid nonempty PNG".to_string();
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(invalid());
    }
    let mut offset = 8usize;
    let mut header = false;
    let mut data = false;
    while offset.checked_add(12).is_some_and(|n| n <= bytes.len()) {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|n| n.checked_add(length))
            .ok_or_else(invalid)?;
        if end > bytes.len() {
            return Err(invalid());
        }
        let kind = &bytes[offset + 4..offset + 8];
        let payload = &bytes[offset + 8..end - 4];
        let crc = u32::from_be_bytes(bytes[end - 4..end].try_into().unwrap());
        if crc32(&bytes[offset + 4..end - 4]) != crc {
            return Err(invalid());
        }
        if !header {
            if kind != b"IHDR" || length != 13 || payload[..4] == [0; 4] || payload[4..8] == [0; 4]
            {
                return Err(invalid());
            }
            let width = u32::from_be_bytes(payload[..4].try_into().unwrap());
            let height = u32::from_be_bytes(payload[4..8].try_into().unwrap());
            let valid_depth = match payload[9] {
                0 => [1, 2, 4, 8, 16].contains(&payload[8]),
                2 | 4 | 6 => [8, 16].contains(&payload[8]),
                3 => [1, 2, 4, 8].contains(&payload[8]),
                _ => false,
            };
            if !valid_depth
                || payload[10] != 0
                || payload[11] != 0
                || payload[12] > 1
                || width > 32768
                || height > 32768
                || u64::from(width) * u64::from(height) > 100_000_000
            {
                return Err(
                    "PNG format/dimensions unsupported (maximum 100 million pixels)".into(),
                );
            }
            header = true;
        } else if kind == b"IHDR" {
            return Err(invalid());
        }
        if kind == b"IDAT" && length > 0 {
            data = true;
        }
        if kind == b"IEND" {
            return if length == 0 && data && end == bytes.len() {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        offset = end;
    }
    Err(invalid())
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(crc & 1)));
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ u32::from(*byte)) & 255) as usize];
    }
    !crc
}

fn read_frame(stream: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut size = [0; 4];
    stream
        .read_exact(&mut size)
        .map_err(|e| io::Error::new(e.kind(), format!("read observation frame: {e}")))?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "observation frame exceeds allowed size",
        ));
    }
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .map_err(|e| io::Error::new(e.kind(), format!("read observation payload: {e}")))?;
    Ok(bytes)
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    let size = u32::try_from(bytes.len()).map_err(|e| e.to_string())?;
    stream
        .write_all(&size.to_be_bytes())
        .and_then(|()| stream.write_all(bytes))
        .map_err(|e| format!("write observation frame: {e}"))
}

fn private_temp() -> Result<TempDir> {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(|e| e.to_string())
}

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        ) != 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(cred.uid)
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let mut user = 0;
        let mut group = 0;
        if libc::getpeereid(stream.as_raw_fd(), &mut user, &mut group) != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(user)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err("same-user observation transport is unsupported on this platform".into())
    }
}

fn check_peer(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    if peer_uid(stream)? != expected_uid {
        return Err(format!(
            "host observation peer is not the authorized UID {expected_uid}"
        ));
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.inode) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Blocking serial broker; a stalled connection has bounded I/O timeouts. The
/// launch agent owns its lifecycle; clients cannot terminate or reconfigure it.
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn serve(
    socket: &Path,
    allow_uid: Option<u32>,
    socket_group: Option<u32>,
    request_permission: bool,
) -> Result<()> {
    let allow_uid = allow_uid.unwrap_or_else(uid);
    socket_access::server(socket, allow_uid, socket_group)?;
    // This entry point is used by the dedicated helper executable only. Signal
    // handlers do no I/O; ordinary control flow closes/unlinks our exact socket.
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = stop_signal as *const () as libc::sighandler_t;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
    }
    if request_permission {
        if let Err(error) = permissions() {
            // Keep serving structured denials, without a LaunchAgent restart/prompt loop.
            eprintln!("host observation permission request: {error}");
        }
    }
    serve_with_backend(socket, &native::Native, allow_uid, socket_group)
}

fn serve_with_backend(
    socket: &Path,
    backend: &dyn Backend,
    allow_uid: u32,
    socket_group: Option<u32>,
) -> Result<()> {
    socket_access::server(socket, allow_uid, socket_group)?;
    // Never unlink an existing socket: it may belong to a live helper.
    if fs::symlink_metadata(socket).is_ok() {
        return Err("socket already exists; stop the existing helper and remove only its stale socket before restarting".into());
    }
    let listener = UnixListener::bind(socket).map_err(|e| e.to_string())?;
    let _guard = SocketGuard {
        path: socket.to_owned(),
        inode: fs::symlink_metadata(socket)
            .map_err(|e| e.to_string())?
            .ino(),
    };
    socket_access::configure(socket, socket_group)?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    while !STOP.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Accepted sockets are explicitly blocking on all supported OSes.
                stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                if let Err(error) = handle_connection(&mut stream, backend, allow_uid) {
                    eprintln!("host observation request failed: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

struct DeadlineIo<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}
impl<'a> DeadlineIo<'a> {
    fn new(stream: &'a UnixStream, timeout: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + timeout,
        }
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "observation transfer deadline exceeded",
                )
            })
    }
}
impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn handle_connection(stream: &mut UnixStream, backend: &dyn Backend, allow_uid: u32) -> Result<()> {
    check_peer(stream, allow_uid)?;
    let response = (|| {
        let bytes = read_frame(
            &mut DeadlineIo::new(stream, Duration::from_secs(5)),
            MAX_REQUEST,
        )
        .map_err(|e| e.to_string())?;
        let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        build_observation(backend, &request)
    })()
    .or_else(error_archive)?;
    write_frame(
        &mut DeadlineIo::new(stream, Duration::from_secs(10)),
        &response,
    )
}

fn connect_bounded(socket: &Path) -> Result<UnixStream> {
    // std's blocking UnixStream::connect can wait indefinitely on a full accept
    // backlog. Connect nonblocking, then bound completion before any framing.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let path = socket.as_os_str().as_bytes();
    if path.len() >= address.sun_path.len() || path.contains(&0) {
        return Err("GUI helper socket path is too long or contains NUL".into());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    for (destination, byte) in address.sun_path.iter_mut().zip(path) {
        *destination = *byte as libc::c_char;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let owned = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(format!("connect GUI helper (it may be busy): {error}"));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("GUI helper connection timed out")?;
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let status = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
            if status < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if status <= 0 {
                return Err("GUI helper connection failed or timed out".into());
            }
            let mut error: libc::c_int = 0;
            let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut size,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error).to_string());
            }
            break;
        }
    }
    let stream = unsafe { UnixStream::from_raw_fd(owned.into_raw_fd()) };
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    Ok(stream)
}

fn connect(socket: &Path, request: &Request, peer_uid: u32) -> Result<Vec<u8>> {
    socket_access::client(socket, peer_uid)?;
    let stream = connect_bounded(socket)?;
    check_peer(&stream, peer_uid)?;
    write_frame(
        &mut DeadlineIo::new(&stream, Duration::from_secs(5)),
        &serde_json::to_vec(request).map_err(|e| e.to_string())?,
    )?;
    read_frame(
        &mut DeadlineIo::new(&stream, Duration::from_secs(60)),
        MAX_ARCHIVE,
    )
    .map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ) {
            format!(
                "{error}; broker connection closed: inspect the GUI helper log and verify --allow-uid matches the daemon service UID ({})",
                uid()
            )
        } else {
            error.to_string()
        }
    })
}

fn decode_archive(bytes: &[u8]) -> Result<(Manifest, Vec<Vec<u8>>)> {
    if bytes.len() > MAX_ARCHIVE {
        return Err("observation archive exceeds 64 MiB".into());
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    if zip.is_empty() || zip.len() > MAX_IMAGES + 1 {
        return Err("invalid observation archive file count".into());
    }
    let mut names = BTreeSet::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(|e| e.to_string())?;
        if !names.insert(entry.name().to_string())
            || entry.is_dir()
            || entry.is_symlink()
            || entry.size() > MAX_ARCHIVE as u64
        {
            return Err("observation archive has duplicate, special, or oversized entries".into());
        }
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 != 0 && mode & 0o170000 != 0o100000 {
                return Err("observation archive contains a non-regular entry".into());
            }
        }
    }
    let mut json = Vec::new();
    zip.by_name("manifest.json")
        .map_err(|e| e.to_string())?
        .take(MAX_MANIFEST as u64 + 1)
        .read_to_end(&mut json)
        .map_err(|e| e.to_string())?;
    if json.len() > MAX_MANIFEST {
        return Err("manifest exceeds 1 MiB".into());
    }
    let manifest: Manifest = serde_json::from_slice(&json).map_err(|e| e.to_string())?;
    let id = manifest
        .observation_id
        .strip_prefix("host-")
        .ok_or("invalid observation ID")?;
    let parsed = uuid::Uuid::parse_str(id).map_err(|e| e.to_string())?;
    if parsed.to_string() != id
        || manifest.schema_version != "1"
        || !["succeeded", "failed"].contains(&manifest.status.as_str())
    {
        return Err("invalid observation manifest identity/status".into());
    }
    if (manifest.status == "failed" && (manifest.errors.is_empty() || !manifest.images.is_empty()))
        || (manifest.status == "succeeded" && !manifest.errors.is_empty())
    {
        return Err("inconsistent observation manifest status".into());
    }
    if zip.len() != manifest.images.len() + 1 {
        return Err("archive does not match manifest".into());
    }
    let mut images = Vec::new();
    let mut total = 0;
    for (index, image) in manifest.images.iter().enumerate() {
        if image.path != format!("image-{index:04}.png") {
            return Err("invalid observation image path".into());
        }
        let mut bytes = Vec::new();
        zip.by_name(&image.path)
            .map_err(|e| e.to_string())?
            .take((MAX_ARCHIVE - total) as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        total += bytes.len();
        if total > MAX_ARCHIVE - MAX_MANIFEST {
            return Err("decoded images exceed transfer budget".into());
        }
        validate_png(&bytes)?;
        images.push(bytes);
    }
    Ok((manifest, images))
}

fn c_name(name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())
}

fn open_directory_at(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
    let name = c_name(name)?;
    // Every component is opened relative to a pinned descriptor, without links.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("artifact cwd must be absolute".into());
    }
    let mut directory = File::open("/").map_err(|e| e.to_string())?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => directory = open_directory_at(&directory, name)?,
            _ => return Err("artifact cwd contains traversal components".into()),
        }
    }
    Ok(directory)
}

fn mkdir_at(parent: &File, name: &str, allow_existing: bool) -> Result<File> {
    let c = c_name(name.as_ref())?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        let error = io::Error::last_os_error();
        if !allow_existing || error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error.to_string());
        }
    }
    let directory = open_directory_at(parent, name.as_ref())?;
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != uid() || metadata.mode() & 0o022 != 0 {
        return Err("artifact parent must be same-user and not group/other writable".into());
    }
    Ok(directory)
}

fn write_file_at(parent: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let name = c_name(name.as_ref())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

struct Staging {
    parent: File,
    directory: File,
    name: String,
    names: Vec<String>,
    published: bool,
}
impl Drop for Staging {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        for name in &self.names {
            if let Ok(name) = c_name(name.as_ref()) {
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0);
                }
            }
        }
        if let Ok(name) = c_name(self.name.as_ref()) {
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
            }
        }
    }
}

#[cfg(test)]
fn publish(bytes: &[u8], cwd: &Path) -> Result<Manifest> {
    let (manifest, images) = decode_archive(bytes)?;
    publish_decoded(manifest, images, cwd)
}

fn publish_decoded(mut manifest: Manifest, images: Vec<Vec<u8>>, cwd: &Path) -> Result<Manifest> {
    let cwd = open_directory(cwd)?;
    let parent = mkdir_at(&cwd, "observations", true)?;
    let name = format!(".host-staging-{}", uuid::Uuid::new_v4());
    let directory = mkdir_at(&parent, &name, false)?;
    let mut staging = Staging {
        parent,
        directory,
        name,
        names: vec![],
        published: false,
    };
    let relative = format!("observations/{}", manifest.observation_id);
    for (image, bytes) in manifest.images.iter_mut().zip(images) {
        staging.names.push(image.path.clone());
        write_file_at(&staging.directory, &image.path, &bytes)?;
        image.path = format!("{relative}/{}", image.path);
    }
    staging.names.push("manifest.json".into());
    write_file_at(
        &staging.directory,
        "manifest.json",
        &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
    )?;
    staging.directory.sync_all().map_err(|e| e.to_string())?;
    // Reserve a fresh destination. Publication is descriptor-relative and never
    // follows a destination symlink or opens a path supplied by the broker.
    let _destination = mkdir_at(&staging.parent, &manifest.observation_id, false)?;
    let old = c_name(staging.name.as_ref())?;
    let new = c_name(manifest.observation_id.as_ref())?;
    if unsafe {
        libc::renameat(
            staging.parent.as_raw_fd(),
            old.as_ptr(),
            staging.parent.as_raw_fd(),
            new.as_ptr(),
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        unsafe {
            libc::unlinkat(staging.parent.as_raw_fd(), new.as_ptr(), libc::AT_REMOVEDIR);
        }
        return Err(error.to_string());
    }
    staging.published = true;
    staging.parent.sync_all().map_err(|e| e.to_string())?;
    Ok(manifest)
}

/// Called by the daemon under its own identity, never through a build task.
/// Scratch must be a new private daemon-owned directory, removed by the caller.
pub(crate) fn observe(
    socket: &Path,
    peer_uid: u32,
    request: &Request,
    scratch: &Path,
) -> Result<Manifest> {
    validate_request(request)?;
    let (mut manifest, images) =
        match connect(socket, request, peer_uid).and_then(|bytes| decode_archive(&bytes)) {
            Ok(value) => value,
            Err(error) => {
                let mut manifest = Manifest::new();
                manifest.fail(error);
                (manifest, vec![])
            }
        };
    // The broker cannot select or reuse the daemon's artifact identity.
    manifest.observation_id = format!("host-{}", uuid::Uuid::new_v4());
    publish_decoded(manifest, images, scratch)
}

pub fn permissions() -> Result<()> {
    native::permissions()
}

#[cfg(test)]
mod tests;
