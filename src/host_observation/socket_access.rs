//! The observation socket grants read-only GUI access without making uploaded
//! tasks run as the desktop account. Filesystem access and kernel peer UID checks
//! are both required; group membership alone never authorizes a request.
use super::{uid, Result};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub(super) fn parent(socket: &Path, owner: u32, group: Option<u32>) -> Result<()> {
    if !socket.is_absolute() || socket.file_name().is_none() {
        return Err("--socket must be an absolute file path".into());
    }
    let parent = socket.parent().ok_or("socket has no parent")?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component),
            _ => return Err("socket path must not contain traversal components".into()),
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|e| format!("inspect socket directory {}: {e}", current.display()))?;
        if !metadata.is_dir() || (metadata.uid() != owner && metadata.uid() != 0) {
            return Err(
                "socket ancestors must be real directories owned by root or the GUI helper UID"
                    .into(),
            );
        }
        let root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if metadata.mode() & 0o022 != 0 && !root_sticky {
            return Err("socket ancestors must not be group/other writable".into());
        }
    }
    let metadata = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    let expected_mode = if group.is_some() { 0o710 } else { 0o700 };
    if metadata.uid() != owner
        || metadata.mode() & 0o7777 != expected_mode
        || group.is_some_and(|gid| metadata.gid() != gid)
    {
        return Err(format!(
            "socket parent must be owned by GUI UID {owner}, mode {expected_mode:04o}, with the configured observation group"
        ));
    }
    Ok(())
}

pub(super) fn server(socket: &Path, allow_uid: u32, group: Option<u32>) -> Result<()> {
    if allow_uid != uid() && group.is_none() {
        return Err("cross-UID observation requires --socket-group and a pre-provisioned mode-0710 directory; do not change the task account".into());
    }
    parent(socket, uid(), group)
}

pub(super) fn configure(socket: &Path, group: Option<u32>) -> Result<()> {
    if let Some(group) = group {
        use std::os::unix::ffi::OsStrExt;
        let path =
            std::ffi::CString::new(socket.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        // The parent is not writable by callers. lchown never follows a symlink.
        if unsafe { libc::lchown(path.as_ptr(), uid(), group) } != 0 {
            return Err(format!(
                "set observation socket group: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    fs::set_permissions(
        socket,
        fs::Permissions::from_mode(if group.is_some() { 0o660 } else { 0o600 }),
    )
    .map_err(|e| e.to_string())
}

pub(super) fn client(socket: &Path, owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(socket).map_err(|e| {
        format!("GUI helper socket unavailable: {e}; start its LaunchAgent in the selected graphical session")
    })?;
    if !metadata.file_type().is_socket() || metadata.uid() != owner {
        return Err(
            "GUI helper endpoint must be a real socket owned by the configured GUI peer UID".into(),
        );
    }
    let group = match metadata.mode() & 0o7777 {
        0o600 if owner == uid() => None,
        0o660 => Some(metadata.gid()),
        _ => return Err(
            "GUI helper socket requires mode 0600 (same UID) or 0660 (explicit observation group)"
                .into(),
        ),
    };
    parent(socket, owner, group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use tempfile::TempDir;

    fn private_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn same_uid_and_explicit_group_policy_are_distinct() {
        let dir = private_dir();
        let socket = dir.path().canonicalize().unwrap().join("observe.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        configure(&socket, None).unwrap();
        server(&socket, uid(), None).unwrap();
        client(&socket, uid()).unwrap();
        assert!(client(&socket, uid().wrapping_add(1)).is_err());
        assert!(server(&socket, uid().wrapping_add(1), None).is_err());
        let gid = fs::metadata(dir.path()).unwrap().gid();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o710)).unwrap();
        configure(&socket, Some(gid)).unwrap();
        server(&socket, uid().wrapping_add(1), Some(gid)).unwrap();
        client(&socket, uid()).unwrap();
        assert!(server(&socket, uid(), None).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(client(&socket, uid()).is_err());
        drop(listener);
    }

    #[test]
    fn rejects_writable_ancestors_and_symlink_endpoints() {
        let dir = private_dir();
        let parent = dir.path().canonicalize().unwrap().join("private");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.join("observe.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        configure(&socket, None).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(client(&socket, uid()).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let alias = parent.join("alias.sock");
        std::os::unix::fs::symlink(&socket, &alias).unwrap();
        assert!(client(&alias, uid()).is_err());
    }
}
