use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    #[cfg(target_os = "linux")]
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    #[cfg(target_vendor = "apple")]
    {
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        for fd in fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
                0
            );
        }
    }
    (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    })
}

fn process_group_exists(pgid: i32) -> bool {
    if unsafe { libc::killpg(pgid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[test]
fn daemon_control_eof_kills_term_ignoring_service_group() {
    let (control_read, control_write) = pipe();
    let (status_read, status_write) = pipe();
    let (ready_read, ready_write) = pipe();
    let control_fd = control_read.as_raw_fd();
    let status_fd = status_write.as_raw_fd();
    let readiness_fd = ready_write.as_raw_fd();
    let user = indentured_server::user::lookup_user(unsafe { libc::geteuid() }).unwrap();

    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_indentured-server"));
    supervisor
        .arg("--service-supervisor")
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--status-fd")
        .arg(status_fd.to_string())
        .arg("--readiness-fd")
        .arg(readiness_fd.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        supervisor.pre_exec(move || {
            for fd in [control_fd, status_fd, readiness_fd] {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut supervisor = supervisor.spawn().unwrap();
    drop(control_read);
    drop(status_write);
    drop(ready_write);

    let spec = serde_json::json!({
        "execution": {"Script": "eval \"printf 'ready\\n' >&$INDENTURED_SERVICE_READY_FD\"; eval \"exec $INDENTURED_SERVICE_READY_FD>&-\"; trap '' TERM; while :; do :; done"},
        "cwd": std::env::current_dir().unwrap(),
        "environment": [],
        "username": user.username,
        "home_dir": user.home_dir,
        "uid": user.uid,
        "gid": user.gid,
        "set_ids": false,
        "shutdown_timeout_sec": 1,
        "readiness_fd": readiness_fd
    });
    serde_json::to_writer(supervisor.stdin.take().unwrap(), &spec).unwrap();

    let mut status = BufReader::new(std::fs::File::from(status_read));
    let mut line = String::new();
    status.read_line(&mut line).unwrap();
    let spawned: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(spawned["status"], "spawned");
    let pgid = spawned["pgid"].as_i64().unwrap() as i32;

    let mut ready = String::new();
    std::fs::File::from(ready_read)
        .read_to_string(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");

    drop(control_write);
    line.clear();
    status.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["status"],
        "stopped"
    );
    assert!(supervisor.wait().unwrap().success());

    let deadline = Instant::now() + Duration::from_secs(2);
    while process_group_exists(pgid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!process_group_exists(pgid));
}
