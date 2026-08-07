use std::io::{BufRead, BufReader, Read, Write};
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

fn process_exists(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn process_group_exists(pgid: i32) -> bool {
    if unsafe { libc::killpg(pgid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
fn reap_adopted(pid: i32) {
    while unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
}

#[cfg(not(target_os = "linux"))]
fn reap_adopted(_pid: i32) {}

#[test]
fn parent_group_death_reaps_term_ignoring_service_and_supervisor() {
    if std::env::var_os("INDENTURED_SERVICE_TEST_HELPER").is_some() {
        run_service_test_helper();
    }

    #[cfg(target_os = "linux")]
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );

    let mut helper = Command::new(std::env::current_exe().unwrap());
    helper
        .args([
            "--exact",
            "parent_group_death_reaps_term_ignoring_service_and_supervisor",
            "--nocapture",
        ])
        .env("INDENTURED_SERVICE_TEST_HELPER", "1")
        .process_group(0)
        .stdout(Stdio::piped());
    let mut helper = helper.spawn().unwrap();
    let helper_pgid = helper.id() as i32;
    let mut output = BufReader::new(helper.stdout.take().unwrap());
    let (supervisor_pid, service_pid, service_pgid) = loop {
        let mut line = String::new();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "helper exited early"
        );
        let Some(identity) = line.split("INDENTURED_FIXTURE ").nth(1) else {
            continue;
        };
        let ids: Vec<i32> = identity
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        break (ids[0], ids[1], ids[2]);
    };
    assert!(process_exists(supervisor_pid));
    assert!(process_exists(service_pid));
    assert!(process_group_exists(service_pgid));

    assert_eq!(unsafe { libc::killpg(helper_pgid, libc::SIGKILL) }, 0);
    helper.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(4);
    let cleaned = loop {
        reap_adopted(supervisor_pid);
        reap_adopted(-service_pgid);
        let cleaned = !process_exists(supervisor_pid)
            && !process_exists(service_pid)
            && !process_group_exists(service_pgid);
        if cleaned || Instant::now() >= deadline {
            break cleaned;
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    if !cleaned {
        unsafe {
            libc::kill(supervisor_pid, libc::SIGKILL);
            libc::killpg(service_pgid, libc::SIGKILL);
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < cleanup_deadline {
            reap_adopted(supervisor_pid);
            reap_adopted(-service_pgid);
            if !process_exists(supervisor_pid) && !process_group_exists(service_pgid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(cleaned, "service or supervisor survived parent-group death");
}

#[allow(
    clippy::zombie_processes,
    reason = "the outer test reaps this supervisor after killing the helper"
)]
fn run_service_test_helper() -> ! {
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
    let service_pid = spawned["pid"].as_i64().unwrap() as i32;
    let service_pgid = spawned["pgid"].as_i64().unwrap() as i32;

    let mut ready = String::new();
    std::fs::File::from(ready_read)
        .read_to_string(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");

    println!(
        "INDENTURED_FIXTURE {} {service_pid} {service_pgid}",
        supervisor.id()
    );
    std::io::stdout().flush().unwrap();
    let _keep_control_open = control_write;
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
