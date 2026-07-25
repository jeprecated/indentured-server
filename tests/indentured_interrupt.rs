use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn publish_executable(path: &std::path::Path, contents: &[u8]) {
    let mut temporary = tempfile::Builder::new()
        .prefix(".fake-jj-")
        .tempfile_in(path.parent().unwrap())
        .unwrap();
    temporary.write_all(contents).unwrap();
    temporary.as_file_mut().flush().unwrap();
    temporary.as_file().sync_all().unwrap();
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))
        .unwrap();
    let published = temporary.persist_noclobber(path).unwrap();
    published.sync_all().unwrap();
    drop(published);
}

#[test]
fn sigint_marks_evidence_and_disconnects_the_remote_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = None;
        let mut chunked = false;
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
                if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
        }
        if let Some(length) = content_length {
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
        } else if chunked {
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                let size =
                    usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
                if size == 0 {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    break;
                }
                let mut bytes = vec![0; size + 2];
                reader.read_exact(&mut bytes).unwrap();
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n{\"type\":\"build\",\"id\":\"bld_interrupt\",\"status\":\"started\"}\n").unwrap();
        stream.flush().unwrap();
        ready_tx.send(()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        matches!(stream.read(&mut byte), Ok(0))
    });

    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    fs::write(repo.path().join("source"), "x").unwrap();
    fs::create_dir(repo.path().join(".indentured-server")).unwrap();
    fs::write(
        repo.path().join(".indentured-server/config.toml"),
        format!("[sources]\ninclude = [\"source\"]\n[connection]\nendpoint = \"{endpoint}\"\n"),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(repo.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("run")
        .arg("build")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "client did not exit after SIGINT"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
    assert!(
        server.join().unwrap(),
        "server did not observe request disconnect"
    );
    let runs = state.path().join("indentured/runs");
    let run = fs::read_dir(runs).unwrap().next().unwrap().unwrap().path();
    let provenance = fs::read_to_string(run.join("provenance.json")).unwrap();
    assert!(provenance.contains("\"status\": \"interrupted\""));
    assert!(fs::read_dir(run).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".source-")));
}

#[test]
fn sigint_during_every_jj_preparation_phase_is_controlled_and_cleans_up() {
    for stage in ["pin", "list", "show", "workspace"] {
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let fake_bin = TempDir::new().unwrap();
        fs::create_dir(repo.path().join(".jj")).unwrap();
        fs::create_dir(repo.path().join(".indentured-server")).unwrap();
        fs::write(
            repo.path().join(".indentured-server/config.toml"),
            "[connection]\nendpoint = \"http://127.0.0.1:9\"\n",
        )
        .unwrap();
        let ready = fake_bin.path().join("ready");
        let pid_file = fake_bin.path().join("pid");
        let cleanup = fake_bin.path().join("cleanup");
        let script = fake_bin.path().join("jj");
        publish_executable(
            &script,
            format!(
                r#"#!/bin/sh
stage='{stage}'
block() {{ echo $$ > '{pid}'; : > '{ready}'; while :; do sleep 1; done; }}
last=''; for arg in "$@"; do last=$arg; done
case "$*" in
  *--version*) echo 'jj 99.0.0' ;;
  *' log '*) if [ "$stage" = pin ]; then block; else printf '%064d\n' 0; fi ;;
  *' file list '*)
    if [ "$stage" = list ]; then block
    elif [ "$stage" = workspace ]; then printf '%s\n' '{{"path":"link","type":"symlink","executable":false,"conflict":false}}'
    else printf '%s\n' '{{"path":"file","type":"file","executable":false,"conflict":false}}'; fi ;;
  *' file show '*) if [ "$stage" = show ]; then block; else printf content; fi ;;
  *'workspace add'*) mkdir -p "$last"; ln -s target "$last/link"; block ;;
  *'workspace forget'*) echo "$*" >> '{cleanup}' ;;
  *) exit 2 ;;
esac
"#,
                pid = pid_file.display(),
                ready = ready.display(),
                cleanup = cleanup.display()
            )
            .as_bytes(),
        );
        let path = format!(
            "{}:{}",
            fake_bin.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_indentured"))
            .current_dir(repo.path())
            .env("PATH", path)
            .env("XDG_STATE_HOME", state.path())
            .arg("run")
            .arg("build")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "jj {stage} phase did not start");
            thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(child.id() as i32, libc::SIGINT);
        }
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "client did not exit from jj {stage}"
            );
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(130), "stage {stage}");
        let run = fs::read_dir(state.path().join("indentured/runs"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let provenance = fs::read_to_string(run.join("provenance.json")).unwrap();
        assert!(provenance.contains("\"status\": \"interrupted\""));
        assert!(fs::read_dir(run).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            !name.to_string_lossy().starts_with(".source-")
                && !name.to_string_lossy().starts_with(".jj-workspace-")
        }));
        let pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "jj {stage} survived");
        if stage == "workspace" {
            assert!(cleanup.exists(), "workspace forget was not attempted");
        }
    }
}
