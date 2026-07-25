use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use tempfile::TempDir;

fn start_capture_server(body: String) -> (String, Arc<Mutex<Vec<u8>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = listener.local_addr().expect("server addr");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read request line");
        assert!(
            request_line.starts_with("POST /v1/builds HTTP/1.1"),
            "unexpected request line: {request_line:?}"
        );

        let mut content_length = None;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read header line");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length =
                        Some(value.trim().parse::<usize>().expect("parse content length"));
                }
                if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
        }
        let mut request_body = Vec::new();
        if let Some(content_length) = content_length {
            request_body.resize(content_length, 0);
            reader
                .read_exact(&mut request_body)
                .expect("read request body");
        } else if chunked {
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let size =
                    usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
                if size == 0 {
                    let mut trailer = String::new();
                    reader.read_line(&mut trailer).unwrap();
                    break;
                }
                let start = request_body.len();
                request_body.resize(start + size, 0);
                reader.read_exact(&mut request_body[start..]).unwrap();
                let mut crlf = [0; 2];
                reader.read_exact(&mut crlf).unwrap();
            }
        }
        *captured_clone.lock().expect("capture lock") = request_body;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        stream.flush().expect("flush response");
    });

    (format!("http://{addr}"), captured, handle)
}

#[test]
fn indentured_without_source_patterns_sends_metadata_then_empty_source_zip() {
    let temp = TempDir::new().expect("temp dir");
    let response_body = concat!(
        "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"started\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, captured, handle) = start_capture_server(response_body);

    let state = TempDir::new().expect("state dir");
    let output = Command::new(env!("CARGO_BIN_EXE_indentured"))
        .current_dir(temp.path())
        .env_remove("INDENTURED_SERVER_ENABLED")
        .env("XDG_STATE_HOME", state.path())
        .env("INDENTURED_SERVER_ENDPOINT", &endpoint)
        .arg("run")
        .arg("make")
        .output()
        .expect("run indentured");
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));

    let captured = captured.lock().expect("capture lock");
    let request_body = String::from_utf8_lossy(&captured);
    let metadata_part = find_bytes(&captured, b"name=\"metadata\"").expect("metadata part");
    let source_part = find_bytes(&captured, b"name=\"source\"").expect("source part");
    assert!(
        metadata_part < source_part,
        "metadata must precede source: {request_body}"
    );
    for expected in [
        "\"schema_version\":\"1\"",
        "\"task\":\"make\"",
        "\"source\":{\"format\":\"zip\"}",
    ] {
        assert!(
            request_body.contains(expected),
            "missing {expected}: {request_body}"
        );
    }
    for forbidden in [
        "\"command\"",
        "\"args\"",
        "\"cwd\"",
        "\"env\"",
        "\"timeout_sec\"",
        "\"artifacts\"",
        "\"workspace\"",
    ] {
        assert!(
            !request_body.contains(forbidden),
            "found {forbidden}: {request_body}"
        );
    }
    let empty_zip_start = source_part
        + find_bytes(&captured[source_part..], b"PK\x05\x06").expect("empty ZIP payload");
    let empty_zip_end = empty_zip_start + 22;
    let zip = zip::ZipArchive::new(Cursor::new(&captured[empty_zip_start..empty_zip_end]))
        .expect("valid source ZIP");
    assert_eq!(zip.len(), 0);
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
