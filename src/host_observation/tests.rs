use super::*;
use std::cell::Cell;
use std::os::unix::fs::symlink;

fn png() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    // A deterministic 1x1 grayscale PNG (zlib stream containing filter+pixel).
    for (kind, payload) in [
        (&b"IHDR"[..], &b"\0\0\0\x01\0\0\0\x01\x08\0\0\0\0"[..]),
        (
            &b"IDAT"[..],
            &b"\x78\x01\x01\x02\0\xfd\xff\0\0\0\x02\0\x01"[..],
        ),
        (&b"IEND"[..], &b""[..]),
    ] {
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(payload);
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(payload);
        bytes.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    }
    bytes
}

fn bounds() -> Bounds {
    Bounds {
        x: 0.,
        y: 0.,
        width: 100.,
        height: 100.,
    }
}
fn inventory() -> Inventory {
    Inventory {
        applications: vec![
            Application {
                pid: 123,
                name: "Terminal".into(),
                bundle_id: Some("example.Terminal".into()),
                hidden: false,
            },
            Application {
                pid: 124,
                name: "Windowless".into(),
                bundle_id: None,
                hidden: false,
            },
        ],
        windows: vec![
            Window {
                window_id: 456,
                pid: 123,
                title: "Zellij".into(),
                on_screen: true,
                layer: 0,
                bounds: bounds(),
                capturable: true,
            },
            Window {
                window_id: 457,
                pid: 123,
                title: "Second".into(),
                on_screen: true,
                layer: 0,
                bounds: bounds(),
                capturable: true,
            },
        ],
        displays: vec![
            Display {
                display_id: 99,
                bounds: bounds(),
            },
            Display {
                display_id: 98,
                bounds: bounds(),
            },
        ],
    }
}

struct Fake {
    calls: Cell<usize>,
    denied: bool,
    stale: bool,
    fail_second: bool,
    display_change_at: Option<usize>,
}
impl Fake {
    fn good() -> Self {
        Self {
            calls: Cell::new(0),
            denied: false,
            stale: false,
            fail_second: false,
            display_change_at: None,
        }
    }
}
impl Backend for Fake {
    fn inventory(&self, _deadline: Instant) -> Result<Inventory> {
        if self.denied {
            return Err("Screen Recording denied".into());
        }
        let mut value = inventory();
        if self.stale && self.calls.get() > 0 {
            value.windows[0].pid = 999;
        }
        if self
            .display_change_at
            .is_some_and(|n| self.calls.get() >= n)
        {
            value.displays[0].bounds.x = -1920.;
        }
        self.calls.set(self.calls.get() + 1);
        Ok(value)
    }
    fn capture(&self, _capture: &Capture, path: &Path, _deadline: Instant) -> Result<()> {
        if self.fail_second && self.calls.get() >= 3 {
            return Err("protected/closed window".into());
        }
        fs::write(path, png()).map_err(|e| e.to_string())
    }
}

#[test]
fn strict_envelopes_reject_authority_and_invalid_ids() {
    for input in [
        r#"{"schema_version":"1","action":"host-list","input":{}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"desktop"}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"application","pid":123}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"window","pid":123,"window_id":456}}"#,
    ] {
        assert!(parse_envelope(input.as_bytes()).is_ok(), "{input}");
    }
    for input in [
        r#"{"schema_version":"2","action":"host-list","input":{}}"#,
        r#"{"schema_version":"1","action":"shell","input":{}}"#,
        r#"{"schema_version":"1","action":"host-list","input":{"path":"/tmp"}}"#,
        r#"{"schema_version":"1","action":"host-list","input":{},"extra":1}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"desktop","pid":123}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"window","pid":0,"window_id":456}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"window","pid":123,"window_id":0}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"application","pid":4294967295}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"application","pid":-1}}"#,
        r#"{"schema_version":"1","action":"host-capture","input":{"target":"application","pid":123,"pid":124}}"#,
        r#"{"schema_version":"1","action":"host-list","input":[]}"#,
    ] {
        assert!(parse_envelope(input.as_bytes()).is_err(), "{input}");
    }
    assert!(parse_envelope(&vec![b' '; MAX_REQUEST + 1]).is_err());
}

#[test]
fn listing_retains_apps_without_windows_and_no_images() {
    let (manifest, images) =
        decode_archive(&build_observation(&Fake::good(), &Request::List {}).unwrap()).unwrap();
    assert_eq!(manifest.status, "succeeded");
    assert!(images.is_empty());
    assert_eq!(
        manifest.inventory.unwrap().applications[1].name,
        "Windowless"
    );
}

#[test]
fn captures_all_app_windows_and_all_desktop_displays() {
    for target in [Target::Application { pid: 123 }, Target::Desktop {}] {
        let (manifest, images) = decode_archive(
            &build_observation(&Fake::good(), &Request::Capture { target }).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.status, "succeeded");
        assert_eq!(images.len(), 2);
        assert_eq!(images[0], png());
        assert_eq!(manifest.images[1].path, "image-0001.png");
    }
}

#[test]
fn display_movement_before_or_after_either_capture_discards_all_images() {
    for changed_at in 1..=4 {
        let fake = Fake {
            display_change_at: Some(changed_at),
            ..Fake::good()
        };
        let (manifest, images) = decode_archive(
            &build_observation(
                &fake,
                &Request::Capture {
                    target: Target::Desktop {},
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.status, "failed", "changed at {changed_at}");
        assert!(manifest.errors[0].contains("display topology changed"));
        assert!(manifest.images.is_empty());
        assert!(images.is_empty());
    }
}

#[test]
fn display_topology_checks_all_ids_and_bounds_but_not_enumeration_order() {
    let mut expected = inventory();
    expected.displays.sort_by_key(|d| d.display_id);
    let mut reordered = expected.clone();
    reordered.displays.reverse();
    check_display_topology(&expected, reordered).unwrap();
    for mutation in 0..4 {
        let mut current = expected.clone();
        match mutation {
            0 => {
                current.displays.pop();
            }
            1 => current.displays.push(Display {
                display_id: 100,
                bounds: bounds(),
            }),
            2 => current.displays[0].display_id = 101,
            _ => current.displays[0].bounds.width = 200.,
        }
        assert!(check_display_topology(&expected, current).is_err());
    }
}

#[test]
fn display_capture_uses_explicit_rectangles_not_ordinals_or_pixel_sizes() {
    // Three equally-sized screens: PNG dimensions cannot establish identity.
    for (id, x, y) in [(303, 0., 0.), (101, -1920., 0.), (202, 0., -1080.)] {
        let capture = Capture::Display {
            display_id: id,
            bounds: Bounds {
                x,
                y,
                width: 1920.,
                height: 1080.,
            },
        };
        assert_eq!(
            native::capture_arguments(&capture).unwrap(),
            ["-x", "-t", "png", &format!("-R{x},{y},1920,1080")]
        );
    }
    for bad in [f64::NAN, f64::INFINITY, 0.5, i32::MAX as f64 + 1.] {
        let capture = Capture::Display {
            display_id: 99,
            bounds: Bounds { x: bad, ..bounds() },
        };
        assert!(native::capture_arguments(&capture).is_err());
    }
    for width in [0., -1.] {
        assert!(native::capture_arguments(&Capture::Display {
            display_id: 99,
            bounds: Bounds { width, ..bounds() },
        })
        .is_err());
    }
    assert_eq!(
        native::capture_arguments(&Capture::Window {
            pid: 123,
            window_id: 456
        })
        .unwrap(),
        ["-x", "-t", "png", "-o", "-l", "456"]
    );
}

#[test]
fn too_many_displays_or_windows_are_rejected_before_capture() {
    let mut value = inventory();
    value.displays = (1..=MAX_IMAGES + 1)
        .map(|id| Display {
            display_id: id as u32,
            bounds: bounds(),
        })
        .collect();
    assert!(select(&value, &Target::Desktop {})
        .unwrap_err()
        .contains("image limit"));
    value.windows = (1..=MAX_IMAGES + 1)
        .map(|id| Window {
            window_id: id as u32,
            ..value.windows[0].clone()
        })
        .collect();
    assert!(select(&value, &Target::Application { pid: 123 })
        .unwrap_err()
        .contains("image limit"));
}

#[test]
fn exact_window_selection_never_falls_back_to_desktop() {
    let value = inventory();
    assert!(select(
        &value,
        &Target::Window {
            pid: 999,
            window_id: 456
        }
    )
    .unwrap_err()
    .contains("owner changed"));
    assert!(select(
        &value,
        &Target::Window {
            pid: 123,
            window_id: 999
        }
    )
    .unwrap_err()
    .contains("stale"));
    assert!(select(&value, &Target::Application { pid: 124 })
        .unwrap_err()
        .contains("no capturable"));
    let mut hidden = value;
    hidden.windows[0].capturable = false;
    assert!(select(
        &hidden,
        &Target::Window {
            pid: 123,
            window_id: 456
        }
    )
    .unwrap_err()
    .contains("no desktop fallback"));
}

#[test]
fn denied_stale_and_partial_capture_return_errors_without_images() {
    for fake in [
        Fake {
            denied: true,
            ..Fake::good()
        },
        Fake {
            stale: true,
            ..Fake::good()
        },
        Fake {
            fail_second: true,
            ..Fake::good()
        },
    ] {
        let (manifest, images) = decode_archive(
            &build_observation(
                &fake,
                &Request::Capture {
                    target: Target::Application { pid: 123 },
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.status, "failed");
        assert!(!manifest.errors.is_empty());
        assert!(images.is_empty());
        assert!(manifest.images.is_empty());
    }
}

#[test]
fn png_framing_crc_and_nonempty_data_are_required() {
    let valid = png();
    validate_png(&valid).unwrap();
    for invalid in [
        vec![],
        b"not png".to_vec(),
        valid[..valid.len() - 1].to_vec(),
    ] {
        assert!(validate_png(&invalid).is_err());
    }
    let mut damaged = valid;
    damaged[30] ^= 1;
    assert!(validate_png(&damaged).is_err());
}

#[test]
fn publication_is_fresh_private_and_failure_has_no_stale_images() {
    let cwd = TempDir::new().unwrap();
    let cwd = cwd.path().canonicalize().unwrap();
    let response = build_observation(
        &Fake::good(),
        &Request::Capture {
            target: Target::Desktop {},
        },
    )
    .unwrap();
    let manifest = publish(&response, &cwd).unwrap();
    for image in &manifest.images {
        assert_eq!(fs::read(cwd.join(&image.path)).unwrap(), png());
        assert_eq!(
            fs::metadata(cwd.join(&image.path)).unwrap().mode() & 0o777,
            0o600
        );
    }
    assert!(
        publish(&response, &cwd).is_err(),
        "must not overwrite a previous observation"
    );
    let failed = publish(&error_archive("permission denied".into()).unwrap(), &cwd).unwrap();
    assert_ne!(failed.observation_id, manifest.observation_id);
    assert!(failed.images.is_empty());
    assert_eq!(
        fs::read_dir(
            cwd.join(".indentured-output/action")
                .join(failed.observation_id)
        )
        .unwrap()
        .count(),
        1
    );
}

#[test]
fn publication_rejects_symlinks_and_untrusted_archive_paths() {
    let cwd = TempDir::new().unwrap();
    let cwd = cwd.path().canonicalize().unwrap();
    let outside = TempDir::new().unwrap();
    symlink(outside.path(), cwd.join(".indentured-output")).unwrap();
    assert!(publish(&error_archive("denied".into()).unwrap(), &cwd).is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    for path in ["../outside.png", "/tmp/outside.png", "subdir/image.png"] {
        let mut manifest = Manifest::new();
        manifest.images.push(Image {
            path: path.into(),
            pid: Some(123),
            window_id: Some(456),
            display_id: None,
        });
        let archive = encode_archive(&manifest, &[(path.into(), png())]).unwrap();
        assert!(decode_archive(&archive).is_err());
    }
}

#[test]
fn transport_authenticates_same_uid_and_survives_invalid_request() {
    for request in [
        b"not json".to_vec(),
        serde_json::to_vec(&Request::Capture {
            target: Target::Desktop {},
        })
        .unwrap(),
    ] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&client).unwrap(), uid());
        let thread = std::thread::spawn(move || {
            handle_connection(&mut server, &Fake::good(), uid()).unwrap()
        });
        write_frame(&mut client, &request).unwrap();
        let bytes = read_frame(&mut client, MAX_ARCHIVE).unwrap();
        let (manifest, images) = decode_archive(&bytes).unwrap();
        if request == b"not json" {
            assert_eq!(manifest.status, "failed");
        } else {
            assert_eq!(images.len(), 2);
        }
        thread.join().unwrap();
    }
}

#[test]
fn bounded_frames_and_socket_parent_policy() {
    assert!(read_frame(&mut Cursor::new(u32::MAX.to_be_bytes()), MAX_REQUEST).is_err());
    assert!(read_frame(&mut Cursor::new([0; 4]), MAX_REQUEST).is_err());
    let directory = private_temp().unwrap();
    let directory = directory.path().canonicalize().unwrap();
    let socket = directory.join("helper.sock");
    socket_access::server(&socket, uid(), None).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(socket_access::server(&socket, uid(), None).is_err());
    assert!(socket_access::server(Path::new("relative.sock"), uid(), None).is_err());
}

#[test]
fn kernel_peer_identity_rejects_wrong_uid_before_reading_requests() {
    let (client, mut server) = UnixStream::pair().unwrap();
    check_peer(&client, uid()).unwrap();
    assert!(check_peer(&client, uid().wrapping_add(1)).is_err());
    assert!(handle_connection(&mut server, &Fake::good(), uid().wrapping_add(1)).is_err());
}

#[test]
fn absolute_transfer_deadlines_cannot_be_extended_by_partial_reads() {
    let (client, _server) = UnixStream::pair().unwrap();
    let mut io = DeadlineIo {
        stream: &client,
        deadline: Instant::now() - Duration::from_secs(1),
    };
    assert_eq!(
        io.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(io.write(&[0]).unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn symlink_archive_entries_and_corrupt_pngs_are_rejected() {
    let mut manifest = Manifest::new();
    manifest.images.push(Image {
        path: "image-0000.png".into(),
        pid: Some(123),
        window_id: Some(456),
        display_id: None,
    });
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    zip.start_file("manifest.json", options).unwrap();
    zip.write_all(&serde_json::to_vec(&manifest).unwrap())
        .unwrap();
    zip.add_symlink("image-0000.png", "/tmp/outside", options)
        .unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    assert!(decode_archive(&bytes).is_err());
    assert!(decode_archive(
        &encode_archive(&manifest, &[("image-0000.png".into(), b"invalid".to_vec())]).unwrap()
    )
    .is_err());
}
