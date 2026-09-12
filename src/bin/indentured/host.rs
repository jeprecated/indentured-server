use super::*;
use indentured_server::host_observation::{
    valid_observation_id, ObservationResponse, Request as HostRequest, Target,
};

#[derive(Clone, Debug, Parser)]
pub(super) struct HostArgs {
    #[arg(
        long,
        global = true,
        help = "Absolute base directory for private observation evidence"
    )]
    result_root: Option<PathBuf>,
    #[command(subcommand)]
    command: HostCommand,
}
#[derive(Clone, Debug, Subcommand)]
enum HostCommand {
    /// List graphical applications, windows, and displays on the host.
    List,
    /// Capture images and return validated absolute local PNG paths.
    Capture {
        #[command(subcommand)]
        target: HostTarget,
    },
}
#[derive(Clone, Debug, Subcommand)]
enum HostTarget {
    /// Capture every logical display (one local PNG per display).
    Desktop,
    /// Capture the eligible windows of an application from a fresh host list.
    Application {
        /// Application PID from inventory.applications[].pid in a fresh host list.
        pid: u32,
    },
    /// Capture an exact window using its owner PID and window ID from a fresh host list.
    Window {
        /// Owner PID from inventory.windows[].pid in a fresh host list.
        pid: u32,
        /// Window ID from inventory.windows[].window_id in the same fresh host list.
        window_id: u32,
    },
}

pub(super) async fn command(
    args: HostArgs,
    endpoint_arg: Option<String>,
    token_arg: Option<PathBuf>,
) -> ExitCode {
    // Deliberately no working-directory lookup, repository discovery, client
    // config loading, source collection, or managed-session provenance.
    if !resolve_connection_enabled(None) {
        eprintln!("{OUTPUT_PREFIX} disabled (INDENTURED_SERVER_ENABLED)");
        return ExitCode::from(CONNECTION_FALLBACK_EXIT_CODE);
    }
    let result = async {
        let endpoint = endpoint_arg
            .filter(|value| !value.trim().is_empty())
            .or_else(|| env::var(ENDPOINT_ENV).ok().filter(|value| !value.trim().is_empty()))
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidInput,
                "host endpoint must be provided via --endpoint or INDENTURED_SERVER_ENDPOINT; host commands ignore project configuration",
            ))?;
        let endpoint = parse_endpoint(&endpoint)?;
        let token = resolve_token(token_arg.clone(), None)?;
        let base = resolve_result_root(args.result_root.as_deref())?;
        if let Some(credential) = selected_token_path(token_arg, None) {
            reject_credential_result_overlap(&credential, &base)?;
        }
        fs::create_dir_all(&base)?;
        let directory = fs::canonicalize(base)?.join(uuid::Uuid::new_v4().to_string());
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        eprintln!("{OUTPUT_PREFIX} results: {}", directory.display());
        write_new_private(&directory.join("result.json"), b"{\"status\":\"in_progress\"}\n")?;
        let request = match args.command {
            HostCommand::List => HostRequest::List {},
            HostCommand::Capture { target } => HostRequest::Capture { target: match target {
                HostTarget::Desktop => Target::Desktop {},
                HostTarget::Application { pid } => Target::Application { pid },
                HostTarget::Window { pid, window_id } => Target::Window { pid, window_id },
            } },
        };
        let work = tokio::time::timeout(Duration::from_secs(90), observe(&endpoint, token.as_deref(), &directory, &request));
        let result = tokio::select! {
            result = work => result.unwrap_or_else(|_| Err(io::Error::other("host observation/download timed out after 90 seconds"))),
            _ = tokio::signal::ctrl_c() => Err(io::Error::other("host observation interrupted")),
        };
        let summary = match &result {
            Ok(_) => serde_json::json!({"status":"succeeded"}),
            Err(error) => serde_json::json!({"status":"failed", "error":error.to_string()}),
        };
        // Private directory; atomic replacement preserves evidence on failure.
        write_new_private(&directory.join(".result.json.tmp"), &serde_json::to_vec_pretty(&summary)?)?;
        fs::rename(directory.join(".result.json.tmp"), directory.join("result.json"))?;
        match result {
            Ok(output) => { println!("{}", serde_json::to_string(&output)?); Ok(()) },
            Err(error) => Err(error),
        }
    }.await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host observation failed: {error}");
            ExitCode::from(1)
        }
    }
}

async fn observe(
    endpoint: &Endpoint,
    token: Option<&str>,
    directory: &Path,
    request: &HostRequest,
) -> io::Result<serde_json::Value> {
    let bytes = serde_json::to_vec(request)?;
    indentured_server::host_observation::parse_request(&bytes).map_err(io::Error::other)?;
    let builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            builder.build(),
            format!("{base}/v1/host/observations"),
            true,
        ),
        Endpoint::Unix { path } => (
            builder.unix_socket(path.clone()).build(),
            "http://localhost/v1/host/observations".into(),
            false,
        ),
    };
    let mut builder = client
        .map_err(io::Error::other)?
        .post(url)
        .header("content-type", "application/json")
        .body(bytes);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }
    let mut response = builder.send().await.map_err(io::Error::other)?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err(io::Error::other("host response exceeds 2 MiB"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if status == reqwest::StatusCode::NOT_FOUND && bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(io::Error::other(
            "server returned 404 Not Found: host observation endpoint is unavailable; verify the endpoint URL and that the daemon version supports host observation",
        ));
    }
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "server returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        )));
    }
    let response: ObservationResponse = serde_json::from_slice(&bytes)?;
    let manifest = &response.manifest;
    if !valid_observation_id(&manifest.observation_id)
        || manifest.schema_version != "1"
        || !["succeeded", "failed"].contains(&manifest.status.as_str())
        || manifest.images.len() > 32
        || (manifest.status == "succeeded" && !manifest.errors.is_empty())
        || (manifest.status == "failed"
            && (manifest.errors.is_empty() || !manifest.images.is_empty()))
    {
        return Err(io::Error::other("invalid host observation manifest"));
    }
    for (index, image) in manifest.images.iter().enumerate() {
        if image.path
            != format!(
                "observations/{}/image-{index:04}.png",
                manifest.observation_id
            )
        {
            return Err(io::Error::other("invalid host image path"));
        }
    }
    write_new_private(
        &directory.join("remote-manifest.json"),
        &serde_json::to_vec_pretty(manifest)?,
    )?;
    if let Some(archive) = &response.artifacts {
        // Existing downloader accepts arbitrary URLs for other protocols. This
        // endpoint must only follow this invocation's exact same-origin path.
        if archive.path
            != format!(
                "/v1/host/observations/{}/artifacts.zip",
                manifest.observation_id
            )
        {
            return Err(io::Error::other("invalid host artifact path"));
        }
        download_and_extract_with_redirect_policy(
            archive,
            endpoint,
            token,
            directory,
            reqwest::redirect::Policy::none(),
        )
        .await?;
    }
    if let Some(restrictions) = &response.artifact_restrictions {
        eprintln!("{}", artifact_restrictions_notice(restrictions));
        if restrictions.omitted_count > 0 {
            return Err(io::Error::other(
                "host artifacts omitted by server restrictions",
            ));
        }
    }
    if manifest.status != "succeeded" {
        return Err(io::Error::other(manifest.errors.join("; ")));
    }
    if matches!(request, HostRequest::Capture { .. }) && manifest.images.is_empty() {
        return Err(io::Error::other("capture succeeded without images"));
    }
    let mut output = serde_json::to_value(manifest)?;
    let mut total = 0usize;
    for (index, image) in manifest.images.iter().enumerate() {
        let path = directory.join("artifacts").join(&image.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() > (63 * 1024 * 1024 - total) as u64 {
            return Err(io::Error::other("host image is not a bounded regular PNG"));
        }
        let bytes = fs::read(&path)?;
        total += bytes.len();
        if total > 63 * 1024 * 1024 {
            return Err(io::Error::other("host images exceed 63 MiB"));
        }
        indentured_server::host_observation::validate_png(&bytes).map_err(io::Error::other)?;
        let local_path = fs::canonicalize(path)?;
        if !local_path.starts_with(directory.join("artifacts")) {
            return Err(io::Error::other("host image escaped the result directory"));
        }
        output["images"][index]["local_path"] = serde_json::to_value(local_path)?;
    }
    // Do not announce success or paths until every download and PNG is validated.
    write_new_private(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&output)?,
    )?;
    Ok(output)
}
