use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use indentured_server::artifacts::{prepare_artifact_storage_root, spawn_gc_task};
use indentured_server::config::Config;
use indentured_server::http;
use indentured_server::logging::LoggingSettings;

#[derive(Debug, Parser)]
#[command(author, version, about = "Host-side build daemon")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, hide = true)]
    service_supervisor: bool,
    #[arg(long, hide = true, requires = "service_supervisor")]
    control_fd: Option<i32>,
    #[arg(long, hide = true, requires = "service_supervisor")]
    status_fd: Option<i32>,
    #[arg(long, hide = true, requires = "service_supervisor")]
    readiness_fd: Option<i32>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    if args.service_supervisor {
        let result = indentured_server::services::run_supervisor(
            args.control_fd.expect("required supervisor control FD"),
            args.status_fd.expect("required supervisor status FD"),
            args.readiness_fd.expect("required supervisor readiness FD"),
        );
        if let Err(err) = result {
            eprintln!("service supervisor failed: {err}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    let config = match Config::load_from_sources(args.config.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to load config: {err}");
            return ExitCode::from(1);
        }
    };

    let logging_settings = match LoggingSettings::from_config(&config.logging) {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("failed to validate logging config: {err}");
            return ExitCode::from(1);
        }
    };

    let _guards = match logging_settings.init_tracing() {
        Ok(guards) => guards,
        Err(err) => {
            eprintln!("failed to init logging: {err}");
            return ExitCode::from(1);
        }
    };

    tracing::info!("indentured-server starting");

    if let Err(err) = prepare_artifact_storage_root(&config.artifacts.storage_root) {
        eprintln!("failed to protect artifact storage root: {err}");
        return ExitCode::from(1);
    }
    if let Err(err) = spawn_gc_task(config.clone()) {
        eprintln!("failed to start artifact gc: {err}");
        return ExitCode::from(1);
    }
    let config = Arc::new(config);

    if let Err(err) = http::run(config).await {
        eprintln!("indentured-server failed: {err}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
