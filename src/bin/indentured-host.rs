use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Read-only macOS desktop observation for Indentured", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve bounded requests in the selected logged-in graphical session.
    Serve {
        #[arg(long)]
        socket: PathBuf,
        /// Exact authorized task UID (defaults to this helper's UID).
        #[arg(long)]
        allow_uid: Option<u32>,
        /// Observation group GID; requires a pre-provisioned mode-0710 directory.
        #[arg(long)]
        socket_group: Option<u32>,
        /// Request Screen Recording access through this LaunchAgent invocation.
        #[arg(long)]
        request_permission: bool,
    },
    /// Read one Indentured dispatcher envelope on stdin and publish local artifacts.
    Action {
        #[arg(long)]
        socket: PathBuf,
        /// Expected GUI helper UID (defaults to the task's UID).
        #[arg(long)]
        peer_uid: Option<u32>,
    },
    /// Explicitly request Screen Recording permission (run in the graphical session).
    Permissions,
}

fn main() {
    let result = match Cli::parse().command {
        Command::Serve {
            socket,
            allow_uid,
            socket_group,
            request_permission,
        } => indentured_server::host_observation::serve(
            &socket,
            allow_uid,
            socket_group,
            request_permission,
        ),
        Command::Action { socket, peer_uid } => {
            indentured_server::host_observation::action(&socket, peer_uid)
        }
        Command::Permissions => indentured_server::host_observation::permissions(),
    };
    if let Err(error) = result {
        eprintln!("host observation failed: {error}");
        std::process::exit(1);
    }
}
