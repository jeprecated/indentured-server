use super::{Backend, Capture, Inventory, Result};
use std::path::Path;
use std::time::Instant;

pub struct Native;

#[cfg(not(target_os = "macos"))]
impl Backend for Native {
    fn inventory(&self, _deadline: Instant) -> Result<Inventory> {
        Err("host observation requires macOS and a logged-in graphical user; this platform is unsupported".into())
    }
    fn capture(&self, _capture: &Capture, _path: &Path, _deadline: Instant) -> Result<()> {
        Err("host observation requires macOS".into())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn permissions() -> Result<()> {
    Err("Screen Recording permission is only available on macOS; run this command in the graphical user's session".into())
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const SCRIPT: &str = include_str!("enumerate.js");
    const PERMISSION_HELP: &str = "Grant Screen Recording (Screen & System Audio Recording on newer macOS) to this GUI helper/responsible executable in System Settings > Privacy & Security, then restart the LaunchAgent. Run `indentured-host permissions` once from the logged-in graphical session to request access. Do not run capture as root.";

    struct ChildGuard {
        child: std::process::Child,
        running: bool,
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if !self.running {
                return;
            }
            // Own process group only; never kill by executable or app name.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }

    fn run(mut command: Command, deadline: Instant) -> Result<Vec<u8>> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        let directory = super::super::private_temp()?;
        let out_path = directory.path().join("stdout");
        let err_path = directory.path().join("stderr");
        let stdout = File::create(&out_path).map_err(|e| e.to_string())?;
        let stderr = File::create(&err_path).map_err(|e| e.to_string())?;
        command
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .process_group(0);
        // Commands and argv are built here, never from caller text. No PATH lookup.
        let mut child = ChildGuard {
            child: command
                .spawn()
                .map_err(|e| format!("start native observation: {e}"))?,
            running: true,
        };
        let status = loop {
            if Instant::now() >= deadline
                || super::super::STOP.load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err("native observation timed out; check GUI session and Screen Recording permission".into());
            }
            for path in [&out_path, &err_path] {
                if fs::metadata(path).map_err(|e| e.to_string())?.len() > 2 * 1024 * 1024 {
                    return Err("native observation output exceeded 2 MiB".into());
                }
            }
            if let Some(status) = child.child.try_wait().map_err(|e| e.to_string())? {
                child.running = false;
                break status;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let mut stderr = String::new();
        File::open(err_path)
            .map_err(|e| e.to_string())?
            .take(4096)
            .read_to_string(&mut stderr)
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!(
                "native observation failed ({status}): {}; {PERMISSION_HELP}",
                stderr.trim()
            ));
        }
        let mut stdout = Vec::new();
        File::open(out_path)
            .map_err(|e| e.to_string())?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut stdout)
            .map_err(|e| e.to_string())?;
        if stdout.len() > 2 * 1024 * 1024 {
            return Err("native observation output exceeded 2 MiB".into());
        }
        Ok(stdout)
    }

    fn enumerate(mode: &str, deadline: Instant) -> Result<serde_json::Value> {
        let mut command = Command::new("/usr/bin/osascript");
        command.args([
            "-l",
            "JavaScript",
            "-e",
            SCRIPT,
            mode,
            &super::super::uid().to_string(),
        ]);
        let bytes = run(command, deadline)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid native inventory: {e}"))?;
        if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
            return Err(format!("{error}; {PERMISSION_HELP}"));
        }
        Ok(value)
    }

    impl Backend for Native {
        fn inventory(&self, deadline: Instant) -> Result<Inventory> {
            serde_json::from_value(enumerate("list", deadline)?)
                .map_err(|e| format!("invalid native inventory: {e}"))
        }
        fn capture(&self, capture: &Capture, path: &Path, deadline: Instant) -> Result<()> {
            let mut command = Command::new("/usr/sbin/screencapture");
            command.args(["-x", "-t", "png"]);
            match capture {
                Capture::Window { window_id, .. } => {
                    command.args(["-o", "-l", &window_id.to_string()]);
                }
                Capture::Display { index, .. } => {
                    command.args(["-D", &index.to_string()]);
                }
            }
            command.arg(path);
            run(command, deadline).map(|_| ())
        }
    }

    pub fn permissions() -> Result<()> {
        let result = enumerate("permissions", Instant::now() + Duration::from_secs(15))?;
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|e| e.to_string())?
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub use macos::permissions;
