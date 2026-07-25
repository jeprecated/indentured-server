# indentured-server

`indentured-server` is a small synchronous build service and client for running server-owned named tasks against an uploaded source tree. The daemon streams stdout and stderr as NDJSON and can return only the artifacts allowed by the selected task.

The authority boundary is deliberately narrow: callers select a task, not a command. Initial scope explicitly excludes remote-shell transport, source publication, caller/request-controlled shell execution, asynchronous jobs or queues, signing credentials, physical-device access, durable schedulers, and third-party orchestration integrations.

## Security model

A request may contain only:

- the required request protocol version;
- an optional bounded request identifier;
- a bounded server task identifier; and
- closed source metadata describing the required ZIP payload.

The selected server task owns the absolute executable, fixed arguments, relative working directory, fixed environment, timeout, artifact allowlist, and fresh-workspace policy. Unknown fields—including every former command, argv, cwd, environment, timeout, artifact, and workspace field—are rejected. Missing, legacy, and unknown request versions are rejected before source bytes are accepted, a workspace is created, an archive is extracted, or a process is spawned.

Every accepted run receives a new unpredictable workspace under `build.workspace_root`. The workspace is removed after execution and artifact collection. Clients cannot identify, reuse, reset, or delete server workspaces. Protocol v3 command requests are not parsed, even as a compatibility mode.

Uploaded build systems still execute code with the daemon's configured task identity. Named tasks remove caller control over process configuration; they are not a sandbox. Use a dedicated secretless non-admin account, container, or VM when uploaded source is not fully trusted. The root/service daemon loads credentials and owns artifacts/control paths before task processes drop to that separate identity; task environments are cleared and never receive daemon credentials.

Bearer values are loaded once at startup from protected runtime files, reduced to SHA-256 digests, and compared as fixed-size values without an early successful return. Each 1–4096-byte file contains exactly one RFC 6750 `b64token` line and at most one final LF; the daemon and client enforce the same parser. The token file and its direct runtime directory must be owned by the effective daemon UID; the file is mode `0600` or stricter, while the real, non-symlink parent is not group/other writable or owned by the task identity. Token values, headers, and digests are never logged or included in errors. Restart the daemon to rotate credentials.

The global active-build limit defaults to one. Admission uses an immediate non-waiting check after authentication and metadata/task validation but before accepting source bytes. Excess requests receive `503` with `{"error":"busy"}` and `Retry-After: 0`; this is throughput control, not a queue.

## Components

- `indentured-server`: host daemon.
- `indentured`: client that pins and packages the current Jujutsu tree (or reviewed filesystem patterns outside Jujutsu), submits one named task, streams output, and stores non-destructive run evidence.

The service supports HTTP/HTTPS and explicitly enabled Unix-domain sockets. UDS is disabled by default and bypasses bearer authentication: its parent-directory ownership and socket mode are its entire authority boundary. Every enabled UDS deployment requires a root daemon, a configured non-root task identity distinct from the daemon/socket owner, no socket group, and mode `0600` or stricter. Startup fails closed otherwise. A hardened macOS deployment must not expose that socket to its build identity. Built-in rustls TLS is optional server-side transport encryption for generic direct deployments; it does not authenticate clients or accept a client-CA setting. Bearer authentication remains required wherever application authority is needed.

## Build and test

### Nix packages and apps

The flake exposes native packages and apps for `x86_64-linux`, `aarch64-linux`, and `aarch64-darwin`:

```sh
nix build --no-link .#indentured-server
nix build --no-link .#indentured
nix run .#indentured-server -- --help
nix run .#indentured -- --help
```

`nix build .` and `nix run .` default to the `indentured-server` daemon. The server and client packages are separate outputs of one Cargo compilation; each named package contains only its matching executable. `Cargo.lock` is the authoritative Rust dependency lock.

Run `nix flake check --print-build-logs` natively on each supported system. A Linux check builds only that native Linux system's outputs; evaluating the `aarch64-darwin` attributes from Linux does not attest Darwin SDK linkage or runtime behavior. On Apple-silicon Darwin, `scripts/check-darwin.sh` performs the native package/layout checks and package builds. The Darwin package and Devenv shell use the Nix-provided clang wrapper, Apple SDK/frameworks, and Rust toolchain without invoking ambient/host `xcrun` or `xcodebuild` and without depending on `/Applications/Xcode`; Nix-provided SDK tooling is allowed. The full `cargo:test` task remains a Linux validation obligation because its protected-runtime credential test currently uses Linux `/run/user/<uid>`; Darwin flake validation intentionally claims package/compile coverage only. The native hardened macOS deployment behavioral gate below also remains required.

### Devenv contributor tasks

Enter the pinned contributor environment or run its named tasks directly:

```sh
devenv shell
devenv tasks list
devenv tasks run cargo:fmt
devenv tasks run cargo:clippy
devenv tasks run cargo:test
devenv tasks run cargo:release-build
devenv tasks run integration:packaged-local
devenv tasks run nix:flake-check
```

The same deterministic Cargo obligations remain available without Devenv:

```sh
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
cargo test --locked --offline --all-targets --all-features
cargo build --locked --offline --release --all-features
```

The offline Cargo commands require the locked crates to be present in the local Cargo cache. Nix package builds vendor dependencies from `Cargo.lock` and are the clean-checkout reproducibility path.

The Cargo release build creates:

- `target/release/indentured-server`
- `target/release/indentured`

## Server configuration

The daemon loads `/etc/indentured-server/config.toml` by default. Override it with `--config` or `INDENTURED_SERVER_CONFIG`. The current daemon configuration schema is `6`; request protocol versions are separate. Schema 5 configurations fail closed and must explicitly migrate the version; existing absolute-executable/fixed-argument task bodies remain supported.

```toml
schema_version = "6"

[service]
max_concurrent_builds = 1

[service.socket]
enabled = false
path = "/run/indentured-server/control/server.sock"
mode = "0600"

[service.http]
enabled = true
listen_addr = "127.0.0.1:8080"

[service.http.auth]
type = "bearer"
required = true
token_files = ["/run/credentials/indentured-server.service/bearer-token"]

[service.http.tls]
enabled = false
# cert_path = "/etc/indentured-server/tls/server.crt"
# key_path = "/etc/indentured-server/tls/server.key"

[build]
workspace_root = "/var/lib/indentured-server/workspaces"
max_timeout_sec = 1800
max_output_bytes = 67108864
run_as_user = "indentured-build"
run_as_group = "indentured-build"

[tasks.build]
script = '''
printf 'starting build\n'
make -j4 all
'''
cwd = "."
timeout_sec = 600
workspace = "fresh"

[tasks.build.environment]
PATH = "/usr/bin:/bin"
LANG = "C.UTF-8"

[tasks.build.artifacts]
include = ["out/**"]
exclude = ["out/**/*.tmp"]

[sources]
max_transfer_bytes = 134217728
max_uncompressed_bytes = 1342177280
max_files = 50000
max_depth = 64
upload_timeout_sec = 120

[artifacts]
storage_root = "/var/lib/indentured-server/artifacts"
max_transfer_bytes = 536870912
max_uncompressed_bytes = 2147483648
max_files = 10000
max_depth = 64
# restricted_patterns = ["*.key", "**/*.key"]

[logging]
level = "info"
directory = "/var/log/indentured-server"
max_bytes = 104857600
max_files = 5
console = false
```

Task validation occurs at daemon startup:

- task names must match `[A-Za-z0-9_-]+` and are bounded to 64 bytes;
- each task defines exactly one of a server-owned `script` or an absolute `executable`; executable mode retains optional fixed `args` compatibility;
- scripts contain 1–65,536 UTF-8 bytes, include non-whitespace text, contain no NUL, and cannot be combined with `executable` or nonempty `args`;
- scripts run exactly as `/bin/sh -eu -c SCRIPT`; `/bin/sh` and configured executables must be accessible executable regular files;
- script tasks require an explicit nonempty `PATH` whose colon-separated components are all absolute and nonempty;
- `cwd` and artifact patterns must be relative and contain no parent traversal;
- task timeouts must be nonzero and no larger than `build.max_timeout_sec`;
- arguments and environment entries must be NUL-free;
- the only workspace policy is the required value `fresh`.

The task environment is fixed by configuration. The daemon clears its inherited environment, applies task values, and supplies `HOME`, `USER`, and `LOGNAME` from the configured execution identity only when the task does not set them. Configure `PATH` only with root-controlled or immutable Nix-store directories; validation proves only that components are absolute, not their ownership or immutability.

Absolute executable and fixed-argument compatibility mode remains available:

```toml
[tasks.compat_build]
executable = "/usr/bin/make"
args = ["-j4", "all"]
cwd = "."
timeout_sec = 600
workspace = "fresh"

[tasks.compat_build.environment]
PATH = "/usr/bin:/bin"

[tasks.compat_build.artifacts]
include = ["out/**"]
exclude = []
```

A bare `devenv shell` line does **not** affect later script lines: it runs as a child process and cannot modify the outer `/bin/sh` environment (and may behave poorly when noninteractive). Keep dependent commands inside a server-owned wrapper, with `--` separating Devenv options:

```toml
schema_version = "6"

[tasks.ci]
script = '''
exec devenv shell -- /bin/sh -eu -c '
  cargo build --locked --release
  cargo test --locked
'
'''
cwd = "."
timeout_sec = 1800
workspace = "fresh"

[tasks.ci.environment]
PATH = "/run/current-system/sw/bin:/usr/bin:/bin"

[tasks.ci.artifacts]
include = ["target/release/**"]
exclude = []
```

The configured `PATH` controls initial unpinned `devenv` resolution; Devenv then intentionally establishes the inner command environment. Configured script bodies and excerpts are redacted from daemon configuration diagnostics. Normal task stdout/stderr can still contain text deliberately emitted by the server-owned script.

## Client configuration and use

`indentured` searches upward for `.indentured-server/config.toml`. Copy [`config/client.toml.example`](config/client.toml.example) to that path to start from the strict client schema. The live `.indentured-server/config.toml` is ignored local state: review its endpoint and credential-file path for the current environment before enabling remote submission. The optional source patterns apply only when no `.jj` repository marker is found.

Run one configured task:

```sh
indentured run build
indentured --endpoint unix:///run/indentured-server/control/server.sock run --request-id agent-42 build
indentured run --result-root /var/tmp/my-run-evidence build
# Outside a Jujutsu repository only:
indentured run --source 'src/**' --source 'Cargo.*' --source-exclude 'target/**' build
```

Inside a Jujutsu repository, the first stateful operation snapshots and pins `@` to one full commit ID. The client uses documented `jj file list` JSONL metadata and `jj file show` bytes; a temporary full workspace is used only to read symlink targets and is forgotten before upload. There is no `jj archive`, fetch, push, remote, or source-publication operation. Deleted paths and ignored/untracked caches or credentials are absent from the pinned tree; new tracked paths are present. Executable bits and safe relative symlinks are preserved. Conflicts, submodules, unsafe paths/links, and incompatible Jujutsu installations fail closed. Every tracked path is intentional submitted source, so secrets must remain untracked and ignored.

The pinned commit is an exact immutable tree. Jujutsu does not document the initial live-filesystem snapshot as atomic against a concurrent writer; provenance therefore records `initial_snapshot_atomicity = "not-guaranteed"`. Changes after the full ID is returned cannot change that run's export.

Outside Jujutsu repositories, explicit include/exclude selection uses no-follow traversal and before/after manifest and file-identity checks. This detects common concurrent changes but is not an atomic filesystem snapshot.

The CLI has no command arguments, remote cwd/environment/timeout/artifact flags, or workspace lifecycle subcommands. Artifact selection remains server-owned.

Connection precedence is CLI, `INDENTURED_SERVER_ENDPOINT`/`INDENTURED_SERVER_TOKEN_FILE`, then client config. Only credential **paths** are accepted (`--token-file`, the environment variable, or `connection.token_file`); raw-token CLI/environment/TOML surfaces are rejected. A configured credential must remain outside both submitted source and the entire configured result-root base, including canonical symlink aliases. `connection.enabled = false` or `INDENTURED_SERVER_ENABLED=false` returns exit code 222 without running a local command. When an unreachable endpoint has `local_fallback = true`, the client also returns 222; no wrapper shim is shipped.

Every invocation creates a unique mode-0700 result directory under `$XDG_STATE_HOME/indentured/runs/<run-id>/` or `$HOME/.local/state/indentured/runs/<run-id>/`; an explicit `--result-root` must be absolute and must not overlap the submitted source in either direction. The resolved path is printed immediately. `stdout.log`, `stderr.log`, `source-manifest.json`, and atomically updated `provenance.json` are retained even on failure or interruption. Artifacts are collected and downloaded after successful, ordinary nonzero, and timed-out remote tasks into a private staging tree and atomically published only as `<run>/artifacts/`; they never overwrite source or run evidence. Failure keeps the task's exit code, while timeout keeps `timed_out: true` and the client exits 124. SIGINT is controlled from source preparation onward: active Jujutsu process groups are killed/reaped, temporary workspace cleanup is attempted for a bounded interval, or the live request stream is dropped so the server cancels the remote process group. Evidence records `interrupted` and the client exits 130.

## Request protocol v1

`POST /v1/builds` requires multipart fields in this exact order:

1. `metadata` (`application/json`, maximum 64 KiB)
2. `source` (`application/zip`, bounded by `sources.max_transfer_bytes`)

Metadata example:

```json
{
  "schema_version": "1",
  "request_id": "agent-42",
  "task": "build",
  "source": {"format": "zip"}
}
```

`request_id` is optional and bounded to 128 bytes. Unknown top-level or source-metadata fields fail closed. Source-first, duplicate, missing, and unknown multipart fields are rejected.

Responses use `application/x-ndjson`:

```json
{"type":"build","id":"bld_123","status":"started"}
{"type":"stdout","data":"compiling...\n"}
{"type":"stderr","data":"warning...\n"}
{"type":"exit","code":0,"timed_out":false,"artifacts":{"path":"/v1/builds/bld_123/artifacts.zip","size":1234}}
```

Artifacts are available at `GET /v1/builds/{build_id}/artifacts.zip`. There are no client workspace endpoints in protocol v1.

Disconnecting the response stream cancels the running process group. Timeout, disconnect, or combined stdout/stderr exceeding `build.max_output_bytes` sends SIGTERM to the configured process group, waits a bounded five-second grace, then sends SIGKILL if any group member remains. A configured timeout returns exit code 124 with `timed_out: true`; output exhaustion returns a stable `output_limit` error. Process groups are cleanup, not a sandbox: uploaded code may attempt `setsid` or exploit the host.

Source ZIPs are bounded during upload and extraction by a server-owned upload deadline, compressed bytes, declared/actual uncompressed bytes, file/symlink count, and path depth. The single `sources.upload_timeout_sec` deadline covers source-field and multipart-trailer consumption; timeout returns `408` with `source_upload_timeout`, removes the partial file, and releases admission. Traversal, non-ASCII/normalization ambiguity, duplicates, case collisions, file/directory collisions, unsafe symlinks, and special files are rejected before extraction. Safe relative symlinks are created only after complete archive preflight and may not escape the fresh workspace. Artifacts use the server task allowlist and global restrictions, reject symlinks and every explicit Unix special-file mode, and enforce transfer, uncompressed, file-count, and depth limits before or during archive creation. Client preflight accepts only explicit Unix regular-file/directory kinds; missing or zero mode-kind fields remain compatible with portable non-Unix ZIP producers and are interpreted from directory spelling.

## macOS launchd and Tailscale deployment

[`docs/macos-launchd-tailscale-deployment.md`](docs/macos-launchd-tailscale-deployment.md) defines the portable macOS/launchd/Tailscale contract for deployment automation. A hardened deployment runs a root daemon with a dedicated non-admin task identity, protected bearer token files, fresh workspaces, one active run with immediate busy rejection, synchronous disconnect/SIGINT cancellation, and private retained client evidence.

The service exposes only a loopback HTTP origin behind Tailscale Serve. Serve terminates external TLS and proxies plaintext HTTP to `127.0.0.1:<port>`; application bearer authentication remains independently required. Built-in rustls HTTPS remains supported for generic direct deployments as server-side transport encryption only; it neither verifies client certificates nor replaces bearer authority, and it is not this Serve edge. The Unix socket is disabled in this topology.

This repository owns generic packages/apps, behavior, documentation, and a parameterized launchd example. Deployment automation/operator policy owns concrete users/groups, the authoritative launchd module and activation, trusted server-configured script or executable/fixed-argv task definitions, secrets/rotation, retention values, Tailscale reconciliation, and the native behavioral acceptance gate. The local packaged harness is:

```sh
devenv tasks run integration:packaged-local
```

It executes the exact Nix package binaries through local package/upload/named-task/stream/exit/artifact behavior without a forge, remote shell, source publication, Xcode, or remote Mac.

## systemd

Install `systemd/indentured-server.service`, the daemon binary, and the server configuration using paths appropriate for the host. The checked-in unit expects `/usr/local/bin/indentured-server` and `/etc/indentured-server/config.toml`, provisions the bearer with `LoadCredential=`, uses daemon-only runtime/state/log directories, and sets `UMask=0077`. The daemon intentionally starts as root so it can own protected state and then drop each task to `build.run_as_user`; do not place bearer values in `Environment=`.

Linux tests and an Apple-target compile do not prove macOS privilege behavior. Before deployment, the operator must run the detailed guide's native checks for configured UID/GID and supplementary groups, credential/artifact/control unreadability, process-group cancellation, workspace cleanup, immediate busy behavior, edge topology, retention, and rotation. That native macOS deployment gate is an external prerequisite.

## License

MIT. See [LICENSE](LICENSE).
