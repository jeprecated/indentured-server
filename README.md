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

Bearer values are loaded once at startup from protected runtime files, reduced to SHA-256 digests, and compared as fixed-size values without an early successful return. Each 1–4096-byte file contains exactly one RFC 6750 `b64token` line and at most one final LF; the daemon and client enforce the same parser. The token file and its direct runtime directory must be owned by the effective daemon UID; every other real ancestor must be owned by that UID or root (root-owned sticky shared directories are allowed), the intentional macOS `/var/run` symlink is allowed, and macOS's exact root-owned, real `/private/var/run` authority may retain its native group-write bit when it is not other-writable and its owning group is absent from the task identity's primary and supplementary groups. The file is mode `0600` or stricter, while the real, non-symlink parent is not group/other writable or owned by the task identity. Token values, headers, and digests are never logged or included in errors. Restart the daemon to rotate credentials.

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

### Self-hosted Darwin gate

The `sd` tasks make native Darwin compilation a pre-publication gate instead of
a post-deployment discovery:

```sh
sd indentured-server check/local   # complete pinned local validation
sd indentured-server check/darwin  # upload the current Jujutsu candidate through Quartz repo_check
sd indentured-server check         # local first, then Darwin
```

`check/darwin` uses the configured `indentured` client and the currently deployed
server to run this repository's `indentured:check` task on Apple-silicon Darwin.
The candidate is the current explicit Jujutsu working-copy revision; the task
publishes nothing and changes no server configuration. Run it before publishing
or pinning a new server revision. The deployed server must already expose the
`repo_check` capability, and the client must have its endpoint and bearer file
configured outside the repository.

Project `.pi/final-review.json` runs `check/local` followed by `check/darwin` as
Final Review command gates after mutating agent turns. A failure is sent back to
the agent and review is deferred until the candidate changes and both checks
pass; automatic model review remains disabled by project configuration.

The Cargo release build creates:

- `target/release/indentured-server`
- `target/release/indentured`

## Server configuration

The daemon loads `/etc/indentured-server/config.toml` by default. Override it with `--config` or `INDENTURED_SERVER_CONFIG`. The current daemon configuration schema is `12`; request protocol versions are separate. Schema 11 configurations migrate by changing only their schema version; retained services remain disabled unless their table is added. Older and future schemas fail closed.

```toml
schema_version = "12"

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

[tasks.build.setup]
script = "printf 'preparing environment\\n'"
timeout_sec = 300

[tasks.build.environment]
PATH = "/usr/bin:/bin"
LANG = "C.UTF-8"

# One-shot output and the final explicit-stop snapshot for a managed session.
[tasks.build.artifacts]
include = ["out/**"]
exclude = ["out/**/*.tmp"]

# Optional managed-session policy. Setup and run initialize the session once.
[tasks.build.session]
idle_timeout_sec = 900
max_lifetime_sec = 14400

# Optional bounded source-update authority; omitted means updates return 404.
[tasks.build.session.source_updates]
timeout_sec = 120
max_transfer_bytes = 67108864
max_uncompressed_bytes = 268435456
max_files = 10000
max_depth = 64
include = ["src/**", "Cargo.*"]
exclude = ["src/private/**"]

# Optional operator-owned retained service. Services start after run, in sorted
# name order, and must close the injected readiness FD after the exact message.
[tasks.build.session.services.metro]
executable = "/usr/local/libexec/indentured/metro-wrapper"
args = ["--fixed-operator-mode"]
startup_timeout_sec = 60
shutdown_timeout_sec = 30
diagnostic_tail_bytes = 65536

# Must be safe to call repeatedly after partial failures.
[tasks.build.session.teardown]
script = "./scripts/session-teardown"
timeout_sec = 60

[tasks.build.session.actions.observe]
script = "./scripts/session-observe"
timeout_sec = 60

[tasks.build.session.actions.observe.artifacts]
include = ["screenshots/**"]
exclude = []

[tasks.build.session.actions.act]
script = "./scripts/session-act"
timeout_sec = 60

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
- each task defines exactly one server-owned run `script` or absolute run `executable`; executable mode retains optional fixed `args` compatibility;
- a task may also define one optional server-owned `setup` command using the same script/executable shape;
- an optional `session` requires nonzero `idle_timeout_sec` and `max_lifetime_sec`, with idle strictly less than lifetime, one idempotent teardown command, and exactly one action mode: a nonempty named `actions` map or one fixed `action_dispatcher`;
- optional `session.source_updates` requires positive timeout, transfer, uncompressed-size, file-count, and depth limits no greater than the global source/build limits, plus a nonempty operator-owned relative-glob `include`; `exclude` is optional, and `.indentured/**` and protected session metadata are always reserved;
- optional `session.services` names use the task-name rules; each service defines exactly one fixed script or absolute executable plus fixed args, positive startup/shutdown timeouts no greater than `build.max_timeout_sec`, and positive `diagnostic_tail_bytes` no greater than `build.max_output_bytes`;
- session action names, including dispatcher policy keys, use the task-name rules; action, teardown, and optional dispatcher override timeouts are nonzero and individually no greater than `build.max_timeout_sec`;
- actions and teardown inherit the task's fixed `cwd`, environment, and identity; named actions may each define an artifact allowlist, while dispatcher policy entries may override only its timeout and artifacts; the top-level task artifact policy controls the final explicit-stop snapshot;
- scripts contain 1–65,536 UTF-8 bytes, include non-whitespace text, contain no NUL, and cannot be combined with `executable` or nonempty `args`;
- scripts run exactly as `/bin/sh -eu -c SCRIPT`; `/bin/sh` and configured executables must be accessible executable regular files;
- script tasks require an explicit nonempty `PATH` whose colon-separated components are all absolute and nonempty;
- `cwd` and artifact patterns must be relative and contain no parent traversal;
- setup and run timeouts must be nonzero and their sum must not exceed `build.max_timeout_sec`;
- arguments and environment entries must be NUL-free;
- the only workspace policy is the required value `fresh`.

Setup and run execute sequentially in the same fresh workspace, with the same `cwd`, task identity, and configured environment. Filesystem changes survive into run, but shell exports do not because each phase is a separate process. Setup's process group is terminated before run starts, so background helpers cannot cross the phase boundary. A setup failure or timeout skips run; the setup result remains the task result, and configured artifacts are still collected. The output-byte limit and disconnect cancellation cover both phases together.

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
schema_version = "12"

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

A dispatcher is an alternative to the named `[tasks.<task>.session.actions.<name>]` tables above, not an additional fallback:

```toml
[tasks.build.session.action_dispatcher]
executable = "/run/current-system/sw/bin/devenv"
args = ["tasks", "run", "indentured:session:action"]
timeout_sec = 120
allow_unlisted = false

[tasks.build.session.action_dispatcher.artifacts]
include = [".indentured-output/action/**"]
exclude = []

# Policy-only entries inherit omitted values from the dispatcher.
[tasks.build.session.action_dispatcher.actions.observe]
timeout_sec = 30

# An explicitly empty artifacts table overrides the dispatcher to no artifacts.
[tasks.build.session.action_dispatcher.actions.mutate.artifacts]
```

The executable, arguments, working directory, environment, and identity remain fixed for every dispatched name. Policy entries may contain only `timeout_sec` and `artifacts`; omitted values inherit the dispatcher defaults. `allow_unlisted = false` rejects names absent from `actions` before spawning, while the default `true` preserves schema-9 arbitrary-name behavior. The repository dispatcher receives the existing versioned JSON envelope on stdin and must still validate names and input. Use named actions when the operator, rather than uploaded repository code, must own each action implementation.

## Client configuration and use

`indentured` searches upward for `.indentured-server/config.toml`. This repository tracks a no-secret [client configuration](.indentured-server/config.toml) with connection behavior and output defaults; it deliberately contains no endpoint or credential path. Supply those through `INDENTURED_SERVER_ENDPOINT` and `INDENTURED_SERVER_TOKEN_FILE` (or CLI flags). Other repositories can copy [`config/client.toml.example`](config/client.toml.example) as a starting point. The optional source patterns apply only when no `.jj` repository marker is found.

Run one configured task:

```sh
export INDENTURED_SERVER_ENDPOINT=https://builder.example.internal
export INDENTURED_SERVER_TOKEN_FILE=/absolute/operator-local/bearer-token
indentured run build
indentured --endpoint unix:///run/indentured-server/control/server.sock run --request-id agent-42 build
indentured run --result-root /var/tmp/my-run-evidence build
# Outside a Jujutsu repository only:
indentured run --source 'src/**' --source 'Cargo.*' --source-exclude 'target/**' build
```

Inside a Jujutsu repository, the first stateful operation snapshots and pins `@` to one full commit ID. The client uses documented `jj file list` JSONL metadata and `jj file show` bytes; a temporary full workspace is used only to read symlink targets and is forgotten before upload. There is no `jj archive`, fetch, push, remote, or source-publication operation. Deleted paths and ignored/untracked caches or credentials are absent from the pinned tree; new tracked paths are present. Executable bits and safe relative symlinks are preserved. Conflicts, submodules, unsafe paths/links, and incompatible Jujutsu installations fail closed. Every tracked path is intentional submitted source, so secrets must remain untracked and ignored.

The pinned commit is an exact immutable tree. Jujutsu does not document the initial live-filesystem snapshot as atomic against a concurrent writer; provenance therefore records `initial_snapshot_atomicity = "not-guaranteed"`. Changes after the full ID is returned cannot change that run's export.

Outside Jujutsu repositories, explicit include/exclude selection uses no-follow traversal and before/after manifest and file-identity checks. This detects common concurrent changes but is not an atomic filesystem snapshot.

Managed tasks use separate scriptable invocations:

```sh
session_id=$(indentured session start build)
revision=rev_0
revision=$(indentured session update "$session_id" --revision "$revision" \
  --file src/main.rs --file Cargo.toml --delete src/obsolete.rs)
printf '{"gesture":"tap","x":40,"y":80}\n' \
  | indentured session action "$session_id" interact --input -
indentured session action "$session_id" observe --input ./observe.json
indentured session stop "$session_id"
```

`session start` stdout contains exactly the opaque session ID line. `session update` requires an explicit session ID, opaque base `--revision`, and at least one explicit `--file` or `--delete`; success stdout similarly contains only the new revision line. It infers no diff and stores no hidden current session or revision. Inside Jujutsu, all declared files and deletions are proved against one pinned `@` commit. Outside Jujutsu, only the declared paths are checked and read with no-follow identity checks. Updates accept only regular non-executable files, produce deterministic 0644 ZIP entries, and never upload delete entries or undeclared files.

An omitted update `--request-id` is generated and persisted in the private result provenance before upload. After an ambiguous transport failure, inspect `provenance.json` and retry the same base revision, paths, contents, and request ID; the server accepts an exact byte-identical retry of its most recent successful update without reapplying it. A `revision_conflict` diagnostic reports `current_revision` when the server supplies it; use that revision with a new request ID after reconciling changes. A reused request ID with different metadata or archive bytes is rejected. Without the task's `session.source_updates` policy, the endpoint returns 404.

Initialization output and human diagnostics go to stderr while stdout/stderr evidence logs retain their original streams. `session action` accepts one JSON object from a file or `-` (stdin), wraps it in the fixed HTTP request, streams configured action output, and extracts advertised evidence into that invocation's result directory. `session stop` waits for teardown and downloads any configured final archive. Session/action identifiers are explicit; the client stores no hidden current-session state. There are no list, reset, arbitrary-command, workspace, or filesystem subcommands, and no remote cwd/environment/timeout/artifact flags. Artifact selection remains server-owned.

Reusable deployments may expose `repo_check` and `repo_session` host profiles. Repositories then own conventional Devenv tasks named `indentured:check`, `indentured:session:setup`, `indentured:session:start`, `indentured:session:action`, and `indentured:session:stop`; see the [macOS deployment guide](docs/macos-launchd-tailscale-deployment.md#reusable-repository-capability-profiles). These hooks are arbitrary uploaded code under the configured task identity, not a security boundary created by the profile name. Separate profiles are warranted only for different identity, permissions, limits, lifecycle, artifact policy, or operator-owned capability. This repository's `indentured:check` intentionally runs the Apple-silicon-Darwin-only `scripts/check-darwin.sh` because its target profile is Quartz, not every development host.

Every session invocation writes private atomic provenance from preparation onward. As soon as a start/action execution ID is observed it is persisted, including on malformed, truncated, output, artifact, and interruption paths. SIGINT is installed and initially polled by the controlling operation before client configuration and source preparation; the same receiver remains directly polled across preparation, final provenance, artifacts, and nonblocking machine-ID output. Once a start ID is observed, interruption or a later start failure drops the stream, attempts a bounded best-effort stop, and records the cleanup outcome—even before Ready. If interruption wins before any ID is observed, cleanup is recorded as unavailable and no DELETE is attempted; a server session that committed Ready without its ID reaching the client is reclaimed by the configured idle expiry. Signal completion is elected before any machine-ID bytes are written, so an interrupted blocked output emits no ID and exits 130. Actions retain the same interruption/stop guarantee through input, response streaming, and artifact download. Client configuration must be a regular file; FIFOs and devices are rejected. A server without `/v1/sessions` produces an explicit upgrade diagnostic; authentication, capacity, conflict, expiry, timeout, and teardown failures retain the existing exit conventions and actionable stderr diagnostics.

Connection precedence is CLI, `INDENTURED_SERVER_ENDPOINT`/`INDENTURED_SERVER_TOKEN_FILE`, then client config. Only credential **paths** are accepted (`--token-file`, the environment variable, or `connection.token_file`); raw-token CLI/environment/TOML surfaces are rejected. A configured credential must remain outside both submitted source and the entire configured result-root base, including canonical symlink aliases. `connection.enabled = false` or `INDENTURED_SERVER_ENABLED=false` returns exit code 222 without running a local command. When an unreachable endpoint has `local_fallback = true`, the client also returns 222; no wrapper shim is shipped.

Every invocation creates a unique mode-0700 result directory under `$XDG_STATE_HOME/indentured/runs/<run-id>/` or `$HOME/.local/state/indentured/runs/<run-id>/`; an explicit `--result-root` must be absolute and must not overlap submitted source when source is uploaded. The resolved path is printed immediately. `stdout.log`, `stderr.log`, optional `source-manifest.json`, and atomically updated `provenance.json` are retained even on failure or interruption. One-shot provenance schema 2 records setup/run durations, exit codes, timeout flags, and the failed phase; session provenance schema 1 records the operation, session/action identity, status, timings, exit/timeout or teardown outcome, artifact restrictions, cleanup outcome, and bounded errors. Artifacts are collected and downloaded after successful, ordinary nonzero, and timed-out remote tasks into a private staging tree and atomically published only as `<run>/artifacts/`; they never overwrite source or run evidence. Failure keeps the task's exit code, while timeout keeps `timed_out: true` and the client exits 124. SIGINT is controlled from source preparation onward: active Jujutsu process groups are killed/reaped, temporary workspace cleanup is attempted for a bounded interval, or the live request stream is dropped so the server cancels the remote process group. Evidence records `interrupted` and the client exits 130.

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
{"type":"build","id":"bld_123","status":"phase_started","phase":"setup"}
{"type":"build","id":"bld_123","status":"phase_finished","phase":"setup","duration_ms":207341,"exit_code":0,"timed_out":false}
{"type":"build","id":"bld_123","status":"phase_started","phase":"run"}
{"type":"stdout","data":"compiling...\n"}
{"type":"stderr","data":"warning...\n"}
{"type":"build","id":"bld_123","status":"phase_finished","phase":"run","duration_ms":812345,"exit_code":0,"timed_out":false}
{"type":"exit","code":0,"timed_out":false,"artifacts":{"path":"/v1/builds/bld_123/artifacts.zip","size":1234},"phases":[{"phase":"setup","duration_ms":207341,"exit_code":0,"timed_out":false},{"phase":"run","duration_ms":812345,"exit_code":0,"timed_out":false}]}
```

The CLI still performs one build request: setup and run share its workspace, admission permit, cancellation flag, and response stream. Phase metadata is additive to the existing `build`, `error`, and `exit` event types, so clients that ignore unknown fields retain wire compatibility. Tasks without `setup` emit only the run phase. The final `phases` list contains phases that produced process outcomes; process-level errors such as spawn, wait, or output-limit failures can set `failed_phase` without adding a matching completed phase result.

Artifacts are available at `GET /v1/builds/{build_id}/artifacts.zip`. There are no client workspace endpoints in protocol v1.

Disconnecting the response stream cancels the active phase's process group. Setup and run have separate deadlines; a setup failure or timeout prevents run. Timeout, disconnect, or combined stdout/stderr exceeding `build.max_output_bytes` sends SIGTERM to the configured process group, waits a bounded five-second grace, then sends SIGKILL if any group member remains. A configured timeout makes the client exit 124 with `timed_out: true` and records the failed phase; output exhaustion returns a stable `output_limit` error. Process groups are cleanup, not a sandbox: uploaded code may attempt `setsid` or exploit the host.

Source ZIPs are bounded during upload and extraction by a server-owned upload deadline, compressed bytes, declared/actual uncompressed bytes, file/symlink count, and path depth. The single `sources.upload_timeout_sec` deadline covers source-field and multipart-trailer consumption; timeout returns `408` with `source_upload_timeout`, removes the partial file, and releases admission. Traversal, non-ASCII/normalization ambiguity, duplicates, case collisions, file/directory collisions, unsafe symlinks, and special files are rejected before extraction. Safe relative symlinks are created only after complete archive preflight and may not escape the fresh workspace. Artifacts use the server task allowlist and global restrictions, reject symlinks and every explicit Unix special-file mode, and enforce transfer, uncompressed, file-count, and depth limits before or during archive creation. Collection walks only the minimal literal prefixes of configured include patterns, so retained dependency trees outside a requested action-artifact path do not consume its traversal limit. Client preflight accepts only explicit Unix regular-file/directory kinds; missing or zero mode-kind fields remain compatible with portable non-Unix ZIP producers and are interpreted from directory spelling.

## Managed-session protocol v1

Managed sessions use the existing bearer authentication unchanged. They add no token ownership or separate authorization model. The managed-session routes are available only when the daemon runs as root and `build.run_as_user` resolves to a distinct non-root task UID; this is required so `.sessions` remains root-owned and inaccessible to task code while the session workspace is task-owned. Otherwise session start/stop returns `503 managed_sessions_unavailable` without reading an upload or reconciling `.sessions`; ordinary one-shot builds retain their existing non-root behavior. Callers can select only a configured task and either a configured named action or a validated action name delivered to one configured dispatcher; argv, environment, cwd, timeouts, artifact patterns, filesystem paths, and process definitions remain server-owned.

`POST /v1/sessions` uses the same ordered `metadata` then `source` multipart shape and upload bounds as `POST /v1/builds`, but its metadata is the separately versioned session-start type:

```json
{"schema_version":"1","request_id":"agent-42","task":"build","source":{"format":"zip"}}
```

Unknown metadata fields and invalid task/request identifiers fail closed. Initialization runs the task's existing optional setup and required run once in one fresh workspace. Setup plus run must still fit `build.max_timeout_sec`; their combined stdout/stderr uses one initialization output budget. A successful stream ends with `ready`, while an initialization process outcome that cannot become Ready ends with `exit`:

```json
{"type":"session","id":"ses_123","status":"started"}
{"type":"session","id":"ses_123","status":"phase_started","phase":"setup"}
{"type":"stdout","data":"initializing...\n"}
{"type":"session","id":"ses_123","status":"phase_finished","phase":"setup","duration_ms":25,"exit_code":0,"timed_out":false}
{"type":"ready","session_id":"ses_123","workspace_revision":"rev_0","phases":[{"phase":"setup","duration_ms":25,"exit_code":0,"timed_out":false},{"phase":"run","duration_ms":50,"exit_code":0,"timed_out":false}]}
```

The Ready commit point is the durable write of protected, daemon-owned mode-`0700`/`0600` session metadata under the protected workspace root followed by the serialized `Initializing` → `Ready` election, before the `ready` event is sent. Commit, disconnect, explicit stop, and lifetime expiry contend on the same state lock, so only one can win while the session is Initializing. The metadata authority is separate from the task-owned session workspace. Disconnect before that commit cancels initialization—including bounded archive preflight, extraction, and recursive ownership preparation—and performs best-effort teardown and cleanup. Disconnect after commit does not undo the session; idle expiry handles a committed session whose caller did not receive its ID.

After authentication and metadata/task validation, a session acquires the same global admission permit as a one-shot build and immediately records its `Initializing` reservation before reading the source field. Its absolute maximum-lifetime deadline therefore includes a slow or blocked upload as well as filesystem preparation and configured initialization. `max_lifetime_sec` is capped at 4,294,967,295 seconds so every accepted deadline is representable by the supported monotonic clocks. With the default `service.max_concurrent_builds = 1`, one reserved or Ready session makes new builds/session starts return immediate `503 busy` until it stops or expires. The started event exposes the already-registered ID, so `DELETE` during configured initialization cancels its process group, joins the single cleanup path, and waits for teardown instead of returning a transient `404`. Idle time begins at Ready and is suspended during lifecycle work. Explicit stop, idle expiry, maximum lifetime, initialization failure, and competing cleanup triggers elect one terminating owner under the lifecycle state lock, so the configured idempotent teardown runs at most once and the workspace and permit are released once. If explicit stop wins that lock it returns `200` with explicit final-artifact semantics; if automatic cleanup already won, stop returns `409 session_conflict` and never returns an automatic result as an explicit success. A missing or already removed ID receives `404`.

Automatic cleanup runs teardown without publishing an unreachable final archive. Explicit `DELETE` alone collects the task's top-level final artifact snapshot. On daemon startup, durable Ready sessions are destroyed rather than resumed: current task configuration is used for best-effort teardown when available, while removed/renamed task configuration, invalid metadata, and pre-commit orphan workspaces receive logged root cleanup. Operators must keep teardown idempotent and preserve sufficient external-state identifiers in the workspace; configuration drift can prevent the operator teardown command from being recovered.

When configured, `POST /v1/sessions/{session_id}/updates` accepts ordered multipart `metadata` then `source` fields using the task-specific timeout and bounds. Metadata schema v1 contains a required request ID, the current opaque `rev_<decimal>` base, ZIP format, and exact file/delete declarations; file declarations carry lowercase SHA-256 and no mode authority. The ZIP must contain exactly the declared regular non-executable file entries. Paths are ASCII relative paths, case-unique, allowlisted, and may not target `.indentured/**` or protected metadata. Verification and protected same-filesystem staging complete before operation reservation; actions and updates then serialize. A stale revision, concurrent operation, or reused request ID with different bytes returns `409`; the session caches only its most recent successful update, and an exact retry means byte-identical metadata and archive bytes for that cached request ID. That one exact retry returns its original response without reapplying. Success durably advances the revision and returns only IDs, revisions, paths, and hashes. Mutation validates no-follow ancestors, backs up existing regular files, uses same-directory atomic replacement, and rolls the full update back on any observed error or cancellation; an unprovable rollback destroys the session. Idle expiry is suspended while Updating, while stop and hard lifetime cancel it and join normal cleanup.

`POST /v1/sessions/{session_id}/actions/{action}` accepts an `application/json` body of at most 65,536 bytes with exactly this authority envelope:

```json
{"schema_version":"1","input":{"operator_data":"value"}}
```

The `input` value must be an object. Names such as `argv` nested inside it are data and never process authority. Unknown top-level fields—including `argv`, `environment`, `cwd`, `timeout_sec`, `artifacts`, and `path`—are rejected. Session IDs and action-execution IDs are opaque `[A-Za-z0-9_-]+` values bounded to 128 bytes; action names retain the 64-byte task-identifier rules. Named mode rejects an unconfigured name with `404 unknown_action` and supplies only the compact serialized `input` object to that action's stdin. Dispatcher mode accepts every syntactically valid name by default; with `allow_unlisted = false`, it accepts only names in the dispatcher's policy map. It supplies this compact internal envelope to the one fixed dispatcher command:

```json
{"schema_version":"1","action":"observe","input":{"operator_data":"value"}}
```

The external encoded request remains bounded to 65,536 bytes. Dispatcher stdin is bounded by that request plus the fixed envelope and an action name of at most 64 bytes. The dispatcher must treat the name and input as data, reject unsupported names promptly with a nonzero exit, and avoid task dependencies that compete to read the inherited stdin. Each accepted name uses the dispatcher timeout and artifact allowlist unless its policy-only entry overrides either value; an explicitly empty artifacts table selects no artifacts. Action streams carry stable session, action-execution, and action-name identity:

```json
{"type":"action","session_id":"ses_123","action_id":"act_456","action":"observe","workspace_revision":"rev_1","status":"started"}
{"type":"stdout","data":"observed\n"}
{"type":"action","session_id":"ses_123","action_id":"act_456","action":"observe","workspace_revision":"rev_1","status":"snapshotting"}
{"type":"exit","session_id":"ses_123","action_id":"act_456","action":"observe","workspace_revision":"rev_1","code":0,"timed_out":false,"artifacts":{"path":"/v1/builds/bld_789/artifacts.zip","size":1234}}
```

Each child receives only its mode's serialized JSON on stdin followed by EOF; stdin delivery is nonblocking with respect to the daemon runtime and an action that exits without reading it is handled normally. Each named or resolved dispatcher action and teardown has its configured deadline and fresh `build.max_output_bytes` accounting; output usage is not cumulative across the session. Action and final explicit-stop archives reuse the existing authenticated artifact path, storage limits, restricted patterns, TTL, and garbage collection.

A Ready session admits one action at a time. The action process and its artifact snapshot form one serialized operation, so another action receives immediate `409 session_conflict` rather than queueing, including while snapshot publication is active. Idle expiry is suspended during the operation and restarts after a completed ordinary action. Snapshot traversal retains an open workspace-root descriptor, opens every path component relative to it with no-follow semantics, verifies the opened file identity against traversal, and archives from the already-open descriptor. A task-owned symlink or rename swap therefore fails the action rather than redirecting snapshot reads.

A nonzero configured action exit is reported in the final event and leaves the session Ready for diagnosis. Ready is restored only after the HTTP body consumes the final action frame and acknowledges it; enqueueing the event alone is not a commit point. A disconnect before that acknowledgement destroys the session and immediately removes any action archive already published, even when artifact TTL/GC is disabled. An action timeout, output exhaustion, response disconnect/backpressure, snapshot failure, or internal execution failure likewise makes session state untrustworthy and therefore cancels and reaps the whole action process group, runs teardown, and removes the session. Maximum lifetime remains hard during traversal, archive writing, publication, and final delivery. Explicit stop preempts every stage, waits for the same exactly-once cleanup path, and alone may collect final stop artifacts; automatic cleanup never publishes an unreachable archive. Once expiry has elected termination, a racing action receives `404` rather than observing a partially torn-down workspace.

`DELETE /v1/sessions/{session_id}` waits for bounded idempotent teardown and returns JSON containing the teardown exit/timeout outcome plus any final archive selected by the task's top-level artifact policy:

```json
{"session_id":"ses_123","teardown":{"duration_ms":40,"exit_code":0,"timed_out":false},"artifacts":{"path":"/v1/builds/bld_790/artifacts.zip","size":4321}}
```

Initialization runs setup, then run, then configured retained services in stable sorted-name order. Run's entire process group is reaped before the first service starts. Any configured service requires a root daemon and an explicit run-as identity distinct from the daemon effective UID. Each service inherits the task's fixed cwd, cleared/fixed environment, and that run-as identity, but runs in its own process group under an Indentured-owned supervisor. The daemon injects only `INDENTURED_SERVICE_READY_FD`; configuration cannot set that reserved key. The wrapper must write exactly `ready\n` to that numeric FD and close it only after its actual dependency (for example, Metro's listening port) is usable. EOF before the exact message, extra bytes, timeout, early exit, or output-drain failure aborts initialization.

Service stdout/stderr is drained continuously. Startup bytes remain part of the session-start stream; after Ready the daemon discards oldest bytes and retains only each configured diagnostic tail, without applying a cumulative lifetime output quota. No log or service-control endpoint is exposed. Unexpected service exit during Ready, Action, or Updating cancels the active operation and destroys the session.

Before the first service spawn the daemon durably records `starting_services` metadata in protected storage, then fsyncs recorded supervisor/service identities after every spawn. The daemon-control channel is established with close-on-exec protection before spawning; until `RunningService` owns it, an RAII guard closes control and performs bounded supervisor termination/reaping on every setup or status error, so the metadata write-after-spawn interval cannot orphan the service. Each supervisor owns the actual service group behind an armed RAII guard and watches a daemon control pipe; every unfinished supervisor exit closes control and performs bounded TERM, configured shutdown wait, KILL escalation, and reap verification. Daemon-side stop independently terminates and verifies the recorded service group after bounded supervisor handling, so a dead or wedged supervisor is never trusted as the sole cleanup owner. Normal cleanup first cancels/joins the active operation, then stops services in reverse start order before idempotent teardown, workspace removal, and permit release. A pathological survivor records `service_cleanup_failed` without retaining the admission permit forever. If supervisor or service-group disappearance cannot be proven within the bound, protected metadata is deliberately retained for fail-closed startup reconciliation even though the workspace, in-memory session, and permit are released. Startup reconciliation never recovers a session: it waits conservatively for every recorded supervisor to disappear before teardown/removal, verifies that the recorded service leader and group are gone, and refuses unsafe cleanup rather than signaling a possibly reused PID.

Initialization, actions, teardown, and services retain bounded whole-process-group termination and reaping behavior. Process groups are cleanup rather than a sandbox against deliberate escape. The contract adds no session list, reset, reconnect, generic service-control, arbitrary-command, workspace, or filesystem endpoint.

## macOS launchd and Tailscale deployment

[`docs/macos-launchd-tailscale-deployment.md`](docs/macos-launchd-tailscale-deployment.md) defines the portable macOS/launchd/Tailscale contract for deployment automation. A hardened deployment runs a root daemon with a dedicated non-admin task identity, protected bearer token files, fresh workspaces, one active run with immediate busy rejection, synchronous disconnect/SIGINT cancellation, and private retained client evidence.

The service exposes only a loopback HTTP origin behind Tailscale Serve. Serve terminates external TLS and proxies plaintext HTTP to `127.0.0.1:<port>`; application bearer authentication remains independently required. Built-in rustls HTTPS remains supported for generic direct deployments as server-side transport encryption only; it neither verifies client certificates nor replaces bearer authority, and it is not this Serve edge. The Unix socket is disabled in this topology.

This repository owns generic packages/apps, behavior, documentation, and a parameterized launchd example. Deployment automation/operator policy owns concrete users/groups, the authoritative launchd module and activation, trusted server-configured script or executable/fixed-argv task definitions, secrets/rotation, retention values, Tailscale reconciliation, and the native behavioral acceptance gate. The local packaged harness is:

```sh
devenv tasks run integration:packaged-local
```

It executes the exact Nix package binaries through the one-shot flow and a generic fake-state managed-session flow without a forge, remote shell, source publication, Xcode, or remote Mac. On Linux the script enters subordinate-ID user and private PID namespaces so the daemon is root, the configured task remains a verified distinct non-root identity, and harness failure kills only its namespace descendants. The harness proves named-action compatibility, arbitrary names through one fixed dispatcher, exact JSON envelopes, prompt unsupported-name failure, ordinary-nonzero reuse, action/final artifacts, retained admission capacity, explicit/idle/lifetime/timeout/disconnect cleanup, genuine daemon-kill reconciliation, configuration-drift cleanup, and the unchanged setup-then-run provenance/evidence/SIGINT-cancellation regression. This is deterministic protocol/package evidence, not CoreSimulator attestation.

[`docs/managed-session-ios-simulator-example.md`](docs/managed-session-ios-simulator-example.md) provides an operator-owned iOS Simulator configuration and wrapper contract. It pins Xcode/runtime/device policy, records one explicit UDID in the session workspace, keeps JSON action data out of process authority, and defines idempotent simulator deletion. Indentured ships no iOS, MCP, Node, `idb`, or simulator-driver behavior.

## systemd

Install `systemd/indentured-server.service`, the daemon binary, and the server configuration using paths appropriate for the host. The checked-in unit expects `/usr/local/bin/indentured-server` and `/etc/indentured-server/config.toml`, provisions the bearer with `LoadCredential=`, uses daemon-only runtime/state/log directories, and sets `UMask=0077`. The daemon intentionally starts as root so it can own protected state and then drop each task to `build.run_as_user`; do not place bearer values in `Environment=`.

Linux tests and an Apple-target compile do not prove macOS privilege behavior. Before deployment, the operator must run the detailed guide's native checks for configured UID/GID and supplementary groups, credential/artifact/control unreadability, process-group cancellation, workspace cleanup, immediate busy behavior, edge topology, retention, and rotation. That native macOS deployment gate is an external prerequisite.

## License

MIT. See [LICENSE](LICENSE).
