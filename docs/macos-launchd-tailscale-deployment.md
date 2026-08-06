# macOS launchd and Tailscale deployment guide

This document defines a portable macOS service boundary for deployment automation and operators. It is not an authoritative host module and does not create users, materialize secrets, install or activate a launchd job, define concrete tasks, or reconcile Tailscale state.

## Ownership boundary

| `indentured-server` owns | Deployment automation/operator policy owns |
|---|---|
| Generic daemon and CLI protocol | Concrete users, groups, and account lifecycle |
| Stable Nix packages and apps | Package pin and deployed closure |
| Generic named-task configuration | Trusted server-configured scripts or executable/fixed-argv definitions |
| Token-file interface and validation | Token generation, provisioning, rotation, and restart ordering |
| Generic launchd example and required topology | Authoritative launchd module, installation, activation, and rollback |
| Configurable resource and retention limits | Concrete limit values, artifact GC policy, and result-retention policy |
| Portable/Linux behavior tests and Darwin package checks | Native macOS deployment gate |
| Tailscale edge requirements | Serve commands, ACL/grant policy, and drift/reboot reconciliation |

The stable flake surfaces for pinning are `packages.aarch64-darwin.indentured-server` and `packages.aarch64-darwin.indentured`, with matching apps. The default package/app is the server. This repository owns generic packages only; it does not own concrete launchd or Tailscale policy.

## Edge topology and TLS boundary

Use this topology:

```text
indentured client
  └─ HTTPS plus application bearer token
      └─ Tailscale Serve / tailscaled (external TLS terminates here)
          └─ plaintext HTTP to 127.0.0.1:<port>
              └─ root indentured-server daemon
                  └─ dedicated non-root, secretless named-task process
```

The origin **must** bind only to `127.0.0.1:<port>`, never `0.0.0.0`, a LAN address, or the Tailscale address. Tailscale Serve publishes HTTPS to permitted tailnet clients and reverse-proxies to `http://127.0.0.1:<port>`. The Tailscale daemon terminates external TLS; the loopback hop is plaintext HTTP. Tailnet ACLs/grants and application bearer authentication are independent controls, so bearer authentication remains required behind Serve.

Built-in rustls HTTPS remains supported as an alternative topology for generic deployments that expose `indentured-server` directly. It provides server-side transport encryption only: it does not authenticate client certificates, exposes no client-CA setting, and never replaces bearer authority. It is disabled for this Serve edge and is not an additional end-to-end TLS layer there. This topology does not use the unauthenticated Unix socket.

Tailscale HTTPS requires the relevant tailnet certificate/MagicDNS prerequisites. Machine and tailnet names included in certificates can appear in public Certificate Transparency logs, so deployment-selected names must not contain secrets. Deployment automation/operator policy owns exact Serve commands and desired-state reconciliation. See the official [Tailscale Serve documentation](https://tailscale.com/docs/features/tailscale-serve), [Serve CLI reference](https://tailscale.com/docs/reference/tailscale-cli/serve), and [HTTPS certificate guidance](https://tailscale.com/docs/how-to/set-up-https-certificates).

Loopback limits remote bypass; it does not isolate the service from malicious processes already running on the Mac.

## Generic launchd example

[`launchd/indentured-server.plist.example`](../launchd/indentured-server.plist.example) is an illustrative system LaunchDaemon. Replace its label and immutable Nix store path in the authoritative deployment module. It deliberately runs the foreground daemon as root so the daemon can create protected state and then execute each task as the separate identity configured by `build.run_as_user` and `build.run_as_group`.

The example is installed conceptually at `/Library/LaunchDaemons/<reverse-dns-label>.plist`. It uses absolute executable, config, working-directory, and log paths; `UserName=root`; `RunAtLoad`; bounded restart throttling; and umask `077`. The plist must be root-owned and not group/world writable. Check its final semantics against `man 5 launchd.plist` on the deployed macOS version. Apple distinguishes system daemons from login-session agents; this headless service must not be installed as a per-user LaunchAgent or daemonize behind launchd. See Apple's [launchd job guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

launchd has no direct equivalent to the checked-in systemd unit's `LoadCredential=`. Deployment automation must materialize the runtime token atomically before loading/restarting the job. The token value must never appear in the plist, `ProgramArguments`, `EnvironmentVariables`, the Nix store, the server TOML, or logs.

### Required paths and permissions

The concrete names and paths are deployment policy. These generic examples describe the required authority boundary:

| Item | Generic example | Required contract |
|---|---|---|
| LaunchDaemon plist | `/Library/LaunchDaemons/<label>.plist` | `root:wheel`, mode `0644` (or stricter), regular file, never group/world writable |
| Server executable | `/nix/store/<pinned-output>/bin/indentured-server` | Immutable pinned package output; executable by root |
| Server config | `/etc/indentured-server/config.toml` | `root:wheel`, mode `0600`; contains the token **path**, never its value |
| Runtime-token parent | `/private/var/run/indentured-server` | Effective-daemon-UID-owned real non-symlink directory, mode `0700`, not group/other/task writable or replaceable |
| Bearer token | `/private/var/run/indentured-server/bearer-token` | Effective-daemon-UID-owned regular non-symlink, mode `0600`, 1–4096 total bytes, exactly one nonempty RFC 6750 `b64token` line, and at most one final LF; not task-owned; provisioned before launch |
| Workspace root | `/var/db/indentured-server/workspaces` | Root/daemon-owned real directory; daemon enforces `0711`; only each random fresh run tree is assigned to the task UID/GID |
| Artifact root | `/var/db/indentured-server/artifacts` | Root/daemon-owned real directory, mode `0700`; never task-readable |
| Log root | `/var/log/indentured-server` | Root/daemon-owned real directory, mode `0700`; daemon and launchd stdout/stderr files mode `0600` |
| Task identity | deployment-selected non-admin user/group | Secretless; distinct from root, token/artifact/log owners, and control endpoints |
| HTTP origin | `127.0.0.1:<selected-port>` | Bearer required; built-in TLS disabled; `max_concurrent_builds = 1` |
| Unix socket | disabled | Not part of the Serve edge; task identity must have no control-socket access |
| Client evidence | `$XDG_STATE_HOME/indentured/runs/<run-id>` | Unique mode-`0700` directory; evidence files mode `0600`; outside submitted source |

The token line uses the RFC 6750 `b64token` character language: one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+`, or `/`, optionally followed by any number of `=` padding characters. Padding is trailing only. The complete file is 1–4096 bytes; it contains exactly that one nonempty token line and may contain one final LF. CR, embedded or multiple LF, NUL, spaces, tabs, other controls, non-ASCII bytes, invalid UTF-8, and misplaced padding are rejected.

Token contents are loaded once at daemon startup and retained only as digests. Rotation therefore requires a controlled daemon restart after atomic reprovisioning.

## Runtime contract

Initial throughput is exactly one active operation: `service.max_concurrent_builds = 1`. A one-shot run holds the permit until completion; a managed session holds it from reservation before upload through explicit or automatic teardown. A second eligible build/session request receives immediate HTTP `503`, `Retry-After: 0`, and `{"error":"busy"}` before source persistence. Long idle/lifetime settings therefore reserve the only default slot. There is no queue.

Every accepted request gets a new unpredictable workspace. The server-owned `sources.upload_timeout_sec` deadline covers source chunks and multipart trailer consumption; timeout returns stable HTTP `408 source_upload_timeout`, removes the partial file, and releases the single-run permit. Upload and complete archive preflight/extraction finish before the fixed server-owned task starts. A root daemon refuses every enabled transport unless a distinct non-root run-as identity is configured. The daemon calls `initgroups`, `setgid`, and `setuid` for that identity, clears inherited environment, and retains ownership of credentials, logs, artifacts, and control paths. Only the fresh workspace transfers to the task identity.

The one-shot lifecycle is synchronous. Client SIGINT or response disconnect closes the request and cancels the remote process group. Managed sessions use separate start/action/stop requests: setup+run initialize once, one named action or one fixed dispatcher runs at a time with bounded JSON on stdin, and configured idempotent teardown owns cleanup. The session retains only workspace files and operator-owned external state identifiers. Initialization, each action, and teardown still reap their process groups; an external service that must persist between commands must be handed to its supported launchd/CoreSimulator service context, never daemonized merely to evade cleanup.

A Ready session is destroyed by explicit stop, idle expiry, maximum lifetime, unsafe action failure/disconnect, or daemon-start reconciliation. A daemon restart destroys rather than resumes durable sessions. If task configuration drifted away, the daemon can remove protected metadata/workspace but cannot reconstruct removed operator teardown authority, so wrappers must be idempotent and deployment changes must drain sessions first. Reuse of bearer authentication is unchanged; there is no new session-specific auth model.

Timeout and output exhaustion use bounded SIGTERM-then-SIGKILL escalation and require group disappearance before artifact collection and cleanup. Process groups are cleanup, not a sandbox against a deliberately escaped `setsid` process; account/VM isolation remains required for untrusted uploaded code.

Client run/session evidence remains private and non-destructive in its XDG result directory until client-side policy removes it. Server artifact archives remain until operator-selected `artifacts.ttl_sec` and/or `artifacts.max_bytes` GC bounds remove them; when both are unset, no finite server retention period is implied. Automatic session cleanup does not publish unreachable final archives; only explicit stop may return the configured final snapshot.

## Local packaged integration evidence

Run:

```sh
devenv tasks run integration:packaged-local
# or from an entered Devenv shell:
scripts/check-packaged-local-integration.sh
```

The harness builds the stable Nix server/client outputs, verifies that each package contains only its named binary, and executes those exact store binaries through bounded local loopback flows. The unchanged one-shot regression reads uploaded source, verifies exactly two provenance outcomes in setup-then-run order, observes stdout/stderr markers while the client is still active, writes an allowlisted artifact, exits 7, and verifies exact exit, private evidence/modes, provenance/manifest, artifact retrieval, controlled SIGINT cancellation, and workspace cleanup.

The managed-session regression uses only distinguishable fake file-backed external state and fixed server-owned commands. It proves named-action compatibility, arbitrary names through one fixed dispatcher, exact JSON stdin envelopes, prompt unsupported-name failure, ordinary nonzero reuse, action/final artifacts, explicit stop, retained capacity, dispatcher timeout/disconnect cleanup, and Ready-to-torn-down evidence for idle expiry, hard lifetime, action disconnect, and real daemon-kill restart reconciliation. It separately proves current-policy teardown after configuration drift and root-only workspace/metadata fallback when task policy was removed. Commands record their effective UID, GID, and supplementary groups; the test requires the configured distinct non-root identity and rejects root membership. On Linux the script uses subordinate UID/GID mappings so the packaged daemon is namespace-root while the task remains non-root, and runs the harness as PID-namespace init with kill-child semantics so a panic cannot orphan daemon/action descendants. It never weakens the production authority check or uses a broad process-name kill.

This is package/protocol evidence, not a production security bypass or a native macOS/CoreSimulator runtime attestation. The supported unauthenticated loopback setting exists only inside the isolated test and does not change production defaults or bearer behavior. Tasks are trusted server-owned commands, not caller-provided shell authority. The harness uses no forge, SSH/remote-shell transport, source publication, Xcode, or remote Mac. It remains a Devenv/script check rather than a universal flake check because loopback networking and privilege setup are not portable across all Nix build sandboxes.

## Reusable repository capability profiles

Deploy schema 10 once with host profiles named for capabilities rather than individual repository scripts. `repo_check` runs each uploaded repository's conventional `indentured:check` Devenv task. `repo_session` fixes the host identity, limits, lifecycle, and artifact policy while the uploaded repository supplies conventional setup/start/action/stop tasks:

```toml
[tasks.repo_check]
executable = "/run/current-system/sw/bin/devenv"
args = ["tasks", "run", "indentured:check"]
cwd = "."
timeout_sec = 1800
workspace = "fresh"

[tasks.repo_check.environment]
PATH = "/run/current-system/sw/bin:/usr/bin:/bin"

[tasks.repo_check.artifacts]
include = []
exclude = []

[tasks.repo_session]
executable = "/run/current-system/sw/bin/devenv"
args = ["tasks", "run", "indentured:session:start"]
cwd = "."
timeout_sec = 600
workspace = "fresh"

[tasks.repo_session.setup]
executable = "/run/current-system/sw/bin/devenv"
args = ["tasks", "run", "indentured:session:setup"]
timeout_sec = 600

[tasks.repo_session.environment]
PATH = "/run/current-system/sw/bin:/usr/bin:/bin"

[tasks.repo_session.artifacts]
include = [".indentured-output/final/**"]
exclude = []

[tasks.repo_session.session]
idle_timeout_sec = 900
max_lifetime_sec = 14400

[tasks.repo_session.session.teardown]
executable = "/run/current-system/sw/bin/devenv"
args = ["tasks", "run", "indentured:session:stop"]
timeout_sec = 120

[tasks.repo_session.session.action_dispatcher]
executable = "/run/current-system/sw/bin/devenv"
args = ["tasks", "run", "indentured:session:action"]
timeout_sec = 120
allow_unlisted = true

[tasks.repo_session.session.action_dispatcher.artifacts]
include = [".indentured-output/action/**"]
exclude = []

# Optional policy-only override; artifacts still inherit the dispatcher default.
[tasks.repo_session.session.action_dispatcher.actions.observe]
timeout_sec = 60
```

Use an absolute, operator-selected Devenv executable and adjust only deployment-owned paths and limits. Repository tasks are ordinary Devenv tasks:

- `indentured:check` runs the repository check appropriate to this host profile;
- `indentured:session:setup` prepares files consumed by session startup;
- `indentured:session:start` initializes the retained external state once and then exits successfully; the server retains the session record and workspace, not that foreground process;
- `indentured:session:action` reads exactly one dispatcher envelope from inherited stdin;
- `indentured:session:stop` performs idempotent cleanup and may populate `.indentured-output/final/`.

The action task receives compact JSON with no trailing newline, such as `{"schema_version":"1","action":"observe","input":{}}`. A shell task can capture it with `IFS= read -r envelope || test -n "$envelope"`. It must validate schema and action, treat every input field as data, reject unsupported names promptly with a nonzero exit, and avoid Devenv task dependencies that compete for stdin. Dispatcher `actions` entries may override only `timeout_sec` and `artifacts`; omitted values inherit the fixed defaults, and an explicitly empty artifacts table selects no artifacts. `allow_unlisted` defaults to `true` for schema-9 compatibility; set it to `false` to reject names absent from the policy map before spawn. Use strict named actions instead when implementations must remain operator-owned.

Uploaded repository hooks are arbitrary code under the configured task identity. A fixed `repo_check` or `repo_session` name is not a per-script security boundary. Create a separate host profile only for a distinct identity, permission set, resource limit, lifecycle, artifact policy, or operator-owned capability. The source tree uploaded by `session start` is initially pinned. It can change only through the bounded `session.source_updates` policy and authenticated revisioned update endpoint; without that operator-owned policy the endpoint is unsupported. This is not generic filesystem authority: updates are declared, hashed, allowlisted regular non-executable file replacements/deletions with rollback-or-destroy semantics.

This repository defines `indentured:check` as `scripts/check-darwin.sh`. That convention means “this repository's check for the selected Quartz capability profile,” not a portable local check; it deliberately refuses non-Apple-silicon-Darwin execution. From a trusted client:

```sh
export INDENTURED_SERVER_ENDPOINT=https://mac-builder.example.ts.net
export INDENTURED_SERVER_TOKEN_FILE=/absolute/operator-local/bearer-token
indentured run repo_check
session_id=$(indentured session start repo_session)
indentured session action "$session_id" observe --input ./observe.json
indentured session stop "$session_id"
```

Leave `INDENTURED_DARWIN_SESSION_GATE` unset inside `repo_check`: a one-shot task holds the default global permit, so recursively calling the same service would receive `503 busy`. Drive native managed-session/CoreSimulator acceptance externally. Endpoint, credential, users, absolute deployment paths, and native results remain operator-local.

## Native macOS acceptance gate

Deployment automation/operator policy must block live-service acceptance until tests against the actual launchd job and concrete configured task prove all of the following:

- **Privilege drop:** effective UID, primary GID, and supplementary groups equal the declared task identity; inherited daemon variables are absent; `HOME`, `USER`, and `LOGNAME` have the expected fixed values.
- **Credential/control denial:** the task cannot read, open, traverse to, rename, replace, or delete the bearer token; cannot read/delete daemon logs or artifact archives; and cannot connect to any Unix/control socket.
- **Authentication secrecy:** missing and wrong bearers return the same 401 response, the valid bearer works only over the intended HTTP edge, and no token/header/digest appears in launchd, daemon, or client logs.
- **Cancellation:** timeout, client disconnect/SIGINT, and output exhaustion terminate and reap the leader plus descendants. A TERM-ignoring descendant must exercise SIGKILL escalation, and no descendant may retain the fresh workspace.
- **Cleanup:** different fresh workspaces are used and removed after success, nonzero exit, timeout, output limit, disconnect, extraction failure, and artifact failure.
- **Immediate busy behavior:** while one run is active, a second request gets stable immediate 503 busy before source persistence; the permit is released after every completion/error path.
- **Edge topology:** Tailscale HTTPS plus a valid bearer reaches the loopback origin; no daemon listener is exposed on a non-loopback address; UDS and built-in rustls are disabled; Serve state is reconciled after reboot and deliberate drift.
- **Managed-session identity:** a root daemon and distinct non-root task identity preserve the protected metadata boundary; a Ready session retains the one global permit; named input or the dispatcher envelope reaches only stdin; caller data cannot select process authority; and another action conflicts rather than queues.
- **CoreSimulator context:** the exact task UID/GID/supplementary groups can reach the intended per-user launchd/bootstrap context using pinned `DEVELOPER_DIR`, runtime, and device type. Every operation uses the recorded explicit UDID, never `booted`.
- **Simulator lifecycle:** initialization builds once and creates/boots/installs/launches once; separate observe/act invocations reuse it; observe returns a screenshot; explicit stop, idle/lifetime expiry, disconnect, failure, and restart cleanup delete the recorded simulator. `simctl list devices -j` confirms the UDID is absent after every cleanup case.
- **Simulator authority separation:** the simulator task cannot read or modify bearer credentials, daemon config/logs/artifacts, launchd policy, control paths, or other users' simulator state. Signing and unrelated deployment credentials are absent.
- **Retention and rotation:** client evidence remains private/non-destructive, configured server GC bounds work, and a rotated credential takes effect only after controlled daemon restart.

Use [`managed-session-ios-simulator-example.md`](managed-session-ios-simulator-example.md) as the operator-owned configuration/wrapper checklist. Linux behavioral tests and native Darwin package compilation are supporting evidence, not substitutes for this live gate. `scripts/check-darwin.sh` records whether an operator-supplied native CoreSimulator gate was exercised; without that evidence the runtime is explicitly unattested. The authoritative users, launchd module, Tailscale state, secrets, concrete tasks, and native acceptance results belong to deployment automation/operator policy.

## Initial-scope exclusions

This guide does not add asynchronous jobs or queues, signing credentials, physical-device access, caller/request-controlled shell execution, source publication, remote-shell transport, or third-party orchestration integrations.
