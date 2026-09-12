# Built-in, server-wide macOS host observation

Host observation is an optional **Indentured Server feature**, disabled by default.
Enable it once on a Mac and every authorized client can list graphical applications
and windows, capture an exact window or application's windows, or capture the whole
desktop. It works from any project and from an empty directory. **No named task,
source upload, project configuration, dispatcher, or managed session is involved.**
It does not send keys, focus applications, or depend on Zellij/app automation.

## Architecture and authority

```text
indentured host → authenticated daemon host API → private observation socket
               → Aqua LaunchAgent → inventory/PNGs → ordinary artifact storage
               → authenticated artifact download → client opens local PNGs
```

The daemon directly speaks the bounded broker protocol under its own service UID.
It does not spawn a task or drop privileges to the build account for observation.
The root LaunchDaemon cannot itself enter a graphical login session: the separate
`indentured-host` Aqua LaunchAgent runs in the selected GUI account. Native tools
remain `/usr/bin/osascript` and `/usr/sbin/screencapture`; no Node, simulator driver,
Xcode project or extra runtime installation is required.

Do not change `build.run_as_user` to a personal GUI account. Existing daemon/task
identity isolation remains in force, even when the server has no named tasks.
Grant broker access to the **daemon UID**, typically 0, not the build-task UID.
Uploaded projects should not belong to the observation socket group. All authorized
HTTP clients (and holders of the protected daemon control UDS) have the enabled
host-wide capability; there is no per-project isolation of screenshots. Screenshots
and titles may expose unrelated windows, notifications and secrets. Prefer a
purpose-specific debugging GUI account.

The broker authenticates the exact daemon UID with kernel peer credentials. The
daemon checks the configured GUI peer UID. This authenticates accounts, not code
identity: the GUI account is trusted and can impersonate its own helper. The
broker takes identities, never arbitrary executables, paths, shell text or input
events. Do not expose its socket over TCP.

## Enable once on the Mac

Building/pushing packages does not activate services. Deployment automation owns
installation, activation, and permissions. Install matching daemon/client builds
as well as the helper; an older client will not know `indentured host`, and an
older daemon will return an empty `404 Not Found` for its API. For that response,
the client advises checking both the endpoint URL and daemon version; it does not
assume the feature is merely disabled. Build `nix build --no-link .#indentured-host`
and use the [LaunchAgent template](../launchd/indentured-host.plist.example).

1. Keep the existing secretless build-task identity. Select the GUI account.
   Provision an observation-only group for the GUI and daemon accounts, **not the
   build account**. Create a short absolute GUI-owned socket directory, group-owned
   by that group, mode `0710`. Ancestors must be real directories owned by root or
   the GUI UID, not group/other-writable (root-owned sticky directories excepted).
   Do not broadly loosen home-directory permissions; a separately provisioned
   protected directory can be used instead.
2. Install the root-controlled LaunchAgent with pinned helper path and arguments
   `serve --socket <path> --allow-uid <daemon-uid> --socket-group <gid>`. Load it in
   the selected user's Aqua `gui/<UID>` domain, not a root LaunchDaemon or terminal
   pane. The helper creates a mode-`0660` socket and authorizes only the daemon UID.
3. During attended provisioning, add `--request-permission` to that LaunchAgent.
   Approve Screen Recording / Screen & System Audio Recording for the invocation
   chain macOS identifies. Remove the option after setup; ordinary listing/capture
   never requests permission. Restart the agent if macOS requires it. Approval
   from `indentured-host permissions` in Terminal alone does not attest LaunchAgent
   permission. Do not grant blanket Accessibility/Automation permissions.
4. Enable the feature in the **daemon** configuration, using actual socket/GUI UID:

   ```toml
   [host_observation]
   enabled = true
   socket = "/Users/debug/.indentured-host/control.sock"
   peer_uid = 501
   ```

   See the [feature fragment](../config/host-observation.toml.example). HTTP must
   require bearer authentication when this is enabled. The protected daemon UDS
   retains its existing filesystem authorization. No task is added to `[tasks]`;
   that table may be empty or omitted. Existing schema-12 configurations default
   to the feature being disabled. Apply configuration through your deployment.
5. Test through `indentured host`, not a Terminal-only screenshot. Setting
   `enabled = false` denies both new observations and downloads of retained host
   artifacts. It does not delete old evidence or stop the independently managed
   LaunchAgent. Existing artifact retention/GC settings govern stored evidence.

If daemon and helper deliberately share a dedicated service account, omit broker
`--allow-uid`/`--socket-group` and use a private `0700` directory / `0600` socket.
The daemon configuration still specifies `peer_uid` explicitly. This is not a
recommendation to share a personal GUI identity with uploaded builds.

If the broker closes the connection without a complete response, inspect the GUI
LaunchAgent's stderr log and verify `--allow-uid` matches the **daemon service UID**
(normally 0), not the build-task UID. An unauthorized peer is deliberately rejected
before any protocol response. The daemon includes this troubleshooting hint for
EOF/reset errors, but a closed connection can also mean a helper crash; the hint
is not proof of an authorization failure. Do not relax peer checks to diagnose it.

Orderly SIGTERM/SIGINT removes the helper socket. After SIGKILL/crash, it refuses
an existing socket: stop the agent, confirm no helper is running, remove only the
stale socket, then restart. Package/OS changes or revocation may require renewed
TCC consent; an unsigned Nix store path does not promise permanent permission.

## Client usage (no project required)

Set `INDENTURED_SERVER_ENDPOINT` and `INDENTURED_SERVER_TOKEN_FILE` or use the
existing wrapper's global `--endpoint`/`--token-file`. A protected `unix://` endpoint
also works. Host commands intentionally **ignore project client configuration**,
including malformed configuration in the current directory. Connection flags and
global environment, not repository discovery, select the server. A missing-endpoint
error therefore asks for `--endpoint` or `INDENTURED_SERVER_ENDPOINT`, not a project
config. `INDENTURED_SERVER_ENABLED=0` (or `false`) returns the same disabled-connection
exit code **222** as other client commands, without creating a result directory or
contacting the host.

```sh
indentured host list
indentured host capture window 123 456  # owner PID, window ID from fresh list
indentured host capture application 123
indentured host capture desktop
# Optional absolute local evidence base (accepted anywhere after `host`):
indentured host --result-root /absolute/results capture desktop
```

Only a fully successful invocation prints a JSON manifest to stdout. The client
first downloads and validates **all** requested PNGs (framing, CRCs, dimensions,
regular-file/byte limits), then adds an **absolute `local_path` for every image**.
For example, `images[0].local_path` is immediately usable by an agent's image tool:

```json
{"images":[{"path":"observations/host-<UUID>/image-0000.png","local_path":"/absolute/results/<invocation>/artifacts/observations/host-<UUID>/image-0000.png","display_id":123}]}
```

The full manifest also includes `schema_version`, `observation_id`, `captured_at`,
`status`, `inventory`, and `errors`. Multiple windows/displays return all local
paths. No success/path JSON is printed for capture failure, failed download,
invalid PNG or artifact restrictions; failures go to stderr and `result.json`.
The private local evidence directory is always reported on stderr after creation.
`remote-manifest.json` preserves the server response; `manifest.json` is written
only after local image validation and includes local paths. No build/session
provenance is synthesized. The daemon assigns a fresh observation ID independently
of the broker.

The agent must **open each returned `images[].local_path` with an image-capable
tool**. A remote path, base64 or ZIP filename is not visual input. Do not reconstruct
paths from stdout logs or search for an arbitrary older observation.

The daemon publishes a fresh protected artifact archive using the ordinary artifact
limits, restrictions, storage and GC. Scratch is daemon-private and removed after
each observation; no project workspace or session history accumulates. Capture
failure has no partial images. Artifact restriction/download failure is distinct
from capture success: the client exits unsuccessfully if evidence is omitted or
requested images are not downloaded. It checks the exact host artifact path before
using the existing bounded, private, atomic ZIP extractor. Host artifact downloads
reject all HTTP redirects, even same-origin redirects, so only that exact URL is
requested; rejected redirects produce failure with no success/path JSON. Existing
build/session download redirect behavior is unchanged.

## Host API

`POST /v1/host/observations` accepts only a bounded JSON request:

```json
{"operation":"list"}
{"operation":"capture","target":{"target":"desktop"}}
{"operation":"capture","target":{"target":"application","pid":123}}
{"operation":"capture","target":{"target":"window","pid":123,"window_id":456}}
```

The response contains `manifest`, `artifacts` (ordinary `path`/`size`, or null), and
`artifact_restrictions`. Download through the returned host-specific
`GET /v1/host/observations/host-<UUID>/artifacts.zip`. Build routes do not accept host
IDs. Requests never contain task/session IDs or source data. Unknown fields and
malformed identities fail; the old dispatcher envelope/`indentured-host action`
interface is removed.

Authentication precedes broker/filesystem access. Responses are `401` for missing
HTTP authentication, `404 host_observation_disabled` when disabled, `400` for an
invalid/oversized request, `408` for a body taking over five seconds, and `503 busy`
when another observation is in flight. One dedicated observation permit is
independent of build/session slots; disconnect cannot release it while bounded
broker work is still running. Missing helper, wrong UID, unavailable GUI and TCC
denial produce a failed observation manifest with no images. Artifact/publication
failures return a server error. Clients must check status, not just HTTP 200.

## Inventory and capture semantics

- Graphical apps include regular and accessory applications in the selected
  login session, independently of their windows. Apps with no windows remain
  listed; this is not an inventory of every Unix process or every logged-in user.
- Windows carry owner PID, window ID, title where available, bounds and visibility
  information. Missing/redacted titles are not grounds to omit an application.
  Window and display bounds both use CoreGraphics global screen points: origin
  at the main display's top-left, x rightward and y downward. Displays above or
  left of the main display have negative coordinates. PNG dimensions are pixels,
  not points, and may differ with Retina scaling.
- Use a fresh inventory: PIDs/window IDs are ephemeral, not durable bookmarks.
  An exact-window request checks the owner and fails if stale; it never falls
  back to a similarly titled window, coordinate crop, or whole desktop.
- Application capture returns eligible windows individually. An app with no
  capturable windows returns an explicit error, not an unrelated screenshot.
- Whole-desktop capture returns one PNG per logical display with its CoreGraphics
  display ID. Mirrored physical displays share a desktop; `NSScreen` lists one
  representative, not duplicate captures of each connector. The helper uses the
  explicit `CGDisplayBounds` rectangle with `screencapture -R`, never an assumed
  mapping from `NSScreen` order to `screencapture -D`. There is no display ordinal
  in the manifest. Nonintegral/invalid rectangles fail rather than being rounded.
  All display IDs/bounds are rechecked before and after each capture; any detected
  topology change discards the entire observation. Captures across displays are
  sequential, not an atomic panorama; an undetected change-and-revert between
  checks remains possible.
- Minimized, hidden, off-Space, protected and transient windows may not be
  capturable. Only layer-zero windows are eligible; floating panels and
  Picture-in-Picture windows on other layers are listed but not captured. Enumeration and capture cannot be atomic; a window can disappear
  between them. Permission denial/unavailable GUI and capture failures must be
  treated as failures, not evidence of a blank app.
- `captured_at` records the observation's start, not a simultaneous exposure
  time for all PNGs.
- A valid PNG proves transport/encoding, not that DRM-protected or otherwise
  unavailable pixels became visible. Inspect the image and recorded errors.

Requests are limited to 4 KiB; an observation permits at most 32 images and
63 MiB of PNGs in a 64 MiB transfer (manifest at most 1 MiB). Capture work has a
45-second deadline, with at most 15 seconds per native tool. If an application
exceeds these limits, select individual windows. Socket transfers also have
absolute deadlines; a slow sender cannot extend them by trickling bytes. Transfers
put their private sockets in nonblocking descriptor mode and use nonblocking I/O
with deadline-bounded polling, including for a stalled receiver. Darwin's Unix
send path can still block with `MSG_DONTWAIT` alone, so descriptor mode is required. They drain buffered responses after the helper closes its connection.
They do not repeatedly set socket timeouts: Darwin rejects those updates after
peer close with `EINVAL`, even while a complete payload remains readable.

## Native acceptance gate

The offline tests use fake inventories and PNGs. Packaged-local validation runs a
real authenticated packaged daemon and client against a fake broker, including
normal artifact storage/download and absolute local PNG paths. That one test uses
a minimal private root filesystem inside the existing user/mount/PID namespace so
credential/socket ancestor ownership is coherent; the Nix store is read-only.
Production authority checks are not relaxed for the test. No project or GUI code
executes. `nix flake check` also executes
`enumerate.js` with opaque CF-reference fixtures, actual session dictionary key
spellings, wrong-user/locked-session denials, and three equal-size displays with
negative origins. Node is a pinned test-only dependency, not a helper runtime.
On Darwin, `scripts/check-darwin.sh` additionally executes the shipped CF bridge
against real, synthetic native CF collections and CGRect values without touching
GUI contents or requesting permissions. The `host-observation-transport` flake
check runs the Rust socket-deadline tests natively on each supported platform,
including peer closure before the header or between header and payload reads,
truncated frames, closed-peer writes, and stalled-transfer deadlines. This check
is included in the Darwin gate; package builds alone disable Cargo tests and would
not exercise these runtime socket semantics. Filesystem-ownership fixtures still
run in the full local Cargo suite, outside Nix's isolated UID mapping. These checks do **not** attest GUI/TCC.
Before declaring the deployed
Mac usable, run these checks through its **actual LaunchAgent and authenticated
Indentured host API/artifact flow**, not merely from Terminal:

1. With Zellij unavailable, list a normal app, an accessory app and a running app
   with all windows closed; confirm all expected apps remain in inventory.
2. Open two same-title windows, obscure one, and capture by owner PID/window ID;
   inspect the returned local PNG and verify it is the selected window.
3. Capture an app with multiple windows and one with none. Close a selected
   window before capture; require an error, with no fallback or stale image.
4. Capture every logical display; verify actual images against manifest IDs
   on at least three displays (including equal-size screens), mixed Retina/non-Retina
   scales, negative origins, mirroring and hotplug. Mirrored connectors share one
   logical desktop. Match recognizable content, not merely PNG dimensions.
5. Deny/revoke then grant permission using the deployed invocation chain. Check
   logout/login, locked screen, no GUI session and fast user switching; never
   accept evidence from an unintended login session.
6. Verify another UID (including the build-task UID) cannot invoke the broker socket or replace its
   directory/plist/helper, and malformed/oversized requests cannot introduce
   commands/paths or stop subsequent observations. Keep bearer/control paths
   inaccessible to both the task and GUI account.
7. Confirm the remote PNG downloads intact and the agent's image tool opens it;
   capture failure, artifact exclusion and download failure must remain distinct.
8. Record macOS version, package path, task/helper UID/GID, permission attribution,
   selected window/display IDs and inspection results. Recheck after package or
   OS changes.

Deployment automation can provide an absolute executable
`INDENTURED_DARWIN_HOST_GATE` implementing this live gate. `scripts/check-darwin.sh`
runs it and propagates failure; without it, host observation is explicitly
`UNATTESTED`. Native package compilation alone is not a GUI/TCC acceptance test.
