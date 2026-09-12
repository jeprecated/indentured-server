# Observe the Mac when app automation or the terminal breaks

`indentured-host` supplies read-only graphical application/window enumeration and
PNG capture through normal Indentured managed-session actions. It does not send
keys, focus windows, depend on Zellij, expose a remote shell, or require the iOS
app's automation driver to work. A desktop capture means every display, not a
scrolling browser-page capture. Physical-device capture remains out of scope.

## Architecture and authority

```text
agent → authenticated Indentured session action → fixed indentured-host action
      → private observation socket → selected user's Aqua LaunchAgent
      → app/window inventory + PNG bytes → normal action artifacts
      → client's local result directory → agent opens the PNG
```

The existing root LaunchDaemon and its bearer/control socket stay unchanged.
Dropping a task to a user's UID does not enter that user's graphical login
session. The helper must run as a LaunchAgent in the intended `gui/<UID>` domain,
with a logged-in graphical user. Native tools are macOS's fixed
`/usr/bin/osascript` (JXA/AppKit/CoreGraphics) and `/usr/sbin/screencapture`; the
package needs no Node, simulator driver, Xcode project, or extra runtime install.
Linux builds provide CLI/protocol tests, not a Linux screenshot backend.

**Do not change `build.run_as_user` to your personal desktop account to make
screenshots work.** Uploaded repository tasks execute arbitrary code under that
identity. Instead, explicitly grant the existing task UID access to the
read-only observation socket. Every process running under that UID then has
observation authority; action names are not isolation between uploaded projects.
Screenshots and titles may reveal unrelated windows, notifications and secrets.
Prefer a dedicated debugging Mac/GUI account and trusted repositories.

The observation socket is separate from the daemon's protected control socket.
It authenticates the configured UID using kernel peer credentials, not a token
in the uploaded workspace. It has no caller-controlled executable, filename,
output directory or shell text. The client checks the expected GUI helper UID.
This authenticates the account, not code identity: the GUI account is trusted
and can impersonate its own helper. Do not expose this socket over TCP.

## Provision once on the Mac

Build the pinned package:

```sh
nix build --no-link .#indentured-host
```

Deployment automation owns installation and activation; nothing is enabled by
building the package. Use
[`launchd/indentured-host.plist.example`](../launchd/indentured-host.plist.example)
and [`config/host-observation.toml.example`](../config/host-observation.toml.example)
as templates. Replace every placeholder and numeric UID/GID with actual values.

1. Keep the daemon's existing secretless task UID. Select the GUI account whose
   desktop may be observed. Provision an observation-only group containing both
   accounts. Provision an absolute, short socket directory owned by the GUI
   account, group-owned by that group, mode `0710`; its ancestors must permit
   traversal without becoming task-writable. Do not loosen the user's home
   directory broadly: if necessary choose a separately provisioned directory.
2. Install the root-controlled LaunchAgent with the pinned helper path,
   `serve --socket <path> --allow-uid <task-uid> --socket-group <gid>`. Load it in
   the selected user's Aqua login session. Do not launch it through the failing
   terminal pane or as a root LaunchDaemon. The task may connect to the socket,
   but must not be able to replace the helper, plist or socket directory.
3. During initial attended provisioning, add `--request-permission` to the
   LaunchAgent's arguments. Approve **Screen & System Audio Recording** (called
   Screen Recording on older macOS versions) in Privacy & Security for the
   actual invocation chain macOS identifies. Remove this option after setup;
   ordinary observations must not continually prompt. `indentured-host
   permissions` is also available as a local diagnostic/request, but approval
   from Terminal alone does not prove the LaunchAgent has permission.
4. Restart the agent if macOS requires it, then test through the actual
   Indentured action. Root privilege, matching UIDs and an earlier Terminal
   screenshot are not substitutes for this check. AppKit/CoreGraphics listing
   does not intentionally use System Events UI scripting; do not grant blanket
   Accessibility/Automation permissions unless a native diagnostic establishes
   a separate need.
5. Merge the task fragment into the daemon's schema-12 configuration, keeping
   its existing task identity. Set the action's `--peer-uid` to the GUI UID.
   Normal authenticated session actions now cross only the explicit observation
   boundary. No HTTP protocol/configuration-schema change is required.

For a dedicated debugging GUI account that is already the intentionally chosen
secretless task account, omit `--allow-uid`, `--socket-group` and `--peer-uid`:
defaults use same-UID peers, a private `0700` directory and `0600` socket. This
shortcut is not a recommendation to run arbitrary uploads as a personal user.

The helper removes its socket on orderly SIGTERM/SIGINT shutdown. After a crash
or SIGKILL, it refuses an existing socket rather than risk replacing a live
helper. Stop the LaunchAgent, confirm no helper is running, remove only its stale
socket, and restart it. Do not delete the directory or observation logs wholesale.

macOS can require renewed consent after an OS upgrade, binary/path/identity
change or revocation. A stable operator-managed signed identity can improve TCC
continuity; the unsigned Nix store path does not promise permanent one-time
permission. Test the deployed version and attribution rather than guessing.

## Agent usage

From the client machine, start the configured capability and list the remote
GUI apps/windows. Each invocation prints its own **local result directory** to
stderr:

```sh
session_id=$(indentured session start host_observation)
printf '{}\n' | indentured session action "$session_id" host-list --input -

# Capture exactly the window selected from that fresh inventory (owner PID + ID).
printf '{"target":"window","pid":123,"window_id":456}\n' \
  | indentured session action "$session_id" host-capture --input -

# Capture each eligible window of this application separately.
printf '{"target":"application","pid":123}\n' \
  | indentured session action "$session_id" host-capture --input -

# Capture the whole desktop: a separate PNG per display.
printf '{"target":"desktop"}\n' \
  | indentured session action "$session_id" host-capture --input -

indentured session stop "$session_id"
```

The dispatcher executable receives the existing envelope, for example
`{"schema_version":"1","action":"host-capture","input":{"target":"desktop"}}`.
Do not add that envelope around the CLI's `--input`; the client supplies it.
Unknown fields, action names and invalid numeric identifiers fail rather than
becoming command-line options. No source updates or simulator initialization
are needed for this observation-only session.

The helper emits one JSON manifest with `schema_version`, `observation_id`,
`captured_at`, `status`, `inventory`, `images`, and `errors`. Each image's `path`
is relative to the remote workspace, for example:

```text
.indentured-output/action/host-<UUID>/image-0000.png
```

The manifest is also saved as `manifest.json` in that observation directory.
The **actual local image** is:

```text
<printed-local-result-directory>/artifacts/<image.path>
```

The agent must read/open that file with its image-capable tool. A shell's text
output, remote pathname, base64 text or ZIP pathname is not visual input to the
model. Indentured downloads PNG bytes; it cannot automatically attach images to
every possible agent integration. Integration instructions should explicitly
say: after `host-capture`, locate this invocation's manifest under `artifacts/`,
check `status`/`errors`, then open every requested image. Prefer the current
`observation_id`; never pick an arbitrary older PNG.

Artifacts use a fresh private `host-<UUID>` directory on every invocation, so a
failed capture cannot appear to succeed by reusing a previous PNG. Within a
retained session, previous observations remain in the workspace and the
configured artifact glob includes them. Stop/start the small observation-only
session periodically to bound history and transfer size; no shared output
folder is destructively cleared. Server artifact limits and restricted patterns
still apply. Session stop removes the workspace, not the independent GUI
LaunchAgent or the applications being inspected.

## Inventory and capture semantics

- Graphical apps include regular and accessory applications in the selected
  login session, independently of their windows. Apps with no windows remain
  listed; this is not an inventory of every Unix process or every logged-in user.
- Windows carry owner PID, window ID, title where available, bounds and visibility
  information. Missing/redacted titles are not grounds to omit an application.
- Use a fresh inventory: PIDs/window IDs are ephemeral, not durable bookmarks.
  An exact-window request checks the owner and fails if stale; it never falls
  back to a similarly titled window, coordinate crop, or whole desktop.
- Application capture returns eligible windows individually. An app with no
  capturable windows returns an explicit error, not an unrelated screenshot.
- Whole-desktop capture returns one PNG per display with display identity.
  Display ordinal and CoreGraphics display ID are different values. Captures
  across displays are sequential, not an atomic panorama.
- Minimized, hidden, off-Space, protected and transient windows may not be
  capturable. Enumeration and capture cannot be atomic; a window can disappear
  between them. Permission denial/unavailable GUI and capture failures must be
  treated as failures, not evidence of a blank app.
- A valid PNG proves transport/encoding, not that DRM-protected or otherwise
  unavailable pixels became visible. Inspect the image and recorded errors.

Requests are limited to 4 KiB; an observation permits at most 32 images and
63 MiB of PNGs in a 64 MiB transfer (manifest at most 1 MiB). Capture work has a
45-second deadline, with at most 15 seconds per native tool. If an application
exceeds these limits, select individual windows. Socket transfers also have
absolute deadlines; a slow sender cannot extend them by trickling bytes.

## Native acceptance gate

The offline tests use fake inventories and PNGs. Before declaring the deployed
Mac usable, run these checks through its **actual LaunchAgent and authenticated
Indentured artifact flow**, not merely from Terminal:

1. With Zellij unavailable, list a normal app, an accessory app and a running app
   with all windows closed; confirm all expected apps remain in inventory.
2. Open two same-title windows, obscure one, and capture by owner PID/window ID;
   inspect the returned local PNG and verify it is the selected window.
3. Capture an app with multiple windows and one with none. Close a selected
   window before capture; require an error, with no fallback or stale image.
4. Capture every connected display; verify actual images against manifest IDs
   on mixed Retina/non-Retina scales, negative origins, mirroring and hotplug.
5. Deny/revoke then grant permission using the deployed invocation chain. Check
   logout/login, locked screen, no GUI session and fast user switching; never
   accept evidence from an unintended login session.
6. Verify another UID cannot invoke the socket, the task cannot replace its
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
