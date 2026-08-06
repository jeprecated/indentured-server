# Operator-owned iOS Simulator managed-session example

This example shows how an operator can use Indentured's generic managed-session contract for an iOS Simulator workflow. It is policy and wrapper code owned by the deployment, not built-in iOS behavior. Indentured does not install Xcode, choose a runtime, parse action JSON, invoke `simctl`, or ship MCP, Node, `idb`, or a simulator driver.

This remains the strict **named-action** example: root-owned wrappers and per-action policy are deliberate. When uploaded repository code may own dispatch instead, use the generic `repo_session` convention in [the macOS deployment guide](macos-launchd-tailscale-deployment.md#reusable-repository-capability-profiles); do not treat that profile name as an additional security boundary.

## Fixed deployment inputs

Pin these values in deployment configuration and review them when Xcode or the runtime changes:

- `DEVELOPER_DIR`, pointing to the selected Xcode application;
- an exact CoreSimulator runtime identifier and device-type identifier;
- the application scheme/configuration and bundle identifier;
- absolute, root-controlled wrapper/helper paths;
- a dedicated non-admin macOS task user that can reach its per-user CoreSimulator/launchd bootstrap context.

Do not use the ambiguous `booted` selector. Every wrapper reads the one explicit UDID created during initialization from `.indentured-session/simulator.udid`. The bearer token, server config, logs, artifact archives, launchd plist, and control paths remain root-owned and inaccessible to the task user. The task user must not hold signing or unrelated deployment credentials.

Example operator configuration:

```toml
schema_version = "12"

[build]
workspace_root = "/var/db/indentured-server/workspaces"
max_timeout_sec = 1800
max_output_bytes = 67108864
run_as_user = "indentured-simulator"
run_as_group = "indentured-simulator"

[tasks.ios_simulator]
executable = "/usr/local/libexec/indentured/ios-session-start"
args = []
cwd = "."
timeout_sec = 900
workspace = "fresh"

[tasks.ios_simulator.setup]
executable = "/usr/local/libexec/indentured/ios-session-build"
args = []
timeout_sec = 900

[tasks.ios_simulator.environment]
PATH = "/usr/bin:/bin"
DEVELOPER_DIR = "/Applications/Xcode-16.4.app/Contents/Developer"
SIMULATOR_RUNTIME = "com.apple.CoreSimulator.SimRuntime.iOS-18-5"
SIMULATOR_DEVICE_TYPE = "com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro"
APP_BUNDLE_ID = "com.example.Example"

[tasks.ios_simulator.artifacts]
include = ["session-final/**"]
exclude = []

[tasks.ios_simulator.session]
idle_timeout_sec = 900
max_lifetime_sec = 14400

[tasks.ios_simulator.session.teardown]
executable = "/usr/local/libexec/indentured/ios-session-stop"
args = []
timeout_sec = 120

[tasks.ios_simulator.session.actions.observe]
executable = "/usr/local/libexec/indentured/ios-session-observe"
args = []
timeout_sec = 60

[tasks.ios_simulator.session.actions.observe.artifacts]
include = ["observations/**"]
exclude = []

[tasks.ios_simulator.session.actions.act]
executable = "/usr/local/libexec/indentured/ios-session-act"
args = []
timeout_sec = 60
```

`setup` builds once. `run` creates, boots, installs, and launches one simulator once. Later CLI invocations execute only the named `observe` or `act` command in the retained workspace.

## Wrapper contract

Install wrappers as root-owned, non-writable executable files. The snippets are illustrative; production wrappers must check every command and validate expected files. `ios-session-driver` is an operator-owned fixed executable. JSON fields remain data and never become shell text, paths, environment, timeouts, or artifact policy.

The driver also owns all session-state file I/O. `publish-pending-name` generates an exact unique `indentured-<UUID>` name and durably publishes it before printing it. `publish-udid` publishes one validated UUID. Each publisher must pin the state directory with `openat(2)`/`O_DIRECTORY|O_NOFOLLOW`, verify its identity, lstat and reject an existing target including a dangling symlink, create a mode-`0600` random temporary file with `mkstemp(3)`/`O_EXCL|O_NOFOLLOW`, write and `fsync`, publish relative to the pinned directory with `linkat(2)`/hard-link no-replace semantics, `fsync` the directory, unlink the temporary name, and reopen/validate through the strict reader before success. It must never use predictable `> .tmp`, rename-overwrite, or a path-following `cat`/`wc` sequence.

`read-udid` and `read-pending-name` use descriptor-relative `openat(2)` with `O_NOFOLLOW`, require a regular file with one exactly framed line, verify inode identity through open, and validate respectively a UUID or exact `indentured-<UUID>` name. `clear-journal` verifies the opened inode and expected value before descriptor-relative unlink. `resolve-created-udid --name NAME` parses `simctl list devices -j` and returns a UUID only when that exact operator-generated name identifies one simulator; exit 3 means absent and every ambiguity/inspection failure is an error. `device-state --udid UUID` prints only `present` or `absent`. Every operation validates UUIDs and rejects `booted`.

`capture-command-output` pins the state directory, creates its capture with the same exclusive no-follow temporary-file rules, forks the fixed command with that already-open regular file as stdout, waits, fsyncs, and publishes the capture with hard-link no-replace semantics even when the command exits nonzero. The shell never redirects to or truncates a capture pathname. `parse-create-output` and `clear-capture` reopen/unlink descriptor-relative without following links. `ensure-uuid-evidence` similarly creates final evidence without replacement; on an existing target it succeeds only after a no-follow regular-file read validates exactly the same UUID. Live or dangling symlinks and mismatched content are hard failures.

Build wrapper:

```sh
#!/bin/sh
set -eu
: "${DEVELOPER_DIR:?}"
state_dir="$PWD/.indentured-session"
if test -L "$state_dir" || { test -e "$state_dir" && test ! -d "$state_dir"; }; then
  exit 1
fi
if test ! -d "$state_dir"; then /bin/mkdir -m 700 "$state_dir"; fi
test -d "$state_dir" && test ! -L "$state_dir"
/bin/mkdir -p observations session-final
exec /usr/bin/xcrun xcodebuild \
  -scheme Example \
  -configuration Debug \
  -sdk iphonesimulator \
  -derivedDataPath "$PWD/.derived-data" \
  build
```

Initialization wrapper. The pending-name ownership journal is securely persisted before `simctl create`, so even invalid output or failed/interrupted inspection leaves exact retryable ownership. Signals are deferred while a signal-ignoring supervised create child finishes. A remembered signal then resolves only the journaled exact name, deletes/verifies it when possible, and exits nonzero; if resolution or deletion cannot complete, the journal remains for configured teardown. Invalid, missing, or mismatched create output also returns nonzero even when exact-name inspection recovers a UUID: the recovered UUID is securely journaled alongside the pending name and left for configured teardown. Only valid matching create output permits pending ownership to clear and boot/install/launch to continue.

```sh
#!/bin/sh
set -eu
: "${DEVELOPER_DIR:?}" "${SIMULATOR_RUNTIME:?}" "${SIMULATOR_DEVICE_TYPE:?}"
driver=/usr/local/libexec/indentured/ios-session-driver
state_dir="$PWD/.indentured-session"
pending_file="$state_dir/pending-simulator-name"
udid_file="$state_dir/simulator.udid"
app="$PWD/.derived-data/Build/Products/Debug-iphonesimulator/Example.app"
test -d "$state_dir" && test ! -L "$state_dir" && test -d "$app"
for target in "$pending_file" "$udid_file"; do
  test ! -e "$target" && test ! -L "$target"
done
created_udid=
pending_signal=0
umask 077

cleanup_pending() {
  rc=$1
  trap - EXIT HUP INT TERM
  set +e
  name=$($driver read-pending-name --path "$pending_file")
  if test $? -ne 0; then exit 1; fi
  if test -n "$created_udid"; then
    cleanup_udid=$created_udid
    resolve_rc=0
  else
    cleanup_udid=$($driver resolve-created-udid --name "$name")
    resolve_rc=$?
  fi
  if test "$resolve_rc" -eq 3; then
    $driver clear-journal --path "$pending_file" --expected "$name" || exit 1
    exit "$rc"
  fi
  if test "$resolve_rc" -ne 0; then
    # Inspection failed: retain the exact pending-name journal for teardown.
    exit 1
  fi
  $driver validate-udid --udid "$cleanup_udid" || exit 1
  /usr/bin/xcrun simctl shutdown "$cleanup_udid" 2>/dev/null || true
  if ! /usr/bin/xcrun simctl delete "$cleanup_udid" 2>/dev/null; then
    test "$($driver device-state --udid "$cleanup_udid")" = absent || exit 1
  fi
  test "$($driver device-state --udid "$cleanup_udid")" = absent || exit 1
  $driver clear-journal --path "$pending_file" --expected "$name" || exit 1
  exit "$rc"
}
remember_hup() { pending_signal=129; }
remember_int() { pending_signal=130; }
remember_term() { pending_signal=143; }

# Secure publication happens before create. If assignment is interrupted, the
# journal—not a shell variable—remains the teardown source of truth.
create_name=$($driver publish-pending-name \
  --directory "$state_dir" --target "$pending_file")
test "$($driver read-pending-name --path "$pending_file")" = "$create_name"

trap 'cleanup_pending $?' EXIT
trap remember_hup HUP
trap remember_int INT
trap remember_term TERM
create_capture="$state_dir/create-output-$create_name"
(
  trap '' HUP INT TERM
  exec $driver capture-command-output \
    --directory "$state_dir" --target "$create_capture" -- \
    /usr/bin/xcrun simctl create \
    "$create_name" "$SIMULATOR_DEVICE_TYPE" "$SIMULATOR_RUNTIME"
) &
create_pid=$!
set +e
while :; do
  wait "$create_pid"
  create_rc=$?
  kill -0 "$create_pid" 2>/dev/null || break
done
create_output_udid=$($driver parse-create-output --path "$create_capture")
parse_rc=$?
$driver clear-capture --path "$create_capture"
capture_clear_rc=$?

# Exact-name resolution is authoritative even when create output looks valid.
# Inspection failure retains the pending journal and exits nonzero.
created_udid=$($driver resolve-created-udid --name "$create_name")
resolve_rc=$?
if test "$resolve_rc" -ne 0; then exit 1; fi
$driver validate-udid --udid "$created_udid" || exit 1
output_valid=0
if test "$parse_rc" -eq 0; then
  $driver validate-udid --udid "$create_output_udid" || exit 1
  if test "$create_output_udid" = "$created_udid"; then output_valid=1; fi
fi
set -e

# Securely journal the recovered exact UUID before deciding whether create was
# successful. Invalid/missing/mismatched output can therefore never continue.
$driver publish-udid \
  --directory "$state_dir" --target "$udid_file" --udid "$created_udid"
persisted_udid=$($driver read-udid --path "$udid_file")
test "$persisted_udid" = "$created_udid"
if test "$create_rc" -ne 0 || test "$capture_clear_rc" -ne 0 || \
   test "$output_valid" -ne 1; then
  # Retain both exact journals for configured teardown, then fail.
  created_udid=
  trap - EXIT HUP INT TERM
  exit 1
fi
if test "$pending_signal" -ne 0; then cleanup_pending "$pending_signal"; fi
$driver clear-journal --path "$pending_file" --expected "$create_name"
created_udid=
trap - EXIT HUP INT TERM
if test "$pending_signal" -ne 0; then exit "$pending_signal"; fi

/usr/bin/xcrun simctl boot "$persisted_udid"
/usr/bin/xcrun simctl bootstatus "$persisted_udid" -b
/usr/bin/xcrun simctl install "$persisted_udid" "$app"
/usr/bin/xcrun simctl launch "$persisted_udid" "$APP_BUNDLE_ID"
```

Observe wrapper:

```sh
#!/bin/sh
set -eu
driver=/usr/local/libexec/indentured/ios-session-driver
IFS= read -r input || test -n "$input"
udid=$($driver read-udid --path "$PWD/.indentured-session/simulator.udid")
# The fixed helper validates both JSON data and the UUID again.
printf '%s' "$input" | $driver observe --udid "$udid"
/usr/bin/xcrun simctl io "$udid" screenshot "$PWD/observations/screen.png"
```

Act wrapper:

```sh
#!/bin/sh
set -eu
driver=/usr/local/libexec/indentured/ios-session-driver
IFS= read -r input || test -n "$input"
udid=$($driver read-udid --path "$PWD/.indentured-session/simulator.udid")
printf '%s' "$input" | $driver act --udid "$udid"
```

Idempotent teardown handles either journal. Corrupt/dangling state is a hard failure and is never passed to `simctl`. A pending-name journal is resolved only as one exact operator-generated name. An already absent device is success; ambiguity, inspection failure, or unverifiable deletion retains the journal and fails. Success evidence is written only after UUID and pending ownership are both verified absent.

```sh
#!/bin/sh
set -eu
driver=/usr/local/libexec/indentured/ios-session-driver
state_dir="$PWD/.indentured-session"
pending_file="$state_dir/pending-simulator-name"
udid_file="$state_dir/simulator.udid"
final_dir="$PWD/session-final"
evidence_file="$final_dir/deleted-udid.txt"
test -d "$state_dir" && test ! -L "$state_dir"
for target in "$pending_file" "$udid_file" "$evidence_file"; do
  if test -L "$target"; then exit 1; fi
done
if test -L "$final_dir" || { test -e "$final_dir" && test ! -d "$final_dir"; }; then
  exit 1
fi
if test ! -d "$final_dir"; then /bin/mkdir -m 700 "$final_dir"; fi
test -d "$final_dir" && test ! -L "$final_dir"

delete_udid() {
  target_udid=$1
  $driver validate-udid --udid "$target_udid"
  state=$($driver device-state --udid "$target_udid")
  case "$state" in
    absent) return 0 ;;
    present)
      /usr/bin/xcrun simctl terminate \
        "$target_udid" "$APP_BUNDLE_ID" 2>/dev/null || true
      /usr/bin/xcrun simctl shutdown "$target_udid" 2>/dev/null || true
      if ! /usr/bin/xcrun simctl delete "$target_udid"; then
        test "$($driver device-state --udid "$target_udid")" = absent
      fi
      ;;
    *) return 1 ;;
  esac
  test "$($driver device-state --udid "$target_udid")" = absent
}

cleaned_udid=
if test -e "$udid_file"; then
  cleaned_udid=$($driver read-udid --path "$udid_file")
  delete_udid "$cleaned_udid"
fi
if test -e "$pending_file"; then
  pending_name=$($driver read-pending-name --path "$pending_file")
  set +e
  pending_udid=$($driver resolve-created-udid --name "$pending_name")
  resolve_rc=$?
  set -e
  case "$resolve_rc" in
    0)
      $driver validate-udid --udid "$pending_udid"
      if test -n "$cleaned_udid"; then
        test "$pending_udid" = "$cleaned_udid" || exit 1
      fi
      delete_udid "$pending_udid"
      cleaned_udid=${cleaned_udid:-$pending_udid}
      ;;
    3) ;; # Exact pending name is already absent.
    *) exit 1 ;; # Retain journal after ambiguity/inspection failure.
  esac
  $driver clear-journal --path "$pending_file" --expected "$pending_name"
fi
if test -n "$cleaned_udid"; then
  test "$($driver device-state --udid "$cleaned_udid")" = absent
  $driver ensure-uuid-evidence \
    --directory "$final_dir" --target "$evidence_file" --udid "$cleaned_udid"
  test "$($driver read-udid --path "$evidence_file")" = "$cleaned_udid"
fi
```

Initialization, actions, and teardown still receive Indentured's normal process-group cleanup. CoreSimulator is an external OS service and may outlive one wrapper command through its supported per-user service/bootstrap context; workspace files retain the explicit UDID. Do not background or daemonize a child merely to evade Indentured's reaping.

## Native Mac acceptance gate

Run the gate as the exact launchd task identity and against the pinned Xcode/runtime before accepting a deployment:

1. `xcode-select`/`DEVELOPER_DIR` and `xcrun simctl list runtimes -j` confirm the configured Xcode and exact runtime are installed and available.
2. The task identity can create, boot, install, launch, observe, act on, shut down, and delete an explicitly recorded UDID; it never selects `booted`.
3. `indentured session start ios_simulator`, multiple `session action` invocations, and `session stop` use separate CLI processes while the build occurs only once.
4. Observe returns a screenshot artifact; an ordinary nonzero action leaves the session reusable.
5. Explicit stop deletes the simulator. Idle expiry, maximum lifetime, action disconnect, daemon restart, and partial initialization also run idempotent teardown or are reconciled as documented. Native fault injection covers signals during create, invalid/missing create output, inspection failure, delete failure, pre-existing/dangling journals, and races at both no-clobber publications. Failures retain the exact pending journal; after a successful retry, `xcrun simctl list devices -j` shows the recorded UUID or exact pending name absent.
6. The task runs in the intended per-user launchd/bootstrap context. If a system LaunchDaemon cannot reach that CoreSimulator context after privilege drop, deployment automation must provide a supported external per-user service handoff; do not weaken daemon ownership or run simulator actions as root.
7. The task cannot read or modify bearer credentials, launchd configuration, daemon logs, artifact storage, control sockets, or another user's simulator state.

Record the Xcode build, runtime identifier, device type, task UID/GID/groups, every created UDID, cleanup result, and native host. Linux tests and cross-compilation are not CoreSimulator attestation. Deployment automation can set `INDENTURED_DARWIN_SESSION_GATE` to an absolute operator-owned executable that performs the checks above against the live service; `scripts/check-darwin.sh` runs it and propagates failure. Without that executable the script prints `UNATTESTED` and makes no runtime claim.
