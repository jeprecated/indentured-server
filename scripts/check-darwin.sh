#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo "check-darwin.sh must run natively on Apple-silicon Darwin; Linux and cross-checks do not attest Darwin package or runtime behavior" >&2
  exit 2
fi

/usr/bin/plutil -lint launchd/indentured-host.plist.example
# Run the actual JXA bridge against synthetic native CF collections. This is
# deterministic/offline and does not inspect the logged-in user's desktop.
bridge_result=$(/usr/bin/osascript -l JavaScript \
  -e "$(cat src/host_observation/enumerate.js)" \
  -e "$(cat tests/host_observation_bridge.js)")
expected_bridge_result='native host-observation CF/CGRect bridge: passed (no GUI/TCC attestation)'
if [ "$bridge_result" != "$expected_bridge_result" ]; then
  echo "native bridge assertions did not produce the expected success marker: $bridge_result" >&2
  exit 1
fi
printf '%s\n' "$bridge_result" >&2
nix flake check --print-build-logs
nix build --no-link --print-build-logs .#indentured-server .#indentured .#indentured-host

# Native package checks do not prove GUI/TCC or screenshot runtime behavior.
# This optional operator gate must exercise the deployed LaunchAgent and remote
# artifact flow described in docs/macos-host-observation.md.
if [ -n "${INDENTURED_DARWIN_HOST_GATE:-}" ]; then
  case "$INDENTURED_DARWIN_HOST_GATE" in
    /*) ;;
    *)
      echo "INDENTURED_DARWIN_HOST_GATE must be an absolute executable path" >&2
      exit 2
      ;;
  esac
  test -x "$INDENTURED_DARWIN_HOST_GATE" || {
    echo "INDENTURED_DARWIN_HOST_GATE is not executable" >&2
    exit 2
  }
  "$INDENTURED_DARWIN_HOST_GATE"
  echo "native host-observation deployment gate: attested by $INDENTURED_DARWIN_HOST_GATE"
else
  echo "native host-observation deployment gate: UNATTESTED (set INDENTURED_DARWIN_HOST_GATE to the operator-owned live gate)" >&2
fi

# Native package checks do not prove launchd task identity or CoreSimulator behavior.
# Deployment automation may provide an absolute, operator-owned gate executable that
# implements docs/managed-session-ios-simulator-example.md against the live service.
if [ -n "${INDENTURED_DARWIN_SESSION_GATE:-}" ]; then
  case "$INDENTURED_DARWIN_SESSION_GATE" in
    /*) ;;
    *)
      echo "INDENTURED_DARWIN_SESSION_GATE must be an absolute executable path" >&2
      exit 2
      ;;
  esac
  test -x "$INDENTURED_DARWIN_SESSION_GATE" || {
    echo "INDENTURED_DARWIN_SESSION_GATE is not executable" >&2
    exit 2
  }
  "$INDENTURED_DARWIN_SESSION_GATE"
  echo "native managed-session/CoreSimulator deployment gate: attested by $INDENTURED_DARWIN_SESSION_GATE"
else
  echo "native managed-session/CoreSimulator deployment gate: UNATTESTED (set INDENTURED_DARWIN_SESSION_GATE to the operator-owned live gate)" >&2
fi
