#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo "check-darwin.sh must run natively on Apple-silicon Darwin; Linux and cross-checks do not attest Darwin package or runtime behavior" >&2
  exit 2
fi

nix flake check --print-build-logs
nix build --no-link --print-build-logs .#indentured-server .#indentured

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
