#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo "check-darwin.sh must run natively on Apple-silicon Darwin; Linux and cross-checks do not attest Darwin package or runtime behavior" >&2
  exit 2
fi

nix flake check --print-build-logs
nix build --no-link --print-build-logs .#indentured-server .#indentured
