#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  if command -v devenv >/dev/null 2>&1 && [ "${INDENTURED_PACKAGED_IN_DEVENV:-0}" != 1 ]; then
    exec devenv shell env INDENTURED_PACKAGED_IN_DEVENV=1 "$0"
  fi
  echo "cargo is required; run through 'devenv tasks run integration:packaged-local'" >&2
  exit 2
fi

server_out=$(nix build --no-link --print-out-paths .#indentured-server)
client_out=$(nix build --no-link --print-out-paths .#indentured)

test "$(printf '%s\n' "$server_out" | wc -l | tr -d ' ')" -eq 1 || {
  echo "expected one server output path" >&2
  exit 1
}
test "$(printf '%s\n' "$client_out" | wc -l | tr -d ' ')" -eq 1 || {
  echo "expected one client output path" >&2
  exit 1
}

test -x "$server_out/bin/indentured-server"
test ! -e "$server_out/bin/indentured"
test -x "$client_out/bin/indentured"
test ! -e "$client_out/bin/indentured-server"

export INDENTURED_TEST_SERVER_BIN="$server_out/bin/indentured-server"
export INDENTURED_TEST_CLIENT_BIN="$client_out/bin/indentured"

cargo test --locked --offline --test packaged_local_integration packaged_local_flow -- --exact --ignored --nocapture
