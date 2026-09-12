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

printf '%s\n' '{"probe":"devenv-stdin"}' | devenv tasks run integration:stdin-probe >/dev/null

server_out=$(nix build --no-link --print-out-paths .#indentured-server)
client_out=$(nix build --no-link --print-out-paths .#indentured)
host_out=$(nix build --no-link --print-out-paths .#indentured-host)

test "$(printf '%s\n' "$server_out" | wc -l | tr -d ' ')" -eq 1 || {
  echo "expected one server output path" >&2
  exit 1
}
test "$(printf '%s\n' "$client_out" | wc -l | tr -d ' ')" -eq 1 || {
  echo "expected one client output path" >&2
  exit 1
}

test "$(printf '%s\n' "$host_out" | wc -l | tr -d ' ')" -eq 1 || {
  echo "expected one host-helper output path" >&2
  exit 1
}

test -x "$server_out/bin/indentured-server"
test ! -e "$server_out/bin/indentured"
test -x "$client_out/bin/indentured"
test ! -e "$client_out/bin/indentured-server"
test -x "$host_out/bin/indentured-host"
test ! -e "$host_out/bin/indentured-server"
test ! -e "$host_out/bin/indentured"
test ! -e "$server_out/bin/indentured-host"
test ! -e "$client_out/bin/indentured-host"
"$host_out/bin/indentured-host" --help >/dev/null

# Preserve the outer namespace identity so the optional host fixture can prove
# it is mounting only inside the private namespace created below.
INDENTURED_TEST_OUTER_MOUNT_NS=$(readlink /proc/self/ns/mnt)
export INDENTURED_TEST_OUTER_MOUNT_NS

export INDENTURED_TEST_SERVER_BIN="$server_out/bin/indentured-server"
export INDENTURED_TEST_CLIENT_BIN="$client_out/bin/indentured"
INDENTURED_TEST_ID_COMMAND=$(command -v id)
case "$INDENTURED_TEST_ID_COMMAND" in
  /*) ;;
  *)
    echo "id must resolve to an absolute executable path" >&2
    exit 2
    ;;
esac
export INDENTURED_TEST_ID_COMMAND

if [ "$(id -u)" -eq 0 ]; then
  if [ -z "${INDENTURED_TEST_TASK_USER:-}" ]; then
    INDENTURED_TEST_TASK_USER=nobody
  fi
  if [ -z "${INDENTURED_TEST_TASK_GROUP:-}" ]; then
    INDENTURED_TEST_TASK_GROUP=$(id -gn "$INDENTURED_TEST_TASK_USER")
  fi
  export INDENTURED_TEST_TASK_USER INDENTURED_TEST_TASK_GROUP
  test "$(id -u "$INDENTURED_TEST_TASK_USER")" -ne 0 || {
    echo "packaged session task identity must be non-root" >&2
    exit 2
  }
  if [ "$(uname -s)" != Linux ] || ! command -v unshare >/dev/null 2>&1; then
    echo "packaged lifecycle validation requires Linux PID-namespace isolation; refusing to run descendants unsupervised" >&2
    exit 2
  fi
  exec unshare --pid --fork --kill-child=KILL --mount-proc \
    env INDENTURED_TEST_TASK_USER="$INDENTURED_TEST_TASK_USER" \
    INDENTURED_TEST_TASK_GROUP="$INDENTURED_TEST_TASK_GROUP" \
    INDENTURED_TEST_ID_COMMAND="$INDENTURED_TEST_ID_COMMAND" \
    INDENTURED_TEST_SERVER_BIN="$INDENTURED_TEST_SERVER_BIN" \
    INDENTURED_TEST_CLIENT_BIN="$INDENTURED_TEST_CLIENT_BIN" \
    cargo test --locked --offline --test packaged_local_integration -- --ignored --nocapture --test-threads=1
fi

if [ "$(uname -s)" != Linux ] || ! command -v unshare >/dev/null 2>&1; then
  echo "managed-session packaged validation needs a root daemon and distinct task user; rerun this task through an isolated root test environment" >&2
  exit 2
fi

user=$(id -un)
group=$(id -gn)
uid=$(id -u)
subuid=$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subuid)
subgid=$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subgid)
subgid_count=$(awk -F: -v user="$user" '$1 == user { print $3; exit }' /etc/subgid)
test -n "$subuid" && test -n "$subgid" && test -n "$subgid_count" || {
  echo "managed-session packaged validation needs subordinate UID/GID mappings for $user" >&2
  exit 2
}

# The cargo test process is PID 1 in a private PID namespace. If it exits or
# panics, the kernel and --kill-child kill only that namespace's descendants;
# no repository-wide or name-based kill is used.
exec unshare --user --map-root-user \
  --map-users="$uid:$subuid:1" \
  --map-groups="1:$subgid:$subgid_count" \
  --pid --fork --kill-child=KILL --mount-proc \
  env INDENTURED_TEST_TASK_USER="$user" INDENTURED_TEST_TASK_GROUP="$group" \
  INDENTURED_TEST_ID_COMMAND="$INDENTURED_TEST_ID_COMMAND" \
  INDENTURED_TEST_SERVER_BIN="$INDENTURED_TEST_SERVER_BIN" \
  INDENTURED_TEST_CLIENT_BIN="$INDENTURED_TEST_CLIENT_BIN" \
  cargo test --locked --offline --test packaged_local_integration -- --ignored --nocapture --test-threads=1
