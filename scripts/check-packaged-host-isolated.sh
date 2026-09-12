#!/bin/sh
# Test-only coherent filesystem ownership inside the packaged test's existing
# user/mount/PID namespace. No host mount or account policy is changed.
set -eu
[ "$(id -u)" = 0 ] || { echo 'host fixture requires namespace root' >&2; exit 2; }
[ -n "${INDENTURED_TEST_OUTER_MOUNT_NS:-}" ] &&
  [ "$(readlink /proc/self/ns/mnt)" != "$INDENTURED_TEST_OUTER_MOUNT_NS" ] || {
  echo 'host fixture refuses to mount outside the packaged private mount namespace' >&2
  exit 2
}
mount --make-rprivate /
root=$(mktemp -d /tmp/indentured-host-test-root.XXXXXX)
cleanup() {
  set +e
  umount -l "$root/dev/null" 2>/dev/null
  umount -l "$root/proc" 2>/dev/null
  umount -l "$root/bin/host-test" 2>/dev/null
  umount -l "$root/nix/store" 2>/dev/null
  # Never recursively remove a still-mounted store, even on cleanup failure.
  if mountpoint -q "$root/nix/store" || mountpoint -q "$root/bin/host-test" || mountpoint -q "$root/proc" || mountpoint -q "$root/dev/null"; then
    echo "leaving test root for namespace teardown: $root" >&2
  else
    rm -rf "$root"
  fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$root/nix/store" "$root/bin" "$root/etc" "$root/tmp" "$root/run/host-test" "$root/proc" "$root/dev"
chmod 700 "$root/run/host-test" "$root/tmp"
cp /etc/passwd /etc/group "$root/etc/"
mount --bind /nix/store "$root/nix/store"
mount -o remount,bind,ro /nix/store "$root/nix/store"
: > "$root/bin/host-test"
mount --bind "$1" "$root/bin/host-test"
mount -o remount,bind,ro "$1" "$root/bin/host-test"
mount -t proc -o ro proc "$root/proc"
: > "$root/dev/null"
mount --bind /dev/null "$root/dev/null"
# Compile outside; run only this test inside. The outer namespace remains the
# kill/reap boundary; timeout bounds a test failure without touching other hosts.
INDENTURED_HOST_TEST_ROOT=1 XDG_RUNTIME_DIR=/run/host-test TMPDIR=/tmp HOME=/tmp \
  timeout 60s chroot "$root" /bin/host-test \
    --exact packaged_host_observation_is_source_free_and_uses_normal_artifacts --ignored --nocapture
