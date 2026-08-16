#!/bin/sh
# Installs shinu onto a host.
#
# The three binaries are not interchangeable and one placement rule is load
# bearing: `shinu-vsock` MUST sit next to `shinu`, because `exec` resolves the
# helper through `current_exe()` rather than a compiled-in path. Installing
# only `shinu` and `shinud` yields a system where every `exec` fails with
# "vsock helper missing".
set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN="$PREFIX/bin"
SVDIR="${SVDIR:-/etc/sv}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -x "$SRC/target/release/shinud" ]; then
    echo "build first: cargo build --release" >&2
    exit 1
fi
# Ensure unprivileged jailer user/group (default 30000) exists
JAIL_UID="${SHINU_JAIL_UID:-30000}"
JAIL_GID="${SHINU_JAIL_GID:-30000}"

if ! getent group "$JAIL_GID" >/dev/null 2>&1 && ! getent group shinu-jail >/dev/null 2>&1; then
    groupadd -g "$JAIL_GID" -r shinu-jail 2>/dev/null || addgroup -g "$JAIL_GID" -S shinu-jail 2>/dev/null || true
fi

if ! getent passwd "$JAIL_UID" >/dev/null 2>&1 && ! id -u shinu-jail >/dev/null 2>&1; then
    useradd -u "$JAIL_UID" -g "$JAIL_GID" -r -s /usr/sbin/nologin -d /nonexistent shinu-jail 2>/dev/null || \
    adduser -u "$JAIL_UID" -G shinu-jail -S -D -H -s /sbin/nologin shinu-jail 2>/dev/null || true
fi

# `shinu` and `shinu-vsock` are a unit; `shinud` is the privileged daemon.
install -d -m 0755 "$BIN"
for binary in shinu shinu-vsock shinud; do
    install -m 0755 "$SRC/target/release/$binary" "$BIN/$binary"
done

install -d -m 0755 "$SVDIR/shinud"
sed "s|/usr/local/bin/shinud|$BIN/shinud|g" "$SRC/packaging/sv/shinud/run" > "$SVDIR/shinud/run"
chmod 0755 "$SVDIR/shinud/run"

echo "installed to $BIN; enable with: ln -s $SVDIR/shinud /var/service/"
echo
echo "runtime requirements on this host:"
echo "  /dev/kvm present, root on btrfs (spaces are reflink clones)"
echo "  jailer user/group (uid/gid $JAIL_UID/$JAIL_GID) and cgroup v2 enabled"
echo "  external commands: curl tar mkfs.ext4 e2fsck mount umount truncate"
echo "                     ssh ssh-keygen setsid cp chown btrfs df kill"
