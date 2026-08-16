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

# `shinu` and `shinu-vsock` are a unit; `shinud` is the privileged daemon.
install -d -m 0755 "$BIN"
for binary in shinu shinu-vsock shinud; do
    install -m 0755 "$SRC/target/release/$binary" "$BIN/$binary"
done

install -d -m 0755 "$SVDIR/shinud"
install -m 0755 "$SRC/packaging/sv/shinud/run" "$SVDIR/shinud/run"

echo "installed to $BIN; enable with: ln -s $SVDIR/shinud /var/service/"
echo
echo "runtime requirements on this host:"
echo "  /dev/kvm present, root on btrfs (spaces are reflink clones)"
echo "  external commands: curl tar mkfs.ext4 e2fsck mount umount truncate"
echo "                     ssh ssh-keygen setsid cp chown btrfs df kill"
