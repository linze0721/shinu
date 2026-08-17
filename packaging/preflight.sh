#!/bin/sh
# Checks whether this host can run shinud, before anything is installed.
#
# Every condition here has a known failure mode that otherwise surfaces late
# and misleadingly: a missing /dev/kvm looks like a Firecracker crash, a
# non-btrfs root looks like a space-creation error, and a missing binary
# looks like a build failure inside a guest. Failing here names the cause.
#
# Usage: preflight.sh [root-path]   (default /var/lib/shinu)
set -u

ROOT="${1:-/var/lib/shinu}"
FAIL=0
WARN=0

red()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
warn() { printf '  WARN  %s\n' "$1"; WARN=$((WARN + 1)); }
ok()   { printf '  ok    %s\n' "$1"; }

echo "shinu preflight: $ROOT"
echo

echo "virtualisation"
if [ -e /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        ok "/dev/kvm present and accessible"
    else
        red "/dev/kvm exists but is not readable/writable by this user (run as root)"
    fi
else
    red "/dev/kvm missing: bare metal needs VT-x/AMD-V enabled in firmware; a VPS needs nested virtualisation from its provider"
fi

if [ -r /proc/cpuinfo ]; then
    if grep -qE '^flags.*\b(vmx|svm)\b' /proc/cpuinfo; then
        ok "CPU exposes hardware virtualisation (vmx/svm)"
    else
        red "CPU exposes no vmx/svm flag: this host cannot run Firecracker"
    fi
fi

echo
echo "filesystem"
if [ -d "$ROOT" ]; then
    TARGET="$ROOT"
else
    TARGET="$(dirname "$ROOT")"
    [ -d "$TARGET" ] || TARGET=/
fi
FSTYPE="$(stat -f -c %T "$TARGET" 2>/dev/null || echo unknown)"
case "$FSTYPE" in
    btrfs|xfs)
        ok "$TARGET is $FSTYPE (supports reflink)"
        ;;
    *)
        red "$TARGET is $FSTYPE: spaces are cloned with cp --reflink=always, which needs btrfs or reflink-capable xfs"
        ;;
esac

# A filesystem that claims support can still refuse the call, so prove it.
PROBE="$TARGET/.shinu-reflink-probe.$$"
if dd if=/dev/zero of="$PROBE.src" bs=4k count=1 >/dev/null 2>&1; then
    if cp --reflink=always "$PROBE.src" "$PROBE.dst" >/dev/null 2>&1; then
        ok "cp --reflink=always works here"
    else
        red "cp --reflink=always failed on $TARGET: every space creation would fail the same way"
    fi
    rm -f "$PROBE.src" "$PROBE.dst"
fi

echo
echo "required binaries"
MISSING=""
for bin in curl tar mkfs.ext4 e2fsck mount umount truncate ssh ssh-keygen \
           setsid cp chown btrfs df kill ip iptables unshare debugfs losetup; do
    command -v "$bin" >/dev/null 2>&1 || MISSING="$MISSING $bin"
done
if [ -n "$MISSING" ]; then
    red "missing:$MISSING"
else
    ok "all external binaries present"
fi

echo
echo "privileges and kernel"
[ "$(id -u)" -eq 0 ] && ok "running as root" \
                     || red "shinud must run as root (loop devices, tap interfaces, iptables)"

if [ -d /sys/fs/cgroup ]; then
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        ok "cgroup v2 mounted (jailer resource limits)"
    else
        warn "cgroup v1 detected: the jailer expects cgroup v2"
    fi
fi

if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
    ok "net.ipv4.ip_forward is on"
else
    warn "net.ipv4.ip_forward is off: guests will have no egress until it is enabled"
fi

modprobe vhost_vsock >/dev/null 2>&1
if [ -e /dev/vhost-vsock ]; then
    ok "vhost_vsock available (exec transport)"
else
    red "/dev/vhost-vsock missing: exec tunnels over AF_VSOCK and cannot work without it"
fi

echo
if [ "$FAIL" -gt 0 ]; then
    echo "not ready: $FAIL blocking, $WARN warning"
    exit 1
fi
echo "ready${WARN:+ ($WARN warning)}"
