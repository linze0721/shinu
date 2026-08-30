#!/bin/sh
# Check host prerequisites before installation.
#
# Usage: preflight.sh [root-path] (default /var/lib/shinu)
set -u

ROOT="${1:-/var/lib/shinu}"
FAIL=0
WARN=0

red()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
warn() { printf '  WARN  %s\n' "$1"; WARN=$((WARN + 1)); }
ok()   { printf '  ok    %s\n' "$1"; }

printf 'shinu preflight: %s\n\n' "$ROOT"

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
    if grep -Eq '(^|[[:space:]])(vmx|svm)($|[[:space:]])' /proc/cpuinfo; then
        ok "CPU exposes hardware virtualisation (vmx/svm)"
    else
        case "$?" in
            1) red "CPU exposes no vmx/svm flag: this host cannot run Firecracker" ;;
            *) red "could not inspect /proc/cpuinfo for hardware virtualisation flags" ;;
        esac
    fi
else
    red "/proc/cpuinfo is unreadable: cannot verify hardware virtualisation"
fi

echo
printf '%s\n' 'filesystem'
TARGET="$ROOT"
case "$TARGET" in
    -*) TARGET="./$TARGET" ;;
esac
while [ ! -d "$TARGET" ]; do
    PARENT="$(dirname "$TARGET")"
    if [ "$PARENT" = "$TARGET" ]; then
        TARGET=/
        break
    fi
    TARGET="$PARENT"
done
case "$TARGET" in
    /*|./*) ;;
    *) TARGET="./$TARGET" ;;
esac
if FSTYPE="$(stat -f -c %T "$TARGET" 2>/dev/null)"; then
    :
else
    FSTYPE=unknown
fi
case "$FSTYPE" in
    btrfs|xfs)
        ok "$TARGET is $FSTYPE (supports reflink)"

        # Filesystem type alone is not enough; verify an actual CoW clone.
        PROBE="$TARGET/.shinu-reflink-probe.$$"
        if mkdir "$PROBE" 2>/dev/null; then
            if dd if=/dev/zero of="$PROBE/src" bs=4k count=1 >/dev/null 2>&1; then
                if cp --reflink=always -- "$PROBE/src" "$PROBE/dst" >/dev/null 2>&1; then
                    ok "cp --reflink=always works here"
                else
                    red "cp --reflink=always failed on $TARGET: every space creation would fail the same way"
                fi
            else
                red "cannot write reflink probe on $TARGET: every space creation would fail the same way"
            fi
            if ! rm -rf "$PROBE"; then
                warn "could not remove reflink probe $PROBE"
            fi
        else
            red "cannot create reflink probe on $TARGET: check permissions"
        fi
        ;;
    *)
        red "$TARGET is $FSTYPE: spaces are cloned with cp --reflink=always, which needs btrfs or reflink-capable xfs"
        ;;
esac

echo
echo "required binaries"
MISSING=""
for bin in curl tar mkfs.ext4 e2fsck resize2fs mount umount truncate \
           ssh ssh-keygen setsid cp chown btrfs df kill ip iptables unshare chroot \
           sha256sum uname cat dd dirname grep id mkdir rm stat; do
    command -v "$bin" >/dev/null 2>&1 || MISSING="$MISSING $bin"
done
if [ -n "$MISSING" ]; then
    red "missing:$MISSING"
else
    ok "all external binaries present"
fi

echo
echo "privileges and kernel"
if [ "$(id -u 2>/dev/null)" = "0" ]; then
    ok "running as root"
else
    red "shinud must run as root (loop devices, tap interfaces, iptables)"
fi

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    ok "cgroup v2 mounted (jailer resource limits)"
elif [ -d /sys/fs/cgroup ]; then
    warn "cgroup v1 detected: the jailer expects cgroup v2"
else
    red "cgroup hierarchy missing: the jailer expects cgroup v2 at /sys/fs/cgroup"
fi

if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || printf 0)" = "1" ]; then
    ok "net.ipv4.ip_forward is on"
else
    warn "net.ipv4.ip_forward is off: guests will have no egress until it is enabled"
fi

if command -v modprobe >/dev/null 2>&1; then
    modprobe vhost_vsock >/dev/null 2>&1 || :
fi
if [ -e /dev/vhost-vsock ]; then
    ok "vhost_vsock available (exec transport)"
else
    red "/dev/vhost-vsock missing: exec tunnels over AF_VSOCK and cannot work without it"
fi

printf '\n'
if [ "$FAIL" -gt 0 ]; then
    printf 'not ready: %s blocking, %s warning\n' "$FAIL" "$WARN"
    exit 1
fi
if [ "$WARN" -gt 0 ]; then
    printf 'ready (%s warning)\n' "$WARN"
else
    printf 'ready\n'
fi
