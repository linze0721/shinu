#!/bin/sh
# Destructive host smoke test for a real KVM + reflink filesystem + cgroup-v2 host.
#
# The harness owns one temporary daemon root and one loopback listener. It does
# not change accounts, install binaries, or reuse an operator's shinu root.
#
# Usage:
#   host-smoke.sh [--shinu-bin PATH] [--shinud-bin PATH]
#                [--root-parent DIR] [--port PORT]
#
# The same values may be supplied with SHINU_BIN, SHINUD_BIN,
# SHINU_SMOKE_ROOT_PARENT, and SHINU_SMOKE_PORT. The shinu-vsock helper must
# live beside the selected shinu binary, as it does in an installed release.

set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

SHINU_BIN=${SHINU_BIN:-$REPO_ROOT/target/release/shinu}
SHINUD_BIN=${SHINUD_BIN:-$REPO_ROOT/target/release/shinud}
ROOT_PARENT=${SHINU_SMOKE_ROOT_PARENT:-${SHINU_ROOT_PARENT:-$REPO_ROOT}}
PORT=${SHINU_SMOKE_PORT:-17878}

ROOT=
ROOT_MARKER=
DAEMON_PID=
DAEMON_START_TIME=
DAEMON_LOG=
TOKEN_A=
TOKEN_B=
TRACK_A=
TRACK_B=
CLI_OUT=
CLI_ERR=

PROJECT_A=smoke-project-a
PROJECT_B=smoke-project-b
NETWORK=smoke-lan
SPACE_MAIN=smoke-main
SPACE_PEER=smoke-peer
SPACE_BETA=smoke-beta
SPACE_FORK=smoke-fork
SPACE_REMOVE=smoke-remove
GUEST_HTTP_PORT=18080
NET_BASE=172.30
export SHINU_NET_BASE="$NET_BASE"

LEDGER=
BASE_TAPS=
BASE_IPTABLES=
BASE_LOOPS=
BASE_CGROUPS=
BASE_PROCESSES=
BASELINE_COMPLETE=
BASE_INPUT_JUMP=
BASE_INPUT_CHAIN=
OWNED_TAPS=
OWNED_IPTABLES=
OWNED_LOOPS=
OWNED_CGROUPS=
OWNED_PROCESSES=
OWNED_INPUT_JUMP=
OWNED_INPUT_CHAIN=

LAST_SPACE_ID=
LAST_COMMIT_ID=
LAST_COMMIT_SHORT=

fail() {
    printf 'host-smoke: FAIL: %s\n' "$*" >&2
    exit 1
}

step() {
    printf 'host-smoke: %s\n' "$*"
}

usage() {
    cat <<'EOF'
usage: packaging/host-smoke.sh [options]

Options:
  --shinu-bin PATH    shinu client binary (default target/release/shinu)
  --shinud-bin PATH   shinud daemon binary (default target/release/shinud)
  --root-parent DIR   reflink-capable parent for the isolated root
  --port PORT         loopback daemon port (default 17878)
  --help              show this help
EOF
}

# Signal traps pass an explicit nonzero status. The EXIT trap passes the status
# that caused the shell to leave, avoiding the common signal-to-success bug.
cleanup() {
    rc=$1
    trap - 0 1 2 3 15
    set +e
    cleanup_ok=1
    baseline_ready=1

    if [ -n "${ROOT:-}" ]; then
        if [ ! -f "${ROOT_MARKER:-}" ] \
            || [ ! -f "${BASELINE_COMPLETE:-}" ] \
            || [ "$(cat "$BASELINE_COMPLETE" 2>/dev/null || printf '')" != baseline-complete-v1 ] \
            || [ ! -f "${BASE_TAPS:-}" ] || [ ! -f "${BASE_IPTABLES:-}" ] \
            || [ ! -f "${BASE_LOOPS:-}" ] || [ ! -f "${BASE_CGROUPS:-}" ] \
            || [ ! -f "${BASE_PROCESSES:-}" ] || [ ! -f "${BASE_INPUT_JUMP:-}" ] \
            || [ ! -f "${BASE_INPUT_CHAIN:-}" ]; then
            printf 'host-smoke: refusing cleanup with incomplete host baseline: %s\n' "$ROOT" >&2
            cleanup_ok=0
            baseline_ready=0
        fi

        if [ "$baseline_ready" -eq 1 ] && command -v record_owned_resources >/dev/null 2>&1; then
            if ! record_owned_resources; then
                cleanup_ok=0
            fi
        fi


        daemon_owned=0
        if [ -n "${DAEMON_PID:-}" ]; then
            if daemon_identity "$DAEMON_PID" "$DAEMON_START_TIME"; then
                daemon_owned=1
                stop_tracked_spaces "$TOKEN_A" "$TRACK_A"
                stop_tracked_spaces "$TOKEN_B" "$TRACK_B"
                if daemon_identity "$DAEMON_PID" "$DAEMON_START_TIME"; then
                    kill -TERM "$DAEMON_PID" >/dev/null 2>&1 || cleanup_ok=0
                    wait "$DAEMON_PID" >/dev/null 2>&1 || :
                elif [ -e "/proc/$DAEMON_PID" ]; then
                    printf 'host-smoke: daemon identity changed before cleanup signal\n' >&2
                    cleanup_ok=0
                fi
            elif [ -e "/proc/$DAEMON_PID" ]; then
                printf 'host-smoke: refusing to signal an untrusted daemon pid %s\n' "$DAEMON_PID" >&2
                cleanup_ok=0
            fi
            DAEMON_PID=
        fi

        # If the daemon died before its normal stop path, start an isolated
        # recovery instance. It is still subject to exact executable, argv,
        # and /proc start-time checks before any signal is sent.
        if [ "$daemon_owned" -eq 0 ] \
            && { [ -n "${TRACK_A:-}" ] || [ -n "${TRACK_B:-}" ]; } \
            && { [ -n "${TOKEN_A:-}" ] || [ -n "${TOKEN_B:-}" ]; }; then
            recovery_log="$ROOT/cleanup-daemon.log"
            (daemon_exec) > "$recovery_log" 2>&1 &
            recovery_pid=$!
            recovery_start_time=$(proc_start_time "$recovery_pid" 2>/dev/null || printf '')
            recovery_ready=0
            recovery_attempts=0
            while [ "$recovery_attempts" -lt 120 ]; do
                if [ -z "$recovery_start_time" ]; then
                    recovery_start_time=$(proc_start_time "$recovery_pid" 2>/dev/null || printf '')
                fi
                if [ -n "$recovery_start_time" ] && daemon_identity "$recovery_pid" "$recovery_start_time"; then
                    if recovery_status=$(curl --noproxy '*' -sS --max-time 2 -o /dev/null \
                        -w '%{http_code}' "http://127.0.0.1:$PORT/" 2>/dev/null); then
                        if [ "$recovery_status" = 302 ]; then
                            recovery_ready=1
                            break
                        fi
                    fi
                else
                    recovery_cmd=$(proc_args "$recovery_pid" 2>/dev/null || printf '')
                    [ -n "$recovery_cmd" ] || break
                fi
                sleep 1
                recovery_attempts=$((recovery_attempts + 1))
            done
            if [ "$recovery_ready" -eq 1 ]; then
                stop_tracked_spaces "$TOKEN_A" "$TRACK_A"
                stop_tracked_spaces "$TOKEN_B" "$TRACK_B"
            else
                printf 'host-smoke: recovery daemon did not become ready\n' >&2
                cleanup_ok=0
            fi
            if [ -n "$recovery_start_time" ] \
                && daemon_identity "$recovery_pid" "$recovery_start_time"; then
                kill -TERM "$recovery_pid" >/dev/null 2>&1 || cleanup_ok=0
                wait "$recovery_pid" >/dev/null 2>&1 || :
            elif [ -e "/proc/$recovery_pid" ]; then
                printf 'host-smoke: refusing to signal an untrusted recovery pid %s\n' "$recovery_pid" >&2
                cleanup_ok=0
            fi
        fi

        # The ledger is captured before daemon teardown, so a chrooted
        # Firecracker process remains addressable even when its command line no
        # longer contains the host root.
        if [ "$baseline_ready" -eq 1 ] && command -v terminate_owned_processes >/dev/null 2>&1; then
            terminate_owned_processes
            remove_owned_firewall
            remove_owned_loops
            remove_owned_taps
            remove_owned_cgroups
            verify_owned_resources
        fi

        if [ "$cleanup_ok" -eq 1 ] && [ -f "$ROOT_MARKER" ]; then
            if ! rm -rf "$ROOT"; then
                cleanup_ok=0
            fi
            if [ -e "$ROOT" ]; then
                printf 'host-smoke: cleanup could not remove %s\n' "$ROOT" >&2
                cleanup_ok=0
            fi
        fi

        if [ "$cleanup_ok" -ne 1 ]; then
            printf '%s\n' \
                "host-smoke: teardown is uncertain; preserving $ROOT" \
                "host-smoke: inspect $ROOT/host-ledger and remove only its exact owned resources" \
                "host-smoke: do not reuse this root until Firecracker, taps, firewall rules, loops, and cgroups are gone" >&2
            rc=1
        fi
    fi

    [ "$rc" -eq 0 ] || :
    exit "$rc"
}
trap 'cleanup "$?"' 0
trap 'cleanup 129' 1
trap 'cleanup 130' 2
trap 'cleanup 131' 3
trap 'cleanup 143' 15

while [ "$#" -gt 0 ]; do
    case "$1" in
        --shinu-bin|--shinu)
            [ "$#" -ge 2 ] || fail "$1 requires a path"
            SHINU_BIN=$2
            shift 2
            ;;
        --shinud-bin|--shinud)
            [ "$#" -ge 2 ] || fail "$1 requires a path"
            SHINUD_BIN=$2
            shift 2
            ;;
        --root-parent)
            [ "$#" -ge 2 ] || fail "$1 requires a directory"
            ROOT_PARENT=$2
            shift 2
            ;;
        --port)
            [ "$#" -ge 2 ] || fail "$1 requires a port"
            PORT=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1 (use --help for usage)"
            ;;
    esac
done

for command in awk basename btrfs cat chmod chown cp cut curl dd df dirname e2fsck \
    env find grep id ip iptables iptables-save kill losetup mkfs.ext4 mktemp mount \
    readlink rm rmdir resize2fs sed setsid sleep sha256sum sort ssh ssh-keygen stat \
    tar tr truncate umount unshare wc; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

[ "$(id -u)" = 0 ] || fail "run as root; shinud needs KVM, loop, tap, and firewall access"
[ -x "$SHINU_BIN" ] || fail "shinu binary is not executable: $SHINU_BIN"
[ -x "$SHINUD_BIN" ] || fail "shinud binary is not executable: $SHINUD_BIN"
SHINU_BIN_REAL=$(readlink -f "$SHINU_BIN") || fail "could not resolve shinu binary: $SHINU_BIN"
SHINUD_BIN_REAL=$(readlink -f "$SHINUD_BIN") || fail "could not resolve shinud binary: $SHINUD_BIN"
SHINU_BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$SHINU_BIN_REAL")" && pwd -P)
VSOCK_BIN=${SHINU_VSOCK_BIN:-$SHINU_BIN_DIR/shinu-vsock}
VSOCK_BIN_REAL=$(readlink -f "$VSOCK_BIN" 2>/dev/null || printf '')
[ -x "$VSOCK_BIN" ] || fail "shinu-vsock helper is not executable beside shinu: $VSOCK_BIN"
[ "$VSOCK_BIN_REAL" = "$SHINU_BIN_DIR/shinu-vsock" ] || \
    fail "shinu-vsock helper must resolve beside SHINU_BIN: $VSOCK_BIN"
case "$PORT" in
    ''|*[!0-9]*) fail "port must be an integer between 1024 and 65535: $PORT" ;;
esac
[ "$PORT" -ge 1024 ] || fail "port must be at least 1024: $PORT"
[ "$PORT" -le 65535 ] || fail "port must be at most 65535: $PORT"
case "$ROOT_PARENT" in
    /*) ;;
    *) fail "root parent must be an absolute path: $ROOT_PARENT" ;;
esac
[ -d "$ROOT_PARENT" ] || fail "root parent is not a directory: $ROOT_PARENT"

[ -e /dev/kvm ] || fail "/dev/kvm is missing"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "/dev/kvm is not readable and writable"
[ -r /proc/cpuinfo ] || fail "/proc/cpuinfo is unreadable"
if ! grep -Eq '(^|[[:space:]])(vmx|svm)($|[[:space:]])' /proc/cpuinfo; then
    fail "CPU exposes neither vmx nor svm"
fi
[ -f /sys/fs/cgroup/cgroup.controllers ] || fail "cgroup v2 is not mounted at /sys/fs/cgroup"
[ -e /dev/vhost-vsock ] || fail "/dev/vhost-vsock is missing"
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || printf 0)" = 1 ] || \
    fail "net.ipv4.ip_forward must be 1 for network scenarios"

FSTYPE=$(stat -f -c %T "$ROOT_PARENT" 2>/dev/null || printf unknown)
case "$FSTYPE" in
    btrfs|xfs) ;;
    *) fail "$ROOT_PARENT is $FSTYPE; host smoke needs btrfs or reflink-capable xfs" ;;
esac

ROOT=$(mktemp -d "$ROOT_PARENT/shinu-host-smoke.XXXXXX") || fail "could not create isolated root under $ROOT_PARENT"
chmod 700 "$ROOT"
chown 0:0 "$ROOT"
ROOT_MARKER=$ROOT/.host-smoke-root
: > "$ROOT_MARKER"
chmod 600 "$ROOT_MARKER"

PROBE=$ROOT/reflink-probe
mkdir "$PROBE"
chmod 700 "$PROBE"
if ! dd if=/dev/zero of="$PROBE/source" bs=4096 count=1 >/dev/null 2>&1; then
    fail "cannot write reflink probe on $ROOT_PARENT"
fi
if ! cp --reflink=always -- "$PROBE/source" "$PROBE/destination" >/dev/null 2>&1; then
    fail "cp --reflink=always failed on $ROOT_PARENT"
fi
rm -rf "$PROBE"

JAIL_UID=${SHINU_JAIL_UID:-30000}
JAIL_GID=${SHINU_JAIL_GID:-30000}
case "$JAIL_UID" in ''|*[!0-9]*) fail "SHINU_JAIL_UID must be numeric: $JAIL_UID" ;; esac
case "$JAIL_GID" in ''|*[!0-9]*) fail "SHINU_JAIL_GID must be numeric: $JAIL_GID" ;; esac
actual_uid=$(id -u shinu-jail 2>/dev/null || printf '')
actual_gid=$(id -g shinu-jail 2>/dev/null || printf '')
[ "$actual_uid" = "$JAIL_UID" ] || fail "shinu-jail uid is $actual_uid, expected $JAIL_UID"
[ "$actual_gid" = "$JAIL_GID" ] || fail "shinu-jail primary gid is $actual_gid, expected $JAIL_GID"

case "${SHINU_NET_ENABLE:-1}" in
    0|false|False|FALSE) fail "SHINU_NET_ENABLE disables required network scenarios" ;;
esac
SHINU_NET_UPLINK=${SHINU_NET_UPLINK:-}
if [ -z "$SHINU_NET_UPLINK" ]; then
    SHINU_NET_UPLINK=$(ip route show default | awk '$1 == "default" { print $5; exit }')
fi
[ -n "$SHINU_NET_UPLINK" ] || fail "could not determine the default uplink; set SHINU_NET_UPLINK"

# Every daemon setting is copied into explicit values for env -i. Network
# allowlists are deliberately empty and the address pool is fixed for this
# isolated run; inherited operator policy must not weaken this test.
SMOKE_PATH=${SHINU_SMOKE_PATH:-/usr/sbin:/usr/bin:/sbin:/bin}
SMOKE_REFLOG_DAYS=${SHINU_REFLOG_DAYS:-7}
SMOKE_VCPUS=${SHINU_VCPUS:-1}
SMOKE_MEM_MIB=${SHINU_MEM_MIB:-512}
SMOKE_IDLE_SECS=${SHINU_IDLE_SECS:-3600}
SMOKE_DISK_MIB=${SHINU_DISK_MIB:-2048}
SMOKE_LIMIT_SPACES=${SHINU_LIMIT_SPACES:-16}
SMOKE_LIMIT_DISK_MIB=${SHINU_LIMIT_DISK_MIB:-65536}
SMOKE_LIMIT_VCPUS=${SHINU_LIMIT_VCPUS:-8}
SMOKE_LIMIT_MEM_MIB=${SHINU_LIMIT_MEM_MIB:-16384}
SMOKE_LIMIT_RUNNING=${SHINU_LIMIT_RUNNING:-3}
SMOKE_LIMIT_API_PER_MIN=${SHINU_LIMIT_API_PER_MIN:-10000}
SMOKE_FULL_EVERY=${SHINU_FULL_EVERY:-8}
SMOKE_SESSION_DAYS=${SHINU_SESSION_DAYS:-7}
SMOKE_GUEST_DNS=${SHINU_GUEST_DNS:-}
SMOKE_ROOTFS_TARBALL=${SHINU_ROOTFS_TARBALL:-}
SMOKE_MIRROR=${SHINU_MIRROR:-}
SMOKE_ARCH=${SHINU_ARCH:-}
SMOKE_PAYLOAD=${SHINU_PAYLOAD:-}
SMOKE_PAYLOAD_SERVICE=${SHINU_PAYLOAD_SERVICE:-}
SMOKE_ADMIN_TOKEN=${SHINU_ADMIN_TOKEN:-}

LEDGER=$ROOT/host-ledger
mkdir "$LEDGER"
chmod 700 "$LEDGER"
BASE_TAPS=$LEDGER/baseline.taps
BASELINE_COMPLETE=$LEDGER/baseline.complete
BASE_INPUT_JUMP=$LEDGER/baseline.input-jump
BASE_INPUT_CHAIN=$LEDGER/baseline.input-chain
BASE_IPTABLES=$LEDGER/baseline.iptables
BASE_LOOPS=$LEDGER/baseline.loops
BASE_CGROUPS=$LEDGER/baseline.cgroups
BASE_PROCESSES=$LEDGER/baseline.processes
OWNED_TAPS=$LEDGER/owned.taps
OWNED_IPTABLES=$LEDGER/owned.iptables
OWNED_LOOPS=$LEDGER/owned.loops
OWNED_CGROUPS=$LEDGER/owned.cgroups
OWNED_PROCESSES=$LEDGER/owned.processes
OWNED_INPUT_JUMP=$LEDGER/owned.input-jump
OWNED_INPUT_CHAIN=$LEDGER/owned.input-chain

: > "$OWNED_TAPS"
: > "$OWNED_IPTABLES"
: > "$OWNED_LOOPS"
: > "$OWNED_CGROUPS"
: > "$OWNED_PROCESSES"
: > "$OWNED_INPUT_JUMP"
: > "$OWNED_INPUT_CHAIN"

proc_start_time() {
    pid=$1
    [ -r "/proc/$pid/stat" ] || return 1
    awk '{ print $22; exit }' "/proc/$pid/stat" 2>/dev/null
}

proc_name() {
    pid=$1
    sed -n 's/^Name:[[:space:]]*//p' "/proc/$pid/status" 2>/dev/null | sed -n '1p'
}

proc_args() {
    pid=$1
    tr '\000' '\012' < "/proc/$pid/cmdline" 2>/dev/null
}

append_unique() {
    append_file=$1
    append_line=$2
    if ! grep -Fqx -- "$append_line" "$append_file" >/dev/null 2>&1; then
        printf '%s\n' "$append_line" >> "$append_file"
    fi
}

record_process_snapshot() {
    snapshot_file=$1
    : > "$snapshot_file"
    for proc in /proc/[0-9]*; do
        [ -r "$proc/stat" ] || continue
        snapshot_pid=${proc#/proc/}
        snapshot_start=$(proc_start_time "$snapshot_pid") || continue
        snapshot_exe=$(readlink -f "$proc/exe" 2>/dev/null || printf unknown)
        printf '%s|%s|%s\n' "$snapshot_pid" "$snapshot_start" "$snapshot_exe" >> "$snapshot_file"
    done
}

capture_host_baseline() {
    baseline_suffix=.$$
    baseline_taps_tmp="$BASE_TAPS$baseline_suffix"
    baseline_iptables_tmp="$BASE_IPTABLES$baseline_suffix"
    baseline_loops_tmp="$BASE_LOOPS$baseline_suffix"
    baseline_cgroups_tmp="$BASE_CGROUPS$baseline_suffix"
    baseline_processes_tmp="$BASE_PROCESSES$baseline_suffix"
    baseline_jump_tmp="$BASE_INPUT_JUMP$baseline_suffix"
    baseline_chain_tmp="$BASE_INPUT_CHAIN$baseline_suffix"
    baseline_marker_tmp="$BASELINE_COMPLETE$baseline_suffix"
    rm -f "$BASELINE_COMPLETE" "$baseline_marker_tmp" \
        "$baseline_taps_tmp" "$baseline_iptables_tmp" "$baseline_loops_tmp" \
        "$baseline_cgroups_tmp" "$baseline_processes_tmp" "$baseline_jump_tmp" "$baseline_chain_tmp"
    if ! ip -o link show > "$baseline_taps_tmp" 2> "$LEDGER/baseline.ip.stderr"; then
        printf 'host-smoke: could not capture link baseline\n' >&2
        return 1
    fi
    if ! iptables-save > "$baseline_iptables_tmp" 2> "$LEDGER/baseline.iptables.stderr"; then
        printf 'host-smoke: could not capture iptables baseline\n' >&2
        return 1
    fi
    if ! losetup -a > "$baseline_loops_tmp" 2> "$LEDGER/baseline.losetup.stderr"; then
        printf 'host-smoke: could not capture loop baseline\n' >&2
        return 1
    fi
    if ! find /sys/fs/cgroup -xdev -type d -print > "$baseline_cgroups_tmp" \
        2> "$LEDGER/baseline.cgroup.stderr"; then
        printf 'host-smoke: could not capture cgroup baseline\n' >&2
        return 1
    fi
    if ! record_process_snapshot "$baseline_processes_tmp"; then
        printf 'host-smoke: could not capture process baseline\n' >&2
        return 1
    fi
    : > "$baseline_jump_tmp"
    : > "$baseline_chain_tmp"
    grep -F -- '-A INPUT -j SHINU-INPUT' "$baseline_iptables_tmp" > "$baseline_jump_tmp" || :
    grep -F -- ':SHINU-INPUT ' "$baseline_iptables_tmp" > "$baseline_chain_tmp" || :
    if ! mv -f "$baseline_taps_tmp" "$BASE_TAPS" \
        || ! mv -f "$baseline_iptables_tmp" "$BASE_IPTABLES" \
        || ! mv -f "$baseline_loops_tmp" "$BASE_LOOPS" \
        || ! mv -f "$baseline_cgroups_tmp" "$BASE_CGROUPS" \
        || ! mv -f "$baseline_processes_tmp" "$BASE_PROCESSES" \
        || ! mv -f "$baseline_jump_tmp" "$BASE_INPUT_JUMP" \
        || ! mv -f "$baseline_chain_tmp" "$BASE_INPUT_CHAIN"; then
        printf 'host-smoke: could not publish host baseline\n' >&2
        return 1
    fi
    printf 'baseline-complete-v1\n' > "$baseline_marker_tmp"
    chmod 600 "$baseline_marker_tmp"
    if ! mv -f "$baseline_marker_tmp" "$BASELINE_COMPLETE"; then
        printf 'host-smoke: could not publish baseline completion marker\n' >&2
        return 1
    fi
    return 0
}

hex_network_for_id() {
    net_id=$1
    net_hex=$(printf '%s\n' "$net_id" | tr -d '-' | cut -c 1-4)
    net_value=$(printf '%d' "0x$net_hex" 2>/dev/null) || return 1
    net_index=$((net_value & 16383))
    net_third=$((net_index / 64))
    net_fourth=$(((net_index % 64) * 4))
    printf '%s.%s.%s.%s/30' "${NET_BASE%.*}" "${NET_BASE#*.}" "$net_third" "$net_fourth"
}

tap_for_id() {
    printf 'shinu%s' "$(printf '%s\n' "$1" | tr -d '-' | cut -c 1-10)"
}

vm_id_shape() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
}

daemon_identity() {
    identity_pid=$1
    identity_start=$2
    [ -n "$identity_pid" ] || return 1
    [ -n "$identity_start" ] || return 1
    [ -r "/proc/$identity_pid/cmdline" ] || return 1
    identity_current=$(proc_start_time "$identity_pid") || return 1
    [ "$identity_current" = "$identity_start" ] || return 1
    identity_exe=$(readlink -f "/proc/$identity_pid/exe" 2>/dev/null || printf '')
    [ "$identity_exe" = "$SHINUD_BIN_REAL" ] || return 1
    identity_actual=$(proc_args "$identity_pid") || return 1
    identity_expected=$(printf '%s\n%s\n%s' "$SHINUD_BIN_REAL" '--root' "$ROOT")
    [ "$identity_actual" = "$identity_expected" ]
}

vm_cmdline_identity() {
    identity_pid=$1
    identity_id=$2
    [ -r "/proc/$identity_pid/cmdline" ] || return 1
    [ "$(proc_name "$identity_pid")" = firecracker ] || return 1
    identity_args=$(proc_args "$identity_pid") || return 1
    identity_id_ok=$(printf '%s\n' "$identity_args" | awk -v id="$identity_id" \
        'previous == "--id" && $0 == id { found=1 } $0 == "--id=" id { found=1 } { previous=$0 } END { print found + 0 }')
    [ "$identity_id_ok" = 1 ] || return 1
    identity_config="$ROOT/jail/firecracker/$identity_id/root/fc.json"
    if [ -f "$identity_config" ]; then
        identity_config_ok=$(printf '%s\n' "$identity_args" | awk \
            'previous == "--config-file" && $0 == "fc.json" { found=1 } { previous=$0 } END { print found + 0 }')
        [ "$identity_config_ok" = 1 ] || return 1
    else
        identity_config_ok=$(printf '%s\n' "$identity_args" | awk \
            '$0 == "--config-file" { found=1 } END { print found + 0 }')
        [ "$identity_config_ok" = 0 ] || return 1
    fi
}

jailer_cmdline_identity() {
    identity_pid=$1
    identity_id=$2
    [ -r "/proc/$identity_pid/cmdline" ] || return 1
    [ "$(proc_name "$identity_pid")" = jailer ] || return 1
    identity_args=$(proc_args "$identity_pid") || return 1
    identity_id_ok=$(printf '%s\n' "$identity_args" | awk -v id="$identity_id" \
        'previous == "--id" && $0 == id { found=1 } $0 == "--id=" id { found=1 } { previous=$0 } END { print found + 0 }')
    [ "$identity_id_ok" = 1 ] || return 1
    identity_root_ok=$(printf '%s\n' "$identity_args" | awk -v root="$ROOT/jail" \
        'previous == "--chroot-base-dir" && $0 == root { found=1 } { previous=$0 } END { print found + 0 }')
    [ "$identity_root_ok" = 1 ]
}

vm_identity() {
    identity_pid=$1
    identity_start=$2
    identity_id=$3
    [ -n "$identity_start" ] || return 1
    [ "$(proc_start_time "$identity_pid" 2>/dev/null || printf '')" = "$identity_start" ] || return 1
    vm_cmdline_identity "$identity_pid" "$identity_id"
}

record_owned_resources() {
    [ -n "${LEDGER:-}" ] || return 0
    record_ok=1
    if [ -n "${DAEMON_PID:-}" ]; then
        if daemon_identity "$DAEMON_PID" "$DAEMON_START_TIME"; then
            append_unique "$OWNED_PROCESSES" "$DAEMON_PID|$DAEMON_START_TIME|daemon|-"
        elif [ -e "/proc/$DAEMON_PID" ]; then
            printf 'host-smoke: daemon identity could not be recorded\n' >&2
            record_ok=0
        fi
    fi
    for vm_dir in "$ROOT"/vm/*; do
        [ -d "$vm_dir" ] || continue
        owned_id=$(basename "$vm_dir")
        vm_id_shape "$owned_id" || continue
        owned_tap=$(tap_for_id "$owned_id")
        if ! grep -F "$owned_tap" "$BASE_TAPS" >/dev/null 2>&1; then
            append_unique "$OWNED_TAPS" "$owned_tap"
        fi
        owned_network=$(hex_network_for_id "$owned_id" 2>/dev/null || printf '')
        owned_pid_file="$ROOT/jail/firecracker/$owned_id/root/firecracker.pid"
        owned_vm_found=0
        if [ -r "$owned_pid_file" ]; then
            owned_pid=$(cat "$owned_pid_file" 2>/dev/null || printf '')
            owned_start=$(proc_start_time "$owned_pid" 2>/dev/null || printf '')
            if [ -n "$owned_pid" ] && vm_identity "$owned_pid" "$owned_start" "$owned_id"; then
                append_unique "$OWNED_PROCESSES" "$owned_pid|$owned_start|vm|$owned_id"
                owned_vm_found=1
            elif [ -n "$owned_pid" ] && [ -e "/proc/$owned_pid" ]; then
                printf 'host-smoke: VM identity could not be recorded for %s\n' "$owned_id" >&2
                record_ok=0
            fi
        fi
        for proc in /proc/[0-9]*; do
            [ -r "$proc/cmdline" ] || continue
            owned_proc=${proc#/proc/}
            owned_proc_start=$(proc_start_time "$owned_proc" 2>/dev/null || printf '')
            if [ -n "$owned_proc_start" ] && jailer_cmdline_identity "$owned_proc" "$owned_id"; then
                append_unique "$OWNED_PROCESSES" "$owned_proc|$owned_proc_start|jailer|$owned_id"
            fi
        done
        for proc in /proc/[0-9]*; do
            [ -r "$proc/cmdline" ] || continue
            owned_proc=${proc#/proc/}
            owned_proc_start=$(proc_start_time "$owned_proc" 2>/dev/null || printf '')
            if [ -n "$owned_proc_start" ] && vm_cmdline_identity "$owned_proc" "$owned_id"; then
                append_unique "$OWNED_PROCESSES" "$owned_proc|$owned_proc_start|vm|$owned_id"
                owned_vm_found=1
            fi
        done
        if [ "$owned_vm_found" -eq 0 ] \
            && { [ -e "$owned_pid_file" ] || [ -e "$ROOT/jail/firecracker/$owned_id/root/fc.sock" ] || [ -e "$ROOT/jail/firecracker/$owned_id/root/vsock.sock" ]; }; then
            printf 'host-smoke: running VM identity could not be discovered for %s\n' "$owned_id" >&2
            record_ok=0
        fi
    done
    if ! iptables-save > "$LEDGER/current.iptables" 2> "$LEDGER/current.iptables.stderr"; then
        record_ok=0
    else
        for owned_tap in $(cat "$OWNED_TAPS"); do
            while IFS= read -r owned_rule; do
                case "$owned_rule" in
                    *"$owned_tap"*)
                        if ! grep -Fqx -- "$owned_rule" "$BASE_IPTABLES" >/dev/null 2>&1; then
                            append_unique "$OWNED_IPTABLES" "$owned_rule"
                        fi
                        ;;
                esac
            done < "$LEDGER/current.iptables"
        done
        for vm_dir in "$ROOT"/vm/*; do
            [ -d "$vm_dir" ] || continue
            owned_id=$(basename "$vm_dir")
            vm_id_shape "$owned_id" || continue
            owned_network=$(hex_network_for_id "$owned_id" 2>/dev/null || printf '')
            [ -n "$owned_network" ] || continue
            while IFS= read -r owned_rule; do
                case "$owned_rule" in
                    *"$owned_network"*)
                        if ! grep -Fqx -- "$owned_rule" "$BASE_IPTABLES" >/dev/null 2>&1; then
                            append_unique "$OWNED_IPTABLES" "$owned_rule"
                        fi
                        ;;
                esac
            done < "$LEDGER/current.iptables"
        done
        if ! grep -Fqx -- '-A INPUT -j SHINU-INPUT' "$BASE_INPUT_JUMP" >/dev/null 2>&1; then
            grep -F -- '-A INPUT -j SHINU-INPUT' "$LEDGER/current.iptables" > "$OWNED_INPUT_JUMP" || :
        fi
        if ! grep -Fq ':SHINU-INPUT ' "$BASE_INPUT_CHAIN" >/dev/null 2>&1; then
            grep -F -- ':SHINU-INPUT ' "$LEDGER/current.iptables" > "$OWNED_INPUT_CHAIN" || :
        fi
    fi
    if ! losetup -a > "$LEDGER/current.loops" 2> "$LEDGER/current.loops.stderr"; then
        record_ok=0
    else
        while IFS= read -r owned_loop; do
            case "$owned_loop" in
                *"$ROOT"*)
                    if ! grep -Fqx -- "$owned_loop" "$BASE_LOOPS" >/dev/null 2>&1; then
                        append_unique "$OWNED_LOOPS" "$owned_loop"
                    fi
                    ;;
            esac
        done < "$LEDGER/current.loops"
    fi
    if ! find /sys/fs/cgroup -xdev -type d -print > "$LEDGER/current.cgroups" \
        2> "$LEDGER/current.cgroups.stderr"; then
        record_ok=0
    else
        for vm_dir in "$ROOT"/vm/*; do
            [ -d "$vm_dir" ] || continue
            owned_id=$(basename "$vm_dir")
            vm_id_shape "$owned_id" || continue
            while IFS= read -r owned_cgroup; do
                case "$owned_cgroup" in
                    *"$owned_id"*)
                        if ! grep -Fqx -- "$owned_cgroup" "$BASE_CGROUPS" >/dev/null 2>&1; then
                            append_unique "$OWNED_CGROUPS" "$owned_cgroup"
                        fi
                        ;;
                esac
            done < "$LEDGER/current.cgroups"
        done
    fi
    [ "$record_ok" -eq 1 ]
}

remove_owned_firewall() {
    while IFS= read -r firewall_rule; do
        case "$firewall_rule" in
            -A\ *) ;;
            *) continue ;;
        esac
        while :; do
            if ! iptables-save > "$LEDGER/remove.iptables" 2> "$LEDGER/remove.iptables.stderr"; then
                cleanup_ok=0
                break
            fi
            if ! grep -Fqx -- "$firewall_rule" "$LEDGER/remove.iptables" >/dev/null 2>&1; then
                break
            fi
            set -- $firewall_rule
            if [ "${1:-}" != -A ]; then
                cleanup_ok=0
                break
            fi
            shift
            if ! iptables -w 5 -D "$@" >/dev/null 2>&1 \
                && ! iptables -w 5 -t nat -D "$@" >/dev/null 2>&1; then
                cleanup_ok=0
                break
            fi
        done
    done < "$OWNED_IPTABLES"
    if [ -s "$OWNED_INPUT_JUMP" ]; then
        while :; do
            if ! iptables-save > "$LEDGER/remove.iptables" 2> "$LEDGER/remove.iptables.stderr"; then
                cleanup_ok=0
                break
            fi
            if ! grep -Fqx -- '-A INPUT -j SHINU-INPUT' "$LEDGER/remove.iptables" >/dev/null 2>&1; then
                break
            fi
            if ! iptables -w 5 -D INPUT -j SHINU-INPUT >/dev/null 2>&1; then
                cleanup_ok=0
                break
            fi
        done
    fi
    if [ -s "$OWNED_INPUT_CHAIN" ]; then
        while :; do
            if ! iptables-save > "$LEDGER/remove.iptables" 2> "$LEDGER/remove.iptables.stderr"; then
                cleanup_ok=0
                break
            fi
            if ! grep -Fq ':SHINU-INPUT ' "$LEDGER/remove.iptables" >/dev/null 2>&1; then
                break
            fi
            chain_rules=$(grep -F -- '-A SHINU-INPUT ' "$LEDGER/remove.iptables" || :)
            if [ -n "$chain_rules" ]; then
                cleanup_ok=0
                break
            fi
            if ! iptables -w 5 -X SHINU-INPUT >/dev/null 2>&1; then
                cleanup_ok=0
                break
            fi
        done
    fi
}

remove_owned_loops() {
    [ -s "$OWNED_LOOPS" ] || return
    while IFS= read -r loop_line; do
        loop_device=$(printf '%s\n' "$loop_line" | sed -n 's/:.*//p')
        case "$loop_device" in
            /dev/loop[0-9]*) ;;
            *)
                cleanup_ok=0
                continue
                ;;
        esac
        if ! losetup -a > "$LEDGER/loop-check" 2> "$LEDGER/loop-check.stderr"; then
            cleanup_ok=0
            continue
        fi
        if grep -Fqx -- "$loop_line" "$LEDGER/loop-check" >/dev/null 2>&1; then
            if ! losetup -d "$loop_device" >/dev/null 2>&1; then
                cleanup_ok=0
            fi
            continue
        fi
        loop_association=0
        while IFS= read -r current_loop_line; do
            case "$current_loop_line" in
                "$loop_device:"*) loop_association=1 ;;
            esac
        done < "$LEDGER/loop-check"
        [ "$loop_association" -eq 0 ] || cleanup_ok=0
    done < "$OWNED_LOOPS"
}

remove_owned_taps() {
    [ -s "$OWNED_TAPS" ] || return
    while IFS= read -r owned_tap; do
        if ip link show dev "$owned_tap" >/dev/null 2>&1; then
            ip link del "$owned_tap" >/dev/null 2>&1 || cleanup_ok=0
        fi
    done < "$OWNED_TAPS"
}

remove_owned_cgroups() {
    [ -s "$OWNED_CGROUPS" ] || return
    sort -r "$OWNED_CGROUPS" > "$LEDGER/owned.cgroups.reverse"
    while IFS= read -r owned_cgroup; do
        case "$owned_cgroup" in
            /sys/fs/cgroup/*)
                [ -e "$owned_cgroup" ] || continue
                rmdir "$owned_cgroup" >/dev/null 2>&1 || cleanup_ok=0
                ;;
            *) cleanup_ok=0 ;;
        esac
    done < "$LEDGER/owned.cgroups.reverse"
}

process_identity_for_record() {
    record_pid=$1
    record_start=$2
    record_kind=$3
    record_id=$4
    case "$record_kind" in
        daemon|recovery)
            daemon_identity "$record_pid" "$record_start"
            ;;
        vm)
            vm_identity "$record_pid" "$record_start" "$record_id"
            ;;
        jailer)
            [ "$(proc_start_time "$record_pid" 2>/dev/null || printf '')" = "$record_start" ] || return 1
            jailer_cmdline_identity "$record_pid" "$record_id"
            ;;
        *) return 1 ;;
    esac
}

signal_owned_record() {
    record_pid=$1
    record_start=$2
    record_kind=$3
    record_id=$4
    [ -e "/proc/$record_pid" ] || return
    if process_identity_for_record "$record_pid" "$record_start" "$record_kind" "$record_id"; then
        kill -TERM "$record_pid" >/dev/null 2>&1 || cleanup_ok=0
        sleep 1
        if [ -e "/proc/$record_pid" ] && \
            process_identity_for_record "$record_pid" "$record_start" "$record_kind" "$record_id"; then
            kill -KILL "$record_pid" >/dev/null 2>&1 || cleanup_ok=0
        elif [ -e "/proc/$record_pid" ]; then
            printf 'host-smoke: process identity changed after TERM: %s\n' "$record_pid" >&2
            cleanup_ok=0
        fi
    else
        printf 'host-smoke: refusing to signal changed process identity: %s\n' "$record_pid" >&2
        cleanup_ok=0
    fi
}

terminate_owned_processes() {
    [ -s "$OWNED_PROCESSES" ] || return
    while IFS='|' read -r owned_pid owned_start owned_kind owned_id; do
        [ -n "$owned_pid" ] || continue
        signal_owned_record "$owned_pid" "$owned_start" "$owned_kind" "$owned_id"
    done < "$OWNED_PROCESSES"
}

verify_owned_resources() {
    if ! iptables-save > "$LEDGER/verify.iptables" 2> "$LEDGER/verify.iptables.stderr"; then
        cleanup_ok=0
        return
    fi
    if [ -s "$OWNED_IPTABLES" ]; then
        while IFS= read -r owned_rule; do
            grep -Fqx -- "$owned_rule" "$LEDGER/verify.iptables" >/dev/null 2>&1 && cleanup_ok=0
        done < "$OWNED_IPTABLES"
    fi
    if [ -s "$OWNED_INPUT_JUMP" ]; then
        grep -Fqx -- '-A INPUT -j SHINU-INPUT' "$LEDGER/verify.iptables" >/dev/null 2>&1 && cleanup_ok=0
    fi
    if [ -s "$OWNED_INPUT_CHAIN" ]; then
        grep -Fq ':SHINU-INPUT ' "$LEDGER/verify.iptables" >/dev/null 2>&1 && cleanup_ok=0
    fi
    if [ -s "$OWNED_TAPS" ]; then
        while IFS= read -r owned_tap; do
            ip link show dev "$owned_tap" >/dev/null 2>&1 && cleanup_ok=0
        done < "$OWNED_TAPS"
    fi
    if ! losetup -a > "$LEDGER/verify.loops" 2> "$LEDGER/verify.loops.stderr"; then
        cleanup_ok=0
    elif [ -s "$OWNED_LOOPS" ]; then
        while IFS= read -r owned_loop; do
            grep -Fqx -- "$owned_loop" "$LEDGER/verify.loops" >/dev/null 2>&1 && cleanup_ok=0
        done < "$OWNED_LOOPS"
    fi
    if ! find /sys/fs/cgroup -xdev -type d -print > "$LEDGER/verify.cgroups" \
        2> "$LEDGER/verify.cgroups.stderr"; then
        cleanup_ok=0
    elif [ -s "$OWNED_CGROUPS" ]; then
        while IFS= read -r owned_cgroup; do
            grep -Fqx -- "$owned_cgroup" "$LEDGER/verify.cgroups" >/dev/null 2>&1 && cleanup_ok=0
        done < "$OWNED_CGROUPS"
    fi
    if [ -s "$OWNED_PROCESSES" ]; then
        while IFS='|' read -r owned_pid owned_start owned_kind owned_id; do
            [ -n "$owned_pid" ] || continue
            if [ -e "/proc/$owned_pid" ] && process_identity_for_record "$owned_pid" "$owned_start" "$owned_kind" "$owned_id"; then
                printf 'host-smoke: owned process remains: %s\n' "$owned_pid" >&2
                cleanup_ok=0
            fi
        done < "$OWNED_PROCESSES"
    fi
}

stop_tracked_spaces() {
    stop_token=$1
    stop_spaces=$2
    [ -n "$stop_token" ] || return
    for stop_space in $stop_spaces; do
        stop_out=$ROOT/cleanup-stop.out
        stop_err=$ROOT/cleanup-stop.err
        if "$SHINU_BIN" --endpoint "http://127.0.0.1:$PORT" --token "$stop_token" \
            stop "$stop_space" > "$stop_out" 2> "$stop_err"; then
            :
        else
            stop_error=$(cat "$stop_err" 2>/dev/null || printf '')
            case "$stop_error" in
                *'HTTP 404'*) : ;;
                *)
                    printf 'host-smoke: cleanup stop failed for %s: %s\n' "$stop_space" "$stop_error" >&2
                    cleanup_ok=0
                    ;;
            esac
        fi
    done
}

# Every daemon launch is hermetic. Empty optional values are intentional and
# prevent caller credentials or network policy from leaking into the test.
daemon_exec() {
    exec env -i \
        PATH="$SMOKE_PATH" \
        SHINU_ROOT="$ROOT" \
        SHINU_LISTEN="127.0.0.1:$PORT" \
        SHINU_REFLOG_DAYS="$SMOKE_REFLOG_DAYS" \
        SHINU_VCPUS="$SMOKE_VCPUS" \
        SHINU_MEM_MIB="$SMOKE_MEM_MIB" \
        SHINU_IDLE_SECS="$SMOKE_IDLE_SECS" \
        SHINU_DISK_MIB="$SMOKE_DISK_MIB" \
        SHINU_JAIL_UID="$JAIL_UID" \
        SHINU_JAIL_GID="$JAIL_GID" \
        SHINU_LIMIT_SPACES="$SMOKE_LIMIT_SPACES" \
        SHINU_LIMIT_DISK_MIB="$SMOKE_LIMIT_DISK_MIB" \
        SHINU_LIMIT_VCPUS="$SMOKE_LIMIT_VCPUS" \
        SHINU_LIMIT_MEM_MIB="$SMOKE_LIMIT_MEM_MIB" \
        SHINU_LIMIT_RUNNING="$SMOKE_LIMIT_RUNNING" \
        SHINU_LIMIT_API_PER_MIN="$SMOKE_LIMIT_API_PER_MIN" \
        SHINU_NET_ENABLE=1 \
        SHINU_NET_BASE="$NET_BASE" \
        SHINU_NET_ALLOW= \
        SHINU_HOST_ALLOW= \
        SHINU_NET_UPLINK="$SHINU_NET_UPLINK" \
        SHINU_FULL_EVERY="$SMOKE_FULL_EVERY" \
        SHINU_SESSION_DAYS="$SMOKE_SESSION_DAYS" \
        SHINU_GUEST_DNS="$SMOKE_GUEST_DNS" \
        SHINU_ROOTFS_TARBALL="$SMOKE_ROOTFS_TARBALL" \
        SHINU_MIRROR="$SMOKE_MIRROR" \
        SHINU_ARCH="$SMOKE_ARCH" \
        SHINU_PAYLOAD="$SMOKE_PAYLOAD" \
        SHINU_PAYLOAD_SERVICE="$SMOKE_PAYLOAD_SERVICE" \
        SHINU_ADMIN_TOKEN="$SMOKE_ADMIN_TOKEN" \
        "$SHINUD_BIN_REAL" --root "$ROOT"
}

start_daemon() {
    DAEMON_LOG=$ROOT/daemon.log
    (daemon_exec) > "$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!
    DAEMON_START_TIME=
    start_capture_attempts=0
    while [ -z "$DAEMON_START_TIME" ] && [ "$start_capture_attempts" -lt 10 ]; do
        DAEMON_START_TIME=$(proc_start_time "$DAEMON_PID" 2>/dev/null || printf '')
        [ -n "$DAEMON_START_TIME" ] && break
        sleep 1
        start_capture_attempts=$((start_capture_attempts + 1))
    done
    if [ -z "$DAEMON_START_TIME" ]; then
        printf 'host-smoke: daemon log:\n' >&2
        cat "$DAEMON_LOG" >&2
        fail "could not record daemon start time"
    fi
    attempts=0
    identity_wait=0
    while [ "$attempts" -lt 600 ]; do
        if ! daemon_identity "$DAEMON_PID" "$DAEMON_START_TIME"; then
            if [ ! -e "/proc/$DAEMON_PID" ]; then
                printf 'host-smoke: daemon log:\n' >&2
                cat "$DAEMON_LOG" >&2
                fail "shinud exited before becoming ready"
            fi
            identity_wait=$((identity_wait + 1))
            if [ "$identity_wait" -ge 10 ]; then
                printf 'host-smoke: daemon log:\n' >&2
                cat "$DAEMON_LOG" >&2
                fail "shinud identity did not settle before becoming ready"
            fi
            sleep 1
            attempts=$((attempts + 1))
            continue
        fi
        status=
        if status=$(curl --noproxy '*' -sS --max-time 2 -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:$PORT/" 2>/dev/null); then
            [ "$status" = 302 ] && return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    printf 'host-smoke: daemon log:\n' >&2
    cat "$DAEMON_LOG" >&2
    fail "shinud did not become ready on http://127.0.0.1:$PORT"
}

restart_daemon() {
    old_pid=$DAEMON_PID
    old_start=$DAEMON_START_TIME
    daemon_identity "$old_pid" "$old_start" || fail "daemon identity failed before restart"
    kill -TERM "$old_pid" >/dev/null 2>&1 || fail "could not terminate daemon for restart"
    wait "$old_pid" >/dev/null 2>&1 || :
    DAEMON_PID=
    DAEMON_START_TIME=
    start_daemon
}

mint_token() {
    project=$1
    token_out=$ROOT/token-$project.out
    token_err=$ROOT/token-$project.err
    if ! "$SHINU_BIN" --root "$ROOT" token new --project "$project" \
        > "$token_out" 2> "$token_err"; then
        cat "$token_err" >&2
        fail "could not mint token for $project"
    fi
    [ ! -s "$token_err" ] || fail "token mint wrote unexpected stderr for $project: $(cat "$token_err")"
    token=$(sed -n 's/^token: //p' "$token_out" | sed -n '1p')
    if ! printf '%s\n' "$token" | grep -Eq '^[0-9a-f]{64}$'; then
        fail "token mint returned an invalid token for $project"
    fi
    token_count=$(grep -c '^token: ' "$token_out" || :)
    [ "$token_count" = 1 ] || fail "token mint returned $token_count token lines for $project"
    expected="token: $token
This plaintext token will not be shown again; store it securely now."
    [ "$(cat "$token_out")" = "$expected" ] || fail "token mint output changed for $project"
    token_stat=$(stat -c '%u %a' "$ROOT/tokens.json")
    [ "$token_stat" = '0 600' ] || fail "tokens.json is not root-owned mode 0600: $token_stat"
    printf '%s' "$token"
}

cli_run() {
    token=$1
    shift
    CLI_OUT=$ROOT/cli.out
    CLI_ERR=$ROOT/cli.err
    if ! "$SHINU_BIN" --endpoint "http://127.0.0.1:$PORT" --token "$token" "$@" \
        > "$CLI_OUT" 2> "$CLI_ERR"; then
        printf 'host-smoke: command failed: shinu'
        for arg in "$@"; do printf ' %s' "$arg"; done
        printf '\n' >&2
        cat "$CLI_ERR" >&2
        printf 'host-smoke: daemon log:\n' >&2
        cat "$DAEMON_LOG" >&2
        fail "unexpected CLI failure"
    fi
    [ ! -s "$CLI_ERR" ] || fail "unexpected CLI stderr: $(cat "$CLI_ERR")"
}

cli_failure() {
    token=$1
    fragment=$2
    shift 2
    CLI_OUT=$ROOT/cli.out
    CLI_ERR=$ROOT/cli.err
    status=0
    if "$SHINU_BIN" --endpoint "http://127.0.0.1:$PORT" --token "$token" "$@" \
        > "$CLI_OUT" 2> "$CLI_ERR"; then
        fail "expected CLI failure did not occur"
    else
        status=$?
    fi
    [ "$status" -ne 0 ] || fail "expected CLI failure returned status zero"
    [ ! -s "$CLI_OUT" ] || fail "failed CLI command wrote unexpected stdout: $(cat "$CLI_OUT")"
    error_text=$(cat "$CLI_ERR")
    case "$error_text" in
        *"$fragment"*) ;;
        *) fail "failed CLI command did not contain $fragment: $error_text" ;;
    esac
}

assert_cli_output() {
    expected=$1
    actual=$(cat "$CLI_OUT")
    [ "$actual" = "$expected" ] || fail "unexpected CLI output; expected [$expected], got [$actual]"
}

is_uuid() {
    value=$1
    if ! printf '%s\n' "$value" | grep -Eq \
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
        fail "invalid UUID returned by daemon: $value"
    fi
}

cli_new() {
    token=$1
    space=$2
    network=$3
    if [ -n "$network" ]; then
        cli_run "$token" new "$space" --vcpus "$SMOKE_VCPUS" --mem "$SMOKE_MEM_MIB" \
            --disk "$SMOKE_DISK_MIB" --network "$network"
    else
        cli_run "$token" new "$space" --vcpus "$SMOKE_VCPUS" --mem "$SMOKE_MEM_MIB" \
            --disk "$SMOKE_DISK_MIB"
    fi
    first_line=$(sed -n '1p' "$CLI_OUT")
    [ "$(cat "$CLI_OUT")" = "$first_line" ] || fail "new $space wrote unexpected extra output"
    case "$first_line" in
        "$space  "*) ;;
        *) fail "new $space returned unexpected summary: $first_line" ;;
    esac
    LAST_SPACE_ID=$(printf '%s\n' "$first_line" | awk '{print $2}')
    is_uuid "$LAST_SPACE_ID"
}

cli_start() {
    token=$1
    space=$2
    cli_run "$token" start "$space"
    assert_cli_output "started $space"
}

cli_start_running() {
    token=$1
    space=$2
    cli_run "$token" start "$space"
    assert_cli_output "running $space"
}

cli_stop() {
    token=$1
    space=$2
    cli_run "$token" stop "$space"
    assert_cli_output "stopped $space"
}

cli_remove() {
    token=$1
    space=$2
    cli_run "$token" rm "$space"
    assert_cli_output "removed $space"
}

cli_exec_expect() {
    token=$1
    space=$2
    expected=$3
    shift 3
    cli_run "$token" exec "$space" -- "$@"
    assert_cli_output "$expected"
}

json_object_with() {
    json_file=$1
    json_needle=$2
    JSON_OBJECT=$(tr '}' '\012' < "$json_file" | while IFS= read -r line; do
        case "$line" in
            *"$json_needle"*)
                printf '%s}\n' "$line"
                exit 0
                ;;
        esac
    done)
    [ -n "$JSON_OBJECT" ] || fail "JSON object not found in $json_file: $json_needle"
}

commit_id_for_note() {
    note=$1
    json_object_with "$CLI_OUT" "\"note\":\"$note\""
    LAST_COMMIT_ID=$(printf '%s\n' "$JSON_OBJECT" | sed -n \
        's/.*"id":"\([0-9a-f-]\{36\}\)".*/\1/p')
    is_uuid "$LAST_COMMIT_ID"
}

assert_object_has() {
    needle=$1
    case "$JSON_OBJECT" in
        *"$needle"*) ;;
        *) fail "JSON object did not contain [$needle]: $JSON_OBJECT" ;
    esac
}

assert_object_lacks() {
    needle=$1
    case "$JSON_OBJECT" in
        *"$needle"*) fail "JSON object unexpectedly contained [$needle]: $JSON_OBJECT" ;;
        *) ;;
    esac
}

cli_commit() {
    token=$1
    space=$2
    note=$3
    mode=$4
    case "$mode" in
        cold) cli_run "$token" commit "$space" --note "$note" ;;
        full) cli_run "$token" commit "$space" --note "$note" --hot --full ;;
        diff) cli_run "$token" commit "$space" --note "$note" --hot --diff ;;
        *) fail "internal error: unknown commit mode $mode" ;;
    esac
    commit_line=$(sed -n '1p' "$CLI_OUT")
    LAST_COMMIT_SHORT=$(printf '%s\n' "$commit_line" | awk '{print $1}')
    if ! printf '%s\n' "$LAST_COMMIT_SHORT" | grep -Eq '^[0-9a-f]{8}$'; then
        fail "commit $note returned an invalid short id: $commit_line"
    fi
    [ "$commit_line" = "$LAST_COMMIT_SHORT  $note" ] || \
        fail "commit $note returned unexpected output: $commit_line"
    cli_run "$token" ls --json
    commit_id_for_note "$note"
}

cli_push() {
    token=$1
    space=$2
    local_file=$3
    guest_path=$4
    cli_run "$token" push "$space" "$local_file" "$guest_path"
    bytes=$(wc -c < "$local_file" | awk '{print $1}')
    assert_cli_output "pushed $bytes bytes to $guest_path"
}

cli_network_capture() {
    token=$1
    network=$2
    cli_run "$token" network "$network"
}

space_ip() {
    space=$1
    ip_count=$(awk -v wanted="$space" '$1 == wanted { count += 1 } END { print count + 0 }' "$CLI_OUT")
    [ "$ip_count" = 1 ] || fail "network output contained $ip_count rows for $space"
    ip_value=$(awk -v wanted="$space" '$1 == wanted { print $2; exit }' "$CLI_OUT")
    if ! printf '%s\n' "$ip_value" | grep -Eq \
        '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        fail "network output returned an invalid guest address for $space: $ip_value"
    fi
    printf '%s' "$ip_value"
}

wait_guest_network() {
    token=$1
    space=$2
    ip_value=$3
    wait_command="while ! ip -4 addr show dev eth0 | grep -q '$ip_value'; do sleep 1; done; printf network-ready"
    cli_exec_expect "$token" "$space" network-ready sh -c "$wait_command"
}

snapshot_files_exist() {
    checkpoint=$1
    for extension in ext4 mem state; do
        snapshot_path=$ROOT/ckpts/$checkpoint.$extension
        [ -s "$snapshot_path" ] || fail "snapshot file is missing or empty: $snapshot_path"
    done
}

snapshot_files_absent() {
    checkpoint=$1
    for extension in mem state; do
        [ ! -e "$ROOT/ckpts/$checkpoint.$extension" ] || \
            fail "cold checkpoint unexpectedly has a $extension snapshot: $checkpoint"
    done
}

FC_SOCKET=
FC_BODY=
FC_HEADERS=
firecracker_api() {
    method=$1
    path=$2
    body=$3
    expected_status=$4
    if [ -n "$body" ]; then
        if ! status=$(curl --noproxy '*' -sS --max-time 15 --unix-socket "$FC_SOCKET" \
            -X "$method" -H 'Content-Type: application/json' -d "$body" \
            -o "$FC_BODY" -w '%{http_code}' "http://localhost$path" 2> "$FC_HEADERS"); then
            cat "$FC_HEADERS" >&2
            fail "Firecracker API request failed: $method $path"
        fi
    else
        if ! status=$(curl --noproxy '*' -sS --max-time 15 --unix-socket "$FC_SOCKET" \
            -X "$method" -o "$FC_BODY" -w '%{http_code}' \
            "http://localhost$path" 2> "$FC_HEADERS"); then
            cat "$FC_HEADERS" >&2
            fail "Firecracker API request failed: $method $path"
        fi
    fi
    [ "$status" = "$expected_status" ] || \
        fail "unexpected Firecracker API status for $method $path: $status (expected $expected_status)"
}

check_balloon_and_config() {
    FC_SOCKET=$ROOT/jail/firecracker/$LAST_MAIN_ID/root/fc.sock
    FC_BODY=$ROOT/firecracker-api.body
    FC_HEADERS=$ROOT/firecracker-api.stderr
    [ -e "$FC_SOCKET" ] || fail "Firecracker API socket is not exposed: $FC_SOCKET"
    FC_CONFIG=$ROOT/jail/firecracker/$LAST_MAIN_ID/root/fc.json
    [ -f "$FC_CONFIG" ] || fail "Firecracker config is missing: $FC_CONFIG"
    config=$(tr -d '[:space:]' < "$FC_CONFIG")
    for marker in '"balloon"' '"amount_mib":0' '"deflate_on_oom":true' \
        '"stats_polling_interval_s":1' '"free_page_reporting":true' \
        '"track_dirty_pages":true'; do
        case "$config" in
            *"$marker"*) ;;
            *) fail "Firecracker config is missing balloon/snapshot marker $marker" ;
        esac
    done
    firecracker_api GET /balloon/statistics '' 200
    stats=$(cat "$FC_BODY")
    actual_mib=$(printf '%s\n' "$stats" | sed -n \
        's/.*"actual_mib":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    available_memory=$(printf '%s\n' "$stats" | sed -n \
        's/.*"available_memory":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    [ -n "$actual_mib" ] || fail "balloon statistics omitted actual_mib: $stats"
    [ -n "$available_memory" ] || fail "balloon statistics omitted available_memory: $stats"
    firecracker_api PATCH /balloon '{"amount_mib":0}' 204
    [ ! -s "$FC_BODY" ] || fail "balloon PATCH returned an unexpected body: $(cat "$FC_BODY")"
}

setup_guest_http_server() {
    token=$1
    space=$2
    cli_push "$token" "$space" "$HTTP_SERVER" /tmp/shinu-smoke-http.sh
    cli_exec_expect "$token" "$space" '' chmod 700 /tmp/shinu-smoke-http.sh
    server_command="nohup socat TCP-LISTEN:$GUEST_HTTP_PORT,bind=0.0.0.0,reuseaddr,fork EXEC:/tmp/shinu-smoke-http.sh >/tmp/shinu-smoke-http.log 2>&1 </dev/null & server_pid=\$!; printf '%s\\n' \"\$server_pid\" >/tmp/shinu-smoke-http.pid; sleep 1; kill -0 \"\$server_pid\""
    cli_exec_expect "$token" "$space" '' sh -c "$server_command"
}

check_same_network() {
    token=$1
    source_space=$2
    peer_ip=$3
    request_command="printf 'GET /same-network HTTP/1.0\\r\\nHost: peer\\r\\n\\r\\n' | socat -T 5 - TCP:$peer_ip:$GUEST_HTTP_PORT"
    cli_run "$token" exec "$source_space" -- sh -c "$request_command"
    network_output=$(cat "$CLI_OUT")
    case "$network_output" in
        *'HTTP/1.1 200 OK'*'GET /same-network'*) ;;
        *) fail "same-network peer request did not reach the peer: $network_output" ;;
    esac
}

check_cross_project_isolation() {
    token=$1
    source_space=$2
    target_ip=$3
    marker=$4
    cross_command="rm -f /tmp/shinu-cross.out /tmp/shinu-cross.err; if printf 'cross-project-probe' | socat -T 3 - TCP:$target_ip:$GUEST_HTTP_PORT >/tmp/shinu-cross.out 2>/tmp/shinu-cross.err; then printf unexpected-cross-connect; exit 1; fi; if [ -s /tmp/shinu-cross.out ]; then printf unexpected-cross-output; exit 1; fi; printf '$marker'"
    cli_exec_expect "$token" "$source_space" "$marker" sh -c "$cross_command"
}

step "checking host prerequisites and creating an isolated root"
capture_host_baseline || fail "could not record host resource baseline"
step "starting shinud on http://127.0.0.1:$PORT"
occupied=
if occupied=$(curl --noproxy '*' -sS --max-time 1 -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$PORT/" 2>/dev/null); then
    [ "$occupied" = 000 ] || fail "loopback port $PORT is already serving HTTP (status $occupied)"
fi
start_daemon
step "minting project tokens"
TOKEN_A=$(mint_token "$PROJECT_A")
TOKEN_B=$(mint_token "$PROJECT_B")

step "creating the primary project space and exercising cold lifecycle"
cli_new "$TOKEN_A" "$SPACE_MAIN" "$NETWORK"
LAST_MAIN_ID=$LAST_SPACE_ID
TRACK_A="$TRACK_A $SPACE_MAIN"
cli_start "$TOKEN_A" "$SPACE_MAIN"
cli_exec_expect "$TOKEN_A" "$SPACE_MAIN" cold-exec-ok printf cold-exec-ok
cli_stop "$TOKEN_A" "$SPACE_MAIN"
cli_commit "$TOKEN_A" "$SPACE_MAIN" cold-none cold
COLD_ID=$LAST_COMMIT_ID
COLD_SHORT=$LAST_COMMIT_SHORT
json_object_with "$CLI_OUT" "\"id\":\"$COLD_ID\""
assert_object_has '"auto":false'
assert_object_has '"full":false'
assert_object_has '"snapshot":"none"'
assert_object_has '"snapshot_version":null'
snapshot_files_absent "$COLD_ID"

step "exercising full and diff snapshots, including balloon observables"
cli_start "$TOKEN_A" "$SPACE_MAIN"
check_balloon_and_config
cli_commit "$TOKEN_A" "$SPACE_MAIN" full-memory full
FULL_ID=$LAST_COMMIT_ID
json_object_with "$CLI_OUT" "\"id\":\"$FULL_ID\""
assert_object_has '"auto":false'
assert_object_has '"full":true'
assert_object_has '"base":null'
assert_object_has '"snapshot":"full"'
assert_object_has '"snapshot_version":"'
snapshot_files_exist "$FULL_ID"
cli_exec_expect "$TOKEN_A" "$SPACE_MAIN" '' sh -c 'printf full-marker >/tmp/shinu-full-marker'
cli_commit "$TOKEN_A" "$SPACE_MAIN" diff-memory diff
DIFF_ID=$LAST_COMMIT_ID
json_object_with "$CLI_OUT" "\"id\":\"$DIFF_ID\""
assert_object_has '"auto":false'
assert_object_has '"full":true'
assert_object_has '"snapshot":"diff"'
assert_object_has "\"base\":\"$FULL_ID\""
assert_object_has '"snapshot_version":"'
snapshot_files_exist "$DIFF_ID"
cli_stop "$TOKEN_A" "$SPACE_MAIN"

step "checking out the cold commit and verifying reflog behavior"
cli_run "$TOKEN_A" checkout "$SPACE_MAIN" "$COLD_ID"
checkout_output=$(cat "$CLI_OUT")
printf '%s\n' "$checkout_output" |
    grep -Eq "^checked out $COLD_SHORT \\(auto commit [0-9a-f]{8}\\)$" ||
    fail "checkout returned unexpected output: $checkout_output"
cli_run "$TOKEN_A" log "$SPACE_MAIN" --json
grep -F '"note":"cold-none"' "$CLI_OUT" >/dev/null ||
    fail "log omitted the checked-out cold commit"
case "$(cat "$CLI_OUT")" in
    *'"note":"full-memory"'*|*'"note":"diff-memory"'*)
        fail "log retained an unreachable pre-checkout branch" ;;
    *) ;;
esac
cli_run "$TOKEN_A" reflog "$SPACE_MAIN" --json
grep -F '"auto":true' "$CLI_OUT" >/dev/null ||
    fail "reflog omitted checkout's automatic checkpoint"
grep -F '"note":"auto before checkout ' "$CLI_OUT" >/dev/null ||
    fail "reflog omitted checkout's automatic checkpoint note"
cli_start "$TOKEN_A" "$SPACE_MAIN"
cli_exec_expect "$TOKEN_A" "$SPACE_MAIN" cold-checkout-ok sh -c '[ ! -e /tmp/shinu-full-marker ] && printf cold-checkout-ok'
cli_stop "$TOKEN_A" "$SPACE_MAIN"

step "forking from the full snapshot and restoring guest memory"
cli_run "$TOKEN_A" fork "$FULL_ID" "$SPACE_FORK"
first_line=$(sed -n '1p' "$CLI_OUT")
[ "$(cat "$CLI_OUT")" = "$first_line" ] || fail "fork wrote unexpected extra output"
case "$first_line" in
    "$SPACE_FORK  "*) ;;
    *) fail "fork returned unexpected summary: $first_line" ;;
esac
FORK_ID=$(printf '%s\n' "$first_line" | awk '{print $2}')
is_uuid "$FORK_ID"
TRACK_A="$TRACK_A $SPACE_FORK"
cli_start "$TOKEN_A" "$SPACE_FORK"
cli_exec_expect "$TOKEN_A" "$SPACE_FORK" fork-restored-ok printf fork-restored-ok
cli_stop "$TOKEN_A" "$SPACE_FORK"
cli_remove "$TOKEN_A" "$SPACE_FORK"

step "checking project-scoped listing and removing a space"
cli_new "$TOKEN_A" "$SPACE_REMOVE" ''
TRACK_A="$TRACK_A $SPACE_REMOVE"
cli_remove "$TOKEN_A" "$SPACE_REMOVE"
cli_run "$TOKEN_A" ls --json
case "$(cat "$CLI_OUT")" in
    *"\"name\":\"$SPACE_REMOVE\""*) fail "removed space remains visible" ;;
    *) ;;
esac
cli_run "$TOKEN_B" ls --json
case "$(cat "$CLI_OUT")" in
    *"\"name\":\"$SPACE_MAIN\""*|*"\"project\":\"$PROJECT_A\""*)
        fail "project B can disclose project A through listing" ;;
    *) ;;
esac

step "creating same-named network members in both projects"
cli_new "$TOKEN_A" "$SPACE_PEER" "$NETWORK"
TRACK_A="$TRACK_A $SPACE_PEER"
cli_new "$TOKEN_B" "$SPACE_BETA" "$NETWORK"
TRACK_B="$TRACK_B $SPACE_BETA"
cli_failure "$TOKEN_B" 'HTTP 404' exec "$SPACE_MAIN" -- printf should-not-run
cli_failure "$TOKEN_A" 'HTTP 404' exec "$SPACE_BETA" -- printf should-not-run
cli_run "$TOKEN_A" ls --json
LIST_A=$ROOT/list-project-a.json
cp "$CLI_OUT" "$LIST_A"
case "$(cat "$LIST_A")" in
    *"\"project\":\"$PROJECT_A\""*) ;;
    *) fail "project A listing omitted its project identity" ;;
esac
case "$(cat "$LIST_A")" in
    *"\"name\":\"$SPACE_MAIN\""*) ;;
    *) fail "project A listing omitted the primary space" ;;
esac
case "$(cat "$LIST_A")" in
    *"\"name\":\"$SPACE_PEER\""*) ;;
    *) fail "project A listing omitted the peer space" ;;
esac
case "$(cat "$LIST_A")" in
    *"\"project\":\"$PROJECT_B\""*|*"\"name\":\"$SPACE_BETA\""*)
        fail "project A listing disclosed project B" ;;
    *) ;;
esac
cli_run "$TOKEN_B" ls --json
LIST_B=$ROOT/list-project-b.json
cp "$CLI_OUT" "$LIST_B"
case "$(cat "$LIST_B")" in
    *"\"project\":\"$PROJECT_B\""*) ;;
    *) fail "project B listing omitted its project identity" ;;
esac
case "$(cat "$LIST_B")" in
    *"\"name\":\"$SPACE_BETA\""*) ;;
    *) fail "project B listing omitted its owned space" ;;
esac
case "$(cat "$LIST_B")" in
    *"\"project\":\"$PROJECT_A\""*|*"\"name\":\"$SPACE_MAIN\""*|*"\"name\":\"$SPACE_PEER\""*)
        fail "project B listing disclosed project A" ;;
    *) ;;
esac

step "starting network members and waiting for guest addresses"
cli_start "$TOKEN_A" "$SPACE_PEER"
cli_start "$TOKEN_B" "$SPACE_BETA"
cli_start "$TOKEN_A" "$SPACE_MAIN"
cli_network_capture "$TOKEN_A" "$NETWORK"
MAIN_IP=$(space_ip "$SPACE_MAIN")
PEER_IP=$(space_ip "$SPACE_PEER")
cli_network_capture "$TOKEN_B" "$NETWORK"
BETA_IP=$(space_ip "$SPACE_BETA")
wait_guest_network "$TOKEN_A" "$SPACE_MAIN" "$MAIN_IP"
wait_guest_network "$TOKEN_A" "$SPACE_PEER" "$PEER_IP"
wait_guest_network "$TOKEN_B" "$SPACE_BETA" "$BETA_IP"

HTTP_SERVER=$ROOT/shinu-smoke-http-server.sh
cat > "$HTTP_SERVER" <<'EOF'
#!/bin/sh
request=$(cat)
printf 'HTTP/1.1 200 OK\r\n'
printf 'Set-Cookie: shinu_session=guest-reserved; Path=/\r\n'
printf 'Set-Cookie: guest_cookie=guest-preserved; Path=/\r\n'
printf 'Connection: close\r\n'
printf '\r\n'
printf '%s\n' "$request"
EOF
chmod 700 "$HTTP_SERVER"
setup_guest_http_server "$TOKEN_A" "$SPACE_PEER"
setup_guest_http_server "$TOKEN_B" "$SPACE_BETA"
record_owned_resources || fail "could not record owned host resources"

step "checking same-project peer communication and cross-project isolation"
check_same_network "$TOKEN_A" "$SPACE_MAIN" "$PEER_IP"
check_cross_project_isolation "$TOKEN_A" "$SPACE_MAIN" "$BETA_IP" cross-project-isolated-a-to-b
check_cross_project_isolation "$TOKEN_B" "$SPACE_BETA" "$PEER_IP" cross-project-isolated-b-to-a

step "checking guest HTTP proxy credential stripping"
PROXY_HEADERS=$ROOT/proxy-response.headers
PROXY_BODY=$ROOT/proxy-response.body
if ! proxy_status=$(curl --noproxy '*' -sS --max-time 15 -D "$PROXY_HEADERS" -o "$PROXY_BODY" \
    -H "Authorization: Bearer $TOKEN_A" \
    -H 'Cookie: shinu_session=control-secret; guest_cookie=keep' \
    -H 'X-Smoke: proxy' \
    -w '%{http_code}' "http://127.0.0.1:$PORT/v1/spaces/$SPACE_PEER/proxy/$GUEST_HTTP_PORT/proxy-check" \
    2> "$ROOT/proxy.stderr" ); then
    cat "$ROOT/proxy.stderr" >&2
    fail "guest proxy request failed"
fi
[ "$proxy_status" = 200 ] || fail "guest proxy returned status $proxy_status"
if grep -F 'Set-Cookie: shinu_session=' "$PROXY_HEADERS" >/dev/null 2>&1; then
    fail "proxy forwarded reserved shinu_session Set-Cookie"
fi
if ! grep -F 'Set-Cookie: guest_cookie=guest-preserved' "$PROXY_HEADERS" >/dev/null 2>&1; then
    fail "proxy dropped a non-reserved guest Set-Cookie"
fi
if grep -F 'Authorization:' "$PROXY_BODY" >/dev/null 2>&1; then
    fail "proxy forwarded control-plane Authorization to the guest"
fi
if grep -F 'shinu_session=control-secret' "$PROXY_BODY" >/dev/null 2>&1; then
    fail "proxy forwarded the reserved session cookie to the guest"
fi
for marker in 'Cookie: guest_cookie=keep' 'X-Smoke: proxy' \
    "Host: 127.0.0.1:$GUEST_HTTP_PORT" 'GET /proxy-check HTTP/1.1'; do
    if ! grep -F "$marker" "$PROXY_BODY" >/dev/null 2>&1; then
        fail "proxy did not forward expected sanitized request marker: $marker"
    fi
done

step "restarting shinud with running VMs and verifying recovery"
restart_daemon
cli_start_running "$TOKEN_A" "$SPACE_MAIN"
cli_run "$TOKEN_A" ls --json
case "$(cat "$CLI_OUT")" in
    *"\"name\":\"$SPACE_MAIN\""*'"running":true'*) ;;
    *) fail "running VM was not recovered in daemon state after restart" ;;
esac
cli_exec_expect "$TOKEN_A" "$SPACE_MAIN" restart-recovered printf restart-recovered

step "stopping and removing every remaining smoke space"
cli_stop "$TOKEN_A" "$SPACE_MAIN"
cli_stop "$TOKEN_A" "$SPACE_PEER"
cli_stop "$TOKEN_B" "$SPACE_BETA"
cli_remove "$TOKEN_A" "$SPACE_PEER"
cli_remove "$TOKEN_B" "$SPACE_BETA"
cli_remove "$TOKEN_A" "$SPACE_MAIN"
cli_run "$TOKEN_A" ls --json
case "$(cat "$CLI_OUT")" in
    *"\"name\":\"$SPACE_MAIN\""*|*"\"name\":\"$SPACE_PEER\""*)
        fail "a removed project A space remains visible" ;;
    *) ;;
esac
cli_run "$TOKEN_B" ls --json
case "$(cat "$CLI_OUT")" in
    *"\"name\":\"$SPACE_BETA\""*) fail "a removed project B space remains visible" ;;
    *) ;;
esac

step "host smoke scenarios passed; cleanup will stop the daemon and remove $ROOT"
exit 0
