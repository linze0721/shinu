#!/bin/sh
# Install release binaries and the runit service.
#
# `shinu-vsock` must share `$PREFIX/bin` with `shinu`; the client resolves
# the helper beside its own executable.
set -eu

PREFIX="${PREFIX:-/usr/local}"
SVDIR="${SVDIR:-/etc/sv}"
BASE_DIR="$(pwd -P)"
case "$PREFIX" in
    /*) ;;
    *) PREFIX="$BASE_DIR/$PREFIX" ;;
esac
case "$SVDIR" in
    /*) ;;
    *) SVDIR="$BASE_DIR/$SVDIR" ;;
esac
BIN="$PREFIX/bin"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

for binary in shinu shinu-vsock shinud; do
    if [ ! -f "$SRC/target/release/$binary" ] || [ ! -x "$SRC/target/release/$binary" ]; then
        printf 'missing release binary: %s (run: cargo build --release)\n' "$SRC/target/release/$binary" >&2
        exit 1
    fi
done

# The daemon passes these numeric ids to the jailer.  Keep the values
# canonical so comparisons cannot depend on shell integer parsing.
JAIL_UID="${SHINU_JAIL_UID:-30000}"
JAIL_GID="${SHINU_JAIL_GID:-30000}"

fail_jail_identity() {
    printf 'unsafe shinu-jail identity: %s\n' "$1" >&2
    exit 1
}

validate_jail_id() {
    ID_LABEL=$1
    ID_VALUE=$2
    case "$ID_VALUE" in
        ''|*[!0-9]*)
            fail_jail_identity "$ID_LABEL must be a nonzero decimal ID"
            ;;
    esac
    case "$ID_VALUE" in
        *[1-9]*) ;;
        *) fail_jail_identity "$ID_LABEL must be a nonzero decimal ID" ;;
    esac
}

canonical_jail_id() {
    ID_VALUE=$1
    while [ "${ID_VALUE#0}" != "$ID_VALUE" ]; do
        ID_VALUE=${ID_VALUE#0}
    done
    printf '%s\n' "$ID_VALUE"
}

validate_jail_id SHINU_JAIL_UID "$JAIL_UID"
validate_jail_id SHINU_JAIL_GID "$JAIL_GID"
JAIL_UID="$(canonical_jail_id "$JAIL_UID")"
JAIL_GID="$(canonical_jail_id "$JAIL_GID")"

# Check both NSS directions before making any change.  A numeric match to a
# different name, or a name mapped to a different numeric identity, is never
# safe to reuse.
USER_EXISTS=0
USER_BY_UID="$(getent passwd "$JAIL_UID" 2>/dev/null || :)"
USER_BY_NAME="$(getent passwd shinu-jail 2>/dev/null || :)"
USER_UID_BY_NAME="$(id -u shinu-jail 2>/dev/null || :)"
USER_GID_BY_NAME="$(id -g shinu-jail 2>/dev/null || :)"

case "$USER_BY_UID" in
    '') ;;
    shinu-jail:*)
        USER_EXISTS=1
        USER_FIELDS=${USER_BY_UID#*:}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_RECORD_UID=${USER_FIELDS%%:*}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_RECORD_GID=${USER_FIELDS%%:*}
        [ "$(canonical_jail_id "$USER_RECORD_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "uid $JAIL_UID is not mapped with primary gid $JAIL_GID"
        [ "$(canonical_jail_id "$USER_RECORD_UID")" = "$JAIL_UID" ] || \
            fail_jail_identity "uid $JAIL_UID is not mapped back to shinu-jail"
        ;;
    *) fail_jail_identity "uid $JAIL_UID belongs to another account" ;;
esac

case "$USER_BY_NAME" in
    '') ;;
    shinu-jail:*)
        USER_EXISTS=1
        USER_FIELDS=${USER_BY_NAME#*:}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_NAME_UID=${USER_FIELDS%%:*}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_NAME_GID=${USER_FIELDS%%:*}
        [ "$(canonical_jail_id "$USER_NAME_UID")" = "$JAIL_UID" ] || \
            fail_jail_identity "shinu-jail is not configured with uid $JAIL_UID"
        [ "$(canonical_jail_id "$USER_NAME_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "shinu-jail is not configured with primary gid $JAIL_GID"
        ;;
    *) fail_jail_identity 'the shinu-jail account name is mapped inconsistently' ;;
esac
if [ -z "$USER_BY_NAME" ] && [ -n "$USER_UID_BY_NAME" ]; then
    fail_jail_identity 'shinu-jail account lookup is inconsistent'
fi
if [ -z "$USER_BY_NAME" ] && [ -n "$USER_GID_BY_NAME" ]; then
    fail_jail_identity 'shinu-jail account lookup is inconsistent'
fi
if [ -n "$USER_BY_NAME" ] && [ -z "$USER_UID_BY_NAME" ]; then
    fail_jail_identity 'shinu-jail account lookup is incomplete'
fi
if [ -n "$USER_BY_NAME" ] && [ -z "$USER_GID_BY_NAME" ]; then
    fail_jail_identity 'shinu-jail account lookup is incomplete'
fi
if [ -n "$USER_BY_NAME" ] && [ -z "$USER_BY_UID" ]; then
    fail_jail_identity 'shinu-jail account lookup is incomplete'
fi
if [ -z "$USER_BY_NAME" ] && [ -n "$USER_BY_UID" ]; then
    fail_jail_identity 'shinu-jail account lookup is inconsistent'
fi

if [ -n "$USER_UID_BY_NAME" ]; then
    USER_EXISTS=1
    [ "$(canonical_jail_id "$USER_UID_BY_NAME")" = "$JAIL_UID" ] || \
        fail_jail_identity "shinu-jail is not configured with uid $JAIL_UID"
fi
if [ -n "$USER_GID_BY_NAME" ]; then
    USER_EXISTS=1
    [ "$(canonical_jail_id "$USER_GID_BY_NAME")" = "$JAIL_GID" ] || \
        fail_jail_identity "shinu-jail is not configured with primary gid $JAIL_GID"
fi

GROUP_EXISTS=0
GROUP_BY_GID="$(getent group "$JAIL_GID" 2>/dev/null || :)"
GROUP_BY_NAME="$(getent group shinu-jail 2>/dev/null || :)"

case "$GROUP_BY_GID" in
    '') ;;
    shinu-jail:*)
        GROUP_EXISTS=1
        GROUP_FIELDS=${GROUP_BY_GID#*:}
        GROUP_FIELDS=${GROUP_FIELDS#*:}
        GROUP_RECORD_GID=${GROUP_FIELDS%%:*}
        [ "$(canonical_jail_id "$GROUP_RECORD_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "gid $JAIL_GID is not mapped back to shinu-jail"
        ;;
    *) fail_jail_identity "gid $JAIL_GID belongs to another group" ;;
esac
if [ -n "$GROUP_BY_NAME" ] && [ -z "$GROUP_BY_GID" ]; then
    fail_jail_identity 'shinu-jail group lookup is incomplete'
fi
if [ -z "$GROUP_BY_NAME" ] && [ -n "$GROUP_BY_GID" ]; then
    fail_jail_identity 'shinu-jail group lookup is inconsistent'
fi

case "$GROUP_BY_NAME" in
    '') ;;
    shinu-jail:*)
        GROUP_EXISTS=1
        GROUP_FIELDS=${GROUP_BY_NAME#*:}
        GROUP_FIELDS=${GROUP_FIELDS#*:}
        GROUP_NAME_GID=${GROUP_FIELDS%%:*}
        [ "$(canonical_jail_id "$GROUP_NAME_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "shinu-jail is not configured with gid $JAIL_GID"
        ;;
    *) fail_jail_identity 'the shinu-jail group name is mapped inconsistently' ;;
esac

# Create only an entirely absent side.  Existing identities are never
# repaired in place; the complete mapping is verified after creation/reuse.
if [ "$GROUP_EXISTS" -eq 0 ]; then
    if ! groupadd -g "$JAIL_GID" -r shinu-jail 2>/dev/null && \
       ! addgroup -g "$JAIL_GID" -S shinu-jail 2>/dev/null; then
        printf 'could not create shinu-jail group (gid %s)\n' "$JAIL_GID" >&2
        exit 1
    fi
fi

if [ "$USER_EXISTS" -eq 0 ]; then
    if ! useradd -u "$JAIL_UID" -g "$JAIL_GID" -r -s /usr/sbin/nologin -d /nonexistent shinu-jail 2>/dev/null && \
       ! adduser -u "$JAIL_UID" -G shinu-jail -S -D -H -s /sbin/nologin shinu-jail 2>/dev/null; then
        printf 'could not create shinu-jail user (uid %s, gid %s)\n' "$JAIL_UID" "$JAIL_GID" >&2
        exit 1
    fi
fi

# Re-read every mapping after creation or reuse and require exact
# bidirectional identity, including the user's primary group.
USER_BY_UID="$(getent passwd "$JAIL_UID" 2>/dev/null || :)"
USER_BY_NAME="$(getent passwd shinu-jail 2>/dev/null || :)"
USER_UID_BY_NAME="$(id -u shinu-jail 2>/dev/null || :)"
USER_GID_BY_NAME="$(id -g shinu-jail 2>/dev/null || :)"
case "$USER_BY_UID" in
    shinu-jail:*)
        USER_FIELDS=${USER_BY_UID#*:}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_RECORD_UID=${USER_FIELDS%%:*}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_RECORD_GID=${USER_FIELDS%%:*}
        [ "$(canonical_jail_id "$USER_RECORD_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "uid $JAIL_UID is not mapped with primary gid $JAIL_GID"
        [ "$(canonical_jail_id "$USER_RECORD_UID")" = "$JAIL_UID" ] || \
            fail_jail_identity "uid $JAIL_UID is not mapped back to shinu-jail"
        ;;
    *) fail_jail_identity "uid $JAIL_UID is not mapped to shinu-jail" ;;
esac
case "$USER_BY_NAME" in
    shinu-jail:*)
        USER_FIELDS=${USER_BY_NAME#*:}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_NAME_UID=${USER_FIELDS%%:*}
        USER_FIELDS=${USER_FIELDS#*:}
        USER_NAME_GID=${USER_FIELDS%%:*}
        [ "$(canonical_jail_id "$USER_NAME_UID")" = "$JAIL_UID" ] || \
            fail_jail_identity "shinu-jail is not configured with uid $JAIL_UID"
        [ "$(canonical_jail_id "$USER_NAME_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "shinu-jail is not configured with primary gid $JAIL_GID"
        ;;
    *) fail_jail_identity 'shinu-jail account lookup failed' ;;
esac
[ "$(canonical_jail_id "$USER_UID_BY_NAME")" = "$JAIL_UID" ] || \
    fail_jail_identity "shinu-jail is not configured with uid $JAIL_UID"
[ "$(canonical_jail_id "$USER_GID_BY_NAME")" = "$JAIL_GID" ] || \
    fail_jail_identity "shinu-jail is not configured with primary gid $JAIL_GID"

GROUP_BY_GID="$(getent group "$JAIL_GID" 2>/dev/null || :)"
GROUP_BY_NAME="$(getent group shinu-jail 2>/dev/null || :)"
case "$GROUP_BY_GID" in
    shinu-jail:*)
        GROUP_FIELDS=${GROUP_BY_GID#*:}
        GROUP_FIELDS=${GROUP_FIELDS#*:}
        GROUP_RECORD_GID=${GROUP_FIELDS%%:*}
        [ "$(canonical_jail_id "$GROUP_RECORD_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "gid $JAIL_GID is not mapped back to shinu-jail"
        ;;
    *) fail_jail_identity "gid $JAIL_GID is not mapped to shinu-jail" ;;
esac
case "$GROUP_BY_NAME" in
    shinu-jail:*)
        GROUP_FIELDS=${GROUP_BY_NAME#*:}
        GROUP_FIELDS=${GROUP_FIELDS#*:}
        GROUP_NAME_GID=${GROUP_FIELDS%%:*}
        [ "$(canonical_jail_id "$GROUP_NAME_GID")" = "$JAIL_GID" ] || \
            fail_jail_identity "shinu-jail is not configured with gid $JAIL_GID"
        ;;
    *) fail_jail_identity 'shinu-jail group lookup failed' ;;
esac
# Install all three together; `shinu` resolves `shinu-vsock` beside itself.
install -d -m 0755 "$BIN"
for binary in shinu shinu-vsock shinud; do
    install -m 0755 "$SRC/target/release/$binary" "$BIN/$binary"
done

install -d -m 0755 "$SVDIR/shinud"
RUN="$SVDIR/shinud/run"
RUN_TMP="$RUN.$$"
DAEMON="$BIN/shinud"
DQUOTE='"'
ESCAPED_DAEMON="$(printf '%s\n' "$DAEMON" | sed -e 's/[\\$`]/\\&/g' -e "s/[$DQUOTE]/\\\\&/g" | sed 's/[\\&|]/\\&/g')"
DOLLAR='$'
trap 'rm -f "$RUN_TMP"' 0 1 2 3 15
sed \
    -e "s|/usr/local/bin/shinud|$ESCAPED_DAEMON|g" \
    -e "s|^export SHINU_JAIL_UID=.*|export SHINU_JAIL_UID=\"${DOLLAR}{SHINU_JAIL_UID:-$JAIL_UID}\" # uid used inside the jailer|" \
    -e "s|^export SHINU_JAIL_GID=.*|export SHINU_JAIL_GID=\"${DOLLAR}{SHINU_JAIL_GID:-$JAIL_GID}\" # gid used inside the jailer|" \
    "$SRC/packaging/sv/shinud/run" > "$RUN_TMP"
chmod 0755 "$RUN_TMP"
mv -f "$RUN_TMP" "$RUN"
trap - 0 1 2 3 15

printf 'installed to %s; enable with: ln -s %s /var/service/\n\n' "$BIN" "$SVDIR/shinud"
printf '%s\n' 'runtime requirements on this host:'
printf '%s\n' '  /dev/kvm present, root on btrfs/xfs with reflink support'
printf '  jailer user/group (uid/gid %s/%s) and cgroup v2 enabled\n' "$JAIL_UID" "$JAIL_GID"
printf '%s\n' '  external commands: curl tar mkfs.ext4 e2fsck resize2fs mount umount'
printf '%s\n' '                     truncate ssh ssh-keygen setsid cp chown btrfs df kill'
printf '%s\n' '                     ip iptables unshare chroot sha256sum uname'
