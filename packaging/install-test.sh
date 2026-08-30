#!/bin/sh
# Hermetic identity and path matrix for packaging/install.sh.
#
# Every fixture owns its NSS database and account-mutator commands. The real
# user/group management commands are never reachable through the test PATH.
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
INSTALL_SOURCE=$SCRIPT_DIR/install.sh
RUN_SOURCE=$SCRIPT_DIR/sv/shinud/run
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shinu-install-test.XXXXXX")

cleanup() {
    result=$?
    rm -rf "$TMP_ROOT"
    trap - 0 1 2 3 15
    exit "$result"
}
trap cleanup 0 1 2 3 15

FAKE_BIN=$TMP_ROOT/fake-bin
mkdir -p "$FAKE_BIN"

# Fake getent implements only the two databases and lookup forms used by
# install.sh. Records are fixture-local, so no host NSS state is consulted.
cat > "$FAKE_BIN/getent" <<'EOF_GETENT'
#!/bin/sh
set -eu

state=${SHINU_TEST_STATE:?}
[ "$#" -eq 2 ] || exit 2
database=$1
key=$2
case "$database" in
    passwd|group) ;;
    *) exit 2 ;;
esac
lookup_file=$state/$database

if [ "$database" = passwd ] && [ -f "$state/passwd-by-uid" ]; then
    case "$key" in
        *[!0-9]*) ;;
        *) lookup_file=$state/passwd-by-uid ;;
    esac
fi
if [ "$database" = group ] && [ -f "$state/group-by-gid" ]; then
    case "$key" in
        *[!0-9]*) ;;
        *) lookup_file=$state/group-by-gid ;;
    esac
fi

while IFS= read -r record || [ -n "$record" ]; do
    case "$record" in
        ''|'#'*) continue ;;
    esac
    name=${record%%:*}
    fields=${record#*:}
    fields=${fields#*:}
    case "$database" in
        passwd)
            uid=${fields%%:*}
            [ "$key" = "$name" ] || [ "$key" = "$uid" ] || continue
            ;;
        group)
            gid=${fields%%:*}
            [ "$key" = "$name" ] || [ "$key" = "$gid" ] || continue
            ;;
    esac
    printf '%s\n' "$record"
    exit 0
done < "$lookup_file"
exit 2
EOF_GETENT

# Fake id supplies the name-to-UID/GID NSS direction independently of
# getent, allowing one-way and incomplete lookup cases to be represented.
cat > "$FAKE_BIN/id" <<'EOF_ID'
#!/bin/sh
set -eu

state=${SHINU_TEST_STATE:?}
[ "$#" -eq 2 ] || exit 1
kind=$1
name=$2
[ "$name" = shinu-jail ] || exit 1

record=
while IFS= read -r candidate || [ -n "$candidate" ]; do
    case "$candidate" in
        ''|'#'*) continue ;;
    esac
    [ "${candidate%%:*}" = "$name" ] || continue
    record=$candidate
    break
done < "$state/passwd"
[ -n "$record" ] || exit 1

fields=${record#*:}
fields=${fields#*:}
uid=${fields%%:*}
fields=${fields#*:}
gid=${fields%%:*}
case "$kind" in
    -u) printf '%s\n' "$uid" ;;
    -g) printf '%s\n' "$gid" ;;
    *) exit 1 ;;
esac
EOF_ID

# All four mutator names resolve to this fixture-local implementation. It
# records the invocation and updates fake NSS files so the installer's
# post-create bidirectional checks exercise the real create/recheck path.
cat > "$FAKE_BIN/account-mutator" <<'EOF_MUTATOR'
#!/bin/sh
set -eu

state=${SHINU_TEST_STATE:?}
command_name=${0##*/}
printf '%s' "$command_name" >> "$state/mutations"
for argument do
    printf ' %s' "$argument" >> "$state/mutations"
done
printf '\n' >> "$state/mutations"

case "$command_name" in
    groupadd|addgroup)
        gid=
        name=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -g)
                    [ "$#" -ge 2 ] || exit 2
                    gid=$2
                    shift 2
                    ;;
                -*) shift ;;
                *) name=$1; shift ;;
            esac
        done
        [ "$name" = shinu-jail ] || exit 2
        [ -n "$gid" ] || exit 2
        printf '%s\n' "shinu-jail:x:$gid:" >> "$state/group"
        ;;
    useradd|adduser)
        uid=
        gid=
        group_name=
        name=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -u)
                    [ "$#" -ge 2 ] || exit 2
                    uid=$2
                    shift 2
                    ;;
                -g)
                    [ "$#" -ge 2 ] || exit 2
                    gid=$2
                    shift 2
                    ;;
                -G)
                    [ "$#" -ge 2 ] || exit 2
                    group_name=$2
                    shift 2
                    ;;
                -*) shift ;;
                *) name=$1; shift ;;
            esac
        done
        [ "$name" = shinu-jail ] || exit 2
        [ -n "$uid" ] || exit 2
        if [ -z "$gid" ] && [ -n "$group_name" ]; then
            while IFS= read -r group_record || [ -n "$group_record" ]; do
                [ "${group_record%%:*}" = "$group_name" ] || continue
                group_fields=${group_record#*:}
                group_fields=${group_fields#*:}
                gid=${group_fields%%:*}
                break
            done < "$state/group"
        fi
        [ -n "$gid" ] || exit 2
        printf '%s\n' "shinu-jail:x:$uid:$gid::/nonexistent:/usr/sbin/nologin" >> "$state/passwd"
        ;;
    *) exit 2 ;;
esac
EOF_MUTATOR

chmod 0755 "$FAKE_BIN/getent" "$FAKE_BIN/id" "$FAKE_BIN/account-mutator"
for command_name in groupadd addgroup useradd adduser; do
    cp "$FAKE_BIN/account-mutator" "$FAKE_BIN/$command_name"
    chmod 0755 "$FAKE_BIN/$command_name"
done

fail() {
    printf 'install identity matrix: FAIL: %s\n' "$1" >&2
    exit 1
}

assert_equal() {
    expected=$1
    actual=$2
    description=$3
    [ "$expected" = "$actual" ] || fail "$description (expected [$expected], got [$actual])"
}

assert_file_contains() {
    file=$1
    needle=$2
    description=$3
    contents=$(cat "$file")
    case "$contents" in
        *"$needle"*) ;;
        *) fail "$description (missing [$needle] in $file)" ;;
    esac
}

assert_no_mutation() {
    [ ! -s "$CASE_DIR/state/mutations" ] || \
        fail "$CASE_NAME invoked an account mutator on a rejected identity"
}

begin_case() {
    CASE_NAME=$1
    CASE_DIR=$TMP_ROOT/$CASE_NAME
    mkdir -p "$CASE_DIR/packaging/sv/shinud" "$CASE_DIR/target/release" \
        "$CASE_DIR/work" "$CASE_DIR/state"
    cp "$INSTALL_SOURCE" "$CASE_DIR/packaging/install.sh"
    cp "$RUN_SOURCE" "$CASE_DIR/packaging/sv/shinud/run"
    for binary in shinu shinu-vsock shinud; do
        printf '#!/bin/sh\nexit 0\n' > "$CASE_DIR/target/release/$binary"
        chmod 0755 "$CASE_DIR/target/release/$binary"
    done
    : > "$CASE_DIR/state/passwd"
    : > "$CASE_DIR/state/group"
    : > "$CASE_DIR/state/mutations"

    PREFIX_VALUE=$CASE_DIR/prefix
    SVDIR_VALUE=$CASE_DIR/sv
    ID_MODE=default
    UID_VALUE=30000
    GID_VALUE=30000
}

seed_identity() {
    printf '%s\n' \
        'shinu-jail:x:30000:30000::/nonexistent:/usr/sbin/nologin' \
        > "$CASE_DIR/state/passwd"
    printf '%s\n' 'shinu-jail:x:30000:' > "$CASE_DIR/state/group"
}

seed_user() {
    printf '%s\n' "shinu-jail:x:$1:$2::/nonexistent:/usr/sbin/nologin" \
        >> "$CASE_DIR/state/passwd"
}

seed_group() {
    printf '%s\n' "shinu-jail:x:$1:" >> "$CASE_DIR/state/group"
}

seed_other_user() {
    printf '%s\n' "other:x:$1:$2::/nonexistent:/usr/sbin/nologin" \
        >> "$CASE_DIR/state/passwd"
}

seed_other_group() {
    printf '%s\n' "other:x:$1:" >> "$CASE_DIR/state/group"
}

run_install() {
    stdout_file=$CASE_DIR/stdout
    stderr_file=$CASE_DIR/stderr
    if [ "$ID_MODE" = default ]; then
        if (
            cd "$CASE_DIR/work" &&
            /usr/bin/env -i \
                "PATH=$FAKE_BIN:/usr/bin:/bin" \
                "HOME=$CASE_DIR/home" \
                "SHINU_TEST_STATE=$CASE_DIR/state" \
                "PREFIX=$PREFIX_VALUE" \
                "SVDIR=$SVDIR_VALUE" \
                "$CASE_DIR/packaging/install.sh"
        ) > "$stdout_file" 2> "$stderr_file"; then
            INSTALL_STATUS=0
        else
            INSTALL_STATUS=$?
        fi
    else
        if (
            cd "$CASE_DIR/work" &&
            /usr/bin/env -i \
                "PATH=$FAKE_BIN:/usr/bin:/bin" \
                "HOME=$CASE_DIR/home" \
                "SHINU_TEST_STATE=$CASE_DIR/state" \
                "PREFIX=$PREFIX_VALUE" \
                "SVDIR=$SVDIR_VALUE" \
                "SHINU_JAIL_UID=$UID_VALUE" \
                "SHINU_JAIL_GID=$GID_VALUE" \
                "$CASE_DIR/packaging/install.sh"
        ) > "$stdout_file" 2> "$stderr_file"; then
            INSTALL_STATUS=0
        else
            INSTALL_STATUS=$?
        fi
    fi
}

assert_rejected() {
    expected_error=$1
    assert_equal 1 "$INSTALL_STATUS" "$CASE_NAME must reject the identity"
    assert_equal "unsafe shinu-jail identity: $expected_error" \
        "$(cat "$CASE_DIR/stderr")" "$CASE_NAME error"
    assert_no_mutation
}

assert_accepted() {
    expected_bin=$1
    expected_svdir=$2
    assert_equal 0 "$INSTALL_STATUS" "$CASE_NAME must accept the identity"
    assert_equal '' "$(cat "$CASE_DIR/stderr")" "$CASE_NAME stderr"

    run_file=$expected_svdir/shinud/run
    [ -f "$run_file" ] || fail "$CASE_NAME did not generate $run_file"
    [ -x "$run_file" ] || fail "$CASE_NAME generated a non-executable run script"
    expected_daemon="$expected_bin/shinud"
    escaped_daemon=$(printf '%s\n' "$expected_daemon" | sed -e 's/[$]/\\$/g' -e 's/"/\\"/g')
    actual_daemon=$(sed -n '$p' "$run_file")
    assert_equal "exec \"$escaped_daemon\"" "$actual_daemon" \
        "$CASE_NAME daemon path"
    expected_uid_line=$(printf 'export SHINU_JAIL_UID="${SHINU_JAIL_UID:-%s}" # uid used inside the jailer' "$UID_VALUE")
    expected_gid_line=$(printf 'export SHINU_JAIL_GID="${SHINU_JAIL_GID:-%s}" # gid used inside the jailer' "$GID_VALUE")
    actual_uid_line=$(sed -n '16p' "$run_file")
    actual_gid_line=$(sed -n '17p' "$run_file")
    assert_equal "$expected_uid_line" "$actual_uid_line" "$CASE_NAME persisted UID"
    assert_equal "$expected_gid_line" "$actual_gid_line" "$CASE_NAME persisted GID"
    if ! /usr/bin/env -i "PATH=$FAKE_BIN:/usr/bin:/bin" "$run_file" \
        > "$CASE_DIR/run-stdout" 2> "$CASE_DIR/run-stderr"; then
        fail "$CASE_NAME generated run script did not execute its daemon"
    fi
    assert_equal '' "$(cat "$CASE_DIR/run-stderr")" "$CASE_NAME run stderr"
}

# 1. Existing default identity is accepted without account mutation.
begin_case default-identity
seed_identity
run_install
assert_accepted "$PREFIX_VALUE/bin" "$SVDIR_VALUE"
assert_no_mutation

# 2. Missing custom identities are created only through fake mutators and the
#    canonical values are persisted in the generated runit script.
begin_case custom-identities
ID_MODE=custom
UID_VALUE=31001
GID_VALUE=32002
run_install
assert_accepted "$PREFIX_VALUE/bin" "$SVDIR_VALUE"
assert_file_contains "$CASE_DIR/state/mutations" \
    'groupadd -g 32002 -r shinu-jail' \
    'custom identity did not use the fake group mutator'
assert_file_contains "$CASE_DIR/state/mutations" \
    'useradd -u 31001 -g 32002 -r -s /usr/sbin/nologin -d /nonexistent shinu-jail' \
    'custom identity did not use the fake user mutator'

# 3. A UID owned by another account fails closed before any mutation.
begin_case uid-collision
seed_other_user 30000 30000
run_install
assert_rejected 'uid 30000 belongs to another account'

# 4. A GID owned by another group fails closed before any mutation.
begin_case gid-collision
seed_other_group 30000
run_install
assert_rejected 'gid 30000 belongs to another group'

# 5. The named account may not silently resolve to another UID.
begin_case named-user-wrong-uid
seed_user 31000 30000
run_install
assert_rejected 'shinu-jail is not configured with uid 30000'

# 6. The named account may not silently use another primary GID.
begin_case named-user-wrong-primary-gid
seed_user 30000 31000
: > "$CASE_DIR/state/passwd-by-uid"
run_install
assert_rejected 'shinu-jail is not configured with primary gid 30000'

# 7. The named group may not silently resolve to another GID.
begin_case named-group-wrong-gid
printf '%s\n' 'shinu-jail:x:31000:' >> "$CASE_DIR/state/group"
printf '%s\n' 'shinu-jail:x:30000:' > "$CASE_DIR/state/group-by-gid"
run_install
assert_rejected 'shinu-jail is not configured with gid 30000'
# 8. A UID lookup without the corresponding name lookup is inconsistent.
begin_case one-way-nss
printf '%s\n' 'shinu-jail:x:30000:30000::/nonexistent:/usr/sbin/nologin' \
    > "$CASE_DIR/state/passwd-by-uid"
run_install
assert_rejected 'shinu-jail account lookup is inconsistent'

# 9-12. Zero and non-decimal values are rejected before NSS or mutation.
begin_case zero-uid
ID_MODE=custom
UID_VALUE=0
GID_VALUE=30000
run_install
assert_rejected 'SHINU_JAIL_UID must be a nonzero decimal ID'

begin_case zero-gid
ID_MODE=custom
UID_VALUE=30000
GID_VALUE=0
run_install
assert_rejected 'SHINU_JAIL_GID must be a nonzero decimal ID'

begin_case nondecimal-uid
ID_MODE=custom
UID_VALUE=30x00
GID_VALUE=30000
run_install
assert_rejected 'SHINU_JAIL_UID must be a nonzero decimal ID'

begin_case nondecimal-gid
ID_MODE=custom
UID_VALUE=30000
GID_VALUE=30x00
run_install
assert_rejected 'SHINU_JAIL_GID must be a nonzero decimal ID'

# 13. Relative deployment paths resolve against the invocation directory.
begin_case relative-paths
seed_identity
PREFIX_VALUE='relative prefix'
SVDIR_VALUE='relative svdir'
run_install
assert_accepted "$CASE_DIR/work/$PREFIX_VALUE/bin" "$CASE_DIR/work/$SVDIR_VALUE"

# 14. Spaces, dollar signs, and both quote characters survive path handling.
begin_case quoted-paths
seed_identity
PREFIX_VALUE="$CASE_DIR/prefix space\$and'quote\"double"
SVDIR_VALUE="$CASE_DIR/sv space\$and'quote\"double"
run_install
assert_accepted "$PREFIX_VALUE/bin" "$SVDIR_VALUE"

printf '%s\n' 'install identity matrix: 14 cases passed (hermetic NSS and account mutators)'
