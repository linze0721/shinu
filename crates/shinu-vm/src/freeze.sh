# Executed over vsock as root; all state must remain writable after root freeze.
set -eu
export LC_ALL=C
state=${1:-/run/shinu-freeze}
hooks=${2:-/etc/shinu/freeze.d}
catalog=${3:-/run/shinu-snapshot/mounts}
[ "$(findmnt -n -o FSTYPE --target /run)" = tmpfs ] || {
    echo '/run must be tmpfs for snapshot freeze' >&2; exit 1;
}
mkdir -m 700 "$state"
: > "$state/hooks"
: > "$state/mounts"
for hook in "$hooks"/*; do
    [ -f "$hook" ] && [ -x "$hook" ] || continue
    { printf '%s\n' "$hook"; cat "$state/hooks"; } > "$state/next"
    mv "$state/next" "$state/hooks"
    timeout -k 2 20 "$hook" freeze
done
# The native worker has selected one path per writable block superblock and
# refused uncovered private-namespace filesystems before any hooks run.
# Keep duplicate paths: distinct overmounted filesystems must fail, not vanish.
sort -k2,2r "$catalog" > "$state/ordered-mounts"
while IFS=' ' read -r device mount; do
    { printf '%s\n' "$mount"; cat "$state/mounts"; } > "$state/next"
    mv "$state/next" "$state/mounts"
    timeout -k 2 10 fsfreeze -f "$mount"
done < "$state/ordered-mounts"
