# Executed over vsock as root; all state must remain writable after root freeze.
set -eu
export LC_ALL=C
state=/run/shinu-freeze
[ "$(findmnt -n -o FSTYPE --target /run)" = tmpfs ] || {
    echo '/run must be tmpfs for snapshot freeze' >&2; exit 1;
}
mkdir -m 700 "$state"
: > "$state/hooks"
: > "$state/mounts"
for hook in /etc/shinu/freeze.d/*; do
    [ -f "$hook" ] && [ -x "$hook" ] || continue
    { printf '%s\n' "$hook"; cat "$state/hooks"; } > "$state/next"
    mv "$state/next" "$state/hooks"
    timeout -k 2 20 "$hook" freeze
done
findmnt -rn -t ext4 -O rw -o TARGET > "$state/all-mounts"
# findmnt escapes unusual paths. Fail rather than silently freezing the wrong mount.
if grep -q '\\' "$state/all-mounts"; then
    echo 'escaped ext4 mount paths are not supported by snapshot freeze' >&2; exit 1
fi
# Reverse lexical order places descendants before ancestors, with root last.
sort -ru "$state/all-mounts" > "$state/ordered-mounts"
while IFS= read -r mount; do
    { printf '%s\n' "$mount"; cat "$state/mounts"; } > "$state/next"
    mv "$state/next" "$state/mounts"
    timeout -k 2 10 fsfreeze -f "$mount"
done < "$state/ordered-mounts"
