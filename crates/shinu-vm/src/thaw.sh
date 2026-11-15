# The ledger is also captured in RAM: restored guests must execute this script.
set -u
export LC_ALL=C
state=/run/shinu-freeze
[ -d "$state" ] || exit 0
failed=0
if [ -f "$state/mounts" ]; then
    while IFS= read -r mount; do
        if ! timeout -k 2 10 fsfreeze -u "$mount" 2> "$state/thaw-error"; then
            # A freeze may have failed before it took effect; retries are idempotent.
            if ! grep -q 'Invalid argument' "$state/thaw-error"; then
                cat "$state/thaw-error" >&2
                failed=1
            fi
        fi
    done < "$state/mounts"
fi
if [ -f "$state/hooks" ]; then
    while IFS= read -r hook; do
        timeout -k 2 20 "$hook" thaw || failed=1
    done < "$state/hooks"
fi
[ "$failed" = 0 ] && rm -rf "$state"
exit "$failed"
