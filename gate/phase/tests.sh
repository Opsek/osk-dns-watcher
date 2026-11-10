#!/bin/sh
# Every test with the race detector, run in the build container from the root
# of the tree, which may be read-only. -count=1, because a cached result is
# not a run.
#
# Standard output carries only the events of go test -json. The line
# "ok go-test-race" or "FAIL go-test-race: <reason>" goes to standard error.
set -u

fail() {
	echo "FAIL $1: $2" >&2
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run gate/bin/gate"

events=$(mktemp) || exit 2
trap 'rm -f "$events"' EXIT

go test -count=1 -race -json ./... >"$events"
status=$?
cat "$events"
if [ "$status" -ne 0 ]; then
	grep '"Action":"fail"' "$events" >&2
	fail go-test-race "go test -race ./... failed"
fi
echo "ok go-test-race" >&2
