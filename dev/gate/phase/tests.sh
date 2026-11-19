#!/bin/sh
# Every test with the race detector, run in the build container from the root
# of the tree, which may be read-only. -count=1, because a cached result is
# not a run.
#
# The tests of dev/gate/mutate run after all the others, not with them: each of
# them builds and runs test binaries on several workers, and together they
# take most of the CPU. The tests of the other packages wait a few seconds
# for events of real services, and would starve beside them.
#
# Standard output carries only the events of go test -json. The line
# "ok go-test-race" or "FAIL go-test-race: <reason>" goes to standard error.
set -u

fail() {
	echo "FAIL $1: $2" >&2
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run dev/gate/bin/gate"

module=$(go list -m) || fail go-test-race "go list -m failed"
# The list comes from go, so that a new package is never left out.
packages=$(go list ./...) || fail go-test-race "go list ./... failed"
others=$(printf '%s\n' "$packages" | grep -vxF "$module/dev/gate/mutate")

events=$(mktemp) || exit 2
trap 'rm -f "$events"' EXIT

# run_part <package>...: runs the tests of the packages, prints their events,
# and returns whether they passed.
run_part() {
	go test -count=1 -race -json "$@" >"$events"
	rc=$?
	cat "$events"
	[ "$rc" -eq 0 ] || grep '"Action":"fail"' "$events" >&2
	return "$rc"
}

status=0
run_part $others || status=1
run_part "$module/dev/gate/mutate" || status=1
[ "$status" -eq 0 ] || fail go-test-race "go test -race failed (events above)"
echo "ok go-test-race" >&2
