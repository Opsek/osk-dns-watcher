#!/bin/sh
# The fuzz tests, run in the build container from the root of the tree, which
# may be read-only.
#
#   dev/gate/phase/fuzz.sh                      prints "<folder> <FuzzName>" for each fuzz test
#   dev/gate/phase/fuzz.sh <folder> <FuzzName>  runs it for FUZZTIME (default 20s)
#
# The names come from the lines of the test files that start with "func Fuzz",
# not from a test binary, which would run the code under test. A run prints the
# events of go test -json on standard output, and "ok fuzz <folder> <FuzzName>"
# or "FAIL <name>: <reason>" on standard error.
set -u

fail() {
	echo "FAIL $1: $2" >&2
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run dev/gate/bin/gate"

if [ $# -eq 0 ]; then
	# The same folders as the go command skips.
	find . \( -name testdata -o -name vendor -o -name '[._]?*' \) -prune -o \
		-name '*_test.go' -exec grep -H '^func Fuzz' {} + |
		sed -e 's,^\(.*\)/[^/]*:func \(Fuzz[[:alnum:]_]*\).*,\1 \2,' -e 's,^\./,,' | sort -u
	exit 0
fi
if [ $# -ne 2 ]; then
	echo "usage: dev/gate/phase/fuzz.sh [<folder> <FuzzName>]" >&2
	exit 2
fi

events=$(mktemp) || exit 2
trap 'rm -f "$events"' EXIT

go test -count=1 -json -run '^$' -fuzz "^$2\$" -fuzztime "${FUZZTIME:-20s}" "./$1" >"$events"
status=$?
cat "$events"
# go test also passes when -fuzz matches no fuzz test, so the events must show
# that this one ran and passed.
[ "$status" -eq 0 ] && grep -q "\"Action\":\"pass\",\"Package\":\"[^\"]*\",\"Test\":\"$2\"" "$events" ||
	fail "fuzz $1 $2" "go test -fuzz did not run $2 in $1 to a pass"
echo "ok fuzz $1 $2" >&2
