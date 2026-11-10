#!/bin/sh
# The tests with the build tag lab, run in the build container from the root
# of the tree, which may be read-only.
#
#   gate/phase/labtests.sh           prints "<folder> <import path>" for each package with such tests
#   gate/phase/labtests.sh <folder>  writes the test binary of that package to standard output
#
# The binary has the race detector, and it is static, because the runner of
# the lab has no C library of this container. The lines "ok <name>" and
# "FAIL <name>: <reason>" go to standard error.
set -u

fail() {
	echo "FAIL $1: $2" >&2
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run gate/bin/gate"

case $# in
0)
	# The same folders as the go command skips; a test file counts when its
	# build constraint names the tag lab, and not as !lab.
	for dir in $(find . \( -name testdata -o -name vendor -o -name '[._]?*' \) -prune -o \
		-name '*_test.go' -exec grep -lE '^//go:build( |.*[ (&|])lab([ )&|]|$)' {} + |
		sed 's,/[^/]*$,,' | sort -u); do
		echo "$dir $(go list -e "$dir")"
	done
	;;
1)
	bin=$(mktemp) || exit 2
	trap 'rm -f "$bin"' EXIT
	CGO_ENABLED=1 go test -c -race -tags lab -ldflags '-linkmode=external -extldflags=-static' \
		-o "$bin" "$1" >&2 || fail "lab-build $1" "go test -c -race -tags lab $1 failed"
	cat "$bin"
	echo "ok lab-build $1" >&2
	;;
*)
	echo "usage: gate/phase/labtests.sh [<folder>]" >&2
	exit 2
	;;
esac
