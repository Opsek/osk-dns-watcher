#!/bin/sh
# The mutation tests, run in the build container from the root of the tree,
# which may be read-only. For each small change of the code of the folders
# below, the tests of the folder must fail, or the change must be listed with
# a reason in gate/mutants.txt. Prints a score line for each folder, a line
# for each surviving change that is not listed, and "ok mutate" or
# "FAIL <name>: <reason>" lines.
set -u

fail() {
	echo "FAIL $1: $2"
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run gate/bin/gate"

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

go build -buildvcs=false -o "$tmp/mutate" ./gate/mutate || fail mutate "go build ./gate/mutate failed"
# The folders that hold the judgement of the tool: what differs, when an
# alert opens, escalates or resolves, when a check is due, and how the
# certificate source is read.
"$tmp/mutate" --list gate/mutants.txt internal/decide internal/expect internal/alert internal/schedule internal/sources/certlog || exit 1
