#!/bin/sh
# Scans for known vulnerabilities with govulncheck, run in the build container
# from the root of the tree, which may be read-only:
#
#   gate/phase/vulncheck.sh [<binary>...]
#
# The source scan covers the code that cmd/osk can reach, the Go standard
# library of the toolchain and the modules in go.mod. Each binary named is
# scanned too, so that the file that ships is the one that was checked.
# Prints "ok vulncheck" after a scan that ran, or "FAIL vulncheck: <reason>".
# A finding, or a database that cannot be reached, fails the phase.
#
# The vulnerability database changes every day, so this is the one phase that
# needs the network: gate/bin/gate gives its container one and nothing else
# (a read-only tree and an empty build cache). govulncheck reads only the
# database at https://vuln.go.dev.
#
# What the scan does not cover: the database lists Go modules and the Go
# standard library. The SQLite C code that go-sqlite3 bundles is not in it (the
# database has no entry for the driver), so a fault in SQLite itself
# is never reported here. The phase prints the bundled version, to be looked
# up in SQLite's own advisories.
#
# GOVULNCHECK (default govulncheck) names the scanner command.
set -u

ok() { echo "ok $1"; }
fail() {
	echo "FAIL $1: $2"
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run gate/bin/gate"

govulncheck=${GOVULNCHECK:-govulncheck}

# -version asks the database for its time, and prints no time when it cannot
# be reached, so a missing time means that no scan can have happened.
about=$($govulncheck -version 2>&1) || fail vulncheck "$govulncheck -version failed: $about"
echo "$about"
printf '%s\n' "$about" | grep -q '^DB updated: ' || fail vulncheck "the database cannot be reached: no time of last update"

# scan <label> <command>...: runs the scanner. govulncheck exits 3 for a
# finding; any other failure means that it could not scan.
scan() {
	label=$1
	shift
	out=$("$@" 2>&1)
	rc=$?
	[ "$rc" -eq 0 ] && return 0
	echo "$out"
	[ "$rc" -eq 3 ] && fail vulncheck "the scan of $label found a vulnerability (text above)"
	fail vulncheck "the scan of $label could not run: exit $rc (text above)"
}

scan cmd/osk $govulncheck -show verbose ./cmd/osk
printf '%s\n' "$out" | sed -n '/^Govulncheck scanned/,/^$/p'

for binary in "$@"; do
	scan "$binary" $govulncheck -mode=binary "$binary"
	echo "scanned $binary"
done

sqlite=$(sed -n 's/^#define SQLITE_VERSION  *"\(.*\)"$/\1/p' vendor/github.com/mattn/go-sqlite3/sqlite3-binding.h)
[ -n "$sqlite" ] || fail vulncheck "no SQLite version in vendor/github.com/mattn/go-sqlite3/sqlite3-binding.h"
echo "bundled SQLite $sqlite is not covered by this scan; see https://www.sqlite.org/cves.html"
ok vulncheck
