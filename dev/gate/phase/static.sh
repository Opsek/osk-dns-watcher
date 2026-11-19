#!/bin/sh
# The static checks, run in the build container from the root of the tree,
# which may be read-only: format; vendor/; go vet and the linters, without
# build tags and with the tag lab; the model checker; archcheck. Prints
# "ok <name>" or "FAIL <name>: <reason>" and stops at the first failure.
set -u

ok() { echo "ok $1"; }
fail() {
	echo "FAIL $1: $2"
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run dev/gate/bin/gate"

# The same folders as the go command skips.
files=$(find . \( -name testdata -o -name vendor -o -name '[._]?*' \) -prune -o \
	-name '*.go' -exec gofmt -l {} +) || fail gofmt "gofmt could not read every file"
[ -z "$files" ] || fail gofmt "not formatted: $(echo $files)"
ok gofmt

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# vendor/ must be what the go command makes from the SQLite driver in the
# image, which was checked against sum.golang.org there and against go.sum
# here.
GOPROXY=off go mod vendor -o "$tmp/vendor" ||
	fail vendor "go mod vendor failed; the version in go.mod must be the one dev/gate/Dockerfile downloads"
diff -r vendor "$tmp/vendor" || fail vendor "vendor/ differs from the SQLite driver module (diff above)"
ok vendor

lint() {
	name=$1
	shift
	"$@" || fail "$name" "$* found problems (output above)"
	ok "$name"
}
# exhaustive has no flag for build tags; they reach it through GOFLAGS.
for tags in '' lab; do
	suffix=${tags:+-$tags}
	lint "go-vet$suffix" go vet -tags "$tags" ./...
	lint "errcheck$suffix" errcheck -tags "$tags" ./...
	lint "staticcheck$suffix" staticcheck -tags "$tags" ./...
	lint "exhaustive$suffix" env GOFLAGS="-tags=$tags" exhaustive ./...
done

# A model is checked when a configuration of the same name stands beside it.
for tla in dev/models/*.tla; do
	[ -f "${tla%.tla}.cfg" ] || continue
	tlc "$tla" || fail "tlc $tla" "TLC found a problem (output above)"
	ok "tlc $tla"
done

go build -buildvcs=false -o "$tmp/archcheck" ./dev/gate/archcheck || fail archcheck "go build ./dev/gate/archcheck failed"
"$tmp/archcheck" || exit 1
