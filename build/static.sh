#!/bin/sh
# Builds out/osk-dns-watcher-linux-<arch>: one static binary, from vendor/, with no network.
# Runs inside a build container of the target platform that has Go, gcc and
# musl headers; the SQLite driver needs cgo, so there is no cross-compiling.
# osk-dns-watcher version prints the version given, or 0.0.0-dev for a build that is not
# a release.
set -eu

arch=${1:-}
version=${2:-0.0.0-dev}
case $arch in
arm64 | amd64) ;;
*)
	echo "usage: build/static.sh arm64|amd64 [<version>]" >&2
	exit 2
	;;
esac

host=$(go env GOHOSTARCH)
if [ "$host" != "$arch" ]; then
	echo "build/static.sh: this container is $host, not $arch" >&2
	exit 1
fi

cd "$(dirname "$0")/.."
sh build/version.sh "$version"
out=out/osk-dns-watcher-linux-$arch
mkdir -p out

# -buildvcs=false: the binary must not depend on the git state of the checkout.
CGO_ENABLED=1 GOOS=linux GOARCH=$arch go build \
	-mod=vendor -trimpath -buildvcs=false \
	-ldflags "-X main.version=$version -linkmode=external -extldflags=-static" \
	-o "$out" ./cmd/osk-dns-watcher

# A static file has no program interpreter and needs no shared library.
headers=$(readelf -l -d "$out")
case $headers in
*INTERP* | *NEEDED*)
	echo "build/static.sh: $out is not static" >&2
	exit 1
	;;
esac
echo "$out"
