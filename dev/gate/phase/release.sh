#!/bin/sh
# Checks the files of a release, run in the build container from the root of
# the tree, which may be read-only. It builds nothing, so the files it passes
# are the files that are signed.
#
#   dev/gate/phase/release.sh <version>
#
# out/release/<version>/ holds exactly osk-dns-watcher-linux-amd64, osk-dns-watcher-linux-arm64,
# CONTENTS and SHA256SUMS, and SHA256SUMS.sig once it is signed (not checked
# here). SHA256SUMS lists the other three and sha256sum -c passes. CONTENTS
# states the version and the size and SHA-256 of each binary, and is exactly
# what release/contents.sh makes from these files. Both binaries are static,
# built for Linux with cgo, each for the architecture in its name, with the
# SQLite driver of go.mod as their one dependency; the binary of this
# container's architecture prints the version and the Go and SQLite versions
# of CONTENTS. dev/gate/bin/gate runs both binaries in an empty image as well, but
# the self-test has no Docker.
#
# When CONTENTS names an image, it must be $OSK_IMAGE, and out/image/ must
# hold what dev/gate/bin/gate read from it: index.json, the index with that
# digest, which lists the linux/amd64 and linux/arm64 digests of CONTENTS and
# nothing else, and osk-dns-watcher-linux-<arch>, each the release file of that name.
# Prints "ok <name>" or "FAIL <name>: <reason>" and stops at the first failure.
set -u

ok() { echo "ok $1"; }
fail() {
	echo "FAIL $1: $2"
	exit 1
}

[ -f /etc/osk-gate ] || fail build-container "$0 runs only in the build container; run dev/gate/bin/gate"

if [ $# -ne 1 ] || ! sh build/version.sh "$1"; then
	echo "usage: dev/gate/phase/release.sh <version>" >&2
	exit 2
fi
version=$1
binaries='osk-dns-watcher-linux-amd64 osk-dns-watcher-linux-arm64'
root=$(pwd)
LC_ALL=C
export LC_ALL

cd "out/release/$version" 2>/dev/null ||
	fail release-files "out/release/$version does not exist; make release VERSION=$version makes it"
for f in CONTENTS SHA256SUMS $binaries; do
	[ -f "$f" ] || fail release-files "$f is missing"
done
others=$(ls -A | grep -vxE 'CONTENTS|SHA256SUMS|SHA256SUMS\.sig|osk-dns-watcher-linux-amd64|osk-dns-watcher-linux-arm64')
[ -z "$others" ] || fail release-files "these files do not belong to a release: $(echo $others)"
[ ! -e SHA256SUMS.sig ] || [ -f SHA256SUMS.sig ] || fail release-files "SHA256SUMS.sig is not a file"
ok release-files

# SHA256SUMS must list the other three files, so that its check covers them.
names=$(sed 's/^[0-9a-f]\{64\}  //' SHA256SUMS | sort | tr '\n' ' ')
[ "$names" = "CONTENTS $binaries " ] || fail release-sums "SHA256SUMS lists $names; want CONTENTS $binaries"
sha256sum -c SHA256SUMS || fail release-sums "sha256sum -c SHA256SUMS failed (lines above)"
ok release-sums

[ "$(grep '^version ' CONTENTS)" = "version $version" ] ||
	fail release-contents "CONTENTS must have the one version line \"version $version\""
for f in $binaries; do
	line="file $f $(stat -c %s "$f") $(sha256sum "$f" | cut -d ' ' -f 1)"
	grep -qxF "$line" CONTENTS || fail release-contents "CONTENTS lacks the line \"$line\""
done
# The image lines come once the digests of the pushed image are written.
images=$(grep '^image' CONTENTS | sed -e 's|^image [a-z0-9][a-z0-9./:_-]*$|image <name>|' \
	-e 's|^\(image-digest [a-z0-9/]*\) sha256:[0-9a-f]\{64\}$|\1 <digest>|')
case $images in
'' | 'image <name>
image-digest index <digest>
image-digest linux/amd64 <digest>
image-digest linux/arm64 <digest>') ;;
*) fail release-contents "the image lines must be \"image <name>\", then \"image-digest <index, linux/amd64, linux/arm64> sha256:<64 hex digits>\"" ;;
esac

# A static file has no program interpreter and needs no shared library.
for f in $binaries; do
	headers=$(readelf -l -d "$f" 2>&1) || fail release-static "readelf cannot read $f"
	case $headers in
	*INTERP* | *NEEDED*) fail release-static "$f is not static" ;;
	esac
done
ok release-static

# The build settings and the modules that go version -m reads from each binary.
driver=$(sed -n 's/^require github.com\/mattn\/go-sqlite3 //p' "$root/go.mod")
for arch in amd64 arm64; do
	info=$(go version -m "osk-dns-watcher-linux-$arch") || fail release-arch "go version -m cannot read osk-dns-watcher-linux-$arch"
	for setting in "GOARCH=$arch" GOOS=linux CGO_ENABLED=1; do
		printf '%s\n' "$info" | grep -qxF "$(printf '\tbuild\t%s' "$setting")" ||
			fail release-arch "osk-dns-watcher-linux-$arch was not built with $setting"
	done
	deps=$(printf '%s\n' "$info" | grep -E "^$(printf '\t')(dep|=>)$(printf '\t')" | cut -f 3,4 | tr '\t\n' '  ')
	[ "$deps" = "github.com/mattn/go-sqlite3 $driver " ] ||
		fail release-deps "osk-dns-watcher-linux-$arch depends on $deps; want github.com/mattn/go-sqlite3 $driver only"
done
ok release-arch
ok release-deps

bin=osk-dns-watcher-linux-$(go env GOARCH) || fail release-version "go env GOARCH failed"
want=$(echo "osk-dns-watcher $version"; grep -E '^(go|sqlite) ' CONTENTS)
got=$("./$bin" version 2>&1)
[ "$got" = "$want" ] || fail release-version "$bin version prints \"$(echo $got)\", want \"$(echo $want)\""
ok release-version

# Every line, also one that no check above reads, must be what
# release/contents.sh makes from these files and the values of CONTENTS.
set -f
set -- $(sed -n -e 's/^image //p' -e 's/^image-digest [a-z0-9/]* //p' CONTENTS)
commit=$(sed -n 's/^commit //p' CONTENTS)
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
cp $binaries "$tmp/" &&
	(cd "$tmp" && sh "$root/release/contents.sh" "$version" "$commit" "$@") ||
	fail release-contents "release/contents.sh cannot make CONTENTS again from these files (line above)"
diff "$tmp/CONTENTS" CONTENTS ||
	fail release-contents "CONTENTS is not what release/contents.sh makes from these files (lines above, + is CONTENTS)"
ok release-contents

[ -n "$images" ] || exit 0
name=$(sed -n 's/^image //p' CONTENTS)
[ "$name" = "${OSK_IMAGE-}" ] || fail release-image "CONTENTS names the image $name, but OSK_IMAGE is ${OSK_IMAGE-}"
digest() { sed -n "s|^image-digest $1 ||p" CONTENTS; }
taken=$root/out/image
[ -f "$taken/index.json" ] || fail release-image "out/image/index.json is missing: dev/gate/bin/gate reads it from the image"
[ "sha256:$(sha256sum <"$taken/index.json" | cut -d ' ' -f 1)" = "$(digest index)" ] ||
	fail release-image "out/image/index.json is not the index $(digest index)"
# The index as BuildKit writes it, without its blanks: these two manifests
# and nothing else; only the sizes may be any number.
manifest='{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":N,"platform":{"architecture":"%s","os":"linux"}}'
index=$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s,%s]}' \
	"$(printf "$manifest" "$(digest linux/amd64)" amd64)" "$(printf "$manifest" "$(digest linux/arm64)" arm64)")
[ "$(tr -d ' \n' <"$taken/index.json" | sed 's/"size":[0-9]*,/"size":N,/g')" = "$index" ] ||
	fail release-image "the index $(digest index) does not list exactly the linux/amd64 and linux/arm64 digests of CONTENTS"
for f in $binaries; do
	cmp -s "$taken/$f" "$f" || fail release-image "the binary of the image for linux/${f#osk-dns-watcher-linux-} is not $f of the release"
done
ok release-image
