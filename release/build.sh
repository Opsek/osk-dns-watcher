#!/bin/sh
# Makes the files of a release in the new folder out/release/<version>/:
# osk-linux-amd64 and osk-linux-arm64, each built by build/static.sh in the
# build container of its platform, then CONTENTS and SHA256SUMS
# (release/contents.sh). Runs on the host, where git is:
#
#   release/build.sh <version>      (make release VERSION=<version>)
#
# The builds read a copy of the files of the commit HEAD, made by git archive,
# so no file that is not in the commit can enter the binaries. Every container
# has no network. Each build starts with an empty Go build cache inside its
# container, not with the cache volume of make check, which holds results that
# any tree it ran could have written. DOCKER (default docker) may hold several
# words, so it stays unquoted.
# shellcheck disable=SC2086
set -u

stop() {
	echo "release: $1" >&2
	exit 1
}

cd "$(dirname "$0")/.." || exit 2
version=${1-}
sh build/version.sh "$version" || exit 2
DOCKER=${DOCKER:-docker}
repo=$(pwd)
out=out/release/$version
sum=$(cksum <gate/Dockerfile) || exit 2
image=osk-gate:${sum%% *}

commit=$(git rev-parse --verify 'HEAD^{commit}') || stop "cannot read the commit; run this in a git checkout"
# The release must be the commit that the user sees in the folder.
changed=$(git status --porcelain --untracked-files=no) || stop "git status failed"
if [ -n "$changed" ]; then
	printf '%s\n' "$changed" >&2
	stop "these files have changes that are not in the commit $commit; commit or undo them first"
fi
# Making the build container needs the network; make build makes it.
$DOCKER image inspect "$image" >/dev/null 2>&1 || stop "the build container $image is missing; run make build first"

mkdir -p out/release || exit 2
mkdir "$out" || stop "$out exists; remove it to make this release again"
trap 'rm -rf "$out"' EXIT
trap 'exit 130' INT TERM
# The copy is under out/, which the Docker daemon can mount as it mounts the
# checkout. A failed run leaves no half release; no run leaves the copy.
src=$(mktemp -d out/release-src.XXXXXX) || exit 2
# Only a path of the form that mktemp gave is removed.
scrub() {
	case $src in
	out/release-src.??????) rm -rf -- "$src" ;;
	esac
}
trap 'rm -rf -- "$out"; scrub' EXIT
mkdir "$src/tree" || exit 2
why=$(sh release/export.sh "$commit" "$src/tree" 2>&1) || {
	printf '%s\n' "$why" >&2
	stop "cannot copy the files of the commit $commit"
}
# tree/out is where the release folder is mounted.
mkdir "$src/tree/out" || exit 2
tree=$repo/$src/tree

for arch in amd64 arm64; do
	$DOCKER run --rm --network none --platform "linux/$arch" -e GOCACHE=/tmp/gocache \
		-v "$tree":/src:ro -v "$repo/$out":/src/out -w /src "$image" build/static.sh "$arch" "$version" ||
		stop "build/static.sh $arch failed"
done
$DOCKER run --rm --network none -v "$tree":/src:ro -v "$repo/$out":/src/out -w /src/out \
	"$image" /src/release/contents.sh "$version" "$commit" || stop "release/contents.sh failed"
scrub
trap - EXIT
cat "$out/SHA256SUMS"
echo "release: $out is ready"
