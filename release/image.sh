#!/bin/sh
# Builds the image of a release for linux/amd64 and linux/arm64, in that
# order, and loads it as $OSK_IMAGE:<version>; it prints the commands that
# come next. With push, it pushes the image to its registry instead, and
# only when the registry has no image of that tag yet: a release is never
# replaced. Runs on the host, after release/build.sh:
#
#   release/image.sh <version>        (make image VERSION=<version>)
#   release/image.sh <version> push   (make image-push VERSION=<version>)
#
# The checkout must be the commit of the release (release/commit.sh) and the
# files must match SHA256SUMS. The image is the stage release of
# deploy/Dockerfile: the stage runtime of the quick start's image, plus the
# binary of each platform from out/release/<version>/, which is the whole
# build context. Every time in the image is the time of the commit, so a
# second build of the same release gives the same digests. Only the pull of
# the base image, pinned by digest, can need the network; the one RUN of the
# image has none. DOCKER (default docker) and BUILD_FLAGS (default empty) may
# hold several words, so they stay unquoted.
# shellcheck disable=SC2086
set -u

stop() {
	echo "image: $1" >&2
	exit 1
}

cd "$(dirname "$0")/.." || exit 2
version=${1-}
mode=${2-load}
sh build/version.sh "$version" || exit 2
case $mode in
load | push) ;;
*)
	echo "usage: release/image.sh <version> [push]" >&2
	exit 2
	;;
esac
name=${OSK_IMAGE-}
case $name in
'' | [!a-z0-9]* | *[!a-z0-9./:_-]*) stop "OSK_IMAGE must be an image name such as ghcr.io/opsek/osk-dns-watcher" ;;
esac
DOCKER=${DOCKER:-docker}
BUILD_FLAGS=${BUILD_FLAGS:-}
repo=$(pwd)
dir=out/release/$version
sum=$(cksum <dev/gate/Dockerfile) || exit 2
box=osk-gate:${sum%% *}

why=$(sh release/commit.sh "$version") || stop "$why"
$DOCKER image inspect "$box" >/dev/null 2>&1 || stop "the build container $box is missing; run make build first"
$DOCKER run --rm --network none -v "$repo/$dir":/release:ro -w /release "$box" sha256sum -c SHA256SUMS ||
	stop "the files of $dir do not match SHA256SUMS (lines above)"
epoch=$(git show -s --format=%ct HEAD) || stop "cannot read the time of the commit"

# No attestations: they would hold the time and the machine of the build.
# rewrite-timestamp sets each time after the commit to the time of the
# commit; a layer from the build cache can hold an older time, so the cache
# is not used. It cannot unpack the image; the engine unpacks it on use.
# Some builders, such as BuildKit 0.20, write Docker media types unless told
# otherwise, and the gate requires an OCI index.
output="type=image,name=$name:$version,rewrite-timestamp=true,unpack=false,oci-mediatypes=true"
if [ "$mode" = push ]; then
	# The registry says "not found" only when it has no such tag; any other
	# answer could hide an image that is there.
	if said=$($DOCKER buildx imagetools inspect --raw "$name:$version" 2>&1 >/dev/null); then
		stop "the registry holds $name:$version already: a release is never replaced"
	fi
	case $said in
	*": not found") ;;
	*) stop "cannot tell whether the registry holds $name:$version: $said" ;;
	esac
	# The docker driver of Docker 28 unpacks every image it builds, which
	# rewrite-timestamp refuses: the build pushes, so that a builder in a
	# container can make the image.
	output=$output,push=true
fi
$DOCKER buildx build $BUILD_FLAGS --platform linux/amd64,linux/arm64 --network none --no-cache \
	--provenance=false --sbom=false --target release --build-arg SOURCE_DATE_EPOCH="$epoch" \
	--output "$output" -f deploy/Dockerfile "$dir" || stop "the build of the image failed"
if [ "$mode" = push ]; then
	$DOCKER buildx imagetools inspect "$name:$version" || stop "cannot read $name:$version from the registry"
	echo "image: $name:$version is pushed."
	exit 0
fi
cat <<EOF
image: $name:$version is loaded. Next, once the job of the tag v$version has
pushed the image to the registry:
  make image-digests VERSION=$version
  make check OSK_RELEASE=$version
Sign out/release/$version/SHA256SUMS only after this gate passed: its log
holds the line "release ok $version <sha256 of SHA256SUMS>".
EOF
