#!/bin/sh
# Adds the image lines to CONTENTS of out/release/<version>/ once the image
# $OSK_IMAGE:<version> is pushed, and makes SHA256SUMS again, so that the
# signed files name the image by digest. Runs on the host:
#
#   release/digests.sh <version>      (make image-digests VERSION=<version>)
#
# The checkout must be the commit of the release (release/commit.sh) and the
# files must match SHA256SUMS. The digests come from the registry, not from a
# person: the index of <name>:<version> must list linux/amd64 and then
# linux/arm64 and nothing else. Both platforms are then pulled by the digest
# of the index, so that the gate, which has no network, finds them. Every
# other line of CONTENTS stays as it is, and a failed run changes nothing.
# DOCKER (default docker) may hold several words, so it stays unquoted.
# shellcheck disable=SC2086
set -u

stop() {
	echo "image-digests: $1" >&2
	exit 1
}

cd "$(dirname "$0")/.." || exit 2
version=${1-}
sh build/version.sh "$version" || exit 2
name=${OSK_IMAGE-}
case $name in
'' | [!a-z0-9]* | *[!a-z0-9./:_-]*) stop "OSK_IMAGE must be an image name such as ghcr.io/opsek/osk-dns-watcher" ;;
esac
DOCKER=${DOCKER:-docker}
repo=$(pwd)
dir=out/release/$version
sum=$(cksum <dev/gate/Dockerfile) || exit 2
box=osk-gate:${sum%% *}

why=$(sh release/commit.sh "$version") || stop "$why"
! grep -q '^image' "$dir/CONTENTS" || stop "$dir/CONTENTS has image lines already"
$DOCKER image inspect "$box" >/dev/null 2>&1 || stop "the build container $box is missing; run make build first"
$DOCKER run --rm --network none -v "$repo/$dir":/release:ro -w /release "$box" sha256sum -c SHA256SUMS ||
	stop "the files of $dir do not match SHA256SUMS (lines above)"

# One word for the index, then a platform and its digest for each manifest.
index=$($DOCKER buildx imagetools inspect --format \
	'{{.Manifest.Digest}}{{range .Manifest.Manifests}} {{.Platform.OS}}/{{.Platform.Architecture}}{{with .Platform.Variant}}/{{.}}{{end}} {{.Digest}}{{end}}' \
	"$name:$version") || stop "cannot read the index of $name:$version from the registry"
case $index in
*[!0-9a-z/:\ ]*) stop "the index of $name:$version must list linux/amd64 and linux/arm64 and nothing else: $index" ;;
esac
printf '%s\n' "$index" |
	grep -Eqx 'sha256:[0-9a-f]{64} linux/amd64 sha256:[0-9a-f]{64} linux/arm64 sha256:[0-9a-f]{64}' ||
	stop "the index of $name:$version must list linux/amd64 and linux/arm64 and nothing else: $index"
set -f
set -- $index
for platform in linux/amd64 linux/arm64; do
	$DOCKER pull --platform "$platform" "$name@$1" >/dev/null || stop "cannot pull $name@$1 for $platform"
done

# The new files are written beside the old ones and take their place last.
$DOCKER run --rm --network none -v "$repo/$dir":/release -w /release "$box" sh -euc '
	grep -q "^file osk-dns-watcher-linux-arm64 " CONTENTS
	{
		sed -n "1,/^file osk-dns-watcher-linux-arm64 /p" CONTENTS
		echo "image $1"
		echo "image-digest index $2"
		echo "image-digest linux/amd64 $3"
		echo "image-digest linux/arm64 $4"
		sed "1,/^file osk-dns-watcher-linux-arm64 /d" CONTENTS
	} >CONTENTS.new
	sum=$(sha256sum <CONTENTS.new | cut -d " " -f 1)
	{
		grep -v "  CONTENTS\$" SHA256SUMS
		echo "$sum  CONTENTS"
	} >SHA256SUMS.new
	mv CONTENTS.new CONTENTS
	mv SHA256SUMS.new SHA256SUMS
' sh "$name" "$1" "$3" "$5" || {
	rm -f "$dir/CONTENTS.new" "$dir/SHA256SUMS.new"
	stop "cannot write the image lines"
}
cat "$dir/SHA256SUMS"
cat <<EOF
image-digests: CONTENTS names $name@$1. Next:
  make check OSK_RELEASE=$version
Sign $dir/SHA256SUMS only after this gate passed: its log holds the line
"release ok $version <sha256 of SHA256SUMS>".
EOF
