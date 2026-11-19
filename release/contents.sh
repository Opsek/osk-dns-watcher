#!/bin/sh
# Writes CONTENTS and SHA256SUMS into the current folder, which holds
# osk-linux-amd64 and osk-linux-arm64. Runs in the build container, which has
# no git, so the commit comes from the caller:
#
#   release/contents.sh <version> <commit> [<image> <index> <amd64> <arm64>]
#
# The image lines are written only when the name of the published image and
# its three digests are given: that of the index (the list of the platforms),
# then those of linux/amd64 and linux/arm64, each sha256:<hex>.
set -euf

usage='usage: release/contents.sh <version> <commit> [<image> <index> <amd64> <arm64>]'
stop() {
	echo "release/contents.sh: $1" >&2
	exit 2
}

[ $# -eq 2 ] || [ $# -eq 6 ] || stop "$usage"
version=$1 commit=$2
shift 2
sh "$(dirname "$0")/../build/version.sh" "$version" || exit 2
case $commit in
'' | *[!0-9a-f]*) stop "the commit must be the full hex name of a git commit" ;;
esac
[ ${#commit} -eq 40 ] || [ ${#commit} -eq 64 ] || stop "the commit must be the full hex name of a git commit"
image=
if [ $# -gt 0 ]; then
	image=$1
	shift
	case $image in
	'' | [!a-z0-9]* | *[!a-z0-9./:_-]*) stop "the image name may hold only a-z, 0-9 and . / : _ -" ;;
	esac
fi
# Each value becomes one line of CONTENTS, so none may hold a newline.
for digest; do
	case $digest in
	*[!0-9a-z:]*) stop "a digest is sha256:<64 hex digits>" ;;
	esac
	printf '%s\n' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' || stop "a digest is sha256:<64 hex digits>"
done
for f in osk-linux-amd64 osk-linux-arm64; do
	[ -f "$f" ] || stop "$f is missing"
done

# The Go and SQLite versions are those that the binary reports.
versions=$("./osk-linux-$(go env GOARCH)" version)
{
	echo "version $version"
	echo "commit $commit"
	printf '%s\n' "$versions" | grep -E '^(go|sqlite) '
	for f in osk-linux-amd64 osk-linux-arm64; do
		echo "file $f $(stat -c %s "$f") $(sha256sum "$f" | cut -d ' ' -f 1)"
	done
	if [ -n "$image" ]; then
		echo "image $image"
		echo "image-digest index $1"
		echo "image-digest linux/amd64 $2"
		echo "image-digest linux/arm64 $3"
	fi
	go version -m osk-linux-amd64 osk-linux-arm64
} >CONTENTS
sha256sum osk-linux-amd64 osk-linux-arm64 CONTENTS >SHA256SUMS
