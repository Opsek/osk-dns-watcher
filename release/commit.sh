#!/bin/sh
# release/commit.sh <version> exits 0 when this checkout is the commit that
# out/release/<version>/CONTENTS names: HEAD is that commit, no tracked file
# has a change that is not committed, and the tag v<version>, if there is
# one, is a release tag (release/verify-tag.sh) on that commit. Otherwise it
# prints why and exits 1. Runs on the host,
# where git is: the scripts that run after make release run the code of this
# checkout, so it must be the code of the release.
set -u

cd "$(dirname "$0")/.." || exit 2
version=${1-}
sh build/version.sh "$version" || exit 2
contents=out/release/$version/CONTENTS
commit=$(sed -n 's/^commit //p' "$contents" 2>/dev/null)
case $commit in
'' | *[!0-9a-f]*) commit= ;;
esac
if [ ${#commit} -ne 40 ] && [ ${#commit} -ne 64 ]; then
	echo "$contents names no full commit id"
	exit 1
fi
head=$(git rev-parse --verify 'HEAD^{commit}') || {
	echo "cannot read the commit HEAD"
	exit 1
}
if [ "$head" != "$commit" ]; then
	echo "HEAD is $head, but $contents names $commit"
	exit 1
fi
changed=$(git status --porcelain --untracked-files=no) || {
	echo "git status failed"
	exit 1
}
if [ -n "$changed" ]; then
	echo "tracked files have changes that are not committed: $(printf '%s' "$changed" | tr '\n' ' ')"
	exit 1
fi
# The tag is read once, and its object is what release/verify-tag.sh checks.
if oid=$(git rev-parse -q --verify "refs/tags/v$version"); then
	tagged=$(sh release/verify-tag.sh release/allowed_signers "v$version" "$oid" 2>&1) || {
		echo "the tag v$version is not a release tag: $tagged"
		exit 1
	}
	if [ "$tagged" != "$commit" ]; then
		echo "the tag v$version points at $tagged, not at $commit"
		exit 1
	fi
fi
