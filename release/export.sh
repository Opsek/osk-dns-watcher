#!/bin/sh
# release/export.sh <commit id> <empty folder> writes the files of the commit
# into the folder with git archive, and exits 0 only when each file there is
# the blob of the commit and no other file is there: git archive applies
# attributes and settings of the checkout (export-ignore, export-subst, line
# ends, filters). Otherwise it prints why and exits 1. Runs in the checkout,
# with git 2.34 or later; release/build.sh and deploy/start.sh use it.
set -u

fail() {
	echo "$1" >&2
	exit 1
}

if [ $# -ne 2 ]; then
	echo "usage: release/export.sh <commit id> <empty folder>" >&2
	exit 2
fi
commit=$1 dir=$2
# File names are compared as bytes, whatever they hold.
LC_ALL=C
export LC_ALL
case $dir in
/*) ;;
*) dir=$(pwd)/$dir ;;
esac
# From a folder below the top, git archive and git ls-tree see that folder only.
cd "$(git rev-parse --show-toplevel)" || exit 2
# Only a path of the form that mktemp gave is removed.
lists=$(mktemp -d "${TMPDIR:-/tmp}/osk-export.XXXXXXXX") || exit 2
trap 'case $lists in */osk-export.????????) rm -rf -- "$lists" ;; esac' EXIT

# Each git command writes a file of its own, so that its failure shows.
git archive -o "$lists/tree.tar" "$commit" || fail "git archive of $commit failed (see above)"
tar -x -f "$lists/tree.tar" -C "$dir" || fail "tar could not unpack the files of $commit"
# With -z, git writes each name as it is, unquoted; the lists below hold one
# name on each line, so a name with a line end cannot be compared.
git ls-tree -r -z "$commit" >"$lists/tree.z" || fail "git ls-tree of $commit failed (see above)"
tr -d '\n' <"$lists/tree.z" | cmp -s - "$lists/tree.z" ||
	fail "the commit $commit holds a file whose name has a line end, which this check cannot compare"
tr '\0' '\n' <"$lists/tree.z" >"$lists/tree"
(cd "$dir" && find . ! -type d) >"$lists/found" || fail "find failed in $dir"
sed 's|^\./||' "$lists/found" | LC_ALL=C sort >"$lists/paths"
sed "s|^|$dir/|" "$lists/paths" >"$lists/full"
git hash-object --no-filters --stdin-paths <"$lists/full" >"$lists/ids" || fail "git hash-object failed (see above)"
paste -d ' ' "$lists/ids" "$lists/paths" | LC_ALL=C sort >"$lists/copy"
# A line of git ls-tree is "<mode> <type> <id>", a tab, and the path, which
# may hold a tab too.
LC_ALL=C awk '{ i = index($0, "\t"); split(substr($0, 1, i - 1), f, " ")
	if (f[2] == "blob") print f[3], substr($0, i + 1) }' "$lists/tree" | LC_ALL=C sort >"$lists/commit"
diff "$lists/commit" "$lists/copy" >&2 ||
	fail "the copy differs from the commit $commit (lines above): an attribute or a setting of this checkout changed it"
