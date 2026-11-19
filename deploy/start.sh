#!/bin/sh
# Sets up and starts osk with Docker Compose, from a signed release. The
# first run asks two questions; "start.sh update" first moves the copy to the
# newest signed release. A copy checked out by hand at a higher release counts
# only if an update would have taken that release. Both end with a test
# message through the running service.
#
# What this file checks holds only if this file and the key file of the copy
# are genuine: both come with the copy. release/README.md ("A first copy")
# says how to check the tag of a first copy, with a key compared by its
# fingerprint, before any file of it runs.
#
# It builds only the commit of a release tag that a key of the copy's
# release/allowed_signers signed (release/verify-tag.sh), as git holds that
# commit. The copy keeps the tag object of its release under
# refs/osk/installed, which no fetch writes. An update moves only to a higher
# signed release, checked with the key of the installed one, so a new key
# reaches a copy only through a release that a key of the copy signed.
#
# OSK_UNVERIFIED=1 builds the folder as it is, with no check, to work on osk
# itself; an update ignores it. OSK_COMPOSE_EXTRA names one more Compose file,
# for a lab. Each prints a line when it is used.
set -eu

stop() {
	echo "$1" >&2
	exit 1
}

cd "$(dirname "$0")" || stop "start.sh cannot enter its own folder."
here=$(pwd -P)

# need stops unless git can check SSH signatures (2.34 and later) and
# ssh-keygen is there; release/verify-tag.sh checks the version of OpenSSH.
need() {
	command -v git >/dev/null 2>&1 || stop "start.sh needs git 2.34 or later to check the signature of a release; git is missing."
	# shellcheck disable=SC2046
	set -- $(git --version)
	case ${3-} in
	2.3[4-9]* | 2.[4-9][0-9]* | 2.[1-9][0-9][0-9]* | [3-9].* | [1-9][0-9].*) ;;
	*) stop "start.sh needs git 2.34 or later to check the signature of a release; this is git ${3-?}." ;;
	esac
	command -v ssh-keygen >/dev/null 2>&1 ||
		stop "start.sh needs ssh-keygen of OpenSSH 8.2 or later to check the signature of a release; it is missing."
}

# order <version> prints a text that sorts, byte by byte, as versions do:
# the three numbers as numbers of any length, then a version with a label
# below the same numbers without one, then the label word by word, a number
# below a word and numbers as numbers (rc.9 below rc.10). A number sorts as
# the length of its length, its length, then its digits; build/version.sh
# refuses a leading zero, which would break this.
order() {
	o= rest=${1%%-*}
	while :; do
		n=${rest%%.*}
		l=${#n}
		o=$o${#l}$l$n.
		[ "$rest" != "$n" ] || break
		rest=${rest#*.}
	done
	case $1 in
	*-*)
		rest=${1#*-}
		while :; do
			w=${rest%%.*}
			l=${#w}
			case $w in
			*[!0-9]*) o=${o}1$w. ;;
			*) o=${o}0${#l}$l$w. ;;
			esac
			[ "$rest" != "$w" ] || break
			rest=${rest#*.}
		done
		;;
	*) o=$o~ ;;
	esac
	printf '%s\n' "$o"
}

# later <a> <b> exits 0 when the version a is higher than the version b.
later() {
	a=$(order "$1") b=$(order "$2")
	[ "$a" != "$b" ] && [ "$(printf '%s\n%s\n' "$a" "$b" | LC_ALL=C sort | tail -n 1)" = "$a" ]
}

# releases <file> <git for-each-ref argument>... writes to the file
# "<name> <object id>" of each ref that git lists whose last part is
# v<version>, the highest first. Each name is resolved here, once; any other
# name is ignored, whatever it holds.
releases() {
	out=$1
	shift
	git for-each-ref --format='%(refname) %(objectname)' "$@" >"$work/refs" || return 1
	while read -r ref oid; do
		name=${ref##*/}
		[ "$ref" = "refs/tags/$name" ] || [ "$ref" = "refs/osk-fetched/$name" ] || continue
		[ "$name" != "${name#v}" ] && sh "$top/build/version.sh" "${name#v}" 2>/dev/null || continue
		printf '%s %s %s\n' "$(order "${name#v}")" "$name" "$oid"
	done <"$work/refs" | LC_ALL=C sort -r | cut -d ' ' -f 2,3 >"$out"
}

# verified <name> <object id> prints the commit of a release tag that a key
# of the copy signed, or prints why on standard error and fails.
verified() {
	sh "$top/release/verify-tag.sh" "$work/keys" "$1" "$2"
}

# signed_by <key file> <name> <object id> is verified with another key file.
signed_by() {
	sh "$top/release/verify-tag.sh" "$1" "$2" "$3"
}

# advise stops with a commit that starts: with a record, the commit of the
# recorded release (checked with its own key), from where start.sh update
# moves on; with none, the commit of the highest release here that the key
# of HEAD signed. It names no commit when there is none.
advise() {
	if [ -n "$recorded" ]; then
		if commit=$(signed_by "$work/recorded-keys" "$recorded" "$record" 2>/dev/null); then
			stop "This copy is not at its release, ${recorded#v}. Check it out again, then move on with ./start.sh update:
git checkout $commit"
		fi
	else
		releases "$work/all" refs/tags refs/osk-fetched || stop "git for-each-ref failed (see above)."
		while read -r name oid; do
			if commit=$(verified "$name" "$oid" 2>/dev/null); then
				stop "This copy is not at a signed release. Check out the newest signed release here, ${name#v}, with: git checkout $commit"
			fi
		done <"$work/all"
	fi
	stop "This copy is not at a release that a key of its release/allowed_signers signed, and no such release is here. Fetch the tags with: git fetch --tags"
}

# The temporary folder holds every temporary file; only a path of the form
# that mktemp gave it is removed.
work=
cleanup() {
	case $work in
	*/osk-start.????????) rm -rf -- "$work" ;;
	esac
}

case ${1:-} in
'' | update) ;;
*)
	echo "usage: start.sh [update]" >&2
	exit 2
	;;
esac
if [ -n "${OSK_COMPOSE_EXTRA:-}" ]; then
	echo "OSK_COMPOSE_EXTRA=$OSK_COMPOSE_EXTRA: this Compose file is added to the release and can change what runs."
fi
if [ -z "${1:-}" ] && [ "${OSK_UNVERIFIED:-}" = 1 ]; then
	echo "OSK_UNVERIFIED=1: the signature of this copy is not checked; use this only to work on osk."
	OSK_VERSION=0.0.0-dev
	tree=$(cd .. && pwd -P)
else
	unset OSK_UNVERIFIED
	need
	top=$(git rev-parse --show-toplevel 2>/dev/null) && [ "$(cd "$top/deploy" 2>/dev/null && pwd -P)" = "$here" ] ||
		stop "start.sh must be deploy/start.sh of the git checkout that it checks, and this folder is not."
	# Before the check, only this script and the scripts of the copy that it
	# names run; with no tracked file changed, they are those of HEAD.
	changed=$(git status --porcelain --untracked-files=no) || stop "git status failed (see above)."
	[ -z "$changed" ] || stop "Files of this copy differ from its commit; git status shows them. Undo the changes, then run start.sh again."
	# docker compose reads more files in deploy/ when someone runs it there.
	extra=$(git status --porcelain --untracked-files=all --ignored -- .) || stop "git status failed (see above)."
	[ -z "$extra" ] || stop "deploy/ holds files that are not part of the release, and docker compose would read them: $(printf '%s' "$extra" | tr '\n' ' ')Remove them, then run start.sh again."
	work=$(mktemp -d "${TMPDIR:-/tmp}/osk-start.XXXXXXXX") || stop "start.sh cannot make a temporary folder."
	trap cleanup EXIT
	# The key that decides is read from the commit of the copy, before any
	# fetch, and nothing that the fetch brings can change this file.
	git cat-file blob HEAD:release/allowed_signers >"$work/keys" 2>/dev/null || stop "This copy has no release/allowed_signers."
	head=$(git rev-parse --verify 'HEAD^{commit}') || stop "git rev-parse failed (see above)."

	# The installed release is the recorded tag object, checked again; a copy
	# with no record yet (git clone, then git checkout of a tag) gets one from
	# a release tag on HEAD.
	installed= recorded=
	if record=$(git rev-parse -q --verify refs/osk/installed); then
		body=$(git cat-file tag "$record") || stop "refs/osk/installed is not a tag object."
		recorded=$(printf '%s\n' "$body" | sed -n '/^$/q; s/^tag //p')
		# The record is checked by its signature, with the key of HEAD, on
		# every run.
		if commit=$(verified "$recorded" "$record" 2>/dev/null) && [ "$commit" = "$head" ]; then
			installed=$recorded
		else
			# HEAD moved to a higher release by hand, or an update stopped
			# before it wrote the record: a release here that an update would
			# take, by the key of the recorded release, is taken and recorded.
			git cat-file blob "$record^{commit}:release/allowed_signers" >"$work/recorded-keys" 2>/dev/null ||
				stop "The recorded release has no release/allowed_signers."
			releases "$work/here" --points-at HEAD refs/tags refs/osk-fetched || stop "git for-each-ref failed (see above)."
			while read -r name oid; do
				later "${name#v}" "${recorded#v}" || break
				if commit=$(signed_by "$work/recorded-keys" "$name" "$oid" 2>/dev/null) && [ "$commit" = "$head" ] &&
					verified "$name" "$oid" >/dev/null 2>&1; then
					git update-ref refs/osk/installed "$oid" || stop "git update-ref failed (see above)."
					installed=$name
					break
				fi
			done <"$work/here"
		fi
	else
		releases "$work/here" --points-at HEAD refs/tags refs/osk-fetched || stop "git for-each-ref failed (see above)."
		while read -r name oid; do
			if commit=$(verified "$name" "$oid" 2>/dev/null) && [ "$commit" = "$head" ]; then
				git update-ref refs/osk/installed "$oid" || stop "git update-ref failed (see above)."
				installed=$name
				break
			fi
		done <"$work/here"
	fi
	[ -n "$installed" ] || advise

	if [ "${1:-}" = update ]; then
		# This namespace holds only what this fetch brings: the installed
		# release has its own record and only a higher release is taken, so
		# emptying it loses nothing, and no stale ref can block the fetch.
		git for-each-ref --format='delete %(refname)' refs/osk-fetched >"$work/stale" &&
			git update-ref --stdin <"$work/stale" || stop "git could not empty refs/osk-fetched (see above)."
		git -c fetch.prune=false -c fetch.pruneTags=false fetch --quiet --no-prune --no-tags origin '+refs/tags/*:refs/osk-fetched/*' ||
			stop "git fetch failed (see above), so osk was not updated; $installed keeps running."
		releases "$work/fetched" refs/osk-fetched || stop "git for-each-ref failed (see above)."
		target= skipped= count=0
		while read -r name oid; do
			later "${name#v}" "${installed#v}" || break
			if target=$(verified "$name" "$oid" 2>"$work/why"); then
				break
			fi
			echo "The newest release tag, $name, is not signed by a key of release/allowed_signers of $installed ($(cat "$work/why")); it is skipped." >&2
			skipped="$skipped $name" count=$((count + 1))
		done <"$work/fetched"
		if [ -z "$target" ]; then
			[ "$count" -eq 0 ] || stop "No newer signed release was found; tags that did not verify were skipped ($count):$skipped. $installed keeps running."
			echo "No newer signed release was found; $installed keeps running."
			exit 0
		fi
		git -c advice.detachedHead=false checkout --quiet --detach "$target" ||
			stop "git checkout of the release $name failed (see above), so osk was not updated."
		git update-ref refs/osk/installed "$oid" || stop "git update-ref failed (see above)."
		cleanup
		trap - EXIT
		# The start.sh of the new release does the rest, and checks again.
		exec sh ./start.sh
	fi
	OSK_VERSION=${installed#v}
	tree=$work/tree
	mkdir "$tree" || stop "start.sh cannot make a temporary folder."
	sh "$top/release/export.sh" "$head" "$tree" || stop "start.sh cannot copy the files of the release $installed (see above)."
fi
# compose.yaml passes the version to the build, so osk version shows it. Its
# name, osk, gives the project, the volume osk_data and the images, wherever
# the file is.
export OSK_VERSION
compose() {
	docker compose -f "$tree/deploy/compose.yaml" ${OSK_COMPOSE_EXTRA:+-f "$OSK_COMPOSE_EXTRA"} "$@"
}
docker compose version >/dev/null 2>&1 ||
	stop "start.sh needs Docker with the Compose plugin: 'docker compose version' does not work here."
compose --profile setup build </dev/null ||
	stop "The build of osk failed (see above)."
compose run --rm init ||
	stop "The setup was not written (see above), so osk was not started. Fix what is said above, then run start.sh again."
compose up --detach --wait </dev/null ||
	stop "osk did not start or is not healthy. Its log: docker compose logs osk"
compose exec -T osk osk test-alert --config /data/osk.json </dev/null || {
	echo "The test message did not get through. Find out why with:" >&2
	echo "  docker compose exec osk osk doctor --config /data/osk.json" >&2
	exit 1
}
echo "osk is running. Your channel has a test message from it."
