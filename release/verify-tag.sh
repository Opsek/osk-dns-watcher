#!/bin/sh
# release/verify-tag.sh <allowed signers file> <tag name> [<object id>] prints
# the commit of a release tag and exits 0 when the tag is one: its name is
# v<version> (build/version.sh); its object, the one given or else the one
# that refs/tags/<name> names, read once, is a tag object of that same name
# on a commit, whose message begins with the line "osk <version>"; and it
# carries one signature, an SSH signature by a key of the allowed-signers
# file. Otherwise it prints why and exits 1. deploy/start.sh
# and release/commit.sh use it, and so can anyone:
#
#   sh release/verify-tag.sh release/allowed_signers v0.1.0
set -u

fail() {
	echo "$1" >&2
	exit 1
}

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
	echo "usage: release/verify-tag.sh <allowed signers file> <tag name> [<object id>]" >&2
	exit 2
fi
keys=$1 name=$2
case $keys in
/*) ;;
*) keys=$(pwd)/$keys ;;
esac
[ -f "$keys" ] || fail "$1 is not a file"
case $name in
v*) sh "$(dirname "$0")/../build/version.sh" "${name#v}" 2>/dev/null || fail "$name is not of the form v<version>" ;;
*) fail "$name is not of the form v<version>" ;;
esac
# The release key is a hardware key; OpenSSH knows its type from 8.2 on.
ssh -Q key 2>/dev/null | grep -qx 'sk-ssh-ed25519@openssh.com' ||
	fail "checking a release needs OpenSSH 8.2 or later (ssh and ssh-keygen), which knows the key type sk-ssh-ed25519@openssh.com"

oid=${3:-$(git rev-parse -q --verify "refs/tags/$name")}
[ -n "$oid" ] || fail "there is no tag $name"
[ "$(git cat-file -t "$oid" 2>/dev/null)" = tag ] || fail "$name is not a tag object with a signature"
body=$(git cat-file tag "$oid") || fail "cannot read the tag $name"
header=$(printf '%s\n' "$body" | sed '/^$/q')
printf '%s\n' "$header" | grep -qxF "tag $name" || fail "the tag object of $name holds another name"
printf '%s\n' "$header" | grep -qxF "type commit" || fail "the tag $name is not on a commit"
# The same key signs tags of other projects: the signed message binds the
# tag to osk and to its version.
[ "$(printf '%s\n' "$body" | sed '1,/^$/d' | head -n 1)" = "osk ${name#v}" ] ||
	fail "the message of the tag $name does not begin with the line \"osk ${name#v}\""
# git chooses the checker from the armor of the signature, and gpg would use
# the user's keyring: only one signature, an SSH one, counts, and every other
# checker is made unusable below.
[ "$(printf '%s\n' "$body" | grep -c '^-----BEGIN ')" = 1 ] &&
	printf '%s\n' "$body" | grep -qxF -- '-----BEGIN SSH SIGNATURE-----' ||
	fail "the tag $name does not carry exactly one signature, an SSH signature"
# On a key that is not in the file, git prints a "Good ... signature" line
# before "No principal matched.": the last line says why.
why=$(git -c gpg.format=ssh -c gpg.program=false -c gpg.openpgp.program=false -c gpg.x509.program=false \
	-c gpg.ssh.program=ssh-keygen -c "gpg.ssh.allowedSignersFile=$keys" verify-tag "$oid" 2>&1) ||
	fail "the SSH signature of $name does not verify: $(printf '%s\n' "$why" | tail -n 1)"
git rev-parse -q --verify "$oid^{commit}" || fail "the tag $name is not on a commit"
