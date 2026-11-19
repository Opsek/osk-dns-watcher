#!/bin/sh
# Verifies the files of a release with the key of this tree, as anyone who
# has them can: the signature SHA256SUMS.sig of SHA256SUMS by a key of
# release/allowed_signers, then the sums of the files; then it prints the
# image of the verified CONTENTS by digest. Runs on the host, Linux or macOS,
# and needs ssh-keygen of OpenSSH 8.2 or later, and sha256sum or shasum:
#
#   release/verify.sh <version>      (make verify-release VERSION=<version>)
set -u

stop() {
	echo "verify-release: $1" >&2
	exit 1
}

cd "$(dirname "$0")/.." || exit 2
version=${1-}
sh build/version.sh "$version" || exit 2
dir=out/release/$version
LC_ALL=C
export LC_ALL

command -v ssh-keygen >/dev/null 2>&1 || stop "ssh-keygen of OpenSSH 8.2 or later is missing"
# The release key is a hardware key; OpenSSH knows its type from 8.2 on.
ssh -Q key 2>/dev/null | grep -qx 'sk-ssh-ed25519@openssh.com' ||
	stop "this needs OpenSSH 8.2 or later (ssh and ssh-keygen), which knows the key type sk-ssh-ed25519@openssh.com"
if command -v sha256sum >/dev/null 2>&1; then
	check='sha256sum -c'
elif command -v shasum >/dev/null 2>&1; then
	check='shasum -a 256 -c'
else
	stop "sha256sum or shasum is missing"
fi
[ -f "$dir/SHA256SUMS" ] || stop "$dir/SHA256SUMS is missing"
[ -f "$dir/SHA256SUMS.sig" ] || stop "$dir/SHA256SUMS.sig is missing: this release is not signed"
grep -q '^osk-dns-watcher-release ' release/allowed_signers 2>/dev/null || stop "release/allowed_signers has no key for osk-dns-watcher-release"
ssh-keygen -Y verify -f release/allowed_signers -I osk-dns-watcher-release -n file -s "$dir/SHA256SUMS.sig" <"$dir/SHA256SUMS" ||
	stop "the signature of $dir/SHA256SUMS does not verify with release/allowed_signers"
# A file that SHA256SUMS leaves out would go unchecked.
[ "$(sed 's/^[0-9a-f]\{64\}  //' "$dir/SHA256SUMS" | sort | tr '\n' ' ')" = "CONTENTS osk-dns-watcher-linux-amd64 osk-dns-watcher-linux-arm64 " ] ||
	stop "$dir/SHA256SUMS must list CONTENTS, osk-dns-watcher-linux-amd64 and osk-dns-watcher-linux-arm64"
# shellcheck disable=SC2086
(cd "$dir" && $check SHA256SUMS) || stop "the files of $dir do not match SHA256SUMS (lines above)"
# Signed files of another release in this folder would name another image.
[ "$(sed -n 's/^version //p' "$dir/CONTENTS")" = "$version" ] ||
	stop "$dir/CONTENTS is the CONTENTS of another version than $version"

name=$(sed -n 's/^image //p' "$dir/CONTENTS")
index=$(sed -n 's/^image-digest index //p' "$dir/CONTENTS")
echo "verify-release: the release $version in $dir is signed by a key of release/allowed_signers and complete."
if [ -n "$name" ]; then
	echo "image: $name@$index"
else
	echo "image: none; CONTENTS names no image"
fi
