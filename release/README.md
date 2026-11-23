# Releases

A release of osk-dns-watcher is a signed tag `v<version>`, these files in
`out/release/<version>/`, and an image:

| File | Holds |
|---|---|
| `osk-dns-watcher-linux-amd64`, `osk-dns-watcher-linux-arm64` | osk-dns-watcher for Linux on each architecture: one static file, built from `vendor/` with no network. |
| `CONTENTS` | What the release is made of, one fact for each line (see below), the digests of the image among them. |
| `SHA256SUMS` | The SHA-256 of the two binaries and of `CONTENTS`, in the format that `sha256sum -c` reads. |
| `SHA256SUMS.sig` | The SSH signature of `SHA256SUMS` by the owner's key. |

The image `ghcr.io/opsek/osk-dns-watcher:<version>` holds Alpine with its CA
certificates, the release binary of its platform at `/usr/local/bin/osk-dns-watcher`, and
an empty `/data` for the user 10001.

The key that signs releases is `release/allowed_signers`: one line, for the
signer `osk-dns-watcher-release`, in the namespaces `file` (for `SHA256SUMS`) and `git`
(for the tags).

## Make a release

A version is three numbers with no leading zero, then optionally `-` and words
of letters and digits separated by dots: `0.1.0`, `0.1.0-rc.1`. It has no
leading `v`: the tag `v0.1.0` is the version `0.1.0`. Any other text is
refused before anything runs. A build that is not a release, such as
`make build`, says `osk-dns-watcher 0.0.0-dev`.

The image is built twice from the release commit: by the job
`.github/workflows/release-image.yml` on GitHub, which pushes it, and by
you. `make image-digests` names the pushed image in `CONTENTS` only when it
is the image that your machine built, so what you sign does not depend on
GitHub. In a git checkout of the release commit, whose tracked files have no
change that is not committed, in this order:

```sh
git tag -s v0.1.0 -m 'osk-dns-watcher 0.1.0'
git push origin v0.1.0
make build
make release VERSION=0.1.0
make image VERSION=0.1.0
make image-digests VERSION=0.1.0
make check OSK_RELEASE=0.1.0
ssh-keygen -Y sign -f <your key file> -n file out/release/0.1.0/SHA256SUMS
make verify-release VERSION=0.1.0
```

The tag comes first, on the release commit, with your git settings for SSH
signatures (`gpg.format=ssh`); pushing it starts the job. The first line of
its message must be `osk-dns-watcher <version>`, as above: the same key
signs tags of other projects, and this line binds the tag to osk-dns-watcher. The job
and the gate require the tag, of that form and signed by a key of
`release/allowed_signers`, on the commit that `CONTENTS` names. A tag is
never moved: if the job fails before it pushes, run it again; if
`make image-digests` refuses the image, find out why before any release.

For the first release only, the package of the image is private. Make it
public after the job and before `make image-digests`, which reads it with
no login: on GitHub, the organization's tab **Packages**, `osk-dns-watcher`,
**Package settings**, then under "Danger Zone" **Change visibility** and
**Public**. This cannot be undone.

Sign `SHA256SUMS` only after the gate passed,
and check that the file you sign has the SHA-256 that the gate wrote to
`out/gate.log` in the line `release ok 0.1.0 <sha256 of SHA256SUMS>`.
`ssh-keygen -Y sign` writes `SHA256SUMS.sig` beside it; `<your key file>` is
the file of your key, for a hardware key the file of its handle. Nothing may
change the folder after that. `make verify-release` then checks the files as
a stranger will. Then put the five files on the release page of the tag.

- `make build` makes the build container, which needs the network.
- `make release` (`release/build.sh`) refuses tracked files with changes, and
  a version whose folder exists. It copies the files of the commit `HEAD` with
  `git archive` to a temporary folder under `out/`, and stops when a file of
  the copy is not the blob of the commit, as `export-ignore`,
  `export-subst`, `core.autocrlf` or a filter would make it. It builds each
  binary from that copy with `build/static.sh` in the build container of its
  platform, with no network and an empty Go build cache, and writes `CONTENTS`
  and `SHA256SUMS` with `release/contents.sh`. A failed run leaves no folder.
- `make image` (`release/image.sh`) builds the stage `release` of
  `deploy/Dockerfile` for linux/amd64 and linux/arm64, with the release folder
  as the build context, and loads it as `ghcr.io/opsek/osk-dns-watcher:0.1.0`.
  Set `OSK_IMAGE` for another name. The image of the quick start is the same
  stage `runtime` with a binary built from source. Every time in the image is
  the time of the commit, so a second build gives the same digests. Only the
  first pull of the base image, pinned by digest, needs the network.
- The job runs for a pushed tag `v<major>.<minor>.<patch>`; a version with
  a label, such as `0.1.0-rc.1`, starts none. It stops unless
  `release/verify-tag.sh` accepts the tag and the tag is on the commit of
  the run. Then it runs `make build`, `make release` and `make image-push`
  with the job's own token. `make image-push` (`release/image.sh <version>
  push`) builds the image as `make image` does and pushes it, but refuses
  when the registry holds that tag already, or cannot say that it does not:
  a release is never replaced. In the job, a BuildKit in a container, pinned
  by digest, builds it: the Docker 28 of the runner cannot. The job pushes
  nothing else and makes no release.
- `make image-digests` (`release/digests.sh`) reads the index of the pushed
  image from the registry, requires that it lists linux/amd64 and then
  linux/arm64 and nothing else, and pulls both platforms by the digest of
  the index. Each platform must then be the image of `make image` on this
  machine: the same digest of each layer unpacked, and the same platform and
  config (entrypoint, command, user, environment, working folder, labels,
  volumes, ports, health check and the rest). The history and the packed
  layers are not compared, since two honest builders can write them in two
  ways. When the images differ, it prints the lines that differ and changes
  nothing. Otherwise it adds the `image` lines to `CONTENTS`. It changes no
  other line and makes `SHA256SUMS` again. Nobody types a digest. It needs
  Docker 28.1 or later. Do not pull `ghcr.io/opsek/osk-dns-watcher:0.1.0` by
  its tag on this machine: that would replace the image of `make image`.
- `make image`, `make image-push` and `make image-digests` first require
  that the checkout is the commit of `CONTENTS`, that a tag `v<version>`, if
  there is one, is signed and on that commit (`release/commit.sh`), and that
  `sha256sum -c SHA256SUMS` passes.

`make check OSK_RELEASE=<version>` adds the phase `release`, which builds
nothing and checks:

- the checkout: `HEAD` is the commit of `CONTENTS`, no tracked file has a
  change, and the tag `v<version>` is on that commit and signed by a key of
  `release/allowed_signers`;
- the folder holds exactly the files above; `SHA256SUMS.sig` may be missing,
  since you sign after this gate, but when it is there it must verify;
- `SHA256SUMS` lists the other three files and `sha256sum -c` passes;
- `CONTENTS` is exactly what `release/contents.sh` makes from the files, with
  the version of the folder and the right size and SHA-256 of each binary;
- both binaries are static, built for Linux with cgo and for the architecture
  in their name, depend on `github.com/mattn/go-sqlite3` at the version of
  `go.mod` and on nothing else, and print in an empty image the version and
  the Go and SQLite versions of `CONTENTS`;
- when `CONTENTS` names an image: its name is `OSK_IMAGE`, the index of that
  digest is on this machine and lists exactly the two platform digests of
  `CONTENTS`, and the binary in the image of each platform, read without
  running it, is the release file of that architecture.

It writes `release ok <version> <sha256 of SHA256SUMS>` to `out/gate.log`,
then `release-image ok <version> <digest of the index>`, or
`release-image none <version>` for a release without an image, and
`release-signature ok <version>` when `SHA256SUMS.sig` is there and verifies.
For a release with an image, the quickstart phase also runs the commands of
[Run the image](../docs/install.md#run-the-image) against the lab.

## CONTENTS

The lines come in this order:

```
version 0.1.0
commit <the git commit of the tree, in full>
go 1.27.4
sqlite 3.54.1
file osk-dns-watcher-linux-amd64 <size in bytes> <SHA-256>
file osk-dns-watcher-linux-arm64 <size in bytes> <SHA-256>
image ghcr.io/opsek/osk-dns-watcher
image-digest index sha256:<hex>
image-digest linux/amd64 sha256:<hex>
image-digest linux/arm64 sha256:<hex>
<what go version -m prints for the two binaries>
```

- `go` and `sqlite` are the versions that `osk-dns-watcher version` prints.
- The `image` lines are there only after `make image-digests`: the name of
  the image, and the digests of its index (the list of its platforms) and of
  each platform.
- The last part is the output of `go version -m osk-dns-watcher-linux-amd64
  osk-dns-watcher-linux-arm64`: the module, its one dependency
  `github.com/mattn/go-sqlite3`, and the build settings.

`CONTENTS` holds no date and no host name.

## Verify a release

You need `ssh-keygen` and `ssh` of OpenSSH 8.2 or later, which know the type
of the release key, `sk-ssh-ed25519@openssh.com`; `sha256sum` or `shasum`;
and, for the tag, git 2.34 or later.

### A first copy

A first install trusts the place that the copy came from: the key file and
`start.sh`, which checks with it, both come with the copy, so a copy from
somewhere else can carry another key and a `start.sh` that checks nothing.
After that, `start.sh update` trusts only the key of the installed release.

The first release has one signing key. The owner publishes its fingerprint
in one place: the release page of the repository. That page belongs to the
same account as the repository, so the comparison protects against a wrong
copy from elsewhere (a mirror, a fork, a bad network path), not against
someone who controls the account itself. In a copy, this prints the
fingerprints of the keys of `release/allowed_signers`:

```sh
awk '{ for (i = 1; i < NF; i++) if ($i ~ /^(sk-)?(ssh|ecdsa)-/) { print $i, $(i + 1); break } }' release/allowed_signers | ssh-keygen -lf -
```

A key file can hold a key that this does not show (in a quoted option), so
for a first copy the fingerprint that counts is the one of the key that
signed the tag. Write the version and the published fingerprint in the first
two lines, then paste the block; it stops at the first check that fails. It
clones with no file checked out, writes the key file of the release's commit
outside the copy, verifies the tag with that key file alone and compares the
fingerprint of the key that signed it, shows that the tag names itself, says
`osk-dns-watcher <version>` and carries one signature, an SSH one, and only then checks
out the commit of the tag and runs `start.sh`. Even so, the check is only as
good as the fingerprint.

```
v=0.1.0 &&
fingerprint='SHA256:<the published fingerprint>' &&
git clone --no-checkout https://github.com/Opsek/osk-dns-watcher.git osk-dns-watcher &&
cd osk-dns-watcher &&
keys=$(mktemp) &&
git show "v$v^{commit}:release/allowed_signers" >"$keys" &&
said=$(git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$keys" -c gpg.program=false -c gpg.openpgp.program=false -c gpg.x509.program=false verify-tag "v$v" 2>&1) &&
printf '%s\n' "$said" &&
[ "$(printf '%s\n' "$said" | awk '/^Good /{ print $NF }')" = "$fingerprint" ] &&
git cat-file tag "v$v" | sed '/^$/q' | grep -qx "tag v$v" &&
[ "$(git cat-file tag "v$v" | sed '1,/^$/d' | head -n 1)" = "osk-dns-watcher $v" ] &&
[ "$(git cat-file tag "v$v" | grep -c '^-----BEGIN ')" = 1 ] &&
git cat-file tag "v$v" | grep -qx -- '-----BEGIN SSH SIGNATURE-----' &&
git -c advice.detachedHead=false checkout --quiet "v$v^{commit}" &&
deploy/start.sh
```

### The files and the tag

A user checks them as [docs/install.md](../docs/install.md#verify-a-release)
says: `make verify-release VERSION=<version>` (`release/verify.sh`) for the
files, which ends with the line
`image: ghcr.io/opsek/osk-dns-watcher@sha256:<digest>`, and
`sh release/verify-tag.sh release/allowed_signers v<version>` for the tag.
`start.sh` and the gate run the same script for the tag.

## Keys

The owner's keys are the lines of `release/allowed_signers`, each with the
signer `osk-dns-watcher-release` and the namespaces `file,git`. The first
release has one key and no backup: if it is lost, installed copies cannot
verify a later release, and users must move to a new key by a fresh install.

- To add a key, add a line with the same signer and the same namespaces, in
  a release signed by a key that is already in the file, before the new key
  signs anything.
- `start.sh update` checks a new release with the keys of the installed
  release, and then the `start.sh` of the new release checks it again with
  the keys of the new release. So a release must list the key that signed
  it: the release that adds a key is signed by an old key and lists both,
  and only a release signed by the new key may drop the old one.
- To retire a key, delete its line in a signed release. A copy that has
  updated to that release no longer trusts it.
- A key that leaks stays trusted by every copy that has not updated past the
  release that removes it, and there is no way to revoke it from afar.
  Copies that update do trust the release that removes it, so make that
  release, signed by another key of the file, at once.

## What the signature does not cover

- The tag of the image, such as `:0.1.0`: a tag can be moved. Only the
  digests in a verified `CONTENTS` count.
- The key itself on a first copy: it comes with the copy. Compare the
  fingerprint, as above.
- The commit id in `CONTENTS`: it is a claim of the owner until someone builds
  the release again from that commit and compares the files.
- The base images and the vendored SQLite driver: they are trusted as they
  are committed, pinned by digest and by `go.sum`.
