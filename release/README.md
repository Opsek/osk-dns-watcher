# Releases

A release of osk-dns-watcher is a signed tag `v<version>`, an image, and
these files in `out/release/<version>/`:

| File | Holds |
|---|---|
| `osk-dns-watcher-linux-amd64`, `osk-dns-watcher-linux-arm64` | osk-dns-watcher for Linux, one file for each architecture. Each file is static and built from `vendor/` with no network. |
| `CONTENTS` | What the release is made of, one fact on each line, with the digests of the image among them. See [CONTENTS](#contents). |
| `SHA256SUMS` | The SHA-256 of the two binaries and of `CONTENTS`, in the format that `sha256sum -c` reads. |
| `SHA256SUMS.sig` | The SSH signature of `SHA256SUMS` by the owner's key. |

The image `ghcr.io/opsek/osk-dns-watcher:<version>` holds Alpine with its CA
certificates, the release binary of its platform at
`/usr/local/bin/osk-dns-watcher`, and an empty `/data` for the user 10001.

## Make a release

A version is three numbers with no leading zero, such as `0.1.0`. A label
can follow, made of `-` and words of letters and digits separated by dots,
as in `0.1.0-rc.1`. A version has no leading `v`. The tag `v0.1.0` is the
version `0.1.0`. The release commands refuse any other text before anything
runs.

In a git checkout of the release commit, with no uncommitted change to a
tracked file, run these commands in this order. Read the notes on each step
before you run it.

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

The steps are these:

1. Make the tag on the release commit, with your git settings for SSH
   signatures, such as `gpg.format=ssh`.
   - The first line of the tag message must be `osk-dns-watcher <version>`,
     as above. The same key signs tags of other projects, and this line
     binds the tag to osk-dns-watcher.
   - The job and the gate require the tag, with that first line and a
     signature by a key of `release/allowed_signers`, on the commit that
     `CONTENTS` names.
   - Never move a tag.
2. Push the tag. The push starts the job
   `.github/workflows/release-image.yml`, which builds the image on GitHub
   and pushes it.
   - Before you push the tag, push the release commit to `main`. GitHub
     starts the job only for a tag that arrives after `main` holds the
     workflow file.
   - The job runs only for a pushed tag `v<major>.<minor>.<patch>`. A
     version with a label, such as `0.1.0-rc.1`, starts no job.
   - The job stops unless `release/verify-tag.sh` accepts the tag and the
     tag is on the commit of the run. Then it runs `make build` and
     `make release`, then `make image-push` with the job's own token. The
     job pushes nothing else and makes no release.
   - `make image-push` runs `release/image.sh <version> push`. It builds the
     image as `make image` does, and pushes it. It refuses when the registry
     holds that tag already, or when it cannot tell whether the registry
     holds it. A release is never replaced.
   - If the job fails before it pushes, run the job again.
3. Run `make build`. It makes the build container, and needs the network.
4. Run `make release`, which runs `release/build.sh`.
   - It stops when a tracked file has a change, or when the folder of the
     version exists.
   - It copies the files of the commit `HEAD` with `git archive`. It stops
     when a file of the copy is not the blob of the commit. `export-ignore`,
     `export-subst`, `core.autocrlf`, or a filter can make such a file.
   - It builds each binary from that copy, with no network and an empty Go
     build cache. Then `release/contents.sh` writes `CONTENTS` and
     `SHA256SUMS`.
   - A failed run leaves no folder.
5. Run `make image`, which runs `release/image.sh`.
   - Like `make image-push` and `make image-digests`, it first runs
     `release/commit.sh`. The checkout must be the commit of `CONTENTS`, and
     a tag `v<version>`, if there is one, must be signed and on that commit.
     Then `sha256sum -c SHA256SUMS` must pass.
   - It builds the stage `release` of `deploy/Dockerfile` for linux/amd64
     and linux/arm64, with the release folder as the build context. It loads
     the image as `ghcr.io/opsek/osk-dns-watcher:0.1.0`. For another name,
     set `OSK_IMAGE`.
   - Every time in the image is the time of the commit, so a second build
     gives the same digests.
   - Only the first pull of the base image, pinned by digest, needs the
     network.
   - Do not pull `ghcr.io/opsek/osk-dns-watcher:0.1.0` by its tag on this
     machine. The pull would replace the image of `make image`.
6. For the first release only, make the package of the image public after
   the job has pushed the image. The package starts private, and
   `make image-digests` reads it with no login. On GitHub, open the tab
   **Packages** of the organization, then `osk-dns-watcher`, then
   **Package settings**. Under **Danger Zone**, choose
   **Change visibility**, then **Public**. You cannot undo the change.
7. Run `make image-digests`, which runs `release/digests.sh`.
   - It needs Docker 28.1 or later.
   - It names the pushed image in `CONTENTS` only when it is the image that
     `make image` built on your machine, so what you sign does not depend on
     GitHub. Nobody types a digest.
   - It reads the index of the pushed image from the registry. The index
     must list linux/amd64, then linux/arm64, and nothing else. Then it
     pulls both platforms by the digest of the index.
   - For each platform, the pushed image and the image of `make image` must
     have the same platform, the same digest of each unpacked layer, and the
     same config in every field. It does not compare the history and the
     packed layers, because two honest builders can write them in two ways.
   - When the images differ, it prints the lines that differ and changes
     nothing. Otherwise, it adds the `image` lines to `CONTENTS`, changes
     no other line, and makes `SHA256SUMS` again.
   - If it refuses the image, find out why before any release.
8. Run `make check OSK_RELEASE=<version>`, which adds the phase `release`.
   See [What the gate checks](#what-the-gate-checks).
9. Only after the gate passed, sign `SHA256SUMS` with `ssh-keygen -Y sign`.
   - Before you sign, check that the file has the SHA-256 that the gate
     wrote to `out/gate.log`, in the line
     `release ok 0.1.0 <sha256 of SHA256SUMS>`.
   - `<your key file>` is the file of your key. For a hardware key, it is
     the file of the key's handle.
   - `ssh-keygen -Y sign` writes `SHA256SUMS.sig` beside `SHA256SUMS`.
     After that, nothing may change the folder.
10. Run `make verify-release`. It checks the files as a stranger will.
11. Put the five files on the release page of the tag.

### What the gate checks

The phase `release` builds nothing. It checks the following:

- In the checkout, `HEAD` is the commit of `CONTENTS`, and no tracked file
  has a change. The tag `v<version>` is on that commit and signed by a key
  of `release/allowed_signers`.
- The folder holds exactly the files of a release. `SHA256SUMS.sig` may be
  missing, because you sign after this gate. When it is there, it must
  verify.
- `SHA256SUMS` lists the other three files, and `sha256sum -c` passes.
- `CONTENTS` is exactly what `release/contents.sh` makes from the files. It
  has the version of the folder and the right size and SHA-256 of each
  binary.
- Both binaries are static and built for Linux with cgo, each for the
  architecture in its name. They depend on `github.com/mattn/go-sqlite3` at
  the version of `go.mod`, and on nothing else. In an empty image, they
  print the version, the Go version, and the SQLite version of `CONTENTS`.
- When `CONTENTS` names an image, its name is `OSK_IMAGE`. The index that
  `CONTENTS` names is on this machine and lists exactly the two platform
  digests of `CONTENTS`. The binary in the image of each platform is the
  release file of that architecture. The gate reads that binary without
  running it.

The phase writes `release ok <version> <sha256 of SHA256SUMS>` to
`out/gate.log`. Then it writes `release-image ok <version> <digest of the index>`,
or `release-image none <version>` for a release without an image. When
`SHA256SUMS.sig` is there and verifies, it also writes
`release-signature ok <version>`. For a release with an image, the
quickstart phase also runs the commands of
[Run the image](../docs/install.md#run-the-image) against the lab.

## Verify a release

You need these tools:

- `ssh-keygen` and `ssh` of OpenSSH 8.2 or later, which know the type of
  the release key, `sk-ssh-ed25519@openssh.com`
- `sha256sum` or `shasum`
- git 2.34 or later, for the tag

### A first copy

A first install trusts the place that the copy came from. The key file and
`start.sh`, which checks with that key file, both come with the copy. So a
copy from somewhere else can carry another key and a `start.sh` that checks
nothing. After the first install, `start.sh update` trusts only the key of
the installed release.

The first release has one signing key. The owner publishes its fingerprint
in one place, the release page of the repository. That page belongs to the
same account as the repository. So the comparison protects against a wrong
copy from elsewhere, such as a mirror, a fork, or a bad network path. It
does not protect against someone who controls the account itself.

In a copy, this command prints the fingerprints of the keys of
`release/allowed_signers`:

```sh
awk '{ for (i = 1; i < NF; i++) if ($i ~ /^(sk-)?(ssh|ecdsa)-/) { print $i, $(i + 1); break } }' release/allowed_signers | ssh-keygen -lf -
```

A key file can hold a key that this command does not show, in a quoted
option. So for a first copy, the fingerprint that counts is the fingerprint
of the key that signed the tag.

The block below does these steps in order, and stops at the first check
that fails:

1. It clones the repository with no file checked out.
2. It writes the key file of the release's commit outside the copy.
3. It verifies the tag with that key file alone, and compares the
   fingerprint of the key that signed the tag.
4. It checks that the tag names itself, says `osk-dns-watcher <version>`,
   and carries one signature, an SSH one.
5. Only then, it checks out the commit of the tag and runs `start.sh`.

Even so, the check is only as good as the fingerprint.

Write the version and the published fingerprint in the first two lines of
the block. Then paste the block.

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

Check the files and the tag as
[docs/install.md](../docs/install.md#verify-a-release) says.
For the files, run `make verify-release VERSION=<version>`, which runs
`release/verify.sh`. It ends with the line
`image: ghcr.io/opsek/osk-dns-watcher@sha256:<digest>`. For the tag, run
`sh release/verify-tag.sh release/allowed_signers v<version>`. `start.sh`
and the gate run the same script for the tag.

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
- The `image` lines are there only after `make image-digests`. They hold
  the name of the image, the digest of its index, and the digest of each
  platform. The index is the list of the platforms of the image.
- The last part is the output of
  `go version -m osk-dns-watcher-linux-amd64 osk-dns-watcher-linux-arm64`.
  It holds the module, its one dependency `github.com/mattn/go-sqlite3`,
  and the build settings.

`CONTENTS` holds no date and no host name.

## Keys

The owner's keys are the lines of `release/allowed_signers`. Each line has
the signer `osk-dns-watcher-release` and the namespaces `file,git`. The
namespace `file` is for `SHA256SUMS`, and `git` is for the tags. The first
release has one key and no backup. If that key is lost, installed copies
cannot verify a later release, and users must move to a new key by a fresh
install.

A change of keys follows these rules:

- To add a key, add a line with the same signer and the same namespaces. A
  key that is already in the file must sign the release that adds the line.
  Do not sign anything with the new key before that release.
- `start.sh update` checks a new release with the keys of the installed
  release. Then the `start.sh` of the new release checks it again with the
  keys of the new release. So a release must list the key that signed it.
  The release that adds a key is signed by an old key and lists both keys.
  Only a release signed by the new key may drop the old one.
- To retire a key, delete its line in a signed release. A copy that has
  updated to that release no longer trusts the key.
- A key that leaks stays trusted by every copy that is still at a release
  before the one that removes it. Nobody can revoke it remotely. Copies
  that update do trust the release that removes it. So make that release
  at once, and sign it with another key of the file.

## What the signature does not cover

These things are outside the signature:

- The tag of the image, such as `:0.1.0`. A tag can be moved, so only the
  digests in a verified `CONTENTS` count.
- The key itself on a first copy. The key comes with the copy, so compare
  its fingerprint as [A first copy](#a-first-copy) says.
- The commit id in `CONTENTS`. It is a claim of the owner until someone
  builds the release again from that commit and compares the files.
- The base images and the vendored SQLite driver. They are trusted as they
  are committed, pinned by digest and by `go.sum`.
