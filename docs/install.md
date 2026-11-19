# Install

There are two ways to run osk-dns-watcher: build it from a clone of this repository, or run the ready-made image. Both run it as a Docker Compose service named `watcher`, and keep its files in the volume `osk-dns-watcher_data`. Only these two ways are tested; `go install` is not one of them.

## What you need

- Docker with the Compose plugin, recent enough to know `docker compose up --wait`, on Linux or macOS. On Windows, use WSL 2. WSL 2, rootless Docker and Podman are not tested.
- The URL of a Slack incoming webhook.
- A network that reaches the DNS root servers directly on port 53, over UDP and TCP. VPNs, some routers and some office networks answer those queries themselves; the setup then says so and stops. Run it on another network or machine.
- For a clone, and to verify a release: git 2.34 or later, and `ssh-keygen` and `ssh` of OpenSSH 8.2 or later. `start.sh` checks both and says what is missing.

## Build from a clone

This is the [quick start](../README.md#quick-start). To check the release key and the tag before any file of the copy runs, follow [A first copy](#a-first-copy) instead.

Before it builds, `start.sh` checks that the copy is at a signed release: its commit must be the commit of a release tag `v<version>` that a key of the copy's `release/allowed_signers` signed, with no changed tracked file and no other file in `deploy/`. It builds that commit as git holds it. Otherwise it stops and names the commit of the newest signed release to check out, if there is one. It keeps the tag of the installed release under `refs/osk-dns-watcher/installed`.

The first build takes a few minutes. It pulls the base images from Docker Hub without a login, so on a shared address it can hit Docker Hub's pull limit; the ready-made image avoids the build. Then `start.sh` runs `init` ([expectations.md](expectations.md#what-init-asks-and-writes)), starts the service and sends a test message.

Run the later commands in `osk-dns-watcher/deploy`, with `./osk-dns-watcher` ([config.md](config.md#the-command-in-deploy)). Put no file of yours there: `start.sh` refuses to run when `deploy/` holds files that are not part of the release.

## Run the image

You need the digest of the image of a verified release: the last line that `make verify-release` prints ([The files](#the-files)). Write it in place of `<digest>`. These commands make a folder `osk-dns-watcher` with a Compose file, ask the same two questions as the quick start, start the service and send a test message:

```sh image
mkdir osk-dns-watcher && cd osk-dns-watcher
cat >compose.yaml <<'EOF'
name: osk-dns-watcher
services:
  watcher:
    image: &image ghcr.io/opsek/osk-dns-watcher@sha256:<digest>
    restart: unless-stopped
    volumes: [data:/data]
  init:
    image: *image
    profiles: [setup]
    command: [init, --config, /data/config.json]
    volumes: [data:/data]
volumes:
  data:
EOF
docker compose run --rm init
docker compose up --detach --wait
docker compose exec -T watcher osk-dns-watcher test-alert --config /data/config.json
```

Run the later commands in this folder, in the long form, for example `docker compose exec watcher osk-dns-watcher status --config /data/config.json`: the folder has no `./osk-dns-watcher` script.

The release files also hold the program as one static file for Linux on amd64 and on arm64. You can run `osk-dns-watcher run --config <file>` under a service manager of your own, as an ordinary user. No service file is given, and this way is not tested.

## Update

From a clone, in `osk-dns-watcher/deploy`:

```sh
./start.sh update
```

It fetches the tags and takes the highest version above the installed one that a key of the installed release signed. It names, counts and skips the tags that do not verify, and exits with 1 when it skipped some. It moves to that commit, then builds and restarts the service with the same setup. It never goes back to a lower version. When there is no newer signed release, it changes nothing and the service keeps running.

This is the only way to move a copy: do not use `git pull` or `git checkout`. An update needs the network, for git and for the base images. The restart sends a test message, and a `DOWN` notice when the service did not run for a minute or more.

From the image: verify the new release, write its digest on the line `image: &image` of `compose.yaml`, then run `docker compose up --detach --wait` again.

## Your files

Everything that the service keeps is in the volume `osk-dns-watcher_data`, at `/data` in the container:

| File | Holds |
|---|---|
| `config.json` | the config ([config.md](config.md)) |
| `<domain>.expect` | the expectations of each domain ([expectations.md](expectations.md)) |
| `slack-url` | the Slack webhook URL, mode 600 |
| `state/state.db` | the history: alerts, notices and messages |

Edit a file in the container, for example `docker compose exec watcher vi example.com.expect`. To keep the config and the expectations under version control, copy them to a folder outside the clone:

```sh
mkdir -p ~/osk-dns-watcher-files
docker compose cp watcher:/data/config.json ~/osk-dns-watcher-files/
docker compose cp watcher:/data/example.com.expect ~/osk-dns-watcher-files/
```

More commands:

- Stop the service: `docker compose stop`. Start it again: `docker compose start`.
- Read its log: `docker compose logs -f watcher`. The log has no size limit unless the Docker daemon sets one.
- Docker runs `status` every 10 seconds as the health check of the container; `docker compose ps` shows the result. Docker does not restart a container that is only unhealthy.
- `docker compose down` keeps the volume; `docker compose down --volumes` deletes it.

## Uninstall

This deletes the config, the expectations and the history. Copy out what you want to keep first.

In `osk-dns-watcher/deploy`, or in the folder of the image, stop and remove the service, its volume and its images:

```sh
docker compose --profile setup down --volumes --rmi all
```

Then delete that `osk-dns-watcher` folder: the clone, or the folder of the image. A build from a clone also left the base images `golang` and `alpine`, and Docker's build cache; remove them with `docker image rm` and `docker builder prune` if nothing else of yours needs them.

## Verify a release

A release is a signed tag `v<version>`, these files, and the image `ghcr.io/opsek/osk-dns-watcher:<version>`:

| File | Holds |
|---|---|
| `osk-dns-watcher-linux-amd64`, `osk-dns-watcher-linux-arm64` | The program for Linux on each architecture: one static file. |
| `CONTENTS` | What the release is made of, one fact for each line: the version, the commit, the Go and SQLite versions, the size and SHA-256 of each binary, the digests of the image, and the modules. |
| `SHA256SUMS` | The SHA-256 of the two binaries and of `CONTENTS`. |
| `SHA256SUMS.sig` | The SSH signature of `SHA256SUMS` by the owner's key. |

You need `ssh-keygen` and `ssh` of OpenSSH 8.2 or later, which know the type of the release key, `sk-ssh-ed25519@openssh.com`; `sha256sum` or `shasum`; make; and, for the tag, git 2.34 or later.

### A first copy

A first install trusts the place that the copy came from: the key file `release/allowed_signers` and `start.sh`, which checks with it, both come with the copy. After that, `start.sh update` trusts only the key of the installed release.

The first release has one signing key, and the owner publishes its fingerprint in one place: the release page of the repository. That page belongs to the same account as the repository: the comparison protects you against a wrong copy from elsewhere, such as a mirror, a fork or a bad network path, not against someone who controls the account itself. In a copy, this prints the fingerprints of the keys of `release/allowed_signers`:

```sh
awk '{ for (i = 1; i < NF; i++) if ($i ~ /^(sk-)?(ssh|ecdsa)-/) { print $i, $(i + 1); break } }' release/allowed_signers | ssh-keygen -lf -
```

For a careful first install, use the block in [release/README.md, "A first copy"](../release/README.md#a-first-copy), where a test runs it: you write the version and the published fingerprint in its first two lines and paste it. It clones with no file checked out, verifies the tag with the key file of the release's commit alone, compares the fingerprint of the key that signed the tag, and only then checks out that commit and runs `start.sh`. It stops at the first check that fails.

### The files

Put the files of a release, from its release page, in `out/release/<version>/` of a copy of this repository, then run, for example:

```sh
make verify-release VERSION=0.1.0
```

It checks, in this order: the signature `SHA256SUMS.sig` of `SHA256SUMS` by a key of `release/allowed_signers`; that `SHA256SUMS` lists the two binaries and `CONTENTS` and that `sha256sum -c` (or `shasum -a 256 -c`) passes; and that `CONTENTS` is the `CONTENTS` of the version asked for. Then it prints:

```
verify-release: the release 0.1.0 in out/release/0.1.0 is signed by a key of release/allowed_signers and complete.
image: ghcr.io/opsek/osk-dns-watcher@sha256:<digest>
```

Run the image by that reference only.

### The tag

```sh
sh release/verify-tag.sh release/allowed_signers v0.1.0
```

It prints the commit of the tag when the tag is a release tag: a tag object of that name on a commit, whose signed message begins with the line `osk-dns-watcher 0.1.0`, with one signature, an SSH signature by a key of `release/allowed_signers`. Compare that commit with the one of your copy, `git rev-parse HEAD`. `start.sh` runs the same script.

## Keys

The owner signs releases with an SSH key held on a hardware key. The keys are the lines of `release/allowed_signers`, each with the signer `osk-dns-watcher-release` and the namespaces `file,git`.

The first release has one signing key and no backup key. If the owner loses that key, installed copies cannot verify a later release; the owner will then say on the release page how to move to a new key by a fresh install.

- `start.sh update` checks a new release with the keys of the installed release, then the `start.sh` of the new release checks it again with its own keys. So a new key reaches your copy only through a release that a key you already trust signed.
- A deleted line retires a key: a copy that has updated past that release no longer trusts it.
- A key that leaks stays trusted by every copy that has not updated past the release that removes it. There is no way to revoke it from afar.

## What a first install trusts

- The key file comes with your first copy. `start.sh` shows that the copy is an unchanged release signed by that key, not whose key it is. Compare the fingerprint, as above.
- The tag of an image, such as `:0.1.0`, can be moved. Only the digests in a verified `CONTENTS` count.
- The commit id in `CONTENTS` is a claim of the owner, until someone builds the release again from that commit and compares the files.
- The base images and the SQLite driver in `vendor/` are trusted as they are committed, pinned by digest and by `go.sum`.
