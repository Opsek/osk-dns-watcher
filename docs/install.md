# Install

You can run osk-dns-watcher in two ways: build it from a clone of this repository, or run the ready-made image. Both ways run it as a Docker Compose service named `watcher` and keep its files in the volume `osk-dns-watcher_data`. Only these two ways are tested. `go install` is not one of them.

## What you need

- Docker with the Compose plugin, recent enough to know `docker compose up --wait`, on Linux or macOS. On Windows, you need WSL 2, which is not tested. Rootless Docker and Podman are not tested either.
- The URL of a Slack incoming webhook.
- A network that reaches the DNS root servers directly on port 53, over UDP and TCP. VPNs, some routers, and some office networks answer those queries themselves. On such a network, the setup says so and stops. Run osk-dns-watcher on another network or machine.
- For a clone, and to verify a release: git 2.34 or later, plus `ssh-keygen` and `ssh` of OpenSSH 8.2 or later. `start.sh` checks the git version and that `ssh-keygen` is there. With an older `ssh`, its tag check fails, and `start.sh` stops.

## Build from a clone

The [quick start](../README.md#quick-start) in the README builds from a clone. To check the release key and the tag before any file of the copy runs, follow [A first copy](#a-first-copy) instead.

Before it builds, `start.sh` checks that the copy is at a signed release. Its commit must be the commit of a release tag `v<version>` that a key of the copy's `release/allowed_signers` signed. When the copy fails this check, `start.sh` stops and prints a `git checkout` line for a commit whose tag it verified. The line names the commit of the installed release or, in a copy with none, of the newest signed release in the copy. When there is no such commit, `start.sh` says to fetch the tags. The copy must also have no changed tracked file. When these checks pass, `start.sh` builds that commit as git holds it.

The first build takes a few minutes. Then `start.sh` runs `init` ([expectations.md](expectations.md#what-init-asks-and-writes)), starts the service, and sends a test message.

The build pulls the base images from Docker Hub without a login. On a shared IP address, it can hit Docker Hub's pull limit. The ready-made image needs no build.

Run the later commands in `osk-dns-watcher/deploy`, with `./osk-dns-watcher` ([config.md](config.md#the-command-in-deploy)). Do not put files of your own there. `start.sh` refuses to run when `deploy/` holds files that are not part of the release.

## Run the image

You need the digest of the image of a verified release. `make verify-release` prints it on its last line, as [The files](#the-files) shows. Write it in place of `<digest>`. These commands make a folder `osk-dns-watcher` with a Compose file, ask the same two questions as the quick start, start the service, and send a test message:

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

The folder has no `./osk-dns-watcher` script. Run the later commands in this folder in the long form, for example `docker compose exec watcher osk-dns-watcher status --config /data/config.json`.

The release files also hold the program as one static file for Linux on amd64 and on arm64. You can run `osk-dns-watcher run --config <file>` under a service manager of your own, as an ordinary user. The release has no service file. This way is not tested.

## Update

For a clone, run this command in `osk-dns-watcher/deploy`:

```sh
./start.sh update
```

Move a copy with `start.sh update`. Do not use `git pull`. Use `git checkout` only to run the line that `start.sh` prints. An update needs the network, for git and for the base images.

It fetches the tags and checks those above the installed version, from the highest down, with the keys of the installed release. It names and skips each tag that does not verify. It moves to the first tag that verifies, then builds and restarts the service with the same setup. The restart sends a test message. If the service did not run for a minute or more, the restart also sends a `DOWN` notice. An update never goes back to a lower version. When there is no newer signed release, it changes nothing, and the service keeps running. In that case, if it skipped tags, it prints their count and exits with 1.

For the image, follow these steps:

1. Verify the new release.
2. Write its digest on the line `image: &image` of `compose.yaml`.
3. Run `docker compose up --detach --wait` again.

## Your files

Everything that the service keeps is in the volume `osk-dns-watcher_data`, at `/data` in the container:

| File | Holds |
|---|---|
| `config.json` | the config ([config.md](config.md)) |
| `<domain>.expect` | the expectations of each domain ([expectations.md](expectations.md)) |
| `slack-url` | the Slack webhook URL, mode 600 |
| `state/state.db` | the history: alerts, notices, and messages |

Edit a file in the container, for example `docker compose exec watcher vi example.com.expect`. To keep the config and the expectations under version control, copy them to a folder outside the clone:

```sh
mkdir -p ~/osk-dns-watcher-files
docker compose cp watcher:/data/config.json ~/osk-dns-watcher-files/
docker compose cp watcher:/data/example.com.expect ~/osk-dns-watcher-files/
```

You can also use these commands:

- Stop the service: `docker compose stop`. Start it again: `docker compose start`.
- Read its log: `docker compose logs -f watcher`. The log has no size limit unless the Docker daemon sets one.
- Docker runs `status` every 10 seconds as the health check of the container. `docker compose ps` shows the result. Docker does not restart a container that is only unhealthy.
- `docker compose down` keeps the volume. `docker compose down --volumes` deletes it.

## Uninstall

An uninstall deletes the config, the expectations, and the history. First, copy out what you want to keep.

In `osk-dns-watcher/deploy`, or in the folder of the image, stop and remove the service, its volume, and its images:

```sh
docker compose --profile setup down --volumes --rmi all
```

Then delete that `osk-dns-watcher` folder: the clone, or the folder of the image. A build from a clone also left the base images `golang` and `alpine`, and Docker's build cache. If nothing else of yours needs them, remove them with `docker image rm` and `docker builder prune`.

## Verify a release

A release is a signed tag `v<version>`, these files, and the image `ghcr.io/opsek/osk-dns-watcher:<version>`:

| File | Holds |
|---|---|
| `osk-dns-watcher-linux-amd64`, `osk-dns-watcher-linux-arm64` | The program for Linux on each architecture, as one static file. |
| `CONTENTS` | What the release is made of, one fact for each line: the version, the commit, the Go and SQLite versions, the size and SHA-256 of each binary, the digests of the image, and the modules. |
| `SHA256SUMS` | The SHA-256 of the two binaries and of `CONTENTS`. |
| `SHA256SUMS.sig` | The SSH signature of `SHA256SUMS` by the owner's key. |

You need these programs:

- `ssh-keygen` and `ssh` of OpenSSH 8.2 or later, which know the type of the release key, `sk-ssh-ed25519@openssh.com`
- `sha256sum` or `shasum`
- make
- git 2.34 or later, for the tag

### A first copy

A first install trusts the place that the copy came from. The key file `release/allowed_signers` and `start.sh`, which checks with that key file, both come with the copy. After that, `start.sh update` trusts only the key of the installed release.

The first release has one signing key. The owner publishes its fingerprint in one place, the release page of the repository. A comparison with that fingerprint protects you against a wrong copy from elsewhere, such as a mirror, a fork, or a bad network path. That page belongs to the same account as the repository, so the comparison does not protect you against someone who controls the account itself. In a copy, this command prints the fingerprints of the keys of `release/allowed_signers`:

```sh
awk '{ for (i = 1; i < NF; i++) if ($i ~ /^(sk-)?(ssh|ecdsa)-/) { print $i, $(i + 1); break } }' release/allowed_signers | ssh-keygen -lf -
```

For a careful first install, use the block in [release/README.md, "A first copy"](../release/README.md#a-first-copy). Write the version and the published fingerprint in its first two lines. Then paste the block. It clones with no file checked out and verifies the tag only with the key file of the release's commit. It compares the fingerprint of the key that signed the tag. Only then does it check out that commit and run `start.sh`. It stops at the first check that fails.

### The files

Put the files of a release, from its release page, in `out/release/<version>/` of a copy of this repository. Then run, for example:

```sh
make verify-release VERSION=0.1.0
```

It checks, in this order:

1. `SHA256SUMS.sig` is a signature of `SHA256SUMS` by a key of `release/allowed_signers`.
2. `SHA256SUMS` lists the two binaries and `CONTENTS`, and `sha256sum -c` or `shasum -a 256 -c` passes.
3. `CONTENTS` is the `CONTENTS` of the version asked for.

Then it prints:

```
verify-release: the release 0.1.0 in out/release/0.1.0 is signed by a key of release/allowed_signers and complete.
image: ghcr.io/opsek/osk-dns-watcher@sha256:<digest>
```

Run the image by that reference only.

### The tag

```sh
sh release/verify-tag.sh release/allowed_signers v0.1.0
```

When the tag is a release tag, the script prints the commit of the tag. A release tag is a tag object of that name on a commit. Its signed message begins with the line `osk-dns-watcher 0.1.0`. It has one signature, an SSH signature by a key of `release/allowed_signers`. Compare that commit with the commit of your copy, which `git rev-parse HEAD` prints. `start.sh` runs the same script.

## Keys

The owner signs releases with an SSH key held on a hardware key. Each key is a line of `release/allowed_signers`, with the signer `osk-dns-watcher-release` and the namespaces `file,git`.

The first release has one signing key and no backup key. If the owner loses that key, installed copies cannot verify a later release. The owner will then say on the release page how to move to a new key by a fresh install.

- `start.sh update` checks a new release with the keys of the installed release. Then the `start.sh` of the new release checks it again with its own keys. So a new key reaches your copy only through a release that a key you already trust signed.
- A release that deletes the line of a key retires that key. A copy that has updated past that release no longer trusts the key.
- A key that leaks stays trusted by every copy that has not updated past the release that removes it. There is no way to revoke it remotely.

## What a first install trusts

- The key file comes with your first copy. `start.sh` shows that the copy is an unchanged release signed by that key. It does not show who owns that key. Compare the fingerprint, as in [A first copy](#a-first-copy).
- The tag of an image, such as `:0.1.0`, can be moved. Only the digests in a verified `CONTENTS` count.
- The commit id in `CONTENTS` is a claim of the owner, until someone builds the release again from that commit and compares the files.
- The base images and the SQLite driver in `vendor/` are trusted as they are committed, pinned by digest and by `go.sum`.
