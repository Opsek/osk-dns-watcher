# Development

This page is for people who build the program from source or change it. To run it, see the [README](../README.md). Issues are welcome; pull requests are not taken yet.

## Layout

```
cmd/osk-dns-watcher/  the command
internal/             the packages of the tool; internal/store holds the SQLite code
deploy/               the Docker setup: start.sh, compose.yaml, Dockerfile and the daily command osk-dns-watcher
docs/                 the documents
release/              how a release is made and verified (see release/README.md)
.github/workflows/    the job that builds and pushes the image of a release tag
build/                the build script of one static binary
dev/gate/             the checks: the build container, the gate script, the phase scripts, archcheck, the mutation tool, the self-test
dev/installtest/      the tests of the install paths
dev/lab/              the DNS lab
dev/models/           the TLA+ models that the static phase checks
vendor/               the SQLite driver, kept here so that a build needs no network
```

## What you need

- Docker with the Buildx and Compose plugins, using the containerd image store: the checks load images built for two platforms, which the classic image store cannot hold.
- Docker must run images for both linux/arm64 and linux/amd64, because the checks build and run the program for both. Docker Desktop does; on Linux, install QEMU emulation (binfmt) for the other architecture.
- About 3 GB of disk: 2 GB for the build container of both platforms, 0.9 GB for its build cache and 65 MB for the DNS lab.
- Three free lab numbers: `make check` starts the labs `LAB_ID`, `HOST_LAB_A` and `HOST_LAB_B` (default 0, 8 and 9), and no other lab may use them.
- The network, for the first build of the build container and for `make vulncheck`.

Everything else (Go, the C compiler, the linters, the DNS servers) runs in containers.

## Build

```sh
make build
```

This builds the build container `osk-gate:<checksum of dev/gate/Dockerfile>`, then `out/osk-dns-watcher-linux-arm64` and `out/osk-dns-watcher-linux-amd64` in it, with no network. Each binary is static and is tested in an empty image. On Linux, run the binary of your architecture directly:

```sh
$ out/osk-dns-watcher-linux-amd64 version
osk-dns-watcher 0.0.0-dev
go 1.27.4
sqlite 3.54.1
```

On another system, run it in a container. This is for an Apple silicon Mac; on an Intel or AMD machine, write `amd64` in both places:

```sh
docker run --rm --network none --platform linux/arm64 -v "$PWD/out:/out:ro" alpine:3.24 /out/osk-dns-watcher-linux-arm64 version
```

## Checks

```sh
make check
```

Run `make check` only on code you trust: it runs the code of the tree with access to the Docker daemon.

It runs every check in containers, in this order, and stops at the first failure:

| Phase | What it proves |
|---|---|
| build | Both binaries build with no network, are static, and run `osk-dns-watcher version` in an empty image. |
| static | The code is formatted; `vendor/` is exactly the SQLite driver module; `go vet`, errcheck, staticcheck and exhaustive pass, with and without the build tag `lab`; each model in `dev/models/` that has a `.cfg` file holds; `archcheck` passes (see below). |
| tests | `go test -race ./...` passes, never from cached results; then each fuzz test runs for `FUZZTIME`. |
| mutate | For each small change of the code of `internal/decide`, `internal/expect`, `internal/alert`, `internal/schedule`, `internal/certlog`, `internal/observe`, `internal/observe/obs`, `internal/httpclient`, `internal/mtasts` and `internal/cli`, a test fails, or the change is listed with a reason in `dev/gate/mutants.txt`. |
| selftest | The checks of the static, tests and mutate phases can fail: one fault at a time is put into a copy of the tree, and the check that must catch it fails. |
| lab | The tests with the build tag `lab` pass against the [DNS lab](../dev/lab/README.md), after its own acceptance checks; then the checks that only the host can make. |
| quickstart | The tests of `dev/installtest/`: the quick-start block of the README works as written, against the lab, in a clean container that holds only git and the Docker CLI, on both architectures; so do `./start.sh update`, the refusals of `start.sh`, the first-copy steps and the fingerprint command of `release/README.md`, and `deploy/osk-dns-watcher`. For a release with an image, the image block of [install.md](install.md) works too. |
| clean | No container, network, volume or image of the checks or of the quick start is left behind. |

Two more phases run only on demand:

| Phase | When | What it proves |
|---|---|---|
| release | `make check OSK_RELEASE=<version>` | The files in `out/release/<version>/` and the image that their `CONTENTS` names are the release of this commit. It builds nothing. See `release/README.md`. |
| vulncheck | `make vulncheck`, and every run with `OSK_RELEASE` | `govulncheck` finds no known vulnerability in the code that `cmd/osk-dns-watcher` reaches, the Go standard library and the binaries. It is the one phase with the network. It does not cover SQLite's own C code. |

Each check prints `ok <name>` or `FAIL <name>: <reason>`, and `make check` exits with 0 only if all passed. The results are also written to `out/gate.log` (one line for each phase that passed and for each fuzz run) and `out/tests.json` (every test event, as `go test -json` writes them).

Only one `make check` runs in a checkout at a time. If one was killed, remove `out/lock` before the next. Two checkouts can run `make check` at the same time when no number of `LAB_ID`, `HOST_LAB_A` and `HOST_LAB_B` is used by both.

### Settings

From the environment (the top comment of the `Makefile` names them too):

| Variable | Default | Meaning |
|---|---|---|
| `DOCKER` | `docker` | The Docker command, with any options it needs. |
| `BUILD_FLAGS` | empty | Extra options for `docker buildx build`, such as a builder. |
| `DOCKER_SOCK` | `/var/run/docker.sock` | The socket of the Docker daemon, as the daemon sees it. The quickstart phase mounts it into its clean container. |
| `LAB_ID` | `0` | The lab that the checks use (0 to 9). It also labels the containers of the checks. |
| `HOST_LAB_A`, `HOST_LAB_B` | `8`, `9` | Two more labs that the lab phase starts for a short time. |
| `FUZZTIME` | `20s` | How long each fuzz test runs. |
| `SELFTEST` | `run` | `skip` leaves out the selftest phase: the gate says so and writes `selftest skipped` to `out/gate.log`. Any other value stops the gate before the first phase. |
| `OSK_RELEASE` | empty | A version: adds the release and vulncheck phases. |
| `OSK_IMAGE` | `ghcr.io/opsek/osk-dns-watcher` | The name of the release image. |
| `VERSION` | none | The version for `make release`, `make image`, `make image-digests` and `make verify-release`. |

## Make targets

| Target | What it does |
|---|---|
| `make check` | Runs the checks (above). |
| `make build` | Builds both binaries (above). |
| `make vulncheck` | Runs the vulnerability scan alone. |
| `make release VERSION=<version>` | Builds the files of a release in `out/release/<version>/`. |
| `make image VERSION=<version>` | Builds the release image from those files. |
| `make image-push VERSION=<version>` | Builds the release image and pushes it, unless the registry has that tag already. The release job runs it. |
| `make image-digests VERSION=<version>` | Checks that the pushed image is the image of `make image`, then adds its digests to `CONTENTS`. |
| `make verify-release VERSION=<version>` | Checks the files of a release as a stranger does ([install.md](install.md#verify-a-release)). |
| `make lab-up`, `make lab-down` | Starts and stops the DNS lab. |

How a release is made is in `release/README.md`. A pushed tag `v<major>.<minor>.<patch>` starts the job `.github/workflows/release-image.yml`, which builds the release image and pushes it to `ghcr.io`; the owner checks it against a build of their own before signing.

## The DNS lab

The lab is a small, closed copy of the DNS in Docker: a root, a parent zone `test.`, two authoritative nameservers, two resolvers and a webhook receiver, with real DNS software (BIND and Unbound). No port is published on the host, and no container reaches the internet. `make lab-up` starts it and `make lab-down` removes it. `dev/lab/bin/lab run <command...>` runs a command in its runner, and `labctl` there changes zones the way an attacker or a careless operator would. See [dev/lab/README.md](../dev/lab/README.md).

## The rule of the code

The program uses only the Go standard library and one module, the SQLite driver `github.com/mattn/go-sqlite3`. The checks enforce it: `archcheck` fails when `go.mod` or `vendor/modules.txt` names another module, or when the code of the tool imports one, and the static phase fails when `vendor/` differs from the driver module.

The code of the tool is every package under `cmd/` and `internal/`, without its tests. `archcheck` keeps it plain, so that every check sees the files that the build uses. A package that `cmd/osk-dns-watcher` imports, directly or not, must lie under `cmd/` or `internal/` and not in a folder named `testdata` or starting with `_` or `.`; it holds no source code but Go (no assembly, C or `.syso` files); and none of its files is limited to some systems by its name (such as `_linux.go`) or by a build constraint. Tests may have build constraints, such as the tag `lab`.

`archcheck` also fails when that code listens on a socket (also through `net/http` or `crypto/tls`), starts a process, uses a name of `syscall` other than the signals `SIGTERM` and `SIGPIPE`, imports `unsafe` or `C`, or breaks a line of `dev/gate/imports.txt` (for example, only `internal/store` may use `database/sql`). A line there that names a package of the tool that does not exist fails too.
