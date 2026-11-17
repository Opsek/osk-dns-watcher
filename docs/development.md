# Development

This page is for people who build osk from source or change it. To run osk, see the [README](../README.md).

## What you need

- Docker with the Buildx and Compose plugins, using the containerd image
  store: the checks load images built for two platforms, which the classic
  image store cannot hold.
- Docker must run images for both linux/arm64 and linux/amd64, because the
  checks build and run osk for both. Docker Desktop does; on Linux, install
  QEMU emulation (binfmt) for the other architecture.
- About 3 GB of disk: 2 GB for the build container of both platforms,
  0.9 GB for its build cache and 65 MB for the DNS lab.
- Three free lab numbers: `make check` starts the labs `LAB_ID`, `HOST_LAB_A`
  and `HOST_LAB_B` (default 0, 8 and 9), and no other lab may use them.

Everything else (Go, the C compiler, the linters, the DNS servers) runs in
containers.

## Build

```sh
make build
```

This builds the build container `osk-gate:<checksum of gate/Dockerfile>`,
then builds `out/osk-linux-arm64` and `out/osk-linux-amd64` in it, with no
network. Each binary is static and is tested in an empty image. On Linux, run
the binary of your architecture directly:

```sh
$ out/osk-linux-amd64 version
osk 0.0.0-dev
go 1.27.3
sqlite 3.54.1
```

On another system, run it in a container. This is for an Apple silicon Mac;
on an Intel or AMD machine, write `amd64` in both places:

```sh
docker run --rm --network none --platform linux/arm64 -v "$PWD/out:/out:ro" alpine:3.24 /out/osk-linux-arm64 version
```

## Checks

```sh
make check
```

This runs every check in containers, in this order, and stops at the first
failure:

| Phase | What it checks |
|---|---|
| build | Both binaries build with no network, are static, and run `osk version` in an empty image. |
| static | `gofmt`; that `vendor/` is exactly what the go command makes from the SQLite driver module, which the build container downloaded and checked against the Go checksum database; `go vet`, errcheck, staticcheck and exhaustive over `./...`, each without build tags and with the tag `lab`; each TLA+ model in `models/` that has a `.cfg` file; `archcheck` (see below). |
| tests | `go test -race ./...`, never from cached results, then each fuzz test (a function `Fuzz…` in a test file) for `FUZZTIME` (default 20s). A fuzz test that does not run fails. |
| selftest | `gate/selftest/run.sh` puts one fault at a time into a copy of the tree and requires the line `FAIL <check>` of the check that must catch it. It covers every `archcheck` rule, `gofmt`, the vendor check, `go vet` and each linter (with and without the tag `lab`), the race detector in ordinary and in lab tests, uncached test runs, fuzz runs, and the refusal of the scripts in `gate/phase/` to run outside the build container. The build, lab, quickstart and clean phases have no planted faults. |
| lab | Builds the tests with the build tag `lab` with the race detector, starts the [DNS lab](../lab/README.md), runs its acceptance checks and those tests, then the checks that only the host can make (timing, labels, isolation of two labs). |
| quickstart | Builds a clean container that holds only git and the Docker CLI and reaches Docker through `DOCKER_SOCK`. In it, runs the quick-start block of the [README](../README.md) as it is written, against the DNS lab: the clone comes from the working tree, the answers come on standard input, and a second Compose file puts osk on the lab network. A test message must reach the lab's webhook receiver. It does this for the machine's own architecture and for the other one (under emulation), and checks `osk doctor` in the image of each. On the machine's own architecture it also runs `./start.sh update` and requires the setup and the open alerts to survive. |
| clean | No container, network or volume of the checks is left behind, and no container, network, volume or image of the quick start's Compose project. |

Each check prints `ok <name>` or `FAIL <name>: <reason>`, and `make check`
exits with 0 only if all passed. The results are also written to
`out/gate.log` (one line for each phase that passed and for each fuzz run)
and `out/tests.json` (every test event, as `go test -json` writes them).

Settings, from the environment (the top comment of the `Makefile` names them
too):

| Variable | Default | Meaning |
|---|---|---|
| `DOCKER` | `docker` | The Docker command, with any options it needs. |
| `BUILD_FLAGS` | empty | Extra options for `docker buildx build`, such as a builder. |
| `DOCKER_SOCK` | `/var/run/docker.sock` | The socket of the Docker daemon, as the daemon sees it. The quickstart phase mounts it into its clean container. |
| `LAB_ID` | `0` | The lab that the checks use (0 to 9). It also labels the containers of the checks. |
| `HOST_LAB_A`, `HOST_LAB_B` | `8`, `9` | Two more labs that the lab phase starts for a short time. |
| `FUZZTIME` | `20s` | How long each fuzz test runs. |

Only one `make check` runs in a checkout at a time. If one was killed, remove
`out/lock` before the next. Two checkouts can run `make check` at the same
time when no number of `LAB_ID`, `HOST_LAB_A` and `HOST_LAB_B` is used by
both.

## Layout

```
cmd/osk/          the command
internal/         the packages of the tool; internal/store holds the SQLite code
vendor/           the SQLite driver, kept here so that builds need no network
build/static.sh   builds one static binary
deploy/           the Docker setup: start.sh, compose.yaml, Dockerfile, and its tests
docs/             the config reference and this page
gate/             the checks: build container, gate/bin/gate, phase scripts, archcheck, self-test
lab/              the DNS lab (see lab/README.md)
models/           the TLA+ models that the static phase checks
Makefile          make check, make build, make lab-up, make lab-down
```

## The rule of the code

osk uses only the Go standard library and one module, the SQLite driver
`github.com/mattn/go-sqlite3`. The checks enforce it: `archcheck` fails when
`go.mod` or `vendor/modules.txt` names another module, or when the code of the
tool imports one, and the static phase fails when `vendor/` differs from the
driver module.

The code of the tool is every package under `cmd/` and `internal/`, without
its tests. `archcheck` keeps it plain, so that every check sees the files that
the build uses. A package that `cmd/osk` imports, directly or not, must lie
under `cmd/` or `internal/` and not in a folder named `testdata` or starting
with `_` or `.`; it holds no source code but Go (no assembly, C or `.syso`
files); and none of its files is limited to some systems by its name (such as
`_linux.go`) or by a build constraint. Tests may have build constraints, such
as the tag `lab`.

`archcheck` also fails when that code listens on a socket (also through
`net/http` or `crypto/tls`), starts a process, uses a name of `syscall` other
than the signals `SIGTERM` and `SIGPIPE`, imports `unsafe` or `C`, or breaks a
line of `gate/imports.txt` (for example, only `internal/store` may use
`database/sql`). A line there that names a package of the tool that does not
exist fails too.
