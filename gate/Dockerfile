# The build container of the osk gate, for linux/arm64 and linux/amd64.
# gate/bin/gate tags it with a checksum of this file. Every version below is
# pinned. None of these tools is linked into osk: they are installed here,
# never in osk's go.mod.

ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280

# The Go tools are built with the same Go toolchain as osk.
FROM ${GO_IMAGE} AS tools
ENV CGO_ENABLED=0
RUN go install github.com/kisielk/errcheck@v1.30.0 \
 && go install honnef.co/go/tools/cmd/staticcheck@v0.8.2 \
 && go install github.com/nishanths/exhaustive/cmd/exhaustive@v0.17.1 \
 && go install golang.org/x/vuln/cmd/govulncheck@v1.10.0
# The go command checks every module against sum.golang.org. This also pins each
# tool's own module to the sum written here, so a replaced release is refused.
RUN for pair in \
      errcheck=h1:ZIxNDAfAd4larXHTceoZP/dYPAB90dHg1OYhA2sVh5k= \
      staticcheck=h1:+jPbCzuYxYrcoOvCecYUFDj+XJQRmzIhJmlbpps21Zk= \
      exhaustive=h1:zlwR7GV/UqKrm3AJdeXqldUTSsbyfdqS8f/m0oMYLD0= \
      govulncheck=h1:W/Im35AGknunDiqBysVe9VoMfaeTJE7lptrD+1s//aE= ; do \
      bin=${pair%%=*}; sum=${pair#*=}; \
      go version -m /go/bin/$bin | grep -qF "$sum" || { echo "wrong module sum: $bin"; exit 1; }; \
    done

FROM ${GO_IMAGE}
# Not osk.gate=<n>: a container inherits the labels of its image, and the gate
# looks for leftover containers by that label.
LABEL osk.gate.image=1
# gcc and musl-dev: cgo for github.com/mattn/go-sqlite3, linked fully static.
# binutils: readelf, which build/static.sh uses to prove that the binary is static.
# apk checks each package against the signed index of Alpine 3.24.
RUN apk add --no-cache \
      gcc=15.2.0-r5 \
      binutils=2.45.1-r1 \
      musl-dev=1.2.6-r3 \
      openjdk21-jre-headless=21.0.13.1_p2-r0
# TLC, the TLA+ model checker, run as: tlc [-config <name>.cfg] <name>.tla
ADD --checksum=sha256:936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88 --chmod=644 \
    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar /opt/tla/tla2tools.jar
# Its state files go to a new temporary directory, so the models may be on a read-only mount.
COPY --chmod=755 <<'EOF' /usr/local/bin/tlc
#!/bin/sh
exec java -XX:+UseParallelGC -cp /opt/tla/tla2tools.jar tlc2.TLC -metadir "$(mktemp -d)" "$@"
EOF
COPY --from=tools /go/bin/ /usr/local/bin/
# The SQLite driver at the version of go.mod, checked against sum.golang.org
# here and against go.sum when gate/phase/static.sh rebuilds vendor/ from it.
RUN go mod download github.com/mattn/go-sqlite3@v1.14.53
# gate/phase/*.sh refuse to run where this file is missing.
COPY <<'EOF' /etc/osk-gate
This is the build container of the osk gate.
EOF
