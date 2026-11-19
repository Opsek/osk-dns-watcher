# osk in a container: the binary, Alpine's CA certificates and an empty
# /data for an ordinary user. The stage runtime holds all of it but the
# binary; the two stages after it add the binary. The last stage, the default
# and the one of the quick start, builds osk from source the way
# build/static.sh builds it for a release. The stage release copies the file
# of a release, with the release folder as the build context; release/image.sh
# builds it with --target release, which fails on any other name.

FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
# No versions: Alpine keeps only the newest revision of a package, so a pin
# would break a first build on the day a new one is published.
RUN apk add --no-cache gcc binutils musl-dev
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor vendor
COPY build build
COPY cmd cmd
COPY internal internal
# start.sh gives the version of the release whose signature it checked;
# build/static.sh refuses any other form.
ARG VERSION=0.0.0-dev
# No build cache that other builds share: what they put there would be linked
# into this binary. So each build of a new commit compiles SQLite again.
RUN build/static.sh "$(go env GOARCH)" "$VERSION" && cp out/osk-linux-* /osk

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime
# osk refuses root, and its state folder must be private to its user.
RUN mkdir -m 700 /data && chown 10001:10001 /data
USER 10001:10001
WORKDIR /data
HEALTHCHECK --interval=10s --timeout=10s --start-period=30s --retries=3 \
	CMD ["osk", "status", "--config", "/data/osk.json"]
ENTRYPOINT ["osk"]
CMD ["run", "--config", "/data/osk.json"]

FROM runtime AS release
ARG TARGETARCH
COPY osk-linux-${TARGETARCH} /usr/local/bin/osk

FROM runtime AS source
COPY --from=build /osk /usr/local/bin/osk
