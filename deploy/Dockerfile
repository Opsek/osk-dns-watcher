# osk in a container. The first stage builds the static binary the way
# build/static.sh builds it for a release; the second holds that binary,
# Alpine's CA certificates and an empty /data for an ordinary user.
FROM golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
# No versions: Alpine keeps only the newest revision of a package, so a pin
# would break a first build on the day a new one is published.
RUN apk add --no-cache gcc binutils musl-dev
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor vendor
COPY build build
COPY cmd cmd
COPY internal internal
# The cache keeps the compiled SQLite code, so a rebuild does not compile it again.
RUN --mount=type=cache,target=/root/.cache/go-build \
	build/static.sh "$(go env GOARCH)" && cp out/osk-linux-* /osk

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=build /osk /usr/local/bin/osk
# osk refuses root, and its state folder must be private to its user.
RUN mkdir -m 700 /data && chown 10001:10001 /data
USER 10001:10001
WORKDIR /data
HEALTHCHECK --interval=10s --timeout=10s --start-period=30s --retries=3 \
	CMD ["osk", "status", "--config", "/data/osk.json"]
ENTRYPOINT ["osk"]
CMD ["run", "--config", "/data/osk.json"]
