# The one image of the DNS lab: BIND 9 for root, tld, ns1 and ns2, Unbound for
# resolver and liar, the tools of the runner, and the webhook receiver.
FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS receiver
COPY receiver.go /src/
RUN cd /src && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -o /receiver receiver.go

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache bind=9.20.30-r0 bind-tools=9.20.30-r0 bind-dnssec-tools=9.20.30-r0 \
	unbound=1.25.2-r2 curl=8.23.0-r0 openssl=3.5.9-r0 ca-certificates=20261020-r0
COPY --from=receiver /receiver /usr/local/bin/receiver
COPY --chmod=755 lab-init labctl /usr/local/bin/
COPY named.conf unbound.conf liar.conf /etc/osklab/
COPY zones/ /etc/osklab/zones/
