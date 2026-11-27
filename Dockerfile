# RampartEye: one static binary plus nmap on Alpine.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
	-o /out/ramparteye ./cmd/ramparteye

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# nmap is installed from the distribution at build time.
# /usr/bin/nmap stays without file capabilities: connect scans (-sT) as the
# unprivileged app user. /usr/local/bin/nmap-privileged carries
# cap_net_raw/cap_net_admin for SYN scans (-sS) and ARP discovery; it only
# starts in a container given NET_RAW and NET_ADMIN (cap_add) and is used
# with RAMPART_SCAN_PRIVILEGED=true, RAMPART_NMAP_PATH pointing at it and
# NMAP_PRIVILEGED=1 (see compose.demo.yml).
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata \
	&& apk add --no-cache --virtual .caps libcap-utils \
	&& cp /usr/bin/nmap /usr/local/bin/nmap-privileged \
	&& setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/nmap-privileged \
	&& apk del .caps \
	&& addgroup -S -g 10001 ramparteye \
	&& adduser -S -D -H -u 10001 -G ramparteye -h /var/lib/ramparteye ramparteye \
	&& mkdir -p /var/lib/ramparteye/secrets \
	&& chown -R 10001:10001 /var/lib/ramparteye \
	&& chmod 0700 /var/lib/ramparteye/secrets
COPY --from=build /out/ramparteye /usr/local/bin/ramparteye
# The secrets volume is created from this directory, so it is owned by the
# app user (the key file is published with a hard link: the volume must
# support them, as local Docker volumes do).
VOLUME /var/lib/ramparteye/secrets
ENV RAMPART_SECRETS_DIR=/var/lib/ramparteye/secrets \
	RAMPART_HTTP_ADDR=:9080
USER 10001:10001
EXPOSE 9080
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=30 \
	CMD wget -q -O /dev/null http://127.0.0.1:9080/healthz || exit 1
ENTRYPOINT ["ramparteye"]
CMD ["serve"]
