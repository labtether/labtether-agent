FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.2.0
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-$(go env GOOS)} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/service ./cmd/labtether-agent

# Agent needs a shell for PTY terminal sessions.
# Using Alpine instead of distroless so /bin/sh and /bin/bash are available.
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache \
    bash=5.3.9-r1 \
    ca-certificates=20261020-r0 \
    gstreamer=1.28.3-r0 \
    gst-plugins-base=1.28.3-r0 \
    gst-plugins-good=1.28.3-r0 \
    gst-plugins-bad=1.28.3-r0 \
    gst-plugins-ugly=1.28.3-r0 \
    gst-libav=1.28.3-r0 \
    xdotool=4.20260303.1-r0 \
    xmodmap=1.0.11-r1 && \
    adduser -D -u 1001 agent && \
    mkdir -p /var/lib/labtether && \
    chown agent:agent /var/lib/labtether && \
    chmod 0700 /var/lib/labtether
# The non-root agent cannot write /etc/labtether. Keep the issued agent token,
# enrollment state, saved Hub CA, settings and device key in one private,
# agent-owned directory. Mount a volume here so they survive container updates.
ENV LABTETHER_TOKEN_FILE=/var/lib/labtether/agent-token \
    LABTETHER_AGENT_SETTINGS_FILE=/var/lib/labtether/agent-config.json \
    LABTETHER_DEVICE_KEY_FILE=/var/lib/labtether/device-key \
    LABTETHER_DEVICE_PUBLIC_KEY_FILE=/var/lib/labtether/device-key.pub \
    LABTETHER_DEVICE_FINGERPRINT_FILE=/var/lib/labtether/device-fingerprint
# Run as a non-root user. PTY sessions are proxied through the hub so root is not required.
COPY --from=builder /out/service /service
USER agent
ENTRYPOINT ["/service"]
