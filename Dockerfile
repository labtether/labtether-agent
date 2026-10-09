FROM golang:1.26.9-alpine@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS builder

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
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache \
    bash=5.3.9-r1 \
    ca-certificates=20260909-r0 \
    gstreamer=1.28.3-r0 \
    gst-plugins-base=1.28.3-r0 \
    gst-plugins-good=1.28.3-r0 \
    gst-plugins-bad=1.28.3-r0 \
    gst-plugins-ugly=1.28.3-r0 \
    gst-libav=1.28.3-r0 \
    xdotool=4.20260303.1-r0 && \
    adduser -D -u 1001 agent
# Run as a non-root user. PTY sessions are proxied through the hub so root is not required.
COPY --from=builder /out/service /service
USER agent
ENTRYPOINT ["/service"]
