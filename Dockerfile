FROM golang:1.26-alpine AS builder

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
FROM alpine:3.21
RUN apk add --no-cache \
    bash \
    ca-certificates \
    gstreamer \
    gst-plugins-base \
    gst-plugins-good \
    gst-plugins-bad \
    gst-plugins-ugly \
    gst-libav \
    xdotool
# Run as a non-root user. PTY sessions are proxied through the hub so root is not required.
RUN adduser -D -u 1001 agent
COPY --from=builder /out/service /service
USER agent
ENTRYPOINT ["/service"]
