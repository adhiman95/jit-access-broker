# ─────────────────────────────────────────────────────
# Multi-stage Dockerfile for JIT Ephemeral Access Broker
# Produces a minimal, secure image (~15MB)
# ─────────────────────────────────────────────────────

# ── Stage 1: Build ──
FROM golang:1.22-alpine AS builder

# Install git (needed for go modules) and ca-certificates (for HTTPS to APIs)
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache module downloads — copy only mod files first
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binaries (CGO disabled for static linking)
# -trimpath: removes local paths from binary
# -ldflags="-s -w": strips debug info for smaller image
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /jit-broker . && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /jitctl ./cmd/jitctl

# ── Stage 2: Runtime ──
FROM alpine:3.19

# Install ca-certificates for HTTPS API calls + tzdata for correct timestamps
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

# Copy binaries from builder
COPY --from=builder /jit-broker /usr/local/bin/jit-broker
COPY --from=builder /jitctl /usr/local/bin/jitctl

# Copy sample config
COPY config.yaml /etc/jit-access-broker/config.yaml

# Create directory for persistence state file
RUN mkdir -p /var/lib/jit-access-broker && chown app:app /var/lib/jit-access-broker

# Run as non-root user
USER app
WORKDIR /etc/jit-access-broker

EXPOSE 8080

# Health check — hits the liveness endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["jit-broker"]
CMD ["--config", "/etc/jit-access-broker/config.yaml"]