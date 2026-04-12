FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /datafarmer .

# ──────────────────────────────────────────────────────────────

FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl jq bash openssl

# Tailscale CLI for Funnel setup (only the CLI binary, not the daemon).
# Pinned to a specific version for reproducibility.
COPY --from=docker.io/tailscale/tailscale:v1.96.4 /usr/local/bin/tailscale /usr/local/bin/tailscale

COPY --from=builder /datafarmer /app/datafarmer
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/datafarmer

WORKDIR /app

ENTRYPOINT ["/app/entrypoint.sh"]
