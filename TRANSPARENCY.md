# Obsideo Data Farmer -- What You're Running

This document explains exactly what the Obsideo storage provider binary does,
what it connects to, what it stores, and what it does not do. It is written
for operators who want to inspect before they deploy.

## Source code

The provider is a single statically-linked Go binary called `datafarmer`.
No CGO, no shared libraries, no runtime dependencies beyond the OS kernel.

### File inventory

```

  main.go                       Entry point, delegates to cmd/

  cmd/
    root.go                     CLI setup (cobra), --config flag
    start.go                    "start" command: loads config, opens DB, starts HTTP server
    repl.go                     Interactive REPL (info, harvest, objects, score, wallet)
    scrub.go                    "scrub" command: detect/purge orphaned data
    payments.go                 "harvest" command: request AKT withdrawal

  api/
    api.go                      HTTP server, route registration, CORS, token extraction
    upload.go                   POST /upload/{merkle} -- receive and store data
    download.go                 GET /download/{merkle} -- serve stored data
    challenge.go                POST /challenge -- prove data exists (merkle proof)
    chunked.go                  Chunked upload handling (stage, finalize, status)
    objects.go                  DELETE /objects/{merkle}, GET /list
    replicate.go                POST /replicate -- provider-to-provider data copy
    scrub.go                    GET/POST /admin/scrub -- integrity verification

  config/
    config.go                   YAML config loading (provider_id, coordinator_url, ports, paths)

  file_system/
    file_system.go              BadgerDB metadata + flat file object storage
    keys.go                     DB key format for merkle tree metadata
    monitoring.go               Prometheus gauge (file count, local only, not exposed)
    types.go                    File operation type definitions

  tokens/
    tokens.go                   Ed25519 token verification (validates coordinator-signed JWTs)

  types/
    bytes_seeker.go             Seekable byte slice wrapper
    read_seeker.go              Read+Seek interface
    io.go                       I/O helpers
    proof_types.go              Proof type constants
```

## Network behavior

The provider makes exactly two types of outbound connections:

### 1. Coordinator (configured via `OBSIDEO_COORDINATOR_URL`)

| Call | When | Why |
|------|------|-----|
| `GET /public-key` | On startup | Fetch coordinator's Ed25519 public key for token verification |
| `POST /internal/providers/register` | First startup only | Register this machine as a provider |
| `POST /internal/providers/{id}/heartbeat` | Periodic | Report capacity, update address |
| `GET /internal/providers/{id}/balance` | On demand (REPL) | Check accrued earnings |
| `GET /oracle` | On demand (REPL) | Fetch AKT/USD rate for earnings display |

### 2. Peer providers (only during replication)

| Call | When | Why |
|------|------|-----|
| `GET {peer}/download/{merkle}` | When coordinator issues a replication token | Copy data from another provider for redundancy |

Replication is initiated by the coordinator, not by the provider. The provider
validates the coordinator-signed token before downloading from any peer.

### What it does NOT do

- No telemetry, analytics, or usage reporting
- No phone-home to Obsideo, Anthropic, or any third party
- No DNS queries beyond hostname resolution for configured URLs
- Prometheus client is imported but the `/metrics` endpoint is **not registered** -- metrics are local gauges only
- No outbound connections to any host other than the coordinator and peer providers

## Storage layout

All data lives in a single directory (configurable via `db.path` in config.yaml):

```
{data_dir}/
  .identity_ed25519           Provider's Ed25519 private key (generated once, 0600)
  .obsideo-state.json         Persisted provider ID (survives restarts)
  coordinator_pub.pem         Coordinator's public key (re-fetched on each start)
  config.yaml                 Generated config (re-written on each start)
  objects/                    Stored data chunks (encrypted by uploaders)
    {merkle_hex}              One flat file per object, named by merkle root
  fs/                         BadgerDB metadata (merkle trees for proof verification)
```

### What happens if you lose data

| Lost file | Consequence | Recovery |
|-----------|-------------|----------|
| `.identity_ed25519` | New identity generated, must re-register | Automatic on next start |
| `.obsideo-state.json` | Provider re-registers with new ID | Automatic on next start |
| `coordinator_pub.pem` | Re-fetched on next start | Automatic |
| `config.yaml` | Re-generated on next start | Automatic |
| `objects/` | **Stored data permanently lost** | Coordinator marks objects degraded, replicates from other providers |
| `fs/` | BadgerDB metadata lost, challenges will fail | Rebuild by re-syncing (manual) |

## Exposed endpoints

The provider listens on one HTTP port (default **3334**). TLS is terminated
upstream by Tailscale Funnel or Akash ingress -- the provider itself speaks
plain HTTP.

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /health` | None | Health check (always returns `{"status":"ok"}`) |
| `GET /list` | None | List stored object merkle roots |
| `POST /upload/{merkle}` | Bearer token (coordinator-signed) | Receive data for storage |
| `POST /upload/{merkle}/chunk` | Bearer token | Receive one chunk of a large upload |
| `POST /upload/{merkle}/finalize` | Bearer token | Assemble chunks, verify merkle |
| `GET /upload/{merkle}/status` | Bearer token | Check which chunks are staged |
| `GET /download/{merkle}` | Bearer token (coordinator-signed) | Serve stored data |
| `POST /challenge` | Bearer token (coordinator-signed) | Prove data exists via merkle proof |
| `POST /replicate` | Bearer token (coordinator-signed) | Copy data from a peer provider |
| `DELETE /objects/{merkle}` | Bearer token | Delete a stored object |
| `GET /admin/scrub` | Localhost only | Check stored objects for integrity |
| `POST /admin/scrub` | Localhost only | Purge orphaned data |

Every upload, download, challenge, and replication request requires a token
signed by the coordinator's Ed25519 private key. The provider verifies every
signature before acting. Unsigned or invalid requests are rejected.

## Permissions and isolation

- Runs as non-root user `obsideo` (UID 999) under systemd
- systemd hardening: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`
- Only writable paths: the data directory and `/opt/obsideo-provider`
- Docker: runs as non-root in Alpine container, no `SYS_MODULE` capability needed
- Cannot access files outside its data directory
- Cannot execute arbitrary commands (static Go binary, no shell)

## Dependencies

All direct Go dependencies (from `go.mod`):

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/dgraph-io/badger/v4` | v4.2.0 | Embedded key-value database for merkle metadata |
| `github.com/gorilla/mux` | v1.8.1 | HTTP routing |
| `github.com/json-iterator/go` | v1.1.12 | JSON parsing |
| `github.com/prometheus/client_golang` | v1.18.0 | Local metrics gauge (endpoint NOT exposed) |
| `github.com/rs/cors` | v1.11.0 | CORS middleware |
| `github.com/rs/zerolog` | v1.33.0 | Structured JSON logging to stderr |
| `github.com/spf13/cobra` | v1.8.0 | CLI framework |
| `github.com/TheMarstonConnell/go-merkletree/v2` | v2.0.0 | Merkle tree construction and proofs |
| `github.com/zeebo/blake3` | v0.2.4 | Blake3 cryptographic hashing |
| `golang.org/x/crypto` | v0.23.0 | Ed25519, AES-GCM, HKDF |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML config parsing |

No network-facing dependencies beyond the Go standard library's `net/http`.
No telemetry SDKs, no analytics libraries, no tracking pixels.

## How to verify the image

### Check the source commit

```bash
# If the image has OCI labels (coming soon):
docker inspect obsideo-datafarmer:latest \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'

# Check the binary's version:
docker run --rm obsideo-datafarmer:latest /app/datafarmer version
```

### Build it yourself

```bash
git clone https://github.com/Regan-Milne/obsideo-drive.git
cd obsideo-drive/provider
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o datafarmer .
sha256sum datafarmer
```

Compare the SHA256 of your build against the binary in the image:

```bash
docker run --rm obsideo-datafarmer:latest sha256sum /app/datafarmer
```

### Inspect the Dockerfile

The Dockerfile is in the repo at `Dockerfile`. Multi-stage
build: `golang:1.22-alpine` builder, `alpine:3.19` runtime. No obfuscation,
no binary downloads from external URLs, no post-install scripts.

### Inspect the entrypoint

The entrypoint script (`entrypoint.sh`) is fully readable.
Every step is commented. It does:

1. Wait for Tailscale sidecar (or skip if direct mode)
2. Load persisted provider ID from state file
3. Fetch coordinator public key
4. Generate Ed25519 identity keypair (first run only)
5. Configure Tailscale Funnel (or skip if direct mode)
6. Write config.yaml
7. Start `datafarmer`, wait for `/health`
8. Register with coordinator (retry with backoff)
9. Restart with assigned provider ID
10. Run as PID 1 (container's main process)

No hidden steps, no background processes, no cron jobs.
