# Obsideo Provider — What You're Running

This document describes exactly what the `obsideo-provider` binary does, what it
connects to, what it stores, and what it doesn't do. It is written for operators
who want to inspect before deploying.

For network-level architecture (encryption model, payment flow, threat model,
design principles), see [obsideo-protocol](https://github.com/Regan-Milne/obsideo-protocol).
This document is narrowly scoped to the provider binary's behaviour.

## Source code

The provider is a single statically-linked Go binary called `obsideo-provider`.
No CGO, no shared libraries, no runtime dependencies beyond the OS kernel.
Released artifacts: `obsideo-provider-linux-amd64`, `obsideo-provider-windows-amd64.exe`.

### File inventory

```
main.go                       Entry point. Parses argv, dispatches to cmd/start.
                              Single subcommand: `start --config <path>`.

cmd/
  start.go                    Loads config, opens store, starts HTTP server,
                              kicks off heartbeat + coverage refresher.
  heartbeat.go                Periodic heartbeat to coordinator (30s interval).

config/
  config.go                   YAML config loading: provider_id, server.port,
                              data.path, tokens.public_key_path, coordinator.url,
                              coordinator.provider_api_key, coverage.*.

api/
  server.go                   HTTP router (chi), middleware, helpers.
  upload.go                   POST /upload/{merkle} — receive ciphertext upload.
  download.go                 GET /download/{merkle} — serve ciphertext.
  challenge.go                POST /challenge — return merkle proof for a chunk.
  delete.go                   POST /delete/{merkle} — process customer-signed
                              delete (Ed25519-verified locally, no coord).
  objects.go                  DELETE /objects/{merkle}, GET /list.
  replicate.go                POST /replicate — provider-to-provider data copy.
  pause.go                    POST /control/pause + GET /control/pause —
                              cold-key circuit breaker control plane.

store/
  store.go                    Local object storage: ciphertext blobs, chunk
                              index, ownership records (write-once 0o444),
                              coverage cache. Atomic write semantics.

pausectl/
  pausectl.go                 Pause-control state machine: sequence
                              monotonicity, signature verification, atomic
                              persisted state.
  embedded.go                 Cold-key public key, baked at build time via
                              Go ldflags. Default empty = breaker disarmed.

coverage/
  client.go                   Coverage-status query client (3-retry exponential
                              backoff, typed ErrNonRetryable).
  refresher.go                Periodic coverage cache refresh job.
```

## Network behaviour

The binary makes outbound connections to exactly two destinations:

### 1. Coordinator (configured via `coordinator.url` in config.yaml)

| Call | When | Why |
|------|------|-----|
| `GET /public-key` | On startup | Fetch coordinator's Ed25519 public key for token verification |
| `POST /internal/providers/{id}/heartbeat` | Every 30 seconds | Liveness signal |
| Coverage queries | On the configured refresh interval | Ask coord which held roots are paid-through (used to drive non-contracted GC) |

Registration is **not** automatic — the operator runs a manual `curl` once
before first start (see OPERATOR_SETUP.md).

### 2. Peer providers (only during replication)

| Call | When | Why |
|------|------|-----|
| `GET {peer}/download/{merkle}` | When the coordinator issues a replication token | Copy ciphertext from a peer to restore replication count |

Replication is initiated by the coordinator. The provider validates the
coordinator-signed replication token before contacting any peer.

### What it does NOT do

- No telemetry, analytics, crash reporting, or usage exfiltration to any
  third party
- No phone-home to Obsideo, Anthropic, or anyone else
- No DNS queries beyond hostname resolution for the configured coordinator URL
  and peer URLs in coord-issued tokens
- The Prometheus client library is imported but the `/metrics` endpoint is
  **not registered** — gauges are local-only

## Storage layout

Configurable via `data.path` in config.yaml. On first run the binary creates:

```
{data_dir}/
  .identity_ed25519           Provider's Ed25519 private key (mode 0600,
                              generated once on first start)
  objects/{merkle_hex}        Ciphertext blobs (raw bytes; one flat file
                              per object, named by merkle root)
  index/{merkle_hex}.json     Chunk hashes for proof reconstruction:
                              {chunk_size, total_chunks, chunk_hashes[]}
  ownership/{merkle_hex}.json Customer signing pubkey for this object,
                              write-once (mode 0o444). Used to verify
                              user-signed deletes locally.
  coverage/{merkle_hex}.json  Cached coverage-status results
                              (paid-through? expired? testdrive?)
```

### What happens if you lose data

| Lost file | Consequence | Recovery |
|-----------|-------------|----------|
| `.identity_ed25519` | New identity generated on next start; you re-register as a new provider | Manual re-registration |
| `objects/` | Stored data permanently lost | Coordinator's reconciliation marks objects degraded; replicator restores from peers (under the network's grace period) |
| `index/` | Local proof generation breaks; challenges will fail | Rebuild manually by re-reading objects/ |
| `ownership/` | User-signed deletes can't be authorized locally | Re-fetched per-object from coord on next access |
| `coverage/` | Stale coverage decisions until refresh | Auto-refreshes on the configured interval |

## Exposed endpoints

The provider listens on one HTTP port (default **3334**). TLS is terminated
upstream by Tailscale Funnel or whatever ingress the operator chose; the
provider itself speaks plain HTTP.

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /health` | none | Liveness check (returns `{"status":"ok"}`) |
| `GET /list` | none | List held merkle roots |
| `POST /upload/{merkle}` | coord-signed JWT (Bearer) | Receive ciphertext upload |
| `GET /download/{merkle}` | coord-signed JWT (Bearer) | Serve ciphertext |
| `POST /delete/{merkle}` | **customer-signed** Ed25519 | Process user-signed delete (verified locally, no coord) |
| `POST /challenge` | coord-signed JWT (Bearer) | Return merkle proof for a chunk |
| `POST /replicate` | coord-signed JWT (Bearer) | Pull ciphertext from a peer |
| `DELETE /objects/{merkle}` | coord-signed JWT (Bearer) | Coord-initiated object removal (used by reconciliation flows) |
| `POST /control/pause` | cold-key Ed25519 | Halt coverage-driven prune decisions |
| `GET /control/pause` | none | Read current pause state |

The internal endpoints (`/challenge`, `/replicate`, the coord-side delete) are
called by the coordinator; operators typically firewall them off from the
public internet, exposing only `/upload`, `/download`, `/delete`, `/control/pause`,
`/list`, and `/health` to client-facing traffic.

## Identity

On first start the binary generates an Ed25519 keypair and writes the private
half to `{data_dir}/.identity_ed25519` (mode 0600). The public half is sent to
the coordinator during registration and identifies this specific provider
across re-registrations on the same hardware.

Loss of the private key means the provider must re-register with a fresh
identity — coord will treat it as a new provider; existing placements are
not migrated.

## See also

- [README.md](README.md) — install, configure, run
- [OPERATOR_SETUP.md](OPERATOR_SETUP.md) — full operator setup including the registration ceremony
- [obsideo-protocol](https://github.com/Regan-Milne/obsideo-protocol) — network architecture, design principles, and threat model
