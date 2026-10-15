# Obsideo Provider

Reference implementation of an Obsideo storage provider. Single Go binary,
flat-file storage, end-to-end encrypted (providers only ever hold
ciphertext).

For network-level architecture — design principles, encryption model,
challenge protocol, payment model, threat model — see
[obsideo-protocol](https://github.com/Regan-Milne/obsideo-protocol).
This repository is the operator-facing implementation.

Looking to **store** data instead of hosting it? Start at
[obsideo.io/docs](https://obsideo.io/docs/) (12 GB free tier, self-serve,
no card). AI agents integrating storage: the executable contract lives at
[obsideo.io/agents.md](https://obsideo.io/agents.md), or drop the
[MCP server](https://github.com/Regan-Milne/obsideo-mcp) into Claude
Desktop, Claude Code, or Cursor.

**Alpha.** See [Known limitations](#known-limitations) before deploying.


## What this is

A storage node for the Obsideo decentralized storage network. You run
this on your hardware; the network pays you per gigabyte-month of paid
customer data you verifiably retain. All data is encrypted on the
customer's machine before it reaches your disk — providers never see
plaintext.

Key properties:

- **Flat-file storage.** Each object is written as
  `{data_dir}/objects/{merkle_hex}` (raw ciphertext) plus
  `{data_dir}/index/{merkle_hex}.json` (chunk hashes). No embedded
  database, no IPFS dependency.
- **Ownership persistence.** First upload of an object for a given
  account writes `{data_dir}/ownership/{merkle_hex}.json` containing
  the customer's Ed25519 signing pubkey. Write-once (mode `0o444`).
  The signing pubkey is used to verify user-signed delete commands
  locally — without coordinator mediation.
- **Coverage polling.** The binary periodically asks the coordinator
  "which of the roots I'm holding correspond to paid-through accounts?"
  Results are cached locally per-merkle. Under coordinator unavailability,
  the binary retains everything — never prune under uncertainty.
- **Cold-key circuit breaker.** `POST /control/pause` accepts a cold-
  key-signed pause signal and halts all coverage-driven prune decisions
  until auto-expiry. (The current release binary ships with no cold
  key pinned — the endpoint returns 503 until a subsequent release
  bakes in a post-ceremony pubkey via Go ldflags.)

## Install — native Linux

Four commands, about five minutes. You need a public DNS name with TLS on 443
terminating at a reverse proxy that forwards to the node's local port (3334).
Relays and tunnels are not supported on the data path. Full guide, including the
manual equivalent of every step: [OPERATOR_SETUP.md](OPERATOR_SETUP.md).

```bash
# 1. get the release and verify it
wget https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/obsideo-provider-linux-amd64      https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x obsideo-provider-linux-amd64 && mv obsideo-provider-linux-amd64 obsideo-provider

# 2. key, identity, config, reachability check, register
./obsideo-provider init --address https://storage.example.com --capacity 10TB --data /srv/obsideo

# 3. after approval: paste the API key into config.yaml, then
./obsideo-provider start --config config.yaml
```

`init` fetches the coordinator's public key, generates the node's signing
identity, writes `config.yaml`, checks that the public address reaches this
process, registers with the coordinator and writes the returned provider id
into the config. It prints the id and what happens next. Expect the first-boot
log to include `heartbeat: first success` within ~30 seconds once the API key
is in place.

## Install — Windows

```powershell
# Download obsideo-provider-windows-amd64.exe from:
# https://github.com/Regan-Milne/obsideo-provider/releases/latest
# Place it alongside your config.yaml, then run:
.\obsideo-provider-windows-amd64.exe start --config config.yaml
```

## Install — from source

```bash
git clone https://github.com/Regan-Milne/obsideo-provider.git
cd obsideo-provider
./build.sh                       # stamps the release version into the binary
./obsideo-provider version       # should print provider-v1-7-cors
./obsideo-provider start --config config.yaml
```

`build.sh` runs `go build` with the version ldflag set. A plain
`go build` also produces a working binary, but leaves the version string
at its source default, so the node reports an older version to the
coordinator. Go 1.22+ required; the in-tree module path is
`github.com/obsideo/obsideo-provider`, and you build from the cloned
tree (not via `go install`).

## Upgrading from an older release

Upgrading is a binary swap. The on-disk object format is unchanged, so
your existing `data/` directory carries over untouched.

1. Stop your provider service.
2. Back up your current binary (e.g. rename to `.pre-v1-5`).
3. Download the new binary from the
   [latest release](https://github.com/Regan-Milne/obsideo-provider/releases/latest)
   and put it in place of the old one.
4. Verify version: `./obsideo-provider version` should print
   `provider-v1-7-cors`.
5. Restart the service. Look for `heartbeat: first success` in the logs
   within ~30 seconds.

On first start the provider generates an Ed25519 signing identity at
`{data_dir}/provider_identity.key` (mode 0600) if one does not already
exist. This is the key it uses to sign possession proofs. Back it up
alongside your data directory. Your `provider_id`, API key, payout
address, capacity, and placement record live on the coordinator and
survive the upgrade.

New since provider-v1-1:

- **Streaming ingest.** Uploads are written to disk as they arrive, with
  an incremental Merkle computation, so memory stays flat regardless of
  object size. A corrupt or mis-addressed upload is rejected at ingest.
- **Signed possession proofs.** The provider signs its challenge
  responses with its Ed25519 identity, so a proof is attributable to the
  node that produced it.
- **Security hardening.** The previously unauthenticated
  `DELETE /objects/{merkle}` and `GET /list` endpoints have been removed.
  Erase is now expressible only as a customer-signed
  `POST /delete/{merkle}`.

Full release notes and checksums:
[latest release](https://github.com/Regan-Milne/obsideo-provider/releases/latest).

## Docker

Docker infrastructure is **not included in this release.** The legacy
Docker image (the `datafarmer` binary, relay-tunnel auto-ingress —
since deprecated network-wide — and env-var-driven registration) is incompatible with the new binary's
file-based config. A port to the new binary is tracked as a follow-up
release.

In the meantime, Docker-using operators have three options:

1. Stay on the legacy release
   ([v2-2026-04-22-streaming](https://github.com/Regan-Milne/obsideo-provider/releases/tag/v2-2026-04-22-streaming))
   until Docker support ships for the new binary. You miss out on
   ownership files, coverage polling, and the circuit breaker, but
   existing deployments keep working.
2. Run the native binary on the Docker host directly (e.g., via
   systemd — see native-Linux install above) and skip Docker.
3. Write a minimal Dockerfile locally:

   ```dockerfile
   FROM alpine:3.19
   RUN apk add --no-cache ca-certificates
   COPY obsideo-provider /app/obsideo-provider
   COPY coordinator_pub.pem /app/coordinator_pub.pem
   COPY config.yaml /app/config.yaml
   WORKDIR /app
   EXPOSE 3334
   CMD ["/app/obsideo-provider", "start", "--config", "/app/config.yaml"]
   ```

   You manage your public ingress in a sibling container or on the
   host — use a direct endpoint (port-forward 443 with Let's Encrypt,
   or a routable public IP). Avoid relay tunnels (Tailscale Funnel,
   quick tunnels): they throttle bulk transfer and your node will
   underperform on placement and earnings. Mount a persistent
   volume at `/app/data` so `data.path: /app/data` in `config.yaml`
   is backed by your disk.

## Configuration reference

See `config.example.yaml` for the minimum-viable config. Key fields:

- `provider_id` — UUID assigned at registration. DM the network admin
  to be approved as an operator; you receive this + the API key out
  of band.
- `server.host` / `server.port` — bind address for the provider HTTP
  server. Default `0.0.0.0:3334`.
- `data.path` — absolute path to the directory where objects/, index/,
  ownership/, coverage/, pause/ are created.
- `tokens.public_key_path` — path to `coordinator_pub.pem`, used to
  verify incoming upload tokens.
- `coordinator.url` — coordinator base URL (e.g.
  `https://coordinator.obsideo.io`).
- `coordinator.provider_api_key` — your per-operator bearer token
  for coord-side authentication on coverage polling + earnings APIs.
- `coverage.enabled` — set `true` to start the daily coverage refresh
  loop. Default `false` preserves pre-Phase-1 behavior for operators
  who haven't yet confirmed coordinator compatibility.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | None | `{"status":"ok","challenge_auth":{...}}` (auth mode + counters) |
| `POST` | `/upload/{merkle}` | Bearer (upload token) | Accept an encrypted object |
| `POST` | `/upload/{merkle}/chunk` | Bearer (upload token) | Streaming chunk of a large upload |
| `POST` | `/upload/{merkle}/finalize` | Bearer (upload token) | Close and verify a streamed upload |
| `GET` | `/upload/{merkle}/status` | Bearer (upload token) | Progress of an in-flight upload |
| `GET` | `/download/{merkle}` | Bearer (download token) | Stream encrypted bytes |
| `POST` | `/client-challenge` | Bearer (challenge or download token) | Customer-initiated possession proof |
| `POST` | `/delete/{merkle}` | Customer Ed25519 signature | Customer-signed erase |
| `POST` | `/control/pause` | Cold-key Ed25519 signature | Activate circuit breaker |
| `GET` | `/control/pause` | None | Current circuit-breaker state |
| `POST` | `/challenge` | Bearer (coordinator audit token) | Respond to a proof-of-storage challenge |
| `POST` | `/replicate` | Coordinator upload token (in body) | Pull-and-push replication from a source provider |

`/challenge` takes a coordinator-signed `audit` token bound to one object
and one provider. During the rollout window the token is verified when
present and unsigned challenges are still answered; set
`server.require_challenge_auth: true` to refuse unsigned ones (HTTP 401).
`/health` reports `challenge_auth.unauthenticated`, which stops growing
once the coordinator signs every challenge it sends. `/replicate` acts
only on a coordinator upload token carried in the request body. Every
endpoint is either authenticated (a coordinator-issued token or a
customer signature) or is `/health` / `GET /control/pause`.

The unauthenticated `DELETE /objects/{merkle}` and `GET /list` endpoints
that earlier releases exposed have been removed. Together they were a
remote-wipe primitive reachable from anywhere on the internet; erase now
requires a customer's Ed25519 signature on `POST /delete/{merkle}`.

## Data layout

```
data/
  provider_identity.key              Ed25519 signing identity, generated first start, mode 0600
  objects/{merkle_hex}               ciphertext bytes (atomic temp-rename write)
  index/{merkle_hex}.json            chunk metadata for challenge responses
  ownership/{merkle_hex}.json        owner pubkeys, write-once mode 0o444
  coverage/{merkle_hex}.json         cached coverage answer + first_seen_uncovered
  pause/current.json                 active circuit-breaker pause (if any)
  pause/last_sequence_number         monotonic counter (replay prevention)
```

Back up the entire `data/` tree if you want durability across
migrations. Ownership files are the non-negotiable state — they are
the provider-side cryptographic binding between an object and the
account that uploaded it.

## Source tree provenance

This repo is the public, releasable form of the provider source. The
development history lives in a private upstream monorepo where the
provider code is co-developed with the coordinator; each release here
mirrors the upstream provider source at a specific commit. The Go
module path (`github.com/obsideo/obsideo-provider`) is preserved as-is,
and a small amount of upstream-only tooling and cross-component test
scaffolding is omitted (none of it affects the built binary).

The authoritative source for any release is the tagged commit in this
repo. Release notes name the tag (e.g. `provider-v1-5-streaming-signed`)
and the exact commit. Clone, check out the tag, and run `./build.sh`
with the same Go toolchain version, and you will produce a binary
equivalent to the attached release artifact.

Issues + discussion: file on this repo's issue tracker.

## Known limitations

- Docker infrastructure not yet ported (see above).
- Cold-key circuit breaker inactive until G2 ceremony produces a
  cold-key pubkey and a subsequent release bakes it in via ldflags.
- ARM builds not yet produced — linux-amd64 and windows-amd64 only
  in this release.
- The legacy `datafarmer` binary's BadgerDB data is not readable
  by this binary. Operators with existing deployments face a fresh-
  start migration (rebalancer redistributes; no data loss under the
  network's grace period).

## License

See [LICENSE](LICENSE).

## Security

Vulnerability reporting: see [SECURITY.md](SECURITY.md).
Threat model and design properties live in [obsideo-protocol](https://github.com/Regan-Milne/obsideo-protocol/blob/main/ARCHITECTURE.md) §8.

## Transparency

What this binary actually does, what it stores, what it talks to: [TRANSPARENCY.md](TRANSPARENCY.md).
