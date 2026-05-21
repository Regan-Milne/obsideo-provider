# Obsideo Provider

Reference implementation of an Obsideo storage provider. Single Go binary,
flat-file storage, end-to-end encrypted (providers only ever hold
ciphertext).

For network-level architecture — design principles, encryption model,
challenge protocol, payment model, threat model — see
[obsideo-protocol](https://github.com/Regan-Milne/obsideo-protocol).
This repository is the operator-facing implementation.

**Alpha.** See [Known limitations](#known-limitations) before deploying.

## Upgrading to provider-v1-1

If you are running any older release of this binary, the upgrade is a
straightforward binary swap. The on-disk data format is unchanged.

1. Stop your provider service.
2. Backup your current binary (e.g. rename to `.pre-v1-1`).
3. Download the new binary from the
   [provider-v1-1 release](https://github.com/Regan-Milne/obsideo-provider/releases/tag/provider-v1-1)
   and put it in place of the old one.
4. Verify version: `./obsideo-provider version` should print `provider-v1-1`.
5. Restart the service. Look for `heartbeat: first success` in the logs
   within ~30 seconds.

The coordinator's `/internal/providers` view populates the `version`
field on your next heartbeat. Your `provider_id`, API key, Noble
payout address, capacity, score, and placement record live on the
coordinator and survive the upgrade. Your local data directory is
untouched.

Full release notes, checksums, and what is bundled:
[provider-v1-1 release notes](https://github.com/Regan-Milne/obsideo-provider/releases/tag/provider-v1-1).

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

```bash
# Download the latest binary + checksums:
# https://github.com/Regan-Milne/obsideo-provider/releases/latest

wget https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/obsideo-provider-linux-amd64
wget https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
mv obsideo-provider-linux-amd64 obsideo-provider
chmod +x obsideo-provider

# Copy config.example.yaml from this repo and edit:
#   provider_id:                    (from the admin who approved you)
#   coordinator.provider_api_key:   (delivered per-operator)
#   data.path:                      (absolute path to your storage dir)

./obsideo-provider start --config config.yaml
```

Expect the first-boot log to include `heartbeat: first success` within
~30 seconds; coordinator's placement filter now sees you as live.

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
go build -trimpath -ldflags "-s -w" -o obsideo-provider .
./obsideo-provider start --config config.yaml
```

Go 1.22+ required. Module path is `github.com/Regan-Milne/obsideo-provider`.

## Docker

Docker infrastructure is **not included in this release.** The legacy
Docker image (the `datafarmer` binary, Tailscale auto-funnel setup,
env-var-driven registration) is incompatible with the new binary's
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

   You manage Tailscale Funnel (or whatever public ingress you use)
   in a sibling container or on the host, and mount a persistent
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
| `GET` | `/health` | None | `{"status":"ok"}` |
| `POST` | `/upload/{merkle}` | Bearer (upload token) | Accept encrypted chunks |
| `GET` | `/download/{merkle}` | Bearer (download token) | Stream encrypted bytes |
| `POST` | `/delete/{merkle}` | User Ed25519 signature | User-signed delete (Phase-1) |
| `POST` | `/control/pause` | Cold-key Ed25519 signature | Activate circuit breaker |
| `GET` | `/control/pause` | None | Current circuit-breaker state |
| `POST` | `/challenge` | None | Respond to proof-of-storage challenge |
| `POST` | `/replicate` | None | Pull-and-push replication from a source provider |
| `DELETE` | `/objects/{merkle}` | None | Legacy GC delete (off by default in Phase-1 coord) |
| `GET` | `/list` | None | Enumerate held merkle roots |

Internal endpoints (challenge, replicate, delete, list) are
unauthenticated by design — the coordinator is the only party that
should reach them. Restrict at your firewall in production.

## Data layout

```
data/
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
provider code is co-developed with the coordinator; each release tag
here corresponds to a mirror of the upstream source at a specific
commit, with the Go module path rewritten from the upstream's
internal path (`github.com/obsideo/obsideo-provider`) to this repo's
public path (`github.com/Regan-Milne/obsideo-provider`).

The authoritative source for any release is the tagged commit in
this repo. Release notes name the tag (e.g. `provider-v1-1`) and the
exact commit. Clone, check out the tag, `go build`, and you will
produce a binary equivalent to the attached release artifact (same
SHA-256).

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
