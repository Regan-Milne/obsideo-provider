# Obsideo Provider

Reference implementation of an Obsideo storage provider. Single Go binary,
flat-file storage, end-to-end encrypted (providers only ever hold
ciphertext).

**Alpha.** See [Known limitations](#known-limitations) before deploying.

## What this is

A storage node for the Obsideo decentralized storage network. You run
this on your hardware; the network pays you per gigabyte-month of paid
customer data you verifiably retain. All data is encrypted on the
customer's machine before it reaches your disk — providers never see
plaintext.

Key properties for the v2-2026-04-23-retention-auth release onward:

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
# Download the pre-built binary + bundle from the latest release:
# https://github.com/Regan-Milne/obsideo-provider/releases

wget https://github.com/Regan-Milne/obsideo-provider/releases/download/v2-2026-04-23-retention-auth/obsideo-provider-linux-amd64-v2-2026-04-23.zip
wget https://github.com/Regan-Milne/obsideo-provider/releases/download/v2-2026-04-23-retention-auth/SHA256SUMS
sha256sum -c SHA256SUMS

unzip obsideo-provider-linux-amd64-v2-2026-04-23.zip -d obsideo-provider
cd obsideo-provider

# Edit config.yaml:
#   provider_id:                    (from the admin who approved you)
#   coordinator.provider_api_key:   (delivered per-operator)
#   data.path:                      (absolute path to your storage dir)

./obsideo-provider start --config config.yaml
```

Expect the first-boot log to include `heartbeat: first success` within
~30 seconds; coordinator's placement filter now sees you as live.

## Install — Windows

```powershell
# Download the Windows bundle from releases.
# Unzip; edit config.yaml; run:
.\obsideo-provider.exe start --config config.yaml
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

## Relationship to the main obsideo-drive repo

This repo is a source mirror of
[`obsideo-drive/provider-clean/`](https://github.com/Regan-Milne/obsideo-drive/tree/master/provider-clean).
Coordinator-coupled changes (e.g., upload-token claim shape, coverage
endpoint contract) are developed in the main repo; the provider side
is mirrored here per release. Source-of-truth for any ambiguity is
the main repo's commit referenced in release notes.

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

Report security findings per [SECURITY.md](SECURITY.md).

## Transparency

Architectural transparency statement: [TRANSPARENCY.md](TRANSPARENCY.md).
