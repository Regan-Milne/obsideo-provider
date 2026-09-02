# Operator Setup Guide

This guide covers everything an operator needs to run an Obsideo storage provider:
build, configure, start, register with a coordinator, and verify the full storage lifecycle.

> **Alpha software.** See [Limitations](#limitations) before deploying.

---

## Table of contents

1. [Prerequisites](#prerequisites)
2. [Build](#build)
3. [Configuration](#configuration)
4. [Starting the provider](#starting-the-provider)
5. [Health check](#health-check)
6. [Registering with a coordinator](#registering-with-a-coordinator)
7. [Verifying the full lifecycle](#verifying-the-full-lifecycle)
8. [Production checklist](#production-checklist)
9. [Troubleshooting](#troubleshooting)
10. [Limitations](#limitations)

---

## Prerequisites

- **Go 1.22 or later** — only required to build; the binary has no runtime dependencies
- **A reachable address** — the coordinator must be able to make outbound HTTP(S) requests to your provider at registration time and on every challenge cycle (every 4 hours)
  - For local/dev: `http://127.0.0.1:3334` works
  - For production: a direct, publicly reachable HTTPS endpoint on port 443 (e.g. `https://storage.example.com`), with TLS terminated at the node or a reverse proxy in front of it. This is a hard requirement for a production node.
  - Relay tunnels (ngrok, Cloudflare Tunnel, Tailscale Funnel) are not supported for the data path. They throttle bulk transfer, so a tunneled node underperforms on placement and earnings. Use a routable public IP or a port-forward to 443, not a relay.
- **The coordinator's public key** — fetched from the coordinator's `/public-key` endpoint (see [Coordinator public key](#coordinator-public-key)). It is public, not a credential.

---

## Build

Most operators should take the released binary rather than building:

```bash
wget https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/obsideo-provider-linux-amd64
wget https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
mv obsideo-provider-linux-amd64 obsideo-provider && chmod +x obsideo-provider
./obsideo-provider version    # should print provider-v1-5-streaming-signed
```

To build from source instead:

```bash
git clone https://github.com/Regan-Milne/obsideo-provider.git
cd obsideo-provider
./build.sh                    # stamps the release version into the binary
./obsideo-provider version    # should print provider-v1-5-streaming-signed
```

`build.sh` sets the version ldflag. A plain `go build` also works but
leaves the version string at its source default, so the node reports an
older version to the coordinator. Go 1.22+ required; the result is a
single self-contained binary with no runtime dependencies.

---

## Configuration

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:

```yaml
provider_id: "my-provider-1"   # Human-readable label. Not used for auth — pick anything.

server:
  host: "0.0.0.0"              # Listen on all interfaces. Use "127.0.0.1" for local-only.
  port: 3334

data:
  path: "./data"               # Where objects are stored. Use an absolute path in production.

tokens:
  public_key_path: "coordinator_pub.pem"  # See "Coordinator public key" below.
```

### Coordinator public key

The provider verifies every upload and download token against the coordinator's Ed25519 public key. It is a public key, not a credential, so fetch it from the coordinator directly rather than accepting it as an attachment:

```bash
# Obsideo network coordinator:
curl -sS https://coordinator.obsideo.io/public-key > coordinator_pub.pem

# Verify: PEM header, and a body that decodes to exactly 32 bytes
head -1 coordinator_pub.pem                                  # -----BEGIN PUBLIC KEY-----
grep -v -- '-----' coordinator_pub.pem | base64 -d | wc -c   # 32
```

The file must be a PEM block with type `PUBLIC KEY` whose body is the raw 32-byte Ed25519 key. It is not an SPKI wrapper, so `openssl pkey -pubin` will not read it, and you should not generate one with openssl (the provider rejects a 44-byte SPKI key). If the file is missing or malformed the provider will refuse to start.

If you are running your own coordinator instead, it writes its public key to disk on first start; copy its `data/coordinator.pub` to `./coordinator_pub.pem`.

---

## Starting the provider

```bash
./obsideo-provider start --config config.yaml
```

Expected output:

```
obsideo-provider listening on 0.0.0.0:3334
```

The provider creates `data/objects/` and `data/index/` on first run. Both directories are created automatically; you do not need to create them.

To run as a background service, use your OS service manager (systemd, launchd, etc.) or a process supervisor like `supervisord`.

**systemd example** (`/etc/systemd/system/obsideo-provider.service`):

```ini
[Unit]
Description=Obsideo storage provider
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/obsideo-provider
ExecStart=/opt/obsideo-provider/obsideo-provider start --config config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable obsideo-provider
systemctl start obsideo-provider
```

---

## Health check

```bash
curl http://localhost:3334/health
# → {"status":"ok"}
```

This endpoint always returns 200 when the provider is running. The coordinator polls it at registration time to confirm reachability.

---

## Registering with a coordinator

Registration is a two-step process: register (triggers a liveness check), then wait for operator approval.

### Step 1 — Register

```bash
# Replace <coordinator-url> with the coordinator's address (Obsideo network: https://coordinator.obsideo.io).
# Replace <your-provider-url> with the publicly reachable address of YOUR provider.
# Replace <capacity> with your storage capacity in bytes (e.g. 107374182400 = 100 GiB).

REG=$(curl -s -X POST <coordinator-url>/internal/providers/register \
  -H "Content-Type: application/json" \
  -d '{
    "address":        "<your-provider-url>",
    "connectivity":   "direct",
    "public_key":     "unused-v1",
    "capacity_bytes": 107374182400
  }')

echo "$REG"
# → {"id":"<uuid>","status":"pending",...}
```

The coordinator performs a liveness check (`GET {address}/health`) before accepting the registration. Your provider must be running and reachable at the address you specify.

On success you receive a registration object with `"status":"pending"`. Save the `id`.

### Step 2 — Approval

A coordinator operator must approve your registration before your provider receives uploads:

```bash
# Coordinator operator runs:
curl -s -X POST <coordinator-url>/internal/providers/<your-id>/approve
# → {"id":"...","status":"active",...}
```

Once `status` is `active`, the coordinator will:
- Route new uploads to your provider
- Include your provider in challenge cycles (every 4 hours)
- Replicate to your provider when another provider fails a challenge

### Checking your status

```bash
curl -s <coordinator-url>/internal/providers/<your-id>
```

Key fields:

| Field | Meaning |
|-------|---------|
| `status` | `pending` / `active` / `suspended` |
| `score` | Vestigial field, retained in the schema but not actively updated by the current challenger. Check `last_heartbeat` and recent challenge pass history instead. |
| `used_bytes` | Storage in use as tracked by the coordinator. |
| `last_heartbeat` | Last time the coordinator confirmed your provider was alive. |

---

## Verifying the full lifecycle

The quickest way to confirm your provider is working end-to-end is to run an upload + lifecycle check using the coordinator's dev upload tool.

**Prerequisites:** you need an account API key (from the coordinator operator) and the upload tool binary from the coordinator repo.

```bash
# Build the upload tool (from coordinator repo):
cd provider-tools/upload
go build -o upload .

# Run the full lifecycle check:
./upload \
  --file     /path/to/any/file \
  --bucket   test-bucket \
  --key      test-file.txt \
  --api-key  <your-api-key> \
  --coordinator <coordinator-url> \
  --lifecycle-check
```

A passing run looks like:

```
[upload      ] [1/1] → <your-provider-id> (<your-provider-url>)
[confirm     ] OK
[download    ] PASS — N bytes match exactly
[delete      ] coordinator mapping removed (204)
[gc          ] provider <your-id> — merkle root no longer held by the provider
[lifecycle   ] PASS — upload, download, delete, and GC all verified
```

If this passes, your provider is correctly storing, serving, responding to GC, and physically deleting files.

### Manual challenge test

After uploading a file, you can test the challenge endpoint directly:

```bash
# Get the merkle root from the upload output (the long hex string after "root=")
MERKLE=<merkle-hex>

curl -s -X POST http://localhost:3334/challenge \
  -H "Content-Type: application/json" \
  -d "{
    \"challenge_id\": \"manual-test-1\",
    \"merkle\":       \"${MERKLE}\",
    \"chunk_index\":  0,
    \"nonce\":        \"aabbccddeeff\",
    \"expires_at\":   9999999999
  }"
```

Expected response:

```json
{
  "challenge_id":      "manual-test-1",
  "chunk_hash":        "<64-char hex>",
  "total_chunk_count": 1
}
```

---

## Production checklist

Before accepting real traffic:

- [ ] Provider address is an HTTPS URL (not plain HTTP)
- [ ] TLS terminates at or before the provider process (reverse proxy, load balancer, or direct TLS)
- [ ] Data directory is on a persistent, backed-up volume
- [ ] Provider is running as a non-root user
- [ ] `/challenge` and `/replicate` (the only unauthenticated endpoints) are restricted to the coordinator's source address; the authenticated public endpoints stay reachable
- [ ] `coordinator_pub.pem` matches the live coordinator's public key
- [ ] Service restarts automatically on crash (systemd `Restart=on-failure` or equivalent)
- [ ] Disk space monitoring in place — provider does not enforce capacity limits internally

### Firewall note

Only `/challenge` and `/replicate` are unauthenticated coordinator-facing endpoints. In production, firewall them to the coordinator's source address.

Every other endpoint is authenticated or public and must stay reachable: `/upload/{merkle}` (and the chunked `/upload/{merkle}/chunk|finalize|status`), `/download/{merkle}`, `/client-challenge`, `POST /delete/{merkle}`, and `/health`. Uploads and downloads carry coordinator-issued tokens, delete carries the customer's Ed25519 signature, and `/client-challenge` carries a token bound to the object, so these do not rely on the firewall for their security.

The earlier unauthenticated `DELETE /objects/{merkle}` and `GET /list` endpoints have been removed. They no longer exist to firewall.

---

## Troubleshooting

### Provider fails to start: "load coordinator public key"

The file at `tokens.public_key_path` is missing or malformed.

- Confirm the file exists: `ls coordinator_pub.pem`
- Confirm it contains a PEM block: `head -1 coordinator_pub.pem` should print `-----BEGIN PUBLIC KEY-----`
- Confirm the key body is exactly 32 bytes (the PEM body is the raw Ed25519 key, not an SPKI wrapper, so `openssl pkey -pubin` will NOT read it): `grep -v -- '-----' coordinator_pub.pem | base64 -d | wc -c` should print `32`

If the coordinator writes the file automatically, make sure it has started at least once before copying.

### Registration returns `connection refused` or `timeout`

The coordinator cannot reach your provider at the address you specified.

- Confirm the provider is running: `curl http://localhost:3334/health`
- If your provider is local but you specified a public address, confirm port forwarding or your tunnel is active
- If using a tunnel (ngrok, etc.), confirm the tunnel URL matches the address in your registration request
- Check for firewall rules blocking inbound connections on port 3334

### Registration returns `{"error":"liveness check failed"}`

The coordinator attempted `GET {address}/health` and got a non-200 response or a connection error.

- Same steps as above — confirm the address in your registration body is reachable from the coordinator machine, not just from localhost

### Upload tokens are rejected (401)

The upload or download token signature does not verify against `coordinator_pub.pem`.

- Confirm `coordinator_pub.pem` came from the coordinator that issued the tokens (not a different coordinator instance)
- Re-fetch it (`curl -sS https://coordinator.obsideo.io/public-key > coordinator_pub.pem`) and restart the provider. If the coordinator was ever restarted with a new key, this picks it up.

### Challenge returns 400

The challenge request body could not be parsed. Common causes:

- `expires_at` type mismatch — the coordinator sends it as a Unix timestamp (int64). If you see `cannot unmarshal number into Go struct field ... of type string`, you have an older version of obsideo-provider. Pull the latest.
- Malformed JSON in the request body — check coordinator logs for what it sent

### Challenge returns 404

The provider does not have the object. Possible causes:

- The file was never uploaded to this provider (check the coordinator object record — does it list this provider?)
- The data directory was wiped or the object was deleted before GC issued the delete instruction
- Wrong `merkle` value in the challenge request

### Challenges are failing

The coordinator is issuing challenges that your provider isn't passing. Each
failed challenge means no per-cycle credit for that placement.

1. Check coordinator logs for `challenge error` entries — they include the merkle root and error message
2. Manually test the challenge endpoint (see above) to confirm the provider responds correctly
3. If the data directory was reset or moved, the provider has lost its stored objects — the coordinator's reconciliation flow will eventually replicate them elsewhere

Earnings recover automatically once challenges start passing again; there is no separate score that decays and recovers. The current model is "prove it, get paid; don't, don't" per cycle.

### `data/objects/` is growing but `data/index/` has gaps

Object files without corresponding index files cannot be challenged. This should not happen under normal operation. If you see it:

- Likely caused by an interrupted write (crash after object write, before index write)
- Affected objects will fail challenges; the coordinator will eventually replicate them elsewhere
- Safe to delete orphaned object files (without matching `.json` in `data/index/`) if disk space is a concern

---

## Limitations

This is **alpha software** running on a pre-production network.

| Area | Current state |
|------|---------------|
| **Auth on internal endpoints** | `/challenge` and `/replicate` are unauthenticated; firewall them to the coordinator IP. The unauthenticated `/list` and `DELETE /objects/{merkle}` endpoints have been removed; erase is now the customer-signed `POST /delete/{merkle}`. |
| **No TLS built in** | The provider serves plain HTTP. Use a reverse proxy (nginx, caddy) for HTTPS in production. |
| **Single-node only** | No clustering, no shared storage between provider instances. One process per data directory. |
| **No capacity enforcement** | The provider does not reject uploads when `capacity_bytes` is exceeded. The coordinator tracks used_bytes but does not enforce server-side. |
| **Challenge window is fixed** | Coordinator challenges every 4 hours. No per-provider tuning. |
| **Earnings track challenge pass history per cycle** | A failed challenge means no credit for that placement that cycle. There is no separate score field actively driving placement decisions. |
| **Manual approval required** | All new providers require a coordinator operator to call `/internal/providers/{id}/approve`. |
| **No address update** | If your provider's public address changes, you must re-register. |
| **Chunk size discrepancy** | The platform spec defines 1 MiB chunks. The current coordinator and upload tool use 10,240 bytes in dev mode. The provider records whichever chunk size the client used, so challenges always work — but the discrepancy should be resolved before mainnet. |
| **Replication unverified at scale** | The replicate flow has been unit-tested but not stress-tested with large files or slow networks. |

These are known and tracked. This release is suitable for local testing and single-operator pilots. It is not suitable for production storage of user data.
