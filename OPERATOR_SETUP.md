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
- **A reachable address** — the coordinator must be able to make outbound HTTP(S) requests to your provider at registration time and on every challenge cycle (every 8 hours)
  - For local/dev: `http://127.0.0.1:3334` works
  - For production: a public HTTPS URL (e.g. `https://storage.example.com`)
  - For NAT-restricted setups: a tunnel URL (ngrok, Cloudflare Tunnel, etc.) pointing to your local port
- **The coordinator's public key** — a PEM file you copy from the coordinator operator

---

## Build

```bash
git clone <repo-url>
cd provider-clean
go build -o provider-clean .
```

This produces a single self-contained binary. No additional dependencies are installed.

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

The provider verifies every upload and download token against the coordinator's Ed25519 public key. The coordinator operator must give you this file.

If you are running the coordinator yourself:

```bash
# After the coordinator starts for the first time it writes its public key to disk.
# Copy it to the provider working directory:
cp /path/to/coordinator/data/coordinator.pub ./coordinator_pub.pem
```

The file must be a PEM block with type `PUBLIC KEY` containing the raw 32-byte Ed25519 key. If the file is missing or malformed the provider will refuse to start.

---

## Starting the provider

```bash
./provider-clean start --config config.yaml
```

Expected output:

```
provider-clean listening on 0.0.0.0:3334
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
ExecStart=/opt/obsideo-provider/provider-clean start --config config.yaml
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
# Replace <coordinator-url> with the coordinator's address.
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
- Include your provider in challenge cycles (every 8 hours)
- Replicate to your provider when another provider fails a challenge

### Checking your status

```bash
curl -s <coordinator-url>/internal/providers/<your-id>
```

Key fields:

| Field | Meaning |
|-------|---------|
| `status` | `pending` / `active` / `suspended` |
| `score` | Float `[0.0, 1.0]`. Starts at 1.0. Below 0.7 = excluded from new uploads. |
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
[gc          ] provider <your-id> — merkle root gone from /list
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
- [ ] Provider port (3334) is reachable from the coordinator IP; not exposed to the public internet (internal endpoints are unauthenticated)
- [ ] `coordinator_pub.pem` matches the live coordinator's public key
- [ ] Service restarts automatically on crash (systemd `Restart=on-failure` or equivalent)
- [ ] Disk space monitoring in place — provider does not enforce capacity limits internally

### Firewall note

The internal endpoints (`/challenge`, `/replicate`, `DELETE /objects/{merkle}`, `/list`) are unauthenticated by design — they are intended to be reachable only from the coordinator's IP. In production, firewall these to the coordinator's source address.

The public endpoints (`/upload/{merkle}`, `/download/{merkle}`, `/health`) must be reachable from the coordinator and from clients.

---

## Troubleshooting

### Provider fails to start: "load coordinator public key"

The file at `tokens.public_key_path` is missing or malformed.

- Confirm the file exists: `ls coordinator_pub.pem`
- Confirm it contains a PEM block: `head -1 coordinator_pub.pem` should print `-----BEGIN PUBLIC KEY-----`
- Confirm the key body is exactly 32 bytes: `openssl pkey -pubin -in coordinator_pub.pem -text -noout 2>/dev/null | grep "bit"` should show `256 bit` (Ed25519)

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

- Confirm `coordinator_pub.pem` was copied from the coordinator that issued the tokens (not a different coordinator instance)
- If the coordinator was restarted with a new key, copy the new `coordinator.pub` and restart the provider

### Challenge returns 400

The challenge request body could not be parsed. Common causes:

- `expires_at` type mismatch — the coordinator sends it as a Unix timestamp (int64). If you see `cannot unmarshal number into Go struct field ... of type string`, you have an older version of provider-clean. Pull the latest.
- Malformed JSON in the request body — check coordinator logs for what it sent

### Challenge returns 404

The provider does not have the object. Possible causes:

- The file was never uploaded to this provider (check the coordinator object record — does it list this provider?)
- The data directory was wiped or the object was deleted before GC issued the delete instruction
- Wrong `merkle` value in the challenge request

### Score is dropping

The coordinator is issuing challenges that your provider is failing.

1. Check coordinator logs for `challenge error` entries — they include the merkle root and error message
2. Manually test the challenge endpoint (see above) to confirm the provider responds correctly
3. If the data directory was reset or moved, the provider has lost its stored objects — re-upload or wait for the coordinator to replicate

Score recovers at +0.01 per passing challenge. With the default 8-hour cycle, recovery from 0.6 to 1.0 takes approximately 33 cycles (11 days). There is no manual score reset in v1 — contact the coordinator operator.

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
| **Auth on internal endpoints** | `/challenge`, `/replicate`, `/list`, `DELETE /objects/{merkle}` are unauthenticated. Rely on firewall to restrict to coordinator IP. |
| **No TLS built in** | The provider serves plain HTTP. Use a reverse proxy (nginx, caddy) for HTTPS in production. |
| **Single-node only** | No clustering, no shared storage between provider instances. One process per data directory. |
| **No capacity enforcement** | The provider does not reject uploads when `capacity_bytes` is exceeded. The coordinator tracks used_bytes but does not enforce server-side. |
| **Challenge window is fixed** | Coordinator challenges every 8 hours. No per-provider tuning. |
| **Score recovery is slow** | +0.01 per passing challenge. Recovery from 0.0 to above the 0.7 floor takes 70 cycles (23+ days). |
| **Manual approval required** | All new providers require a coordinator operator to call `/internal/providers/{id}/approve`. |
| **No address update** | If your provider's public address changes, you must re-register. |
| **Chunk size discrepancy** | The platform spec defines 1 MiB chunks. The current coordinator and upload tool use 10,240 bytes in dev mode. The provider records whichever chunk size the client used, so challenges always work — but the discrepancy should be resolved before mainnet. |
| **Replication unverified at scale** | The replicate flow has been unit-tested but not stress-tested with large files or slow networks. |

These are known and tracked. This release is suitable for local testing and single-operator pilots. It is not suitable for production storage of user data.
