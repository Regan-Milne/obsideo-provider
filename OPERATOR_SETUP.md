# Operator Setup Guide

Run a storage node on the Obsideo network. The default path is four commands and about five
minutes; everything else on this page is reference for when you want to do a step by hand.

> **Alpha software.** See [Limitations](#limitations) before deploying.

## The five-minute default

You need a Linux host (amd64), a public DNS name for it, and TLS on 443 terminating at a reverse
proxy (Caddy, nginx) that forwards to the node's local port, 3334. No relays or tunnels on the data
path (ngrok, Cloudflare Tunnel, Tailscale Funnel): they throttle bulk transfer and a tunnelled node
underperforms on placement. Full list: [Requirements](#requirements).

```bash
# 1. get the release and verify it
wget https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/obsideo-provider-linux-amd64 \
     https://github.com/Regan-Milne/obsideo-provider/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x obsideo-provider-linux-amd64 && mv obsideo-provider-linux-amd64 obsideo-provider
./obsideo-provider version            # provider-v1-6-init

# 2. key, identity, config, reachability check, register
#    (your proxy must already forward https://storage.example.com -> 127.0.0.1:3334)
./obsideo-provider init --address https://storage.example.com --capacity 10TB --data /srv/obsideo

# 3. after approval: paste the API key into config.yaml under coordinator.provider_api_key, then
./obsideo-provider start --config config.yaml
```

What `init` does, in order, and prints as it goes:

1. Fetches the coordinator's Ed25519 public key from `https://coordinator.obsideo.io/public-key`
   and writes `coordinator_pub.pem`. It refuses anything that is not a raw 32-byte PEM body.
2. Generates this node's signing identity in the data directory (`provider_identity.key`, mode 600).
   The private key never leaves the box; every proof the node produces is attributable to it.
3. Writes `config.yaml`.
4. Serves a temporary `/health` on the configured port and fetches `https://storage.example.com/health`
   through the public address, so a wrong DNS record, a missing certificate or a proxy pointed at the
   wrong port is reported here with a fix, not as a bare 502 from the coordinator.
5. Registers the node and writes the returned **provider id** into `config.yaml`. The heartbeat URL is
   built from that id; a made-up label there means the node never goes live.

Then it prints what happens next:

| When | What |
|---|---|
| now | Your registration is `pending`. Send the provider id to regan@obsideo.io or the Telegram group. Approval is manual today. |
| on approval | Approval issues your provider API key. It is shown once on our side and comes to you out of band, through the channel your security policy prefers. |
| start + ~5 min | The node heartbeats every 30 s. After 10 consecutive heartbeats it is eligible to receive objects. |
| first cycle | Objects arrive as customers store data. Each is challenged on a continuous cycle of roughly four hours; you earn for every proof you pass, settled in USDC to `noble_wallet_address`. |

`init` is safe to re-run with `--force`: the identity is kept, and the coordinator matches a
registration by (identity, address), so you get the same id back. Flags: `--port` (default 3334),
`--coordinator`, `--config`, `--wallet noble1...`, `--skip-probe`, `--no-register`.

### Run it as a service

`/etc/systemd/system/obsideo-provider.service`:

```ini
[Unit]
Description=Obsideo storage provider
After=network.target

[Service]
Type=simple
User=obsideo
WorkingDirectory=/opt/obsideo-provider
ExecStart=/opt/obsideo-provider/obsideo-provider start --config config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now obsideo-provider
curl -s http://localhost:3334/health      # {"status":"ok"}
```

The first-boot log includes `heartbeat: first success` within ~30 s once the API key is in place.

---

## Requirements

| Need | Detail |
|---|---|
| Linux, amd64 | Any modern distribution. The release is one static Go binary, no runtime dependencies. A Windows build exists for testing. |
| Direct HTTPS on 443 | A public DNS name resolving to your host, TLS at the node or at a reverse proxy forwarding to `127.0.0.1:3334`. Routable public IP or port-forward both fine. **No relays or tunnels on the data path.** |
| Capacity | Disk you are willing to fill, declared at registration (`--capacity 10TB`, `8TiB`, or bytes). The node does not enforce the cap itself; monitor the data volume. |
| Outbound HTTPS | Heartbeat every 30 s, coverage refresh daily. No inbound ports other than 443. |
| A wallet, eventually | Payouts go to a Noble (Cosmos) USDC address, `noble1...`. Register without one and add it to the config later. |

Reverse-proxy example (Caddy, automatic TLS):

```
storage.example.com {
	reverse_proxy 127.0.0.1:3334
}
```

---

## Doing it by hand (reference)

Each `init` step as a manual command, for operators who want to see every byte.

**Build from source** (Go 1.22+):

```bash
git clone https://github.com/Regan-Milne/obsideo-provider.git && cd obsideo-provider
./build.sh                    # stamps the release version; a plain `go build` reports an older version
./obsideo-provider version
```

**Coordinator public key.** It is a public key, not a credential; fetch it yourself rather than accepting an attachment:

```bash
curl -sS https://coordinator.obsideo.io/public-key > coordinator_pub.pem
head -1 coordinator_pub.pem                                  # -----BEGIN PUBLIC KEY-----
grep -v -- '-----' coordinator_pub.pem | base64 -d | wc -c   # 32
```

The body is the raw 32-byte Ed25519 key, not an SPKI wrapper, so `openssl pkey -pubin` will not read
it and you should not generate one with openssl (a 44-byte SPKI key is rejected). If you run your own
coordinator, copy its `data/coordinator.pub` instead.

**Config.** `cp config.example.yaml config.yaml` and set `data.path`, `tokens.public_key_path`,
`coordinator.url`. Leave `provider_id` empty until you have registered.

**Register.** The node must be running and reachable at the address first; the coordinator fetches
`{address}/health` before accepting:

```bash
curl -s -X POST https://coordinator.obsideo.io/internal/providers/register \
  -H "Content-Type: application/json" \
  -d '{"address":"https://storage.example.com","connectivity":"direct","public_key":"<your signing key hex, or unused-v1>","capacity_bytes":10000000000000}'
# → {"id":"<uuid>","status":"pending",...}
```

Put the returned `id` in `config.yaml` as `provider_id`. Re-registering with the same `public_key`
and `address` returns the same record.

**Approve.** A coordinator operator runs `POST /internal/providers/<id>/approve`; that mints your
provider API key, shown exactly once, and sends it to you out of band. Put it under
`coordinator.provider_api_key` and (re)start the node.

**Status.** There is no operator-facing status endpoint yet; ask us, or watch the node log for
`heartbeat: first success`. Our side sees `status`, `last_heartbeat` and the consecutive-heartbeat count.

---

## Verifying a live node

Once approved and heartbeating, the coordinator will place objects on your node as customers store
data. You can confirm the challenge path yourself once you hold an object:

```bash
curl -s -X POST http://localhost:3334/challenge -H "Content-Type: application/json" \
  -d '{"challenge_id":"manual-1","merkle":"<merkle-hex from data/index>","chunk_index":0,"nonce":"aabbccddeeff","expires_at":9999999999}'
# → {"challenge_id":"manual-1","chunk_hash":"<64 hex>","total_chunk_count":N}
```

---

## Production checklist

- [ ] Address is `https://` and the certificate is valid from the public internet
- [ ] Data directory on a persistent volume, disk monitoring in place (the node does not enforce capacity)
- [ ] Running as a non-root user under systemd with `Restart=on-failure`
- [ ] `/challenge` and `/replicate` (the only unauthenticated coordinator-facing endpoints) restricted to the coordinator's source address; everything else stays reachable
- [ ] `coordinator_pub.pem` decodes to 32 bytes
- [ ] `noble_wallet_address` set before you expect a payout

Every other endpoint is authenticated or public and must stay reachable: `/upload/{merkle}` (and the
chunked `/upload/{merkle}/chunk|finalize|status`), `/download/{merkle}`, `/client-challenge`,
`POST /delete/{merkle}` (customer-signed), and `/health`. The old unauthenticated `DELETE /objects/{merkle}`
and `GET /list` endpoints no longer exist.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `init failed: fetch coordinator public key` | No outbound HTTPS to `coordinator.obsideo.io`, or a proxy rewrote the response. `curl -sS https://coordinator.obsideo.io/public-key` should print a PEM block. |
| `init failed: cannot listen on :3334` | Something already holds the port, usually a running provider. Stop it, or pass `--skip-probe` and register while it runs. |
| `init failed: this node is not reachable at https://...` | DNS does not point at this host, TLS is not terminating on 443, or the proxy forwards to the wrong port. The message names which. |
| `coordinator answered HTTP 502` | The coordinator's own probe of `{address}/health` failed from the internet. Same fixes as above; if `init`'s own check passed, look at a firewall that allows your IP but not others. |
| `load coordinator public key: unexpected public key size 44` | An openssl-generated SPKI key. Re-fetch from `/public-key`. |
| Node runs, never becomes eligible | `provider_id` in `config.yaml` is not the coordinator's id (the log shows heartbeat 404s), or `provider_api_key` is empty. Re-run `init --force` or paste the id. |
| Upload tokens rejected (401) | `coordinator_pub.pem` is from a different coordinator or is stale. Re-fetch and restart. |
| Challenges failing | Each failed challenge means no credit for that object that cycle; earnings resume when they pass. Check the coordinator-facing firewall rule and that `data/` was not moved or wiped. If the data directory was lost, the network re-replicates elsewhere. |
| `data/objects/` has files with no matching `data/index/` entry | Interrupted write. Orphaned object files cannot be challenged; safe to delete if disk is tight. |

---

## Limitations

This is **alpha software** on a pre-production network.

| Area | Current state |
|---|---|
| **Manual approval** | Every new node waits for a coordinator operator to approve it and to deliver the API key out of band. |
| **No operator status endpoint** | You cannot query your own registration state; ask us or read your node log. |
| **Auth on internal endpoints** | `/challenge` and `/replicate` are unauthenticated; firewall them to the coordinator. Erase is the customer-signed `POST /delete/{merkle}`. |
| **No TLS built in** | The node serves plain HTTP; terminate TLS in a reverse proxy. |
| **Single node per data directory** | No clustering or shared storage between instances. |
| **No capacity enforcement** | The node does not reject uploads past `capacity_bytes`; the coordinator tracks `used_bytes` but does not enforce it. |
| **Fixed challenge cadence** | Roughly every 4 hours, no per-provider tuning. |
| **No address update** | If your public address changes, re-run `init --force` (same identity, new address registers a new record). |
| **Replication unverified at scale** | The replicate flow is unit-tested, not stress-tested with large files or slow links. |

These are known and tracked. Suitable for single-operator pilots; not for production storage of user data.
