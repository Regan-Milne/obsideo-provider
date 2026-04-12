# Quick Start -- Docker

Get a storage provider running in under 5 minutes.

## Prerequisites

- Docker Engine 20.10+ and Docker Compose v2
- A free [Tailscale](https://tailscale.com) account
- Tailscale Funnel enabled in your tailnet ACL (see below)

## 1. Enable Tailscale Funnel

Log into [Tailscale admin console](https://login.tailscale.com/admin/acls/file)
and add this to your ACL policy:

```json
"nodeAttrs": [
  {
    "target": ["autogroup:member"],
    "attr": ["funnel"]
  }
]
```

This allows nodes in your tailnet to expose services to the public internet.

## 2. Create a Tailscale auth key

Go to [Settings > Keys](https://login.tailscale.com/admin/settings/keys).
Create a **reusable** auth key. Copy it.

## 3. Configure

```bash
git clone https://github.com/Regan-Milne/obsideo-provider.git
cd obsideo-provider
cp .env.example .env
```

Edit `.env` and set:

```
TS_AUTHKEY=tskey-auth-your-key-here
```

That is the only required change. Optional settings:

```
OBSIDEO_WALLET_ADDRESS=akash1your-wallet-address
OBSIDEO_CAPACITY_BYTES=107374182400    # 100 GB
TS_HOSTNAME=my-provider                # custom hostname
```

## 4. Start

```bash
docker compose up -d
```

## 5. Watch it come online

```bash
docker compose logs -f provider
```

You will see:

```
[datafarmer] OK: tailscale online
[datafarmer] OK: coordinator public key saved
[datafarmer] generating ed25519 identity
[datafarmer] OK: provider healthy on localhost:3334
[datafarmer] OK: registered as <provider-id> (status: pending)
[datafarmer] restarting datafarmer with updated config...
[datafarmer]
[datafarmer] ============================================
[datafarmer]   DATA FARMER ONLINE
[datafarmer]   ID:      <your-provider-id>
[datafarmer]   Address: https://<hostname>.tailnet.ts.net
[datafarmer]   Storage: /app/data
[datafarmer] ============================================
```

## 6. Verify

Check health from another machine:

```bash
curl https://<your-hostname>.<your-tailnet>.ts.net/health
# {"status":"ok"}
```

Or from inside the container:

```bash
docker compose exec provider curl -s http://localhost:3334/health
```

## What happens next

Your provider starts in **pending** status. The network admin will approve
it, after which:

- Encrypted uploads start flowing to your node
- The coordinator periodically audits your storage (proof-of-retrievability)
- AKT rewards accrue based on bytes stored and your audit score
- Use `OBSIDEO_WALLET_ADDRESS` in `.env` to set where rewards are paid

## Useful commands

```bash
# View logs
docker compose logs -f provider
docker compose logs -f tailscale

# Restart
docker compose restart

# Stop
docker compose down

# Stop and wipe everything (identity, data, tailnet state)
docker compose down -v

# Rebuild after source changes
docker compose build --no-cache && docker compose up -d
```

## Upgrading

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

Your provider ID, identity key, and stored data survive upgrades.

## Data location

All persistent data is in the Docker volume `provider-data`. To back it up:

```bash
docker run --rm -v obsideo-provider_provider-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/provider-backup.tar.gz -C /data .
```

## Troubleshooting

**Tailscale won't connect** -- check that `TS_AUTHKEY` is valid and the key
is reusable. Generate a new one at
https://login.tailscale.com/admin/settings/keys.

**Registration fails** -- Funnel is probably not enabled in your tailnet ACL.
See step 1. The provider retries for about 6 minutes to allow DNS propagation.

**Provider stuck in pending** -- normal. The network admin needs to approve
your provider. Share your provider ID (shown in logs).

## Next steps

- [TRANSPARENCY.md](TRANSPARENCY.md) -- inspect exactly what you are running
- [SECURITY.md](SECURITY.md) -- understand the encryption and trust model
- [deploy/native-linux/](deploy/native-linux/) -- run without Docker
- [deploy/lxc/](deploy/lxc/) -- Proxmox/LXC deployment
- [deploy/akash/](deploy/akash/) -- deploy on Akash cloud
