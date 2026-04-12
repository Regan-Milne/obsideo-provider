# Obsideo Provider

A storage provider for the Obsideo decentralized storage network. Run this
on your hardware to store encrypted data for the network and earn AKT
rewards.

## What this is

Obsideo Provider is a single Go binary that:

- Receives encrypted file chunks from the network
- Stores them on your disk
- Proves it still has them when audited (proof-of-retrievability)
- Earns AKT rewards proportional to storage contributed and uptime

Providers never see plaintext data. All files are encrypted client-side
before upload. You store ciphertext.

## Why run a provider

- **Earn AKT** for contributing storage capacity
- **No minimum hardware** beyond disk space and a network connection
- **Runs anywhere**: Docker, bare metal, LXC, cloud (Akash)
- **Lightweight**: ~16 MB binary, ~42 MB RAM at runtime

## Quick start (Docker)

```bash
git clone https://github.com/obsideo/obsideo-provider.git
cd obsideo-provider
cp .env.example .env
# Edit .env: set TS_AUTHKEY (get one at https://login.tailscale.com/admin/settings/keys)
docker compose up -d
docker compose logs -f provider
```

Full instructions: [QUICKSTART.md](QUICKSTART.md)

## How it connects to the network

```
Users/Apps
    |
    | HTTPS (encrypted uploads)
    v
Coordinator (coordinator.obsideo.io)
    |
    | HTTPS (signed tokens)
    v
Your Provider (this software)
    |
    | Tailscale Funnel (free HTTPS endpoint)
    v
Public internet
```

The provider connects to one coordinator (`https://coordinator.obsideo.io`).
It does not phone home, collect telemetry, or contact any other service.
See [TRANSPARENCY.md](TRANSPARENCY.md) for a complete list of every network
call the binary makes.

## Where data is stored

All provider data lives in one directory (Docker volume `provider-data`,
or `/opt/obsideo-provider/data` for native installs):

| Path | What it is |
|------|-----------|
| `objects/` | Encrypted file chunks (the actual stored data) |
| `fs/` | Metadata database (BadgerDB, used for merkle proofs) |
| `.identity_ed25519` | Your provider's cryptographic identity (generated once) |
| `.obsideo-state.json` | Your provider ID (persists across restarts) |

Back up this directory to protect stored data. If lost, the coordinator
replicates affected objects to other providers.

## Inspect before you trust

This repo is designed for transparency. Before running anything, you can
review:

| Document | What it covers |
|----------|---------------|
| [TRANSPARENCY.md](TRANSPARENCY.md) | Every source file, every network call, every dependency, every disk write. The complete "what am I running" answer. |
| [SECURITY.md](SECURITY.md) | Encryption model, proof-of-retrievability, token authentication, trust boundaries. |
| [Dockerfile](Dockerfile) | Multi-stage build. No obfuscation, no binary downloads. |
| [entrypoint.sh](entrypoint.sh) | Every startup step, commented. |
| [.env.example](.env.example) | Every configuration variable with explanation. |

You can also build the binary yourself and compare:

```bash
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o datafarmer .
sha256sum datafarmer
```

## Deployment options

| Method | Audience | Guide |
|--------|----------|-------|
| **Docker** (recommended) | Most operators | [QUICKSTART.md](QUICKSTART.md) |
| Native Linux | Ubuntu/Debian sysadmins | [deploy/native-linux/](deploy/native-linux/) |
| Proxmox LXC | Homelab operators with ZFS | [deploy/lxc/](deploy/lxc/) |
| Akash Network | Cloud/decentralized compute | [deploy/akash/](deploy/akash/) |

## Provider lifecycle

1. **Deploy** -- start the provider using any method above
2. **Register** -- the provider auto-registers with the coordinator on first boot
3. **Approval** -- a network admin approves your provider (status: pending -> active)
4. **Receive data** -- encrypted uploads start flowing to your node
5. **Prove storage** -- the coordinator periodically challenges your provider to prove it holds data
6. **Earn rewards** -- AKT accrues based on bytes stored and your proof-of-retrievability score

## Configuration

All configuration is via environment variables (see [.env.example](.env.example)):

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `TS_AUTHKEY` | Yes (Docker) | -- | Tailscale auth key for networking |
| `OBSIDEO_COORDINATOR_URL` | No | `https://coordinator.obsideo.io` | Coordinator endpoint |
| `OBSIDEO_CAPACITY_BYTES` | No | 10 GB | Storage to advertise |
| `OBSIDEO_WALLET_ADDRESS` | No | -- | AKT wallet for earnings |
| `OBSIDEO_PROVIDER_ADDRESS` | No | -- | Set for cloud deploys (skips Tailscale) |

## Status and maturity

Obsideo is in early network operation. The protocol is functional and
tested. Providers are running and passing challenges. The network is small
and growing.

What works today:
- Encrypted uploads and downloads
- Proof-of-retrievability (automated challenge cycles)
- Multi-provider replication (configurable factor, default 3)
- AKT payment accrual and withdrawal
- Docker, native Linux, LXC, and Akash deployment

What is coming:
- Public API documentation portal
- SDK support for additional languages
- Automated provider scoring dashboard

## License

MIT
