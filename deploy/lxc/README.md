# Obsideo Provider -- Native Linux / Proxmox LXC Quickstart

Run an Obsideo storage provider as a plain Linux service inside a Proxmox LXC,
backed by ZFS storage from the host.

## Architecture

```
Proxmox Host
  |
  +-- ZFS pool (e.g. rpool/obsideo-data)
  |     bind-mounted into LXC at /opt/obsideo-provider/data
  |
  +-- LXC (Debian/Ubuntu)
        +-- Tailscale (Funnel provides HTTPS)
        +-- datafarmer binary (systemd service)
        +-- bootstrap.sh (identity, registration, config gen)
```

No Docker. No orchestration. Just a binary, a systemd unit, and Tailscale.

---

## A. Host-side: Expose ZFS Storage to the LXC

### Option 1: Bind mount a ZFS dataset (recommended)

On the Proxmox host, create a dataset for this provider:

```bash
zfs create rpool/obsideo/provider-1
```

Check where ZFS mounted it:

```bash
zfs get mountpoint rpool/obsideo/provider-1
# e.g. /rpool/obsideo/provider-1
```

Then add a bind mount to the LXC config. Edit `/etc/pve/lxc/<CTID>.conf`:

```
mp0: /rpool/obsideo/provider-1,mp=/opt/obsideo-provider/data,backup=0
```

The left side is the host path (ZFS mountpoint). The right side is where it
appears inside the LXC. `backup=0` excludes it from Proxmox backups (the
coordinator can re-replicate data).

### Option 2: Proxmox GUI

Datacenter > Node > LXC > Resources > Add > Mount Point:
- Storage: local-zfs (or wherever your ZFS pool is)
- Mount Point: `/opt/obsideo-provider/data`
- Size: allocate what you want to offer

### Permissions / UID mapping

By default, Proxmox unprivileged LXCs map UIDs with a 100000 offset. The files
on the ZFS dataset will be owned by high UIDs on the host. This is fine -- the
provider only needs read/write access to its own data dir inside the LXC.

If you use a **privileged** LXC, UIDs match 1:1 with the host. Either works.

If using an unprivileged LXC and the mount has wrong permissions, fix ownership
from inside the LXC:

```bash
chown -R obsideo:obsideo /opt/obsideo-provider/data
```

---

## B. LXC Setup

### Create the LXC (if needed)

Any Debian 12+ or Ubuntu 22.04+ template works. Recommended settings:
- 1-2 CPU cores
- 512 MB - 1 GB RAM (provider is lightweight)
- Unprivileged is fine
- Enable nesting (Features > nesting=1) -- needed for Tailscale
- No special device passthrough needed

From Proxmox CLI:

```bash
pct set <CTID> -features nesting=1
```

### LXC caveats

| Concern | Status |
|---------|--------|
| Tailscale inside LXC | Works with `nesting=1`. No `/dev/net/tun` needed for userspace mode. |
| systemd in LXC | Works in Proxmox LXCs by default (they boot with systemd). |
| ZFS bind mounts | Standard Proxmox `mp0:` config line. No special flags. |
| UID mapping | Unprivileged LXCs offset UIDs. Just `chown` inside the LXC. |
| Multiple providers | One LXC per provider. Each gets its own Tailscale identity. |
| IPFS port (4001) | Only used for DHT. Works over Tailscale. No host-side port forwarding needed. |

---

## C. Install (inside the LXC)

### 1. Get the files onto the LXC

Copy the deploy files and the provider binary into the LXC. From the Proxmox host:

```bash
# Build the binary (on a machine with Go 1.22+)
cd /path/to/obsideo-drive/provider
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o datafarmer .

# Copy into LXC
pct push <CTID> datafarmer /tmp/datafarmer
pct push <CTID> deploy/lxc/install.sh /tmp/install.sh
pct push <CTID> deploy/lxc/bootstrap.sh /tmp/bootstrap.sh
pct push <CTID> deploy/lxc/obsideo-provider.service /tmp/obsideo-provider.service
pct push <CTID> deploy/lxc/obsideo-provider.env /tmp/obsideo-provider.env
```

Or just `scp` / `rsync` them in if you have SSH access.

### 2. Run the installer

```bash
pct enter <CTID>
cd /tmp
sudo bash install.sh ./datafarmer
```

This installs:
- Binary to `/opt/obsideo-provider/datafarmer`
- Bootstrap script to `/opt/obsideo-provider/bootstrap.sh`
- Config template to `/etc/obsideo-provider/provider.env`
- systemd unit to `/etc/systemd/system/obsideo-provider.service`
- Creates `obsideo` service user
- Installs `curl`, `jq`, `openssl`, Tailscale

### 3. Configure

Edit the env file:

```bash
sudo nano /etc/obsideo-provider/provider.env
```

Set at minimum:
- `OBSIDEO_COORDINATOR_URL` -- the coordinator endpoint
- `OBSIDEO_DATA_DIR` -- should match your mount point (default: `/opt/obsideo-provider/data`)
- `OBSIDEO_CAPACITY_BYTES` -- how much storage to advertise

### 4. Set up Tailscale

```bash
sudo tailscale up
```

Follow the auth URL. Then ensure Funnel is enabled in your Tailscale ACL policy
(admin console > Access Controls). You need at minimum:

```json
"nodeAttrs": [
  {
    "target": ["autogroup:member"],
    "attr": ["funnel"]
  }
]
```

Verify Tailscale is connected:

```bash
tailscale status
```

### 5. Start the provider

```bash
sudo systemctl start obsideo-provider
```

Watch the logs:

```bash
journalctl -u obsideo-provider -f
```

You should see:
1. Bootstrap fetches coordinator public key
2. Identity keypair generated (first run only)
3. Tailscale Funnel configured
4. Config generated
5. Provider registered (first run only, status will be "pending")
6. Provider starts serving on the configured port

### 6. Request coordinator approval

On first registration, the provider status is "pending". The coordinator admin
needs to approve it. The bootstrap log will show the provider ID and the
approval endpoint.

---

## D. Verification / Live Test Checklist

Run all commands from inside the LXC. Source the env file first so port/paths
are available:

```bash
source /etc/obsideo-provider/provider.env
PORT="${OBSIDEO_PROVIDER_PORT:-3334}"
DATA="${OBSIDEO_DATA_DIR:-/opt/obsideo-provider/data}"
```

### Pre-start checks (run before first `systemctl start`)

```bash
# 1. Binary exists and is executable?
/opt/obsideo-provider/datafarmer --help
# Expected: usage text with "start", "info", "harvest" subcommands

# 2. Env file has a real coordinator URL?
grep -v '^#' /etc/obsideo-provider/provider.env | grep OBSIDEO_COORDINATOR_URL
# Should NOT be "https://your-coordinator.example.com"

# 3. Data dir exists and obsideo user can write?
sudo -u obsideo touch "$DATA/.write-test" && rm "$DATA/.write-test" && echo "PASS"

# 4. Tailscale is authenticated and online?
tailscale status
# Should show "logged in" with an IP address

# 5. Coordinator reachable from this LXC?
curl -sf "${OBSIDEO_COORDINATOR_URL}/health" && echo " PASS" || echo " FAIL"

# 6. systemd unit is installed?
systemctl cat obsideo-provider >/dev/null && echo "PASS"
```

### Post-start checks (run after `systemctl start obsideo-provider`)

```bash
# 7. Service running?
systemctl is-active obsideo-provider
# Expected: "active"

# 8. Bootstrap completed? (check journal for "bootstrap complete")
journalctl -u obsideo-provider --no-pager -n 50 | grep "bootstrap complete"

# 9. Health endpoint responding?
curl -sf "http://localhost:${PORT}/health"
# Expected: {"status":"ok"}

# 10. Tailscale Funnel reachable from public internet?
TS_FQDN=$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')
curl -sf "https://${TS_FQDN}/health"
# Expected: {"status":"ok"}

# 11. Identity key generated?
ls -la "$DATA/.identity_ed25519"
# Should exist, 600 permissions, owned by obsideo

# 12. Provider registered?
cat "$DATA/.obsideo-state.json"
# Expected: {"provider_id": "<uuid>"}

# 13. Config generated correctly?
grep provider_id /opt/obsideo-provider/config.yaml
grep coordinator_url /opt/obsideo-provider/config.yaml
grep "path:" /opt/obsideo-provider/config.yaml
# All should show the expected values
```

### Restart/resilience checks

```bash
# 14. Restart preserves identity?
BEFORE=$(cat "$DATA/.obsideo-state.json")
sudo systemctl restart obsideo-provider
sleep 5
AFTER=$(cat "$DATA/.obsideo-state.json")
[ "$BEFORE" = "$AFTER" ] && echo "PASS: identity preserved" || echo "FAIL: identity changed"

# 15. Health still good after restart?
curl -sf "http://localhost:${PORT}/health" && echo " PASS" || echo " FAIL"

# 16. Simulate crash recovery
sudo systemctl kill -s KILL obsideo-provider
sleep 15  # RestartSec=10 + margin
systemctl is-active obsideo-provider
# Expected: "active" (systemd restarted it)
```

### Upgrade check

```bash
# 17. Binary upgrade without data loss
sudo systemctl stop obsideo-provider
sudo cp /tmp/datafarmer-new /opt/obsideo-provider/datafarmer
sudo systemctl start obsideo-provider
cat "$DATA/.obsideo-state.json"   # provider_id preserved
curl -sf "http://localhost:${PORT}/health"  # healthy
```

---

## E. Operational Notes

### Restarts

```bash
sudo systemctl restart obsideo-provider
```

The bootstrap script re-runs on every start. It is idempotent:
- Reuses existing identity key
- Reuses persisted provider ID
- Re-fetches coordinator public key (picks up rotations)
- Reconfigures Tailscale Funnel

### Logs

```bash
# Follow live
journalctl -u obsideo-provider -f

# Last 100 lines
journalctl -u obsideo-provider -n 100

# Since last boot
journalctl -u obsideo-provider -b
```

### Upgrades

```bash
# Build new binary, copy into LXC, then:
sudo systemctl stop obsideo-provider
sudo cp /tmp/datafarmer /opt/obsideo-provider/datafarmer
sudo systemctl start obsideo-provider
```

Data, identity, and registration survive upgrades. Only the binary changes.

### Running multiple providers on one host

Each provider runs in its own LXC. Each LXC gets:
- Its own Tailscale identity (separate `tailscale up` auth)
- Its own ZFS dataset / bind mount
- Its own provider ID and identity keypair

On the Proxmox host:

```
LXC 100: provider-1 --> mp0: /rpool/obsideo/provider-1
LXC 101: provider-2 --> mp0: /rpool/obsideo/provider-2
LXC 102: provider-3 --> mp0: /rpool/obsideo/provider-3
```

No port conflicts because each LXC has its own network namespace and Tailscale
handles all external connectivity via Funnel.

### Common failure modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| Bootstrap hangs on "fetching coordinator public key" | Coordinator unreachable | Check URL in env file, check DNS/network from LXC |
| "tailscale serve" fails | Funnel not enabled in ACL | Enable funnel attr in Tailscale admin console |
| Permission denied on data dir | UID mismatch | `chown -R obsideo:obsideo /opt/obsideo-provider/data` |
| Provider starts but registration fails | Coordinator rejects payload | Check logs, verify coordinator is accepting registrations |
| Provider registered but not serving traffic | Status is "pending" | Ask coordinator admin to approve |
| IPFS port 4001 conflict | Multiple providers on same LXC (don't do this) | One provider per LXC |

---

## F. Future: Agent/Installer Wrapper

This same native flow can be wrapped into a single-command installer for even
faster onboarding:

```bash
curl -fsSL https://install.obsideo.io/provider | sudo bash -s -- \
  --coordinator https://coordinator.example.com \
  --capacity 100GB \
  --wallet akash1...
```

The installer would:
1. Detect the platform (bare metal, LXC, VM)
2. Install dependencies + Tailscale
3. Download the latest provider binary
4. Run the same install.sh and bootstrap.sh flow
5. Prompt for Tailscale auth
6. Start the service

The systemd + env file + bootstrap pattern is the foundation for all deployment
targets, whether manual, scripted, or agent-driven.
