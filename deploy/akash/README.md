# Akash Deployment (Advanced)

Deploy an Obsideo provider on the Akash decentralized cloud.

This path is for operators who want a cloud-hosted provider without
managing their own hardware. Akash provides the compute, persistent
storage, and a public HTTPS endpoint -- no Tailscale needed.

## How it works

The Akash SDL builds the provider from source inside the container,
caches the binary to persistent storage, and runs it with direct
public addressing (no Tailscale sidecar).

## Setup

1. Copy the example SDL:
   ```bash
   cp deploy.yaml.example deploy.yaml
   ```

2. Edit `deploy.yaml`:
   - Set `GITHUB_TOKEN` to a PAT with read access to the provider repo
   - Set `OBSIDEO_PROVIDER_ADDRESS` to the Akash ingress URL (set after first deploy)

3. Deploy via Akash CLI or Console

4. After first deploy, check the lease status to get the ingress URL,
   then update `OBSIDEO_PROVIDER_ADDRESS` with `https://<ingress-url>`
   and redeploy.

## Resources required

- 1 CPU, 2 Gi RAM (for initial Go build; runtime uses ~42 MB)
- 5 Gi persistent storage (for objects + binary cache)
- Binary is cached after first build; subsequent restarts skip compilation

## Notes

- Use `https://` in `OBSIDEO_PROVIDER_ADDRESS` (coordinator requires HTTPS)
- The `connectivity` field is set to `direct` (not `tunneled`) for Akash
- First build takes 3-5 minutes; subsequent restarts take seconds
