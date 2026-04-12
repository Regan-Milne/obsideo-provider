#!/bin/bash
set -euo pipefail

# Uninstall the Obsideo provider. Leaves Tailscale alone.
# Preserves data directory by default - pass --purge to wipe everything.

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

log() { echo "[uninstall] $*"; }

if [ "$EUID" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

if systemctl list-unit-files obsideo-provider.service >/dev/null 2>&1; then
    log "stopping service"
    systemctl stop obsideo-provider 2>/dev/null || true
    systemctl disable obsideo-provider 2>/dev/null || true
    rm -f /etc/systemd/system/obsideo-provider.service
    systemctl daemon-reload
fi

log "removing tailscale funnel/serve rules"
tailscale serve reset 2>/dev/null || true

log "removing binary + config"
rm -rf /opt/obsideo-provider/datafarmer
rm -rf /opt/obsideo-provider/coordinator_pub.pem
rm -rf /opt/obsideo-provider/config.yaml

if [ "$PURGE" = "1" ]; then
    log "PURGE: removing data dir and all state"
    rm -rf /opt/obsideo-provider
    rm -rf /etc/obsideo-provider
    if id -u obsideo >/dev/null 2>&1; then
        userdel obsideo 2>/dev/null || true
    fi
else
    log "preserved: /opt/obsideo-provider/data, /etc/obsideo-provider"
    log "pass --purge to remove them"
fi

log "done"
