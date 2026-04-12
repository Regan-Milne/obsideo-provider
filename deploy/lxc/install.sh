#!/bin/bash
set -euo pipefail

# ── Obsideo Provider Installer (Native Linux / LXC) ───────────────────────────
# Run as root inside the LXC (or any Debian/Ubuntu box).
# Usage: sudo bash install.sh [path-to-datafarmer-binary]

INSTALL_DIR="/opt/obsideo-provider"
CONFIG_DIR="/etc/obsideo-provider"
SERVICE_NAME="obsideo-provider"
USER_NAME="obsideo"
BINARY_SOURCE="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo "[install] $*"; }
fail() { echo "[install] ERROR: $*" >&2; exit 1; }

if [ "$EUID" -ne 0 ]; then
    fail "run as root (sudo bash install.sh)"
fi

# ── 1. Dependencies ──────────────────────────────────────────────────────────

log "installing dependencies..."
apt-get update -qq
apt-get install -y -qq curl jq openssl > /dev/null

# ── 2. Tailscale ─────────────────────────────────────────────────────────────

if ! command -v tailscale &>/dev/null; then
    log "installing tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
    log "run 'sudo tailscale up' after install to authenticate"
else
    log "tailscale already installed"
fi

# ── 3. Service user ──────────────────────────────────────────────────────────

if ! id -u "$USER_NAME" &>/dev/null; then
    log "creating service user '$USER_NAME'..."
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" "$USER_NAME"
fi

# ── 4. Directories ───────────────────────────────────────────────────────────

log "setting up directories..."
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$INSTALL_DIR"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$INSTALL_DIR/data"
install -d -o root -g root -m 0755 "$CONFIG_DIR"

# ── 5. Binary ────────────────────────────────────────────────────────────────

if [ -n "$BINARY_SOURCE" ] && [ -f "$BINARY_SOURCE" ]; then
    log "installing binary from $BINARY_SOURCE..."
    install -o root -g root -m 0755 "$BINARY_SOURCE" "$INSTALL_DIR/datafarmer"
elif [ -f "$SCRIPT_DIR/datafarmer" ]; then
    log "installing binary from $SCRIPT_DIR/datafarmer..."
    install -o root -g root -m 0755 "$SCRIPT_DIR/datafarmer" "$INSTALL_DIR/datafarmer"
elif [ -f "$INSTALL_DIR/datafarmer" ]; then
    log "binary already at $INSTALL_DIR/datafarmer, keeping"
else
    log "WARNING: no binary found. Build with:"
    log "  CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o datafarmer ."
    log "Then re-run: sudo bash install.sh ./datafarmer"
fi

# ── 6. Bootstrap script ─────────────────────────────────────────────────────

if [ ! -f "$SCRIPT_DIR/bootstrap.sh" ]; then
    fail "bootstrap.sh not found in $SCRIPT_DIR"
fi
log "installing bootstrap script..."
install -o root -g root -m 0755 "$SCRIPT_DIR/bootstrap.sh" "$INSTALL_DIR/bootstrap.sh"

# ── 7. Config ────────────────────────────────────────────────────────────────

if [ ! -f "$SCRIPT_DIR/obsideo-provider.env" ]; then
    fail "obsideo-provider.env not found in $SCRIPT_DIR"
fi
if [ ! -f "$CONFIG_DIR/provider.env" ]; then
    log "installing default env file..."
    install -o root -g root -m 0644 "$SCRIPT_DIR/obsideo-provider.env" "$CONFIG_DIR/provider.env"
    log "EDIT $CONFIG_DIR/provider.env before starting the service"
else
    log "env file exists, not overwriting"
fi

# ── 8. Systemd ───────────────────────────────────────────────────────────────

if [ ! -f "$SCRIPT_DIR/obsideo-provider.service" ]; then
    fail "obsideo-provider.service not found in $SCRIPT_DIR"
fi
log "installing systemd service..."
install -o root -g root -m 0644 "$SCRIPT_DIR/obsideo-provider.service" /etc/systemd/system/obsideo-provider.service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# ── 9. Permissions ───────────────────────────────────────────────────────────

chown -R "$USER_NAME":"$USER_NAME" "$INSTALL_DIR/data"

# ── Done ─────────────────────────────────────────────────────────────────────

log ""
log "============================================"
log "  Obsideo Provider installed"
log "============================================"
log ""
log "Next steps:"
log "  1. Edit $CONFIG_DIR/provider.env"
log "     - Set OBSIDEO_COORDINATOR_URL"
log "     - Set OBSIDEO_DATA_DIR if using a ZFS mount"
log "     - Set OBSIDEO_CAPACITY_BYTES"
log "  2. Authenticate Tailscale:"
log "     sudo tailscale up"
log "  3. Enable Funnel in your Tailscale ACL policy"
log "  4. Start the service:"
log "     sudo systemctl start obsideo-provider"
log "  5. Check logs:"
log "     journalctl -u obsideo-provider -f"
log ""
