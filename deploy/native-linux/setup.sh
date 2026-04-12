#!/bin/bash
set -euo pipefail

# ── Obsideo Storage Provider - Ubuntu/Debian installer ──────────────────────
# One-shot, idempotent. Installs binary + systemd service, brings the
# provider online, and registers it with the coordinator.
#
# Usage:
#   sudo bash setup.sh
#
# Re-running is safe: existing identity, provider ID, and data are preserved.
# Environment overrides (skip interactive prompts):
#   OBSIDEO_COORDINATOR_URL     coordinator URL (no trailing slash)
#   OBSIDEO_CAPACITY            storage to offer (e.g. 10GB, 1TB)
#   OBSIDEO_WALLET_ADDRESS      AKT wallet bech32 (optional)
#   OBSIDEO_DATA_DIR            where to store objects (default: /opt/obsideo-provider/data)
#   TS_AUTHKEY                  Tailscale auth key for unattended install

DEFAULT_COORDINATOR="https://coordinator.obsideo.io"
INSTALL_DIR="/opt/obsideo-provider"
CONFIG_DIR="/etc/obsideo-provider"
SERVICE_NAME="obsideo-provider"
SERVICE_USER="obsideo"
PORT=3334

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;32m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup]\033[0m WARNING: %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[setup]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }

if [ "$EUID" -ne 0 ]; then
    fail "must run as root (sudo bash setup.sh)"
fi

# ── 1. Dependencies ───────────────────────────────────────────────────────

step "Checking dependencies"
MISSING_PKGS=()
for p in curl jq openssl ca-certificates; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
        MISSING_PKGS+=("$p")
    fi
done
if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    log "installing: ${MISSING_PKGS[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING_PKGS[@]}"
fi
log "deps ok"

# ── 2. Tailscale ──────────────────────────────────────────────────────────

step "Tailscale"
if ! command -v tailscale >/dev/null 2>&1; then
    log "installing tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# Ensure tailscaled is running (on systems without systemd this will no-op)
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files tailscaled.service >/dev/null 2>&1; then
    systemctl enable --now tailscaled >/dev/null 2>&1 || true
fi

# Authenticate if not already
if ! tailscale status --json 2>/dev/null | jq -e '.Self.Online == true' >/dev/null 2>&1; then
    if [ -n "${TS_AUTHKEY:-}" ]; then
        log "authenticating with provided TS_AUTHKEY..."
        tailscale up --authkey="${TS_AUTHKEY}" --ssh=false
    else
        log "Tailscale is not authenticated."
        log ""
        log "Run this in another terminal (or pass TS_AUTHKEY=... to this script):"
        log "    sudo tailscale up"
        log ""
        log "Then re-run: sudo bash setup.sh"
        exit 1
    fi
fi

# Wait for Online
for i in $(seq 1 30); do
    if tailscale status --json 2>/dev/null | jq -e '.Self.Online == true' >/dev/null 2>&1; then
        break
    fi
    sleep 1
    if [ "$i" -eq 30 ]; then
        fail "Tailscale did not come online after 30s"
    fi
done
log "tailscale online"

# ── 3. Service user + directories ─────────────────────────────────────────

step "User and directories"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "creating user '$SERVICE_USER'"
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" "$SERVICE_USER"
fi

DATA_DIR="${OBSIDEO_DATA_DIR:-$INSTALL_DIR/data}"
install -d -o root -g root            -m 0755 "$INSTALL_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$DATA_DIR"
install -d -o root -g root            -m 0755 "$CONFIG_DIR"
log "dirs ok"

# ── 4. Binary ─────────────────────────────────────────────────────────────

step "Installing binary"
if [ ! -f "$SCRIPT_DIR/datafarmer" ]; then
    fail "datafarmer binary not found next to setup.sh (expected: $SCRIPT_DIR/datafarmer)"
fi
install -o root -g root -m 0755 "$SCRIPT_DIR/datafarmer" "$INSTALL_DIR/datafarmer"
log "installed $INSTALL_DIR/datafarmer"

# ── 5. Collect configuration ──────────────────────────────────────────────

step "Configuration"

# Coordinator URL
COORDINATOR="${OBSIDEO_COORDINATOR_URL:-}"
if [ -z "$COORDINATOR" ] && [ -f "$CONFIG_DIR/provider.env" ]; then
    # shellcheck disable=SC1091
    COORDINATOR="$(grep -E '^OBSIDEO_COORDINATOR_URL=' "$CONFIG_DIR/provider.env" | head -1 | cut -d= -f2- | tr -d '"')"
fi
if [ -z "$COORDINATOR" ]; then
    if [ -t 0 ]; then
        read -rp "Coordinator URL [${DEFAULT_COORDINATOR}]: " COORDINATOR
    fi
    COORDINATOR="${COORDINATOR:-$DEFAULT_COORDINATOR}"
fi
COORDINATOR="${COORDINATOR%/}"  # strip trailing slash
log "coordinator: $COORDINATOR"

# Capacity
CAPACITY_INPUT="${OBSIDEO_CAPACITY:-}"
if [ -z "$CAPACITY_INPUT" ] && [ -f "$CONFIG_DIR/provider.env" ]; then
    CAPACITY_BYTES_PREV="$(grep -E '^OBSIDEO_CAPACITY_BYTES=' "$CONFIG_DIR/provider.env" | head -1 | cut -d= -f2- | tr -d '"')"
    if [ -n "$CAPACITY_BYTES_PREV" ]; then
        CAPACITY_INPUT="${CAPACITY_BYTES_PREV}B"
    fi
fi
if [ -z "$CAPACITY_INPUT" ]; then
    if [ -t 0 ]; then
        read -rp "Storage to offer (e.g. 10GB, 500GB, 1TB) [10GB]: " CAPACITY_INPUT
    fi
    CAPACITY_INPUT="${CAPACITY_INPUT:-10GB}"
fi

parse_capacity() {
    local raw
    raw="$(echo "$1" | tr -d ' ' | tr '[:lower:]' '[:upper:]')"
    local num unit
    num="$(echo "$raw" | sed -E 's/[A-Z]+$//')"
    unit="$(echo "$raw" | sed -E 's/^[0-9.]+//')"
    # validate num is numeric
    if ! echo "$num" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
        echo "ERR"; return
    fi
    local multiplier=1
    case "$unit" in
        KB|K)     multiplier=1024 ;;
        MB|M)     multiplier=1048576 ;;
        GB|G|"")  multiplier=1073741824 ;;
        TB|T)     multiplier=1099511627776 ;;
        B)        multiplier=1 ;;
        *)        echo "ERR"; return ;;
    esac
    # use awk for decimal math, then truncate to integer
    awk -v n="$num" -v m="$multiplier" 'BEGIN { printf "%.0f", n * m }'
}

CAPACITY_BYTES="$(parse_capacity "$CAPACITY_INPUT")"
if [ "$CAPACITY_BYTES" = "ERR" ] || [ -z "$CAPACITY_BYTES" ] || [ "$CAPACITY_BYTES" = "0" ]; then
    fail "could not parse capacity '$CAPACITY_INPUT' (try 10GB, 500GB, 1TB)"
fi
log "capacity: ${CAPACITY_INPUT} (${CAPACITY_BYTES} bytes)"

# Wallet (optional)
WALLET="${OBSIDEO_WALLET_ADDRESS:-}"
if [ -z "$WALLET" ] && [ -f "$CONFIG_DIR/provider.env" ]; then
    WALLET="$(grep -E '^OBSIDEO_WALLET_ADDRESS=' "$CONFIG_DIR/provider.env" | head -1 | cut -d= -f2- | tr -d '"')"
fi
if [ -z "$WALLET" ] && [ -t 0 ]; then
    read -rp "AKT wallet address for rewards (Enter to skip): " WALLET
fi
if [ -n "$WALLET" ]; then
    log "wallet: $WALLET"
else
    log "wallet: (not set - can add later in $CONFIG_DIR/provider.env)"
fi

# ── 6. Write env file ─────────────────────────────────────────────────────

step "Writing config"
cat > "$CONFIG_DIR/provider.env" <<ENV
# /etc/obsideo-provider/provider.env
# Managed by setup.sh -- safe to edit, changes persist across re-runs.
OBSIDEO_COORDINATOR_URL="${COORDINATOR}"
OBSIDEO_DATA_DIR="${DATA_DIR}"
OBSIDEO_CAPACITY_BYTES=${CAPACITY_BYTES}
OBSIDEO_WALLET_ADDRESS="${WALLET}"
OBSIDEO_PROVIDER_PORT=${PORT}
ENV
chmod 0644 "$CONFIG_DIR/provider.env"

# State file preserves provider_id across restarts/upgrades
STATE_FILE="${CONFIG_DIR}/state.json"
PROVIDER_ID=""
if [ -f "$STATE_FILE" ]; then
    PROVIDER_ID="$(jq -r '.provider_id // empty' "$STATE_FILE" 2>/dev/null || true)"
    if [ -n "$PROVIDER_ID" ]; then
        log "loaded existing provider_id: $PROVIDER_ID"
    fi
fi

# ── 7. Identity keypair ───────────────────────────────────────────────────

step "Identity"
IDENTITY_KEY="$DATA_DIR/.identity_ed25519"
if [ ! -f "$IDENTITY_KEY" ]; then
    log "generating ed25519 identity"
    openssl genpkey -algorithm ed25519 -out "$IDENTITY_KEY" 2>/dev/null
    chown "$SERVICE_USER":"$SERVICE_USER" "$IDENTITY_KEY"
    chmod 0600 "$IDENTITY_KEY"
else
    log "reusing existing identity"
fi
# Extract 32-byte public key hex
PUBLIC_KEY_HEX="$(openssl pkey -in "$IDENTITY_KEY" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | od -An -tx1 | tr -d ' \n')"
log "pubkey: ${PUBLIC_KEY_HEX:0:16}..."

# ── 8. Coordinator public key ─────────────────────────────────────────────

step "Coordinator public key"
COORDINATOR_PUB="$INSTALL_DIR/coordinator_pub.pem"
if ! curl -fsSL --max-time 30 "${COORDINATOR}/public-key" -o "$COORDINATOR_PUB"; then
    fail "could not fetch ${COORDINATOR}/public-key - check the URL and your network"
fi
chown root:root "$COORDINATOR_PUB"
chmod 0644 "$COORDINATOR_PUB"
log "saved $COORDINATOR_PUB"

# ── 9. Write config.yaml ──────────────────────────────────────────────────

step "config.yaml"
CONFIG_YAML="$INSTALL_DIR/config.yaml"
cat > "$CONFIG_YAML" <<YAML
provider_id: "${PROVIDER_ID}"
coordinator_url: "${COORDINATOR}"
wallet_address: "${WALLET}"

server:
  host: "0.0.0.0"
  port: ${PORT}
  read_timeout: 7200
  write_timeout: 7200

db:
  path: "${DATA_DIR}"

tokens:
  public_key_path: "${COORDINATOR_PUB}"
YAML
chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_YAML"
chmod 0644 "$CONFIG_YAML"
log "wrote $CONFIG_YAML"

# ── 10. Tailscale Funnel ──────────────────────────────────────────────────
#
# IMPORTANT: the correct command is `tailscale funnel --bg <port>` directly.
# Do NOT use `tailscale serve --https=443` + `tailscale funnel 443` - that
# combination creates a proxy loop (funnel config ends up as "proxy
# http://127.0.0.1:443" instead of the provider's actual port) and all
# public requests hang/fail.

step "Tailscale Funnel"
tailscale serve reset >/dev/null 2>&1 || true
if ! tailscale funnel --bg "${PORT}" >/dev/null 2>&1; then
    fail "tailscale funnel failed - is Funnel enabled in your tailnet ACL? See https://tailscale.com/kb/1223/funnel"
fi

FQDN="$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//')"
if [ -z "$FQDN" ] || [ "$FQDN" = "null" ]; then
    fail "could not determine Tailscale FQDN"
fi
PROVIDER_ADDRESS="https://${FQDN}"
log "public address: $PROVIDER_ADDRESS"

# ── 11. systemd service ───────────────────────────────────────────────────

step "systemd service"
if [ ! -f "$SCRIPT_DIR/obsideo-provider.service" ]; then
    fail "obsideo-provider.service not found next to setup.sh"
fi
install -o root -g root -m 0644 "$SCRIPT_DIR/obsideo-provider.service" /etc/systemd/system/obsideo-provider.service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1

# (Re)start to pick up current config
if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl restart "$SERVICE_NAME"
    log "restarted service"
else
    systemctl start "$SERVICE_NAME"
    log "started service"
fi

# ── 12. Wait for /health ──────────────────────────────────────────────────

step "Waiting for provider to come online"
HEALTHY=0
for i in $(seq 1 60); do
    if curl -fsS --max-time 2 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        echo ""
        fail "service exited before becoming healthy - check: journalctl -u $SERVICE_NAME -n 50"
    fi
    printf '.'
    sleep 1
done
echo ""
[ "$HEALTHY" = "1" ] || fail "provider did not respond on localhost:${PORT}/health within 60s"
log "provider healthy on localhost:${PORT}"

# ── 13. Registration ──────────────────────────────────────────────────────

if [ -z "$PROVIDER_ID" ]; then
    step "Registering with coordinator"
    REGISTER_BODY=$(cat <<JSON
{"address":"${PROVIDER_ADDRESS}","connectivity":"tunneled","public_key":"${PUBLIC_KEY_HEX}","capacity_bytes":${CAPACITY_BYTES},"wallet_address":"${WALLET}"}
JSON
)
    # Fresh Tailscale nodes need up to 3 minutes for Funnel DNS to propagate
    # globally. We try 20 times with backoff to 20s for ~6 min wall time.
    RESP_FILE="$(mktemp)"
    trap 'rm -f "$RESP_FILE"' EXIT
    REGISTERED=0
    MAX_ATTEMPTS=20
    for attempt in $(seq 1 $MAX_ATTEMPTS); do
        HTTP_CODE="$(curl -sS -o "$RESP_FILE" -w '%{http_code}' \
            -X POST \
            -H 'Content-Type: application/json' \
            -d "$REGISTER_BODY" \
            --max-time 30 \
            "${COORDINATOR}/internal/providers/register" 2>/dev/null || echo 000)"
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
            REGISTERED=1
            break
        fi
        RESP="$(cat "$RESP_FILE" 2>/dev/null || echo "")"
        warn "registration attempt $attempt/$MAX_ATTEMPTS failed (HTTP $HTTP_CODE): $RESP"
        if [ "$attempt" -lt $MAX_ATTEMPTS ]; then
            DELAY=$((attempt < 5 ? attempt * 3 : 20))
            log "retrying in ${DELAY}s..."
            sleep "$DELAY"
        fi
    done

    if [ "$REGISTERED" = "1" ]; then
        PROVIDER_ID="$(jq -r '.id // empty' "$RESP_FILE" 2>/dev/null || true)"
        PROVIDER_STATUS="$(jq -r '.status // empty' "$RESP_FILE" 2>/dev/null || true)"
        if [ -n "$PROVIDER_ID" ]; then
            log "registered as $PROVIDER_ID (status: $PROVIDER_STATUS)"
            printf '{"provider_id":"%s"}\n' "$PROVIDER_ID" > "$STATE_FILE"
            chmod 0644 "$STATE_FILE"
            # Update config.yaml with the assigned ID
            sed -i "s|^provider_id: .*|provider_id: \"${PROVIDER_ID}\"|" "$CONFIG_YAML"
            systemctl restart "$SERVICE_NAME"
            log "service restarted with provider_id"
        else
            warn "registration returned unexpected body: $(cat "$RESP_FILE")"
        fi
    else
        warn "registration failed after 10 attempts"
        warn "the provider is running but not registered with the coordinator"
        warn "you can re-run this script once the issue is resolved"
    fi
else
    log "provider_id already known, skipping registration"
fi

# ── 14. Summary ───────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Obsideo Data Farmer - setup complete"
echo "============================================================"
echo "  Service:         $SERVICE_NAME ($(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown))"
echo "  Public address:  $PROVIDER_ADDRESS"
echo "  Data directory:  $DATA_DIR"
echo "  Capacity:        $CAPACITY_INPUT"
echo "  Wallet:          ${WALLET:-not set}"
echo "  Provider ID:     ${PROVIDER_ID:-not registered}"
echo ""
echo "Useful commands:"
echo "  systemctl status obsideo-provider"
echo "  journalctl -u obsideo-provider -f"
echo "  sudo bash setup.sh      # re-run anytime, it's idempotent"
echo ""
if [ -n "${PROVIDER_STATUS:-}" ] && [ "${PROVIDER_STATUS:-}" = "pending" ]; then
    echo "NOTE: your provider is 'pending' - the coordinator admin must approve it"
    echo "      before it will start receiving uploads."
    echo ""
fi
