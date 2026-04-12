#!/bin/bash
set -euo pipefail

# ── Obsideo Provider Bootstrap ─────────────────────────────────────────────────
# Runs as ExecStartPre before the provider binary.
# Handles: coordinator pubkey fetch, identity generation, config generation,
# Tailscale Funnel setup, and auto-registration.
#
# Env vars come from /etc/obsideo-provider/provider.env via the systemd unit.

INSTALL_DIR="/opt/obsideo-provider"
DATA_DIR="${OBSIDEO_DATA_DIR:-$INSTALL_DIR/data}"
COORDINATOR="${OBSIDEO_COORDINATOR_URL:?OBSIDEO_COORDINATOR_URL is required}"
CAPACITY="${OBSIDEO_CAPACITY_BYTES:-10737418240}"
WALLET="${OBSIDEO_WALLET_ADDRESS:-}"
PROVIDER_ID="${OBSIDEO_PROVIDER_ID:-}"
PORT="${OBSIDEO_PROVIDER_PORT:-3334}"
SERVICE_USER="obsideo"

STATE_FILE="${DATA_DIR}/.obsideo-state.json"
IDENTITY_KEY="${DATA_DIR}/.identity_ed25519"
COORDINATOR_PUB="${INSTALL_DIR}/coordinator_pub.pem"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
TMP_DIR="${DATA_DIR}/.tmp"

log()  { echo "[bootstrap] $*"; }
ok()   { echo "[bootstrap] OK: $*"; }
fail() { echo "[bootstrap] ERROR: $*" >&2; }

mkdir -p "$DATA_DIR" "$TMP_DIR"
chown "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"

# ── Load persisted provider ID ─────────────────────────────────────────────────

if [ -z "$PROVIDER_ID" ] && [ -f "$STATE_FILE" ]; then
    SAVED_ID=$(jq -r '.provider_id // empty' "$STATE_FILE" 2>/dev/null || true)
    if [ -n "$SAVED_ID" ]; then
        PROVIDER_ID="$SAVED_ID"
        log "restored provider_id: $PROVIDER_ID"
    fi
fi

# ── Fetch coordinator public key ───────────────────────────────────────────────

log "fetching coordinator public key..."
RETRY=0
while true; do
    if curl -fsSL "${COORDINATOR}/public-key" -o "$COORDINATOR_PUB" 2>/dev/null; then
        chown "$SERVICE_USER":"$SERVICE_USER" "$COORDINATOR_PUB"
        ok "coordinator public key saved"
        break
    fi
    RETRY=$((RETRY + 1))
    if [ "$RETRY" -ge 30 ]; then
        fail "could not fetch coordinator public key after 30 attempts"
        exit 1
    fi
    DELAY=$((RETRY < 5 ? RETRY * 2 : 10))
    log "coordinator unreachable, retry in ${DELAY}s ($RETRY/30)..."
    sleep "$DELAY"
done

# ── Generate identity keypair ──────────────────────────────────────────────────

if [ ! -f "$IDENTITY_KEY" ]; then
    log "generating provider identity keypair..."
    openssl genpkey -algorithm ed25519 -out "$IDENTITY_KEY" 2>/dev/null
    chown "$SERVICE_USER":"$SERVICE_USER" "$IDENTITY_KEY"
    chmod 600 "$IDENTITY_KEY"
    ok "identity key generated"
else
    log "identity key exists, reusing"
fi

PUBLIC_KEY_HEX=$(openssl pkey -in "$IDENTITY_KEY" -pubout -outform DER 2>/dev/null \
    | tail -c 32 \
    | od -An -tx1 \
    | tr -d ' \n')

# ── Wait for Tailscale ─────────────────────────────────────────────────────────

log "waiting for tailscale..."
for i in $(seq 1 60); do
    if tailscale status --json 2>/dev/null | jq -e '.Self.Online == true' >/dev/null 2>&1; then
        ok "tailscale online"
        break
    fi
    if [ "$i" -eq 60 ]; then
        fail "tailscale did not come online after 60s"
        fail "run 'sudo tailscale up' to authenticate, then restart the service"
        exit 1
    fi
    sleep 1
done

# ── Configure Tailscale Funnel ─────────────────────────────────────────────────

# Use `tailscale funnel --bg <port>` directly. Do NOT use
# `tailscale serve --https=443` + `tailscale funnel 443` -- that creates
# a proxy loop where the config ends up as "proxy http://127.0.0.1:443"
# instead of proxying to the provider's actual port.
log "configuring tailscale funnel..."
tailscale serve reset 2>/dev/null || true

if ! tailscale funnel --bg "${PORT}" 2>&1; then
    fail "tailscale funnel failed -- is Funnel enabled in your ACL policy?"
    fail "see: https://tailscale.com/kb/1223/funnel"
    exit 1
fi

ACTUAL_HOSTNAME=$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//')
if [ -z "$ACTUAL_HOSTNAME" ] || [ "$ACTUAL_HOSTNAME" = "null" ]; then
    fail "could not detect Tailscale hostname"
    exit 1
fi
PROVIDER_ADDRESS="https://${ACTUAL_HOSTNAME}"
ok "funnel active: $PROVIDER_ADDRESS"

# ── Generate config.yaml ──────────────────────────────────────────────────────

log "writing config.yaml..."
cat > "$CONFIG_FILE" <<YAML
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

ipfs:
  port: 4001
  domain: ""
  key: ""

tokens:
  public_key_path: "${COORDINATOR_PUB}"
YAML

# ── Auto-register ─────────────────────────────────────────────────────────────

if [ -z "$PROVIDER_ID" ]; then
    log "registering with coordinator..."
    REGISTER_BODY=$(cat <<JSON
{
    "address": "${PROVIDER_ADDRESS}",
    "connectivity": "tunneled",
    "public_key": "${PUBLIC_KEY_HEX}",
    "capacity_bytes": ${CAPACITY},
    "wallet_address": "${WALLET}"
}
JSON
)
    RESP_FILE="${TMP_DIR}/register_resp.json"
    RETRY=0
    while true; do
        HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$REGISTER_BODY" \
            "${COORDINATOR}/internal/providers/register" 2>/dev/null) || HTTP_CODE="000"
        RESP=$(cat "$RESP_FILE" 2>/dev/null || echo "")

        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
            break
        fi

        RETRY=$((RETRY + 1))
        if [ "$RETRY" -ge 10 ]; then
            fail "registration failed after 10 attempts (HTTP $HTTP_CODE): $RESP"
            log "provider will start but is not registered. Register manually."
            break
        fi
        DELAY=$((RETRY < 5 ? RETRY * 3 : 15))
        log "registration attempt $RETRY failed (HTTP $HTTP_CODE), retry in ${DELAY}s..."
        sleep "$DELAY"
    done

    PROVIDER_ID=$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null || true)
    PROVIDER_STATUS=$(echo "$RESP" | jq -r '.status // empty' 2>/dev/null || true)

    if [ -n "$PROVIDER_ID" ]; then
        ok "registered as $PROVIDER_ID (status: $PROVIDER_STATUS)"
        echo "{\"provider_id\": \"$PROVIDER_ID\"}" > "$STATE_FILE"
        sed -i "s/^provider_id: .*/provider_id: \"${PROVIDER_ID}\"/" "$CONFIG_FILE"

        if [ "$PROVIDER_STATUS" = "pending" ]; then
            log "============================================"
            log "  Provider registered but needs APPROVAL"
            log "  Ask coordinator admin to approve:"
            log "  POST /internal/providers/$PROVIDER_ID/approve"
            log "============================================"
        fi
    else
        fail "registration returned unexpected response: $RESP"
    fi
else
    ok "provider_id: $PROVIDER_ID (already registered)"
fi

# ── Fix ownership ─────────────────────────────────────────────────────────────
# Bootstrap runs as root (ExecStartPre=+), but the provider process runs as
# the service user. Ensure data dir and generated files are owned correctly.

chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"
chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_FILE"
chown "$SERVICE_USER":"$SERVICE_USER" "$COORDINATOR_PUB" 2>/dev/null || true

rm -rf "$TMP_DIR"

log "bootstrap complete"
