#!/bin/bash
set -euo pipefail

# ── Obsideo Data Farmer - Docker entrypoint ─────────────────────────────────
#
# Two modes:
#
#   1. Tailscale mode (default for home operators):
#      Runs alongside a Tailscale sidecar container. Sets up Funnel, detects
#      the public FQDN, registers using it. Requires TS_AUTHKEY + sidecar.
#
#   2. Direct mode (for cloud / Akash / VPS with a public URL):
#      Set OBSIDEO_PROVIDER_ADDRESS to the public URL (e.g. Akash ingress).
#      Skips Tailscale entirely. No sidecar needed.

DATA_DIR="${OBSIDEO_DATA_DIR:-/app/data}"
COORDINATOR="${OBSIDEO_COORDINATOR_URL:?OBSIDEO_COORDINATOR_URL is required}"
CAPACITY="${OBSIDEO_CAPACITY_BYTES:-10737418240}"
WALLET="${OBSIDEO_WALLET_ADDRESS:-}"
PROVIDER_ID="${OBSIDEO_PROVIDER_ID:-}"
PORT="${OBSIDEO_PROVIDER_PORT:-3334}"
PROVIDER_ADDRESS="${OBSIDEO_PROVIDER_ADDRESS:-}"
TS_SOCKET="${TS_SOCKET:-/var/run/tailscale/tailscaled.sock}"
export TAILSCALE_SOCKET="$TS_SOCKET"

STATE_FILE="${DATA_DIR}/.obsideo-state.json"
IDENTITY_KEY="${DATA_DIR}/.identity_ed25519"
COORDINATOR_PUB="${DATA_DIR}/coordinator_pub.pem"
CONFIG_FILE="${DATA_DIR}/config.yaml"

log()  { printf '[datafarmer] %s\n' "$*"; }
ok()   { printf '[datafarmer] OK: %s\n' "$*"; }
warn() { printf '[datafarmer] WARNING: %s\n' "$*" >&2; }
fail() { printf '[datafarmer] ERROR: %s\n' "$*" >&2; exit 1; }

mkdir -p "$DATA_DIR"

ts() { tailscale --socket "$TS_SOCKET" "$@"; }

# Detect mode
USE_TAILSCALE=1
if [ -n "$PROVIDER_ADDRESS" ]; then
    USE_TAILSCALE=0
    log "direct mode: using OBSIDEO_PROVIDER_ADDRESS=$PROVIDER_ADDRESS"
fi

# ── 1. Wait for Tailscale sidecar (skipped in direct mode) ────────────────

if [ "$USE_TAILSCALE" = "1" ]; then
    log "waiting for tailscale sidecar ($TS_SOCKET)..."
    for i in $(seq 1 60); do
        if ts status --json 2>/dev/null | jq -e '.Self.Online == true' >/dev/null 2>&1; then
            ok "tailscale online"
            break
        fi
        if [ "$i" -eq 60 ]; then
            fail "tailscale did not come online after 60s - check the tailscale container logs"
        fi
        sleep 1
    done
fi

# ── 2. Load persisted state ────────────────────────────────────────────────

if [ -z "$PROVIDER_ID" ] && [ -f "$STATE_FILE" ]; then
    SAVED_ID="$(jq -r '.provider_id // empty' "$STATE_FILE" 2>/dev/null || true)"
    if [ -n "$SAVED_ID" ]; then
        PROVIDER_ID="$SAVED_ID"
        log "restored provider_id from state: $PROVIDER_ID"
    fi
fi

# ── 3. Fetch coordinator public key ────────────────────────────────────────

log "fetching coordinator public key..."
RETRY=0
while true; do
    if curl -fsSL --max-time 10 "${COORDINATOR}/public-key" -o "$COORDINATOR_PUB" 2>/dev/null; then
        ok "coordinator public key saved"
        break
    fi
    RETRY=$((RETRY + 1))
    if [ "$RETRY" -ge 30 ]; then
        fail "could not fetch coordinator public key after 30 attempts"
    fi
    DELAY=$((RETRY < 5 ? RETRY * 2 : 10))
    log "coordinator unreachable, retry in ${DELAY}s ($RETRY/30)..."
    sleep "$DELAY"
done

# ── 4. Generate ed25519 identity keypair ───────────────────────────────────

if [ ! -f "$IDENTITY_KEY" ]; then
    log "generating ed25519 identity"
    openssl genpkey -algorithm ed25519 -out "$IDENTITY_KEY" 2>/dev/null
    chmod 0600 "$IDENTITY_KEY"
else
    log "reusing existing identity"
fi
PUBLIC_KEY_HEX="$(openssl pkey -in "$IDENTITY_KEY" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | od -An -tx1 | tr -d ' \n')"
log "pubkey: ${PUBLIC_KEY_HEX:0:16}..."

# ── 5. Configure Tailscale Funnel (skipped in direct mode) ─────────────────
#
# Use `tailscale funnel --bg <port>` DIRECTLY. Do NOT use
# `tailscale serve --https=443 http://localhost:<port>` + `tailscale funnel 443`
# - that creates a proxy loop (serve config ends up as
# "proxy http://127.0.0.1:443" instead of the provider port) and all public
# requests hang.

if [ "$USE_TAILSCALE" = "1" ]; then
    log "configuring tailscale funnel on port $PORT..."
    ts serve reset >/dev/null 2>&1 || true
    if ! ts funnel --bg "$PORT" 2>&1; then
        fail "tailscale funnel failed - is Funnel enabled in your tailnet ACL? See https://tailscale.com/kb/1223/funnel"
    fi

    PROVIDER_FQDN="$(ts status --json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//')"
    if [ -z "$PROVIDER_FQDN" ] || [ "$PROVIDER_FQDN" = "null" ]; then
        fail "could not determine Tailscale FQDN from sidecar"
    fi
    PROVIDER_ADDRESS="https://${PROVIDER_FQDN}"
fi
ok "public address: $PROVIDER_ADDRESS"

# ── 6. Write config.yaml ───────────────────────────────────────────────────

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

tokens:
  public_key_path: "${COORDINATOR_PUB}"
YAML

# ── 7. Start provider in background for /health ────────────────────────────

log "starting datafarmer in background for health check..."
/app/datafarmer start --config "$CONFIG_FILE" &
PROVIDER_PID=$!

cleanup() {
    if kill -0 "$PROVIDER_PID" 2>/dev/null; then
        kill -TERM "$PROVIDER_PID" 2>/dev/null || true
        wait "$PROVIDER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT TERM INT

HEALTHY=0
for i in $(seq 1 60); do
    if curl -fs --max-time 2 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    if ! kill -0 "$PROVIDER_PID" 2>/dev/null; then
        fail "datafarmer exited before becoming healthy"
    fi
    sleep 1
done
[ "$HEALTHY" = "1" ] || fail "datafarmer did not respond on localhost:${PORT}/health within 60s"
ok "provider healthy on localhost:${PORT}"

# ── 8. Register with coordinator (retry + exponential-ish backoff) ─────────

if [ -z "$PROVIDER_ID" ]; then
    log "registering with coordinator..."
    REGISTER_BODY=$(cat <<JSON
{"address":"${PROVIDER_ADDRESS}","connectivity":"tunneled","public_key":"${PUBLIC_KEY_HEX}","capacity_bytes":${CAPACITY},"wallet_address":"${WALLET}"}
JSON
)
    # Max attempts accommodates a brand-new Tailscale node whose Funnel DNS
    # may take 1-3 minutes to propagate globally. After attempt 5 we back off
    # to a flat 20s, giving ~6 minutes total wall time.
    RESP_FILE="$(mktemp)"
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
        warn "registration attempt $attempt/$MAX_ATTEMPTS failed (HTTP $HTTP_CODE): $(cat "$RESP_FILE" 2>/dev/null || echo "")"
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
            ok "registered as $PROVIDER_ID (status: $PROVIDER_STATUS)"
            printf '{"provider_id":"%s"}\n' "$PROVIDER_ID" > "$STATE_FILE"
            sed -i "s|^provider_id: .*|provider_id: \"${PROVIDER_ID}\"|" "$CONFIG_FILE"
            if [ "${PROVIDER_STATUS:-}" = "pending" ]; then
                log ""
                log "============================================"
                log "  Provider registered but needs APPROVAL"
                log "  Ask the coordinator admin to approve:"
                log "  POST /internal/providers/${PROVIDER_ID}/approve"
                log "============================================"
                log ""
            fi
        else
            warn "registration succeeded but response had no id: $(cat "$RESP_FILE")"
        fi
    else
        warn "registration failed after 10 attempts - provider is running but not registered"
        warn "the container will keep running and you can re-run registration manually"
    fi
    rm -f "$RESP_FILE"
else
    ok "provider_id already set: $PROVIDER_ID"
fi

# ── 9. Hand off to the running datafarmer ──────────────────────────────────
# Restart the provider to pick up the updated config (provider_id).
# We kill the background instance and exec the foreground one, which
# becomes the container's main process.

log "restarting datafarmer with updated config..."
kill -TERM "$PROVIDER_PID" 2>/dev/null || true
wait "$PROVIDER_PID" 2>/dev/null || true
trap - EXIT TERM INT

log ""
log "============================================"
log "  DATA FARMER ONLINE"
log "  ID:      ${PROVIDER_ID:-unregistered}"
log "  Address: ${PROVIDER_ADDRESS}"
log "  Storage: ${DATA_DIR}"
log "  Wallet:  ${WALLET:-not set}"
log "============================================"
log ""

exec /app/datafarmer start --config "$CONFIG_FILE"
