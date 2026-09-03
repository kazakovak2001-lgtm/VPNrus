#!/usr/bin/env bash
# B31 - controlled backend CODE upgrade for an already-deployed pocvpn-api
# process (regular gateway role OR ingress role - same script, parameterized
# by --service). Neither role's install script (gateway/DEPLOYMENT.md's
# manual sequence, gateway/scripts/install-ingress-role.sh) has ever
# included an UPGRADE path before this - both only ever describe a fresh
# install. This closes that gap for B31's own requirement: the Germany and
# Stockholm hosts' deployed code predates B25-B30 and must be brought up to
# current main before /v1/relay-health or /v1/ingress-profile can work at
# all, without risking the ALREADY-LIVE traffic either host serves today.
#
# Does NOT:
#   - touch any secret (REALITY private key, activation store, api.env's
#     filled-in values, ingress.env's filled-in values) - those live
#     entirely outside /opt/pocvpn/gateway (in /etc/pocvpn, /etc/nginx,
#     /var/lib/pocvpn-provision*) and this script never reads/writes them;
#   - install/modify nginx configuration - a deliberate separate step (see
#     docs/B31_INGRESS_PRODUCTION_READINESS.md), since an nginx location
#     change is reviewed and applied independently of a code-only upgrade;
#   - restart any transport (nova-xray.service, nova-xray-ingress.service,
#     amnezia-wg) - only the given pocvpn-api-shaped systemd unit;
#   - auto-rollback on failure. A failed health check or smoke test STOPS
#     with the exact backup path and manual rollback command printed - an
#     operator decides, this script never guesses.
#
# Usage (as root, on the target host):
#   deploy-backend-update.sh \
#       --repo-root /tmp/nova-vpn-src \
#       --service pocvpn-api.service \
#       --port 8443
#
# --service: the systemd unit to restart after the code copy (e.g.
#   pocvpn-api.service for an existing gateway role, pocvpn-api-ingress.service
#   for an ingress role once it has already been installed once via
#   install-ingress-role.sh - this script never installs a NEW unit).
# --port: the loopback port THIS service's own env file configures
#   (POCVPN_API_API_PORT) - used only for the post-restart smoke test below,
#   never written anywhere.
set -euo pipefail

REPO_ROOT=""
INSTALL_PREFIX="/opt/pocvpn"
SERVICE=""
PORT=""
BACKUP_ROOT="/opt/pocvpn/gateway-backups"

log() { echo "deploy-backend-update: $*" >&2; }
die() { echo "deploy-backend-update: error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --repo-root) REPO_ROOT="$2"; shift 2 ;;
        --install-prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        --service) SERVICE="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must be run as root"
[ -n "$REPO_ROOT" ] || die "--repo-root is required"
[ -n "$SERVICE" ] || die "--service is required (e.g. pocvpn-api.service)"
[ -n "$PORT" ] || die "--port is required (this service's own loopback POCVPN_API_API_PORT)"
[ -f "$REPO_ROOT/gateway/api/server.py" ] || die "REPO_ROOT ($REPO_ROOT) does not look like this repository"
systemctl cat "$SERVICE" >/dev/null 2>&1 || die "systemd unit $SERVICE is not installed - this script upgrades CODE for an already-installed service, never installs a new one"

GATEWAY_DIR="$INSTALL_PREFIX/gateway"
[ -d "$GATEWAY_DIR" ] || die "$GATEWAY_DIR does not exist - nothing to upgrade (run the appropriate install script first)"

# --- 1. backup currently-installed code (before touching anything) ---
mkdir -p "$BACKUP_ROOT"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_PATH="$BACKUP_ROOT/gateway-$TIMESTAMP"
cp -a "$GATEWAY_DIR" "$BACKUP_PATH"
log "backed up currently-installed code to $BACKUP_PATH"

# --- 2. copy new code (same rsync convention as install-ingress-role.sh) ---
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.git' "$REPO_ROOT/gateway/" "$GATEWAY_DIR/"
else
    rm -rf "$GATEWAY_DIR"
    mkdir -p "$GATEWAY_DIR"
    cp -a "$REPO_ROOT/gateway/." "$GATEWAY_DIR/"
fi
chown -R root:root "$GATEWAY_DIR"
find "$GATEWAY_DIR" -type d -exec chmod 0755 {} +
find "$GATEWAY_DIR" -type f -exec chmod 0644 {} +
chmod 0755 "$GATEWAY_DIR/scripts"/*.sh
log "new code copied to $GATEWAY_DIR"

# --- 3. validate BEFORE reload: pure import sanity, catches a syntax/
# import error before the running process is ever touched. Does not (and
# cannot, without the real env file's secrets) run load_config() - that is
# covered by ingress_preflight.py for the ingress role, and by the smoke
# test below for either role, once the service is actually running. ---
if ! (cd "$GATEWAY_DIR" && python3 -c "import api.server, api.handler, api.config, api.ingress_config, api.ingress_activation, api.relay_probe_token, api.relay_identity_store"); then
    log "FAILED: new code does not even import cleanly - NOT restarting $SERVICE"
    log "rollback: rsync -a --delete '$BACKUP_PATH/' '$GATEWAY_DIR/' && chown -R root:root '$GATEWAY_DIR'"
    die "import validation failed - see output above"
fi
log "import validation passed"

# --- 4. restart and confirm active ---
systemctl restart "$SERVICE"
sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
    log "FAILED: $SERVICE did not reach active state after restart"
    systemctl --no-pager status "$SERVICE" || true
    log "rollback: rsync -a --delete '$BACKUP_PATH/' '$GATEWAY_DIR/' && chown -R root:root '$GATEWAY_DIR' && systemctl restart '$SERVICE'"
    die "$SERVICE failed to start on the new code - see status above"
fi
log "$SERVICE is active"

# --- 5. smoke test existing routes over the SAME loopback port a real
# client request would eventually reach via nginx - GET /v1/manifest is
# chosen deliberately: every deployment (regular gateway OR ingress role)
# already has this route wired, it takes no request body, and it never
# mutates state, so it is safe to call from this script. A 404/503 is an
# ACCEPTABLE result (means the process is alive and routing correctly, the
# manifest/relay-health/ingress-profile fields themselves may simply be
# unconfigured on this host) - only connection-refused/timeout is a
# failure, since that means the process itself is not actually listening.
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/v1/manifest" || echo "CURL_FAILED")"
if [ "$HTTP_CODE" = "CURL_FAILED" ]; then
    log "FAILED: 127.0.0.1:$PORT is not answering at all after restart"
    log "rollback: rsync -a --delete '$BACKUP_PATH/' '$GATEWAY_DIR/' && chown -R root:root '$GATEWAY_DIR' && systemctl restart '$SERVICE'"
    die "smoke test failed - $SERVICE process is not reachable on its own loopback port"
fi
log "smoke test: GET /v1/manifest via 127.0.0.1:$PORT -> HTTP $HTTP_CODE (process is alive and routing)"

log "upgrade complete. Backup retained at $BACKUP_PATH - remove it once you are confident the new deployment is stable."
log "rollback (if needed later): rsync -a --delete '$BACKUP_PATH/' '$GATEWAY_DIR/' && chown -R root:root '$GATEWAY_DIR' && systemctl restart '$SERVICE'"
