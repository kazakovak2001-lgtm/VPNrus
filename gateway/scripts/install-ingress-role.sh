#!/usr/bin/env bash
# B26 (task F/J) - idempotent bootstrap for a fresh Ubuntu host's INGRESS
# role: creates the ownership/filesystem model, installs the privileged
# wrapper + sudoers drop-in + systemd units. Mirrors gateway/DEPLOYMENT.md's
# section 1 filesystem/ownership model for the regular gateway role,
# applied to the ingress-specific paths this slice added
# (config/ingress.env.example, api/ingress_config.py,
# systemd/pocvpn-api-ingress.service, systemd/nova-xray-ingress.service,
# privileged/nova-xray-ingress-reload).
#
# Does NOT:
#   - place any secret (REALITY private key, upstream relay uuid, probe
#     HMAC secret, api.env/ingress.env's filled-in values) - those are a
#     deliberate, separate, human-performed step (see
#     docs/B26_FIRST_INGRESS_RUNBOOK.md);
#   - start any systemd service (nothing is safe to start before the
#     secrets above exist);
#   - touch any OTHER host or any existing gateway role on this host.
#
# Safe to re-run: every step below is idempotent (id -u check before
# useradd, mkdir -p, install -m for file copies, systemctl daemon-reload).
#
# Must be run as root, from the repository root, with REPO_ROOT already
# deployed (or a copy of it) at /opt/pocvpn/gateway/../.. as this script
# assumes - see --repo-root to override for a non-standard checkout path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_PREFIX="/opt/pocvpn"

log() { echo "install-ingress-role: $*" >&2; }
die() { echo "install-ingress-role: error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must be run as root"

while [ $# -gt 0 ]; do
    case "$1" in
        --repo-root) REPO_ROOT="$2"; shift 2 ;;
        --install-prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -f "$REPO_ROOT/gateway/api/server.py" ] || die "REPO_ROOT ($REPO_ROOT) does not look like this repository"

log "using REPO_ROOT=$REPO_ROOT INSTALL_PREFIX=$INSTALL_PREFIX"

# --- 1. system users/groups (idempotent) ---
for user in pocvpn-api nova-xray-ingress; do
    if id -u "$user" >/dev/null 2>&1; then
        log "user $user already exists - leaving it unchanged"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
        log "created system user $user"
    fi
done

# --- 2. application code: read-only, root-owned, never writable by pocvpn-api ---
mkdir -p "$INSTALL_PREFIX/gateway"
# rsync (not cp -r) so re-running this after a code update converges
# cleanly rather than leaving stale files behind.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.git' "$REPO_ROOT/gateway/" "$INSTALL_PREFIX/gateway/"
else
    rm -rf "$INSTALL_PREFIX/gateway"
    mkdir -p "$INSTALL_PREFIX/gateway"
    cp -a "$REPO_ROOT/gateway/." "$INSTALL_PREFIX/gateway/"
fi
chown -R root:root "$INSTALL_PREFIX/gateway"
find "$INSTALL_PREFIX/gateway" -type d -exec chmod 0755 {} +
find "$INSTALL_PREFIX/gateway" -type f -exec chmod 0644 {} +
chmod 0755 "$INSTALL_PREFIX/gateway/scripts"/*.sh
log "application code installed read-only under $INSTALL_PREFIX/gateway"

# --- 2.5. B31A fix: converge the PINNED xray-core binary at the tracked
# canonical path (gateway/systemd/nova-xray-ingress.service's own
# ExecStart hardcodes it, never reads it from an env file). Found live:
# neither real production host has a binary at this path at all (both
# predate this pinned-path convention, running an older, differently-
# versioned /usr/local/bin/xray for their own EXISTING exit role) - a
# manual `ln -s /usr/local/bin/xray ...` "fix" would silently point the
# NEW ingress role at an unpinned, unverified, possibly-different-version
# binary. gateway/xray/fetch-xray-server.sh is the real, reproducible,
# checksum-and-commit-verified installer this repo already has for
# EXACTLY this - reused verbatim here rather than inventing a second
# fetch/verify mechanism. Idempotent (skips if $XRAY_CORE_TAG is already
# installed) and touches nothing but a fresh, independent, version-named
# directory under $INSTALL_PREFIX/xray - never the existing exit role's
# own /usr/local/bin/xray, which this step does not read, modify, or
# depend on at all. ---
XRAY_INSTALL_ROOT="$INSTALL_PREFIX/xray" bash "$REPO_ROOT/gateway/xray/fetch-xray-server.sh"
log "pinned xray-core binary present under $INSTALL_PREFIX/xray (see gateway/xray/VERSION for the exact pinned tag/commit/sha256)"

# --- 3. privileged wrapper (root:root 0750) ---
install -o root -g root -m 0750 "$REPO_ROOT/gateway/privileged/nova-xray-ingress-reload" \
    /usr/local/libexec/nova-xray-ingress-reload
log "installed /usr/local/libexec/nova-xray-ingress-reload (0750 root:root)"

# --- 4. sudoers drop-in - validated BEFORE install, never installed unvalidated ---
if ! visudo -cf "$REPO_ROOT/gateway/privileged/pocvpn-api.sudoers"; then
    die "pocvpn-api.sudoers failed visudo validation - refusing to install"
fi
install -o root -g root -m 0440 "$REPO_ROOT/gateway/privileged/pocvpn-api.sudoers" \
    /etc/sudoers.d/pocvpn-api
log "installed /etc/sudoers.d/pocvpn-api (0440 root:root, visudo-validated)"

# --- 5. /etc/pocvpn (config; secrets filled in by the operator later) ---
# B31A fix (found live on the first real Stockholm deployment): this
# directory previously came out root:root, so pocvpn-api-ingress (running
# as the pocvpn-api service account, not root) could not even traverse
# into it to read the secret files step 3 of the runbook places here,
# regardless of THEIR own ownership/mode - group must be pocvpn-api,
# mirroring the already-correct convention the regular gateway role's own
# /etc/pocvpn/xray directory uses (root:pocvpn-api, 0750).
mkdir -p /etc/pocvpn/ingress
chown root:pocvpn-api /etc/pocvpn
chmod 0755 /etc/pocvpn
chown root:pocvpn-api /etc/pocvpn/ingress
chmod 0750 /etc/pocvpn/ingress
if [ ! -f /etc/pocvpn/ingress.env ]; then
    install -o root -g pocvpn-api -m 0640 "$REPO_ROOT/gateway/config/ingress.env.example" /etc/pocvpn/ingress.env
    log "seeded /etc/pocvpn/ingress.env from the tracked template - EDIT IT before starting the service"
else
    log "/etc/pocvpn/ingress.env already exists - left unchanged"
fi

# --- 6. durable ingress-role state directories (pocvpn-api:pocvpn-api, 0750) ---
# B31A fix (found live): these MUST be owned by the pocvpn-api service
# account itself, not merely group-readable by it - pocvpn-api-ingress
# writes durably into both (the activation/xray-identity stores directly
# in the first, the staged candidate Xray config in xray/) on every real
# request, not just reads. root:pocvpn-api (this directory's pre-B31A
# ownership) grants read+traverse but not write, so every real write here
# failed until an operator manually re-chowned it - mirrors the regular
# gateway role's own /var/lib/pocvpn-activation and /var/lib/pocvpn-xray,
# both pocvpn-api:pocvpn-api on every real deployment.
for dir in /var/lib/pocvpn-provision-ingress /var/lib/pocvpn-provision-ingress/xray; do
    mkdir -p "$dir"
    chown pocvpn-api:pocvpn-api "$dir"
    chmod 0750 "$dir"
done
log "durable state directories ready under /var/lib/pocvpn-provision-ingress (pocvpn-api:pocvpn-api, 0750)"

# --- 7. live Xray config directory for nova-xray-ingress.service (root:nova-xray-ingress) ---
mkdir -p /etc/nova-xray-ingress
chown root:nova-xray-ingress /etc/nova-xray-ingress
chmod 0750 /etc/nova-xray-ingress
log "/etc/nova-xray-ingress ready (root:nova-xray-ingress, 0750)"

# --- 8. a harmless no-op provision-peer stand-in (see ingress.env.example's own note) ---
noop_script=/usr/local/libexec/pocvpn-noop-provision-peer
if [ ! -f "$noop_script" ]; then
    printf '#!/bin/sh\nexit 99\n' > "$noop_script"
    chmod 0750 "$noop_script"
    chown root:root "$noop_script"
    log "installed harmless no-op $noop_script (POCVPN_API_PROVISION_SCRIPT_PATH placeholder)"
fi

# --- 9. systemd units ---
install -o root -g root -m 0644 "$REPO_ROOT/gateway/systemd/pocvpn-api-ingress.service" /etc/systemd/system/
install -o root -g root -m 0644 "$REPO_ROOT/gateway/systemd/nova-xray-ingress.service" /etc/systemd/system/
systemctl daemon-reload
log "installed pocvpn-api-ingress.service and nova-xray-ingress.service, not enabled/started yet"

cat >&2 <<'EOF'

install-ingress-role: bootstrap complete. REMAINING MANUAL STEPS (never
automated by this script - see docs/B26_FIRST_INGRESS_RUNBOOK.md):

  1. generate/place this host's REALITY keypair, and write the PRIVATE key
     to /etc/pocvpn/ingress/reality-private-key.txt (0600, owned by the
     pocvpn-api user - it is THIS process, not root, that reads it at
     activation time);
  2. run gateway/tools/provision_relay_upstream_identity.py to mint the
     ingress->exit relay uuid + probe HMAC secret, transfer the ingress
     files to THIS host at the paths ingress.env points at (same 0600,
     pocvpn-api-owned convention as step 1), and transfer the exit-fragment
     file to the EXIT operator out-of-band;
  3. edit /etc/pocvpn/ingress.env with this host's real values;
  4. B31A - initialize every durable store/lock AS THE pocvpn-api USER
     (sudo -u pocvpn-api), never plain root - a store/lock file created by
     root cannot be written by the pocvpn-api-ingress service itself
     afterward (found live: this is exactly what left the durable state
     directories unwritable even after step 6's chown, until each file
     inside them was ALSO individually re-owned):
       sudo -u pocvpn-api python3 gateway/tools/activation_tokens.py \
           --store <NOVA_INGRESS_ACTIVATION_STORE_PATH> \
           --lock <NOVA_INGRESS_ACTIVATION_LOCK_PATH> init
       cd /opt/pocvpn/gateway && sudo -u pocvpn-api python3 -c \
           "from api import xray_provisioning; xray_provisioning.init_store('<NOVA_INGRESS_XRAY_STORE_PATH>', '<NOVA_INGRESS_XRAY_LOCK_PATH>')"
       cd /opt/pocvpn/gateway && sudo -u pocvpn-api python3 -c \
           "from api import xray_activation; xray_activation.init_activation_lock('<NOVA_INGRESS_ACTIVATION_GLOBAL_LOCK_PATH>')"
  5. run gateway/tools/ingress_preflight.py --env-file /etc/pocvpn/ingress.env
     and confirm PASS before starting anything;
  6. systemctl enable --now pocvpn-api-ingress.service nova-xray-ingress.service;
  7. run gateway/tools/ingress_status.py --env-file /etc/pocvpn/ingress.env.

EOF
