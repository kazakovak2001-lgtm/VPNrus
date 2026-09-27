#!/bin/bash
# B46-4P.3 - Certbot deploy hook for the Hysteria2 server's TLS material.
# Install as /etc/letsencrypt/renewal-hooks/deploy/nova-hysteria-cert.sh
# (root:root 0755). Certbot runs every deploy hook after EVERY renewed
# lineage on this host - including the ~6-day short-lived IP certificate -
# so this hook acts only when $RENEWED_LINEAGE is the lineage of the SNI
# the API advertises (POCVPN_API_HYSTERIA2_SNI in /etc/pocvpn/api.env) and
# is a silent no-op for every other certificate.
#
# Problem it solves: /etc/letsencrypt keys are root:root 0600 and Hysteria2
# runs as the non-root nova-hysteria user. The source stays under
# /etc/letsencrypt; this hook installs a runtime copy readable by
# nova-hysteria ONLY (key 0400, cert 0440, owner nova-hysteria, inside a
# root-owned 0750 directory it cannot write to) - never group/world access
# for any other service.
#
# Reload: none needed and none done. Hysteria2 app/v2.12.3's
# LocalCertificateLoader (app/internal/utils/certloader.go) stats cert+key
# on every TLS handshake and reloads when either mtime changes, keeping the
# previous pair if the new one fails to load. A restart would drop every
# connected client for nothing. The pair is validated BEFORE the swap, and
# the swap is two same-directory renames (key, then cert), so a handshake
# can only ever see the old pair, the new pair, or a transient mismatch
# the loader rejects in favour of the still-valid old pair.
#
# Manual first install (after the nova-hysteria user and api.env exist):
#   sudo RENEWED_LINEAGE=/etc/letsencrypt/live/<sni> \
#        /etc/letsencrypt/renewal-hooks/deploy/nova-hysteria-cert.sh
set -euo pipefail
umask 077

API_ENV=/etc/pocvpn/api.env
RUNTIME_USER=nova-hysteria
RUNTIME_GROUP=nova-hysteria
CONFIG_DIR=/etc/nova-hysteria
TLS_DIR=/etc/nova-hysteria/tls

if [ -z "${RENEWED_LINEAGE:-}" ]; then
    echo "nova-hysteria-cert: RENEWED_LINEAGE is not set (not run by certbot?)" >&2
    exit 1
fi

sni=""
if [ -r "$API_ENV" ]; then
    sni="$(sed -n 's/^POCVPN_API_HYSTERIA2_SNI=//p' "$API_ENV" | tail -n 1 | tr -d '"'"'"' \r')"
fi
if [ -z "$sni" ]; then
    # Hysteria2 not configured on this host: nothing to maintain.
    exit 0
fi
if ! [[ "$sni" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
    echo "nova-hysteria-cert: POCVPN_API_HYSTERIA2_SNI is not a DNS hostname" >&2
    exit 1
fi
if [ "$RENEWED_LINEAGE" != "/etc/letsencrypt/live/$sni" ]; then
    exit 0
fi

if ! getent passwd "$RUNTIME_USER" >/dev/null || ! getent group "$RUNTIME_GROUP" >/dev/null; then
    echo "nova-hysteria-cert: runtime user/group $RUNTIME_USER missing" >&2
    exit 1
fi

src_cert="$RENEWED_LINEAGE/fullchain.pem"
src_key="$RENEWED_LINEAGE/privkey.pem"

# Validate before touching the runtime copy: hostname, not expired, and the
# key really belongs to the certificate.
if ! openssl x509 -in "$src_cert" -noout -checkhost "$sni" | grep -q "does match certificate"; then
    echo "nova-hysteria-cert: $src_cert is not valid for $sni" >&2
    exit 1
fi
if ! openssl x509 -in "$src_cert" -noout -checkend 0 >/dev/null; then
    echo "nova-hysteria-cert: $src_cert is expired" >&2
    exit 1
fi
cert_pub="$(openssl x509 -in "$src_cert" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)"
key_pub="$(openssl pkey -in "$src_key" -pubout -outform DER | sha256sum)"
if [ "$cert_pub" != "$key_pub" ]; then
    echo "nova-hysteria-cert: private key does not match $src_cert" >&2
    exit 1
fi

install -d -o root -g "$RUNTIME_GROUP" -m 0750 "$CONFIG_DIR"
install -d -o root -g "$RUNTIME_GROUP" -m 0750 "$TLS_DIR"
install -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0400 "$src_key" "$TLS_DIR/.privkey.pem.new"
install -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0440 "$src_cert" "$TLS_DIR/.fullchain.pem.new"
mv -f "$TLS_DIR/.privkey.pem.new" "$TLS_DIR/privkey.pem"
mv -f "$TLS_DIR/.fullchain.pem.new" "$TLS_DIR/fullchain.pem"

echo "nova-hysteria-cert: installed runtime TLS copy for $sni (Hysteria2 reloads on next handshake)"
