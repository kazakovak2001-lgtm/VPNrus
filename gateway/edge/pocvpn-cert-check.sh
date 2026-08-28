#!/bin/bash
# B8B2A - certificate-expiry visibility check. A 160-hour (6.67-day)
# Let's Encrypt IP-address certificate leaves far less slack than a
# conventional 90-day certificate: Certbot's own renewal timer (twice
# daily, renewing at 1/2 of remaining lifetime for validity under 10 days)
# is the actual renewal mechanism and is NOT reimplemented here - this
# script only makes a renewal failure visible on its own, independent of
# whether Certbot itself reported success, by checking the certificate
# Certbot is currently maintaining and failing loudly (non-zero exit, a
# journal error) if too little validity remains. Read-only: never touches
# the certificate, nginx, or any Certbot state.
set -euo pipefail

CERT_PATH="/etc/letsencrypt/live/152.70.43.1/fullchain.pem"
# Renewal normally happens around half of a ~160h lifetime remaining
# (~80h out); 48h is a deliberately tighter trip-wire than that normal
# renewal point, so this only fires when renewal has ALREADY failed to
# happen on schedule, not as an early warning duplicating Certbot's own
# logic.
MIN_REMAINING_HOURS=48

fail() { echo "pocvpn-cert-check: ERROR: $1" >&2; exit 1; }

[ -f "$CERT_PATH" ] || fail "certificate not found at $CERT_PATH"

end_date=$(openssl x509 -enddate -noout -in "$CERT_PATH" 2>/dev/null | sed 's/^notAfter=//') \
    || fail "could not read certificate expiry from $CERT_PATH"

end_epoch=$(date -d "$end_date" +%s 2>/dev/null) \
    || fail "could not parse certificate expiry date: $end_date"
now_epoch=$(date +%s)

remaining_hours=$(( (end_epoch - now_epoch) / 3600 ))

if [ "$remaining_hours" -lt 0 ]; then
    fail "certificate at $CERT_PATH already EXPIRED ($end_date) - renewal has failed, HTTPS provisioning is likely down"
fi

if [ "$remaining_hours" -lt "$MIN_REMAINING_HOURS" ]; then
    fail "certificate at $CERT_PATH expires in ${remaining_hours}h (< ${MIN_REMAINING_HOURS}h safety threshold, expires $end_date) - renewal appears to have failed, investigate 'certbot renew' / journalctl -u pocvpn-cert-check"
fi

echo "pocvpn-cert-check: OK - certificate valid for ${remaining_hours}h more (expires $end_date)"
