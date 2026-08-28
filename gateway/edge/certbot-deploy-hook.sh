#!/bin/bash
# B8B2A - Certbot deploy hook, installed under the standard
# /etc/letsencrypt/renewal-hooks/deploy/ mechanism and run automatically by
# `certbot renew` after ANY successful renewal for ANY certificate on this
# host - not only pocvpn's. Deliberately does the smallest possible thing:
# Certbot's own nginx plugin does not support IP-address certificates (see
# gateway/edge/nginx-pocvpn.conf's header comment), so nginx never learns
# about a renewed cert on its own - this hook is what makes it pick up the
# new files from disk.
#
# `nginx -t` runs first and its failure aborts the reload: a renewed
# certificate is already safely on disk at this point (Certbot's own
# atomic replace already happened), so refusing to reload on a config
# error leaves the OLD (still valid, if older) certificate serving rather
# than risking nginx failing to start on a reload.
set -euo pipefail

nginx -t
systemctl reload nginx
