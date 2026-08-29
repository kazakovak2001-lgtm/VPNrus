#!/usr/bin/env bash
# B8K2 - generates a REAL REALITY X25519 keypair using the pinned Xray
# binary's OWN key-generation subcommand - never a fabricated/hand-rolled
# string. Verified this slice against the actual pinned binary:
#
#   $ xray x25519
#   usage: xray x25519 [-i "private key (base64.RawURLEncoding)"] [--std-encoding]
#   PrivateKey: <43-char base64.RawURLEncoding>
#   Password (PublicKey): <43-char base64.RawURLEncoding>
#   Hash32: <ignored - not used by this repo>
#
# Output contract (stdout, machine-parsable, nothing else on stdout):
#   PRIVATE_KEY=<value>
#   PUBLIC_KEY=<value>
#
# The private key is printed to stdout ONCE, by design (this script's only
# job) - the CALLER is responsible for immediately writing it to a
# permission-restricted location and never logging this script's own
# stdout. This script itself never writes any file and never logs.
#
#   bash gateway/xray/scripts/generate-reality-keys.sh /opt/pocvpn/xray/v26.7.28/xray
set -euo pipefail

XRAY_BIN="${1:?usage: generate-reality-keys.sh <path-to-pinned-xray-binary>}"

if [ ! -x "$XRAY_BIN" ]; then
    echo "ERROR: $XRAY_BIN is not an executable file" >&2
    exit 1
fi

output="$("$XRAY_BIN" x25519)"

private_key="$(printf '%s\n' "$output" | sed -n 's/^PrivateKey: //p')"
public_key="$(printf '%s\n' "$output" | sed -n 's/^Password (PublicKey): //p')"

if [ -z "$private_key" ] || [ -z "$public_key" ]; then
    echo "ERROR: could not parse 'xray x25519' output - binary output format may have changed:" >&2
    echo "$output" >&2
    exit 1
fi

printf 'PRIVATE_KEY=%s\n' "$private_key"
printf 'PUBLIC_KEY=%s\n' "$public_key"
