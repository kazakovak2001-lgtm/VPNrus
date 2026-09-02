#!/usr/bin/env python3
"""B25 (task H) - operator tool: mints ONE dedicated ingress->exit relay
identity (a VLESS UUID, never a shared/global plaintext credential, never
committed to this repository - task requirement 9's own "authenticated on
EXIT, never source-IP-only trust").

This script deliberately does NOT touch a live EXIT process - see this
module's own docstring and PROJECT_ARCHITECTURE.md's infra-safety
invariant ("never make destructive production changes without explicit
owner approval"). It only:

  1. generates a fresh UUID;
  2. writes it to a local file (mode 0600) at the path the INGRESS host's
     own NOVA_INGRESS_UPSTREAM_UUID_FILE env var must point at - this file
     is what api/ingress_activation.py's build_upstream_config() reads at
     render time, transiently, never logging or returning it (task H's
     own "never printed in diagnostics/PR/tests" - this script itself
     also never prints the uuid to stdout, only confirms the file was
     written and its byte length);
  3. writes a SEPARATE "exit fragment" JSON file describing the
     RenderedClient the EXIT operator must add to their own
     static_clients=(...) argument to xray_config_renderer.render_server_config
     (see that function's own B25 docs) - the uuid appears in this second
     file too (it must, for the EXIT operator to actually apply it), so
     BOTH output files must be treated as secrets: transferred to their
     respective hosts out-of-band (e.g. scp over an already-authenticated
     channel), never committed, never pasted into a PR/issue/chat;
  4. (B26, task B/C) generates a fresh probe HMAC secret and writes it to a
     THIRD local file at the path the INGRESS host's own
     NOVA_INGRESS_PROBE_HMAC_SECRET_FILE env var must point at - the SAME
     bytes must ALSO end up on the pinned EXIT host's own
     POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE (its hex form is included in
     the exit-fragment file below purely so the operator has exactly one
     thing to copy - see relay_probe_token.py's own docs for what this
     secret is used for and why a stolen probe token alone cannot grant
     VPN access).

Applying the exit-fragment file to a live EXIT (adding it to that
deployment's own xray_activation.py wiring so render_server_config
actually receives it as static_clients) is a deliberate, separate,
human-reviewed step this script does not automate - see this codebase's
own "never mutate production without approval" rule.

    provision_relay_upstream_identity.py \\
        --ingress-endpoint-id ru-ingress-1 \\
        --upstream-uuid-file /etc/pocvpn/ingress/upstream-relay-uuid.txt \\
        --exit-fragment-file /tmp/ru-ingress-1-exit-fragment.json \\
        --probe-hmac-secret-file /etc/pocvpn/ingress/probe-hmac-secret.txt
"""
import argparse
import json
import os
import secrets
import stat
import sys
import uuid


def _fail(message):
    print(f"provision_relay_upstream_identity: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _write_secret_file(path, content):
    if os.path.exists(path):
        _fail(f"refusing to overwrite an existing file: {path} (remove it first if you intend to rotate)")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    except BaseException:
        os.unlink(path)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="provision_relay_upstream_identity.py",
        description="B25 (task H) - mint a dedicated ingress->exit relay identity",
    )
    parser.add_argument("--ingress-endpoint-id", required=True, help="the ingress endpoint id this identity is FOR (label only, non-secret)")
    parser.add_argument("--upstream-uuid-file", required=True, help="output path for the ingress host's NOVA_INGRESS_UPSTREAM_UUID_FILE")
    parser.add_argument("--exit-fragment-file", required=True, help="output path for the EXIT-side static-client fragment (JSON)")
    parser.add_argument(
        "--probe-hmac-secret-file", required=True,
        help="output path for the INGRESS host's own NOVA_INGRESS_PROBE_HMAC_SECRET_FILE (B26 task B/C)",
    )
    args = parser.parse_args(argv)

    relay_uuid = str(uuid.uuid4())
    probe_hmac_secret_hex = secrets.token_hex(32)

    _write_secret_file(args.upstream_uuid_file, relay_uuid + "\n")
    mode = stat.filemode(os.stat(args.upstream_uuid_file).st_mode)
    print(f"provision_relay_upstream_identity: wrote {args.upstream_uuid_file} (mode {mode}) - transfer to the INGRESS host, never commit it")

    _write_secret_file(args.probe_hmac_secret_file, probe_hmac_secret_hex + "\n")
    probe_mode = stat.filemode(os.stat(args.probe_hmac_secret_file).st_mode)
    print(f"provision_relay_upstream_identity: wrote {args.probe_hmac_secret_file} (mode {probe_mode}) - transfer to the INGRESS host, never commit it")

    fragment = {
        "comment": (
            "B25 (task H) exit-side static-client fragment. Apply by adding a "
            "RenderedClient(activation_id=activation_id, device_public_key=device_public_key, "
            "vless_uuid=vless_uuid) to the EXIT deployment's own static_clients=(...) argument "
            "when it calls xray_config_renderer.render_server_config - a deliberate, human-reviewed "
            "change to that deployment's own activation wiring, never automated by this script."
        ),
        "activation_id": f"relay-{args.ingress_endpoint_id}",
        "device_public_key": f"relay:{args.ingress_endpoint_id}",
        "vless_uuid": relay_uuid,
        "relay_probe_hmac_secret_hex": probe_hmac_secret_hex,
        "relay_probe_hmac_secret_apply_note": (
            "Write this EXACT hex string (as raw text, e.g. `echo -n '<hex>' > path`) to a file on the "
            "EXIT host and point that host's POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE at it - it must be "
            "byte-for-byte identical to the ingress host's own NOVA_INGRESS_PROBE_HMAC_SECRET_FILE contents."
        ),
    }
    _write_secret_file(args.exit_fragment_file, json.dumps(fragment, indent=2) + "\n")
    print(f"provision_relay_upstream_identity: wrote {args.exit_fragment_file} - transfer to the EXIT operator, never commit it")
    print("provision_relay_upstream_identity: done. No secret was printed to stdout/logs.")


if __name__ == "__main__":
    main()
