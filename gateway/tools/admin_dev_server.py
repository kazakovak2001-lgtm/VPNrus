#!/usr/bin/env python3
"""Local-only dev launcher for the pocvpn-api admin endpoints (Linux/WSL).

Runs the REAL handler on 127.0.0.1 against a throwaway state dir
(default ~/.pocvpn-admin-dev). On first start it generates a random admin
password file (0600) and issues a few activations through the real
activations.issue_activation. The password is NEVER printed - read it from
<state-dir>/admin-secret. Not for production: use the systemd deployment.

    python3 gateway/tools/admin_dev_server.py [--state-dir DIR] [--port 8787]
"""
import argparse
import os
import secrets
import string
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api import activations, config as config_module, server  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", default=os.path.expanduser("~/.pocvpn-admin-dev"))
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()

    state = os.path.abspath(args.state_dir)
    os.makedirs(state, mode=0o700, exist_ok=True)
    secret_path = os.path.join(state, "admin-secret")
    if not os.path.exists(secret_path):
        alphabet = string.ascii_letters + string.digits
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("".join(secrets.choice(alphabet) for _ in range(32)) + "\n")

    viewer_path = os.path.join(state, "viewer-secret")
    store = os.path.join(state, "activations.json")
    lock = store + ".lock"
    if not os.path.exists(store):
        activations.init_store(store, lock)
        for max_devices in (1, 2, 3):
            activations.issue_activation(store, lock, max_devices, expires_in_days=30)

    cfg = config_module.AppConfig(
        endpoint_host="127.0.0.1", endpoint_port=51820,
        gateway_public_key="A" * 43 + "=", gateway_tunnel_ip="10.77.0.1",
        token_store_path=os.path.join(state, "tokens.json"),
        token_lock_path=os.path.join(state, ".tokens.lock"),
        provision_script_path="/bin/false", subprocess_timeout_seconds=5.0,
        api_port=args.port, activation_store_path=store, activation_lock_path=lock,
        admin_secret_file=secret_path, admin_enabled=True,
        # Optional read-only role: create <state-dir>/viewer-secret (same format) to enable it.
        admin_viewer_secret_file=viewer_path if os.path.exists(viewer_path) else "",
    )
    srv = server.build_server(cfg)
    print(f"admin dev API on http://127.0.0.1:{args.port}  (password file: {secret_path})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
