#!/usr/bin/env python3
"""Run the local admin hub: a read-only aggregate view over several gateways.

The hub runs on the operator's machine and reaches each gateway's admin API
through an SSH tunnel to loopback, for example:

    ssh -N -L 18787:127.0.0.1:<api port> frankfurt

then list the tunnel in a registry file (see gateway/admin_hub/registry.py)
and start:

    python3 gateway/tools/run_admin_hub.py --registry ~/.pocvpn-hub/nodes.json [--port 8790]

It logs in to every node with that node's read-only viewer secret only, binds
to 127.0.0.1 and never prints secrets.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from admin_hub import client, registry, server  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", required=True, help="path to the node registry JSON")
    ap.add_argument("--port", type=int, default=8790)
    args = ap.parse_args()

    try:
        nodes = registry.load_registry(os.path.abspath(os.path.expanduser(args.registry)))
    except registry.RegistryError as exc:
        print(f"run_admin_hub: registry error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    srv = server.HubServer(args.port, client.Hub(nodes))
    print(f"admin hub on http://127.0.0.1:{args.port}{server.PATH_NODES} ({len(nodes)} node(s))")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
