"""B8B1B: authenticated localhost provisioning API (stdlib only).

Architectural invariant (see gateway/README.md and the B8B1B design notes):
this package NEVER parses/mutates awg0.conf, NEVER allocates tunnel IPs
itself, and NEVER acquires .provision.lock. The only gateway mutation
boundary it is allowed to cross is invoking
gateway/scripts/provision-peer.sh as an external subprocess and treating
its stdout/exit-code as an opaque machine protocol (see provision.py).
"""
