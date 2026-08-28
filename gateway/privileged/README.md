# B8B1C2 - privileged root wrapper + sudo boundary

This directory holds the tracked, reviewed *templates* for the privilege
boundary between the non-root `pocvpn-api` HTTP process and the root
mutation of `awg0.conf`. Nothing in this directory is installed to a
system path by this slice - B8B1C3 does that (creates the `pocvpn-api` OS
user, deploys these files with real ownership/mode, installs the systemd
unit). C2 proves the boundary itself: the argv shape, the wrapper, and the
sudoers rule, all under local/WSL-only test harnesses in `tests/`.

## Chain of trust

```
pocvpn-api (non-root)
    | subprocess.run([...], shell=False)   <- gateway/api/provision.py
    v
/usr/bin/sudo -n <wrapper-path> <public-key>
    | sudoers: pocvpn-api -> root, ONE fixed command, env_reset forced
    v
/usr/local/libexec/pocvpn-provision-peer   <- gateway/privileged/pocvpn-provision-peer
    | #!/bin/bash, no sourced files, bash-builtin validation only,
    | then exec /usr/bin/env -i PATH=... LANG=C <fixed-target> <key>
    v
/opt/pocvpn/gateway/scripts/provision-peer.sh   <- unchanged from B8B1A
    | acquires .provision.lock, mutates awg0.conf, converges live state
    v
/etc/amnezia/amneziawg/awg0.conf + systemctl reload
```

Every arrow above is a fixed, absolute path or a fixed argv shape. Nothing
in this chain is chosen at runtime by the non-root caller.

## What pocvpn-api must NEVER do

- Become root.
- Read `awg0.conf` (durable peer state, and the interface's own
  `PrivateKey =` line live in that same file).
- Read the gateway's AmneziaWG/WireGuard server private key by any path.
- Acquire `.provision.lock` - only `provision-peer.sh`, running as root
  inside the exec chain above, ever takes that flock.
- Execute an arbitrary root command - sudoers grants exactly one fixed
  command path, nothing else.
- Choose the wrapper's target script path - `pocvpn-provision-peer`
  hardcodes it as a shell `readonly` literal, never read from an
  environment variable, argument, or config file.

`gateway/api/provision.py` and `gateway/api/handler.py` already hold to
this (see their own docstrings/comments) - this directory is what makes
the *next* hop (root) hold to it too.

## File-ownership invariant (documented now, enforced by B8B1C3)

Every file root executes or reads in the chain above must be
**non-writable by `pocvpn-api`**:

```
/usr/local/libexec/pocvpn-provision-peer
/opt/pocvpn/gateway/scripts/provision-peer.sh
/opt/pocvpn/gateway/lib/common.sh
/opt/pocvpn/gateway/lib/peer_mutations.sh
/opt/pocvpn/gateway/config/*
```

If `pocvpn-api` could write any of these, the sudo boundary above would be
decorative: a non-root process that can edit the very script root is about
to run has already achieved code execution as root. C2 does not install
these files or set that ownership anywhere real - it only documents the
requirement and builds tests (`tests/run_sudo_tests.sh`, checks 22-26)
that prove a disposable test identity *cannot* violate it against an
isolated fixture tree, as a rehearsal for what B8B1C3's real installation
must guarantee.

## Known future requirement - NOT solved here (B8B1C3)

`ProtectSystem=strict` in a systemd unit sandbox also constrains
descendants, including a root child launched through `sudo` from inside
that unit. There is no production `pocvpn-api` systemd service yet (that
is also B8B1C3), so this does not apply to anything C2 installs - but
whoever writes that unit must explicitly design the sandbox so the root
`provision-peer.sh` descendant can still write
`/etc/amnezia/amneziawg/awg0.conf`, while Unix DAC permissions continue to
prevent the `pocvpn-api` service's own (non-root) process from writing
there directly. Do not add a blanket writable exception to make this
"easier" - scope it to exactly the one path the root child needs.

## Testing approach (see `tests/`)

- `tests/run_wrapper_tests.sh` - the wrapper's own logic, invoked directly
  (no sudo, no root required), against an isolated fixture tree reusing
  the same fake-`awg`/fake-`systemctl` pattern as
  `gateway/scripts/tests/run_tests.sh`. A **test copy** of the wrapper
  (the tracked file above, byte-identical except for one substituted
  constant) points `PROVISION_SCRIPT` at the fixture instead of
  `/opt/pocvpn/...` - the tracked production wrapper itself is never
  parameterized or edited for this; see that script's own header comment
  for why (option B from the B8B1C2 handoff: a purpose-built test copy,
  not a runtime-configurable target in the real wrapper).
- `tests/run_sudo_tests.sh` - the real sudo boundary, using a disposable
  `pocvpn-c2-test` OS user, a disposable `/etc/sudoers.d/pocvpn-c2-test`
  drop-in, and a disposable root-owned fixture tree under `/tmp` - never
  `/opt/pocvpn`, never the real gateway. Every artifact this script
  creates is removed in a `trap ... EXIT` cleanup, on success or failure.
  If `sudo`/`visudo`/`useradd` are unavailable, or the test cannot safely
  run, checks are marked SKIPPED with an explicit reason - never silently
  reported as passing.
