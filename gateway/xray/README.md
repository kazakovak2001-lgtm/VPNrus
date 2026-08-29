# B8K2 - Nova Xray VLESS+REALITY server foundation

Repository-side foundation only. **Nothing in this directory has been
deployed to Oracle.** No SSH, no live server, no real credentials. See
`docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md`/`docs/B8K0_RUNTIME_AUDIT.md` for the
Android-side counterpart this is designed to eventually serve.

## Layout

```
VERSION                       pinned release asset + verified sha256
fetch-xray-server.sh          reproducible download+verify+install (not run yet)
scripts/
  generate-reality-keys.sh    real key generation via the pinned binary's
                               own `xray x25519` subcommand - verified this
                               slice against the actual downloaded binary,
                               never a fabricated string
```

Server-side Python (in `gateway/api/`, not this directory, since it's part
of the same authenticated API process):
- `xray_provisioning.py` - durable per-device VLESS identity store,
  extending the existing B8C1 activation/device-binding model
- `xray_config_renderer.py` - deterministic canonical-state -> Xray config
  renderer, atomic write, pluggable validation hook

Systemd unit: `gateway/systemd/nova-xray.service`.

## Why the same xray-core family as Android

Reuses `v26.7.28` / `5ca6f4b7d4dc20a881d4330e498892697627ec0c` - the exact
commit already pinned for `third_party/xray/VERSION` (the Android
AndroidLibXrayLite build). One codebase's worth of VLESS+REALITY wire
behavior to reason about, not two independently-drifting pins.

Unlike the Android side (which builds AndroidLibXrayLite from source via
gomobile), the server uses the **official upstream release binary**
directly - `xray-core` ships real, checksummed Linux binaries and there is
no Android-specific wrapper needed server-side. This is a pinned,
checksum-verified download (see VERSION), never a `curl | sh` installer.

## Listener architecture and port choice

Current gateway occupancy (from the existing `gateway/` tree, not
guessed):
- nginx: public TCP `80` (ACME only) and `443` (HTTPS, proxies `/v1/peers`
  to `pocvpn-api` on `127.0.0.1:8443`)
- AmneziaWG: public UDP `51820`
- `pocvpn-api`: `127.0.0.1:8443` only (never public directly)

**REALITY cannot sit behind nginx.** REALITY works by having the Xray
process itself terminate the real TLS ClientHello at the TCP level and
impersonate a real site's handshake - it is not an HTTP reverse-proxy
target, and putting nginx in front of it (SNI-routing or otherwise) would
either break REALITY's own camouflage or require modifying nginx's `443`
vhost, which this slice is explicitly told not to touch.

**Chosen listener: a separate public TCP port, `2053`.** Rationale:
- Does not collide with nginx (`80`/`443`), AWG (UDP `51820`), or the
  API's loopback-only `8443`.
- `2053` is a commonly-documented, plausible port for legitimate
  HTTPS-adjacent services (unlike an obviously proxy-flavored port) - not
  itself a censorship-resistance claim (see below), just a reasonable,
  non-arbitrary choice that avoids advertising "this is a proxy port" to a
  casual observer.
- A single new port is what the B8K2 instructions call "acceptable for
  the first live proof" - this is not a final production port allocation
  decision, and changing it later is a config value, not an architecture
  change (`RealityServerConfig.listen_port` / `AppConfig.xray_server_port`
  are both plain configuration, read from environment/config file).

**No censorship-resistance claim is made from the port number alone.**
REALITY's actual camouflage comes from the TLS handshake impersonation
itself (a real `dest`/`serverNames` target, e.g. `www.microsoft.com:443`),
not from which port it listens on.

## Firewall / Oracle security-list change required (NOT YET APPLIED)

Before any real listener can be deployed, add exactly one new inbound
rule to the Oracle Cloud instance's security list (or the equivalent
`iptables`/`nftables` input-chain rule, whichever this host actually
enforces ingress with - see the "Known limitations" note in
`gateway/README.md` about this repo's `gateway/nftables/` template being
forward/NAT-only, not an input-chain firewall):

```
Ingress: TCP 2053, source 0.0.0.0/0 (or a narrower CIDR if the operator
prefers a soft-launch allowlist), destination: this instance.
```

This slice makes **no** change to Oracle, no security-list edit, no
`iptables`/`nftables` input-chain rule - this section exists so that
change is explicit and reviewable before anyone applies it, not
discovered by a failed connection later.

## Key management model

- **Private key**: generated ONLY via the real pinned `xray x25519`
  binary (`scripts/generate-reality-keys.sh`) - never fabricated by
  Python or hand-typed. Stored ONLY inside the rendered Xray server
  config file (`gateway/api/xray_config_renderer.py`'s output), at
  filesystem mode `0600`, owned by the `nova-xray` service account (see
  `nova-xray.service`). **The `pocvpn-api` HTTP process never reads,
  holds, or transmits this value at all** - `AppConfig` (see
  `gateway/api/config.py`) only carries the derived PUBLIC key
  (`xray_reality_public_key`), which is safe by design to hand to
  clients. There is no code path in this repository, in either process,
  that could log the private key, because neither process's normal
  operation ever loads it into a variable that isn't immediately
  written to the 0600 config file (`xray_config_renderer.py`) or never
  read at all (`pocvpn-api`).
- **Public key / serverName / fingerprint / shortId**: operator-chosen,
  public-by-design values, configured into `pocvpn-api` via
  `POCVPN_API_XRAY_*` environment variables (see `config.py`) and
  returned verbatim to authenticated, eligible clients by
  `POST /v1/xray-profile`.
- **Per-device VLESS UUID**: generated server-side, one per (activation,
  device), via Python's `uuid.uuid4()` (a real, standard-library RFC 4122
  v4 generator - not fabricated ad hoc) - see `xray_provisioning.py`. The
  client never sends or chooses its own UUID.

## Security

- Never logged: the REALITY private key (never held by the logging
  process at all - see above), the raw activation credential (same rule
  `activations.py` already enforces), and this slice avoids logging the
  full per-device VLESS UUID in `pocvpn-api`'s own request log (only an
  `xray_outcome` field and the existing `pubkey_prefix`/
  `activation_digest` truncated fields are logged - see `handler.py`).
- `xray_config_renderer.atomic_write_config` always writes the rendered
  config at `0600` regardless of any prior file's mode (unlike
  `activations.py`'s stores, which preserve an existing file's mode -
  this file always contains a real secret, so there is no "restore the
  prior, possibly-safe mode" case to preserve).
- `nova-xray.service` runs as a dedicated, non-root `nova-xray` system
  account with `ProtectSystem=strict` and no writable paths at all (see
  that unit file's own comments for why this is stricter than
  `pocvpn-api.service`).
