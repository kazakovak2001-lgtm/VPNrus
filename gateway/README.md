# POC-01 AmneziaWG gateway

Reproducible, source-pinned AmneziaWG 3.1 gateway: userspace `amneziawg-go` +
`amneziawg-tools` (`awg`/`awg-quick`), systemd, nftables. No kernel module,
no Docker, no floating "latest".

## Exact pins (see `../docs/AWG_GENERATION.md` for the client-side pin)

| Component | Tag | Commit |
|---|---|---|
| `amneziawg-go` | `v3.1.20260814` | `1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1` |
| `amneziawg-tools` | `v3.1.20260812` | `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` |

The `amneziawg-tools` commit is **the exact same submodule commit** the
pinned Android client (`v3.1.20260814`) builds its native tunnel library
against - not an independently-chosen version. `build-awg.sh` refuses to
proceed if the resolved tag does not match these SHAs.

## B5A compatibility audit (read-only, done before writing any gateway code)

Checked the pinned `amneziawg-go` UAPI parser (`device/uapi.go`) and the
pinned `amneziawg-tools` config parser (`src/config.c`) directly against the
Android client's `Interface.java` field set (from B2.6):

`jc/jmin/jmax`, `s1/s2/s3/s4`, `h1/h2/h3/h4`, `i1-i5`,
`header_protection_key`, `content_padding_addition`, `rekey_after_time`,
`rekey_timeout`, `reject_after_time`, `keepalive_timeout`,
`max_handshake_attempts`, `random_trailers`, `disable_cookies` are all
present, verbatim, in both the Go UAPI `case` statements and the C config
parser's `key_match()` branches. **No unsupported fields, no silent
omissions.** Conclusion: **COMPATIBLE**.

Per the pinned `amneziawg-go` README (same commit): only
`HeaderProtectionKey` is documented **server-side** (must be identical on
both ends). `Jc/Jmin/Jmax`, `S1-S4`, `H1-H4`, `I1-I5`,
`ContentPaddingAddition`, and the rekey/timeout/keepalive timing fields are
documented **client-side** (junk/padding/signature packets carry no real
data, so the receiver does not need to know the sender's exact values).
`RandomTrailers`/`DisableCookies` are new in this exact commit and not yet
covered by that README section - they are assumed client-side by analogy
with their sibling fields, not confirmed by documentation; flagged as a
known limitation below.

`gateway/config/awg-profile.env` and
`android/.../vpn/config/PocAwgProfile.kt` declare the identical POC values
anyway, as a POC consistency choice, not because the protocol requires it.

## Layout

```
provision.sh          idempotent top-level orchestrator (run as root)
build-awg.sh           clones/builds/installs the two pinned repos above
config/
  poc.env              addressing/networking (non-secret)
  awg-profile.env       shared POC AWG parameter profile (non-secret)
  awg0.conf.example     placeholder-only interface config template
nftables/
  pocvpn.nft.template   forward+NAT rules, scoped to our own table only
systemd/
  awg-poc.service       based on upstream's own wg-quick@.service template
scripts/
  add-peer.sh           manual peer provisioning (public key + tunnel IP only)
  remove-peer.sh
  status.sh              read-only status, never dumps the private key
lib/
  common.sh              shared bash helpers (validation, templating)
```

## Addressing (config/poc.env)

- Tunnel subnet: `10.77.0.0/24`
- Gateway: `10.77.0.1`
- Listen port: UDP `51820`

## Running

```bash
sudo ./provision.sh          # idempotent - safe to re-run
sudo ./scripts/add-peer.sh <CLIENT_PUBLIC_KEY> 10.77.0.2 android-poc-1
./scripts/status.sh
sudo ./scripts/remove-peer.sh <CLIENT_PUBLIC_KEY>
```

## Idempotence guarantees

- **Server identity**: `provision.sh` only generates a new keypair if
  `/etc/amnezia/amneziawg/awg0.conf` does not already exist. An existing
  config is never overwritten - re-running never silently replaces the
  server's identity.
- **nftables**: the rendered ruleset starts with
  `table inet pocvpn` (create-if-missing) then `delete table inet pocvpn`
  then a full redeclaration - re-running never duplicates rules, and never
  touches any table other than our own.
- **systemd**: `systemctl enable --now` is a no-op on an already
  enabled+running unit.
- **Peers**: `add-peer.sh` rejects a duplicate public key or duplicate
  tunnel IP outright rather than silently overwriting.

## Security

- Server private key is generated **on the VPS** by `provision.sh`
  (`awg genkey`), written only to `/etc/amnezia/amneziawg/awg0.conf` at mode
  `600`, owned by `root:root`. Never logged, never echoed after generation
  (only the derived **public** key is logged, for B6 provisioning).
- `add-peer.sh`/`remove-peer.sh` take a **public key only** - there is no
  parameter for a private key. Note: AmneziaWG/WireGuard public and private
  keys are both 32-byte base64 blobs and are not distinguishable by format
  alone, so this is a procedural safeguard (documented here and in the
  script's own usage text), not a cryptographic one.
- Nothing under `gateway/` that could contain a real secret is committed:
  `.gitignore` excludes `*.conf` (except `*.conf.template`), `gateway/generated/`,
  and `gateway/wg-keys/`. Only placeholder templates and non-secret
  config/profile `.env` files are tracked.
- No management port is opened. The only listening service this gateway
  introduces is the AmneziaWG UDP port itself; nftables rules added here are
  scoped to forwarding/NAT for the tunnel and never touch the host's
  existing input-chain/SSH firewall configuration.
- `status.sh` never dumps the interface config (`awg show` itself never
  prints private keys - that is upstream's own guarantee, not something this
  script adds).

## Known limitations / UNVERIFIED without a real VPS

- **No VPS exists yet for this POC.** Everything above was built and
  exercised inside a local Ubuntu WSL2 environment (real Linux, real
  systemd, real nftables) as the closest available stand-in - see the B5
  report for exactly what was and wasn't exercised there. Real-VPS items
  (public reachability, external IP change observed from an Android client,
  reboot persistence, coexistence with a real host firewall) remain
  UNVERIFIED until a VPS is provisioned (B6+).
- `HeaderProtectionKey` is not configured for POC-01 - it is an additional
  shared secret (generated like a PSK) and requires `S1-S4 >= 12`. Deferred;
  `S1-S4` in the current profile already satisfy that constraint (15/20/15/20)
  in case it is enabled later.
- `RandomTrailers`/`DisableCookies` client/server matching semantics are an
  assumption (see B5A section above), not confirmed by upstream
  documentation for this exact commit.
- No IPv6 tunnel addressing (IPv4-only for POC-01, consistent with the
  addressing scheme above).
- DNS is intentionally out of scope here - reserved for a later slice.
