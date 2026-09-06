# B37 - Russia field-test build, AWG 3.1 generation (FIELD_TEST_ONLY)

**Nothing server-side in this document has been applied.** Supersedes
`docs/FIELD_TEST_RUSSIA.md` for the actual AWG generation this build now
exercises - that document's UX/routing/diagnostics description is still
accurate, only the AWG identity/gateway/profile changed.

## Why

The B36 field-test APK (docs/FIELD_TEST_RUSSIA.md) proved registration/
provisioning is NOT the blocker for the target restricted Russian network:
the same build worked outside Russia (Frankfurt handshake, health, PROTECTED)
and failed inside Russia at exactly the AWG transport/handshake step
(Frankfurt timeout -> Stockholm fallback -> timeout ->
ALL_CANDIDATES_EXHAUSTED). This build tests whether the current AmneziaWG
3.1 generation's obfuscation (junk-before-handshake packets I1-I5, header
protection) connects where the prior profile did not.

## Phase 1 audit result (see PR description / task report for full detail)

- Android client: already vendors and wires a REAL, complete AWG 3.1 client
  (`amneziawg-android` v3.1.20260814, `AwgConfigMapper`/`AwgProfile` already
  expose every 3.1 field: I1-I5, `HeaderProtectionKey`,
  `ContentPaddingAddition`, rekey/timeout fields) - the gap was that no
  gateway descriptor actually POPULATED those fields; `ProductionGatewayCatalog`
  only ever set the older Jc/Jmin/Jmax/S1-S4/H1-H4 subset.
- Server: `gateway/build-awg.sh`/`gateway/README.md` already pin and
  cross-verify the SAME v3.1.20260814-generation `amneziawg-go`/
  `amneziawg-tools` - real AWG 3.1 binaries, not a legacy stand-in.
- **PATH B selected** (isolated interface), not PATH A (in-place peer on
  the shared `awg0`): this repo's own history
  (`PocAwgProfile`'s "B8B3B correction") already found a case where a
  documented "client-side only, no need to match" classification for
  S1-S4/H1-H4 was WRONG for the live server. The newly-enabled 3.1 fields
  (`HeaderProtectionKey` especially - an INTERFACE-level setting shared by
  every peer) carry the same classification risk; enabling them on shared
  production `awg0` would risk silently breaking every existing production
  peer if wrong. An isolated interface removes that risk: only this one
  field-test peer is at stake.

## What this is (delta over docs/FIELD_TEST_RUSSIA.md)

- Same `fieldTest` build type, same UX, same Frankfurt-first/Stockholm-
  fallback routing, same real-handshake+health-check proof, same diagnostics/
  report/Share mechanism.
- `FieldTestAwg31Identity` (NEW) - a fresh, dedicated Curve25519/X25519
  keypair, NOT a reuse of `FieldTestIdentity` (B36) or any production/B36-
  bootstrap identity, because it is provisioned on a DIFFERENT server-side
  interface/subnet.
- `FieldTestAwg31GatewayCatalog` (NEW) - Frankfurt/Stockholm gateway facts
  for the ISOLATED `awg-ft31` interface (see below), never
  `ProductionGatewayCatalog` (which remains completely untouched).
- `FieldTestTunnelController` gained a `gatewayLookup`/`awgGeneration`
  constructor param (default: unchanged legacy behavior, for every existing
  test) - `FieldTestViewModel` is the ONE place that switches it to
  `FieldTestAwg31GatewayCatalog`/`AwgGeneration.AWG_3_1`.
- Diagnostics gained `awg_generation`/`endpoint_host`/`endpoint_port`/
  `handshake_timeout_ms` tags and `FieldTestReport.awgGeneration` - a report
  now provably says `AWG_3_1`, not merely "AmneziaWG".

## Isolated AWG 3.1 field-test interface

| Fact | Value |
|---|---|
| Interface name | `awg-ft31` (never production `awg0`) |
| UDP port | `51821` (never production `51820`) |
| Subnet | `10.77.31.0/24` (never production `10.77.0.0/24`) |
| Gateway tunnel IP | `10.77.31.1` |
| Field-test client tunnel IP | `10.77.31.2/32` |
| systemd unit | `awg-poc-ft31.service` (never `awg-poc.service`) |
| nftables table | `inet pocvpn-ft31` (never `inet pocvpn`) |

New AWG 3.1 parameters actually turned on for the first time in this
codebase (never enabled on production `awg0`):

- `I1`-`I5` (junk packets sent before the handshake init message) - tag
  syntax (`<r N>` = N random bytes, `<t>` = a UNIX timestamp field) per the
  pinned `amneziawg-go` README.
- `HeaderProtectionKey` (a shared secret, like a PSK) + `ContentPaddingAddition`.

`Jc/Jmin/Jmax`/`S1-S4`/`H1-H4` reuse the ORIGINALLY-declared POC-01 values
from `gateway/config/awg-profile.env` (not the live-drifted values
`PocAwgProfile` had to correct to for the already-running `awg0` - this is a
brand-new interface with no drift history).

## Field-test identity

```
FIELD_TEST_AWG31_PUBLIC_KEY_BASE64 = Pue7LA2UDHl6dfCmXnpLhV6P4q667O3GRAKqe8W7lVY=
CLIENT_TUNNEL_ADDRESS_CIDR         = 10.77.31.2/32
```

(Private key embedded in the disposable APK - see
`FieldTestAwg31Identity.kt`; same non-secrecy posture as B36.)

## Server-side setup (NOT YET APPLIED - requires owner approval)

See the B37 task report for the exact `provision-ft31.sh` invocation per
gateway (server private key / HeaderProtectionKey are real, freshly
generated values reported there only, never committed to this repository).

### Rollback (either host)

```bash
cd /opt/pocvpn/gateway
sudo ./rollback-ft31.sh
```

Stops/disables `awg-poc-ft31.service`, deletes the isolated `inet
pocvpn-ft31` nftables table, archives (never deletes outright)
`/etc/amnezia/amneziawg/awg-ft31.conf`. Never touches `awg0`,
`awg-poc.service`, or `inet pocvpn`.

## What this explicitly does NOT do

- Does not touch PR #60/B36, does not merge PR #61.
- Does not change registration/provisioning/activation.
- Does not change Xray/REALITY.
- Does not modify `ProductionGatewayCatalog`, `awg0.conf`, `awg-poc.service`,
  or the production `inet pocvpn` nftables table on either gateway.
- Does not deploy anything server-side by itself - the commands in the task
  report are reported only, per this repository's merge/infra-safety rule.
