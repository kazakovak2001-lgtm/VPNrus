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

## Firewall model (corrected after senior review)

The isolated `awg-ft31` interface gets its own NAT-only nftables table
(`inet pocvpn-ft31`, `nat postrouting` hook, `policy accept`) - it
deliberately declares **no** `forward`/filter base chain. A separate
`forward` chain with its own policy (drop or otherwise) at the same hook as
production's forwarding chain would NOT be isolated: netfilter evaluates
every base chain registered at a hook, across every nftables table and
legacy iptables-nft compat rules, for every packet - an ACCEPT verdict in
one chain never makes a DROP verdict (or a policy drop) in another base
chain at the same hook irrelevant. The first version of this template got
this wrong (see PR review) - fixed by removing the `forward` chain entirely
and instead inserting exactly two narrowly-scoped, tagged (`b37-ft31`)
ACCEPT rules directly into each host's OWN, already-verified, real
production forwarding path:

| Host | Real production forwarding backend | Where the 2 b37-ft31 rules go |
|---|---|---|
| Frankfurt | `iptables-nft` (legacy iptables syntax, nft_tables backend), `FORWARD` chain, awg0/ens3 accepts + a final REJECT/DROP | Inserted at the TOP of `FORWARD` via `iptables -I FORWARD 1 ...` (an ACCEPT for non-overlapping `awg-ft31`/`ens3` traffic is behaviorally identical wherever it sits before the final reject) |
| Stockholm | native nftables, `inet pocvpn` table, `forward` chain, `policy drop` | Inserted directly into the EXISTING `inet pocvpn forward` chain via `nft insert rule` |

`gateway/lib/ft31_forward_rules.sh` implements this: `ft31_verify_runtime`
fails closed (dies, zero mutation) unless the LIVE runtime actually matches
every expected fact for the declared `--host` (egress interface name,
firewall backend, existing awg0 rule presence, terminal reject/policy
drop) - never trusts the host argument alone. `provision-ft31.sh` snapshots
the full ruleset before and after mutation and dies if any pre-existing
rule was removed or reordered relative to the others (only additions are
ever possible). `rollback-ft31.sh` removes only the two `b37-ft31`-tagged
rules (found by exact spec/comment match) and verifies the post-rollback
ruleset is an exact subset of the pre-rollback one, in the same order.

## Secret handling (corrected after senior review)

The server's own `awg-ft31` private key and the shared `HeaderProtectionKey`
are generated ON EACH SERVER by `provision-ft31.sh` itself, via `awg
genkey`, at deploy time - never accepted as a script input, never echoed to
stdout, never written to shell history, never passed as a literal
command-line argument. Only the derived PUBLIC key is printed (non-secret).
`HeaderProtectionKey` has no public half (it is shared-secret material, not
a keypair) - the operator retrieves it themselves, directly from that
server's own `/etc/amnezia/amneziawg/awg-ft31.conf` (`sudo grep
'^HeaderProtectionKey' ...`), and pastes it into
`FieldTestAwg31GatewayCatalog.kt` before rebuilding the field-test APK -
never relayed through Claude, a report, a ticket, or a log. The placeholder
values currently committed in `FieldTestAwg31GatewayCatalog.kt`
(`REPLACE_BEFORE_DEPLOY_...`) are deliberately not valid key material.

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

```bash
cd /opt/pocvpn/gateway
sudo FT31_CLIENT_PUBLIC_KEY=<this build's public key> \
     FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
     ./provision-ft31.sh frankfurt   # or: stockholm
```

No private key or `HeaderProtectionKey` is ever passed in - both are
generated locally on that server by the script itself (see "Secret
handling" above). The run prints the server's own public key at the end;
copy it into `FieldTestAwg31GatewayCatalog.kt`, retrieve
`HeaderProtectionKey` yourself directly from that server's config file, and
rebuild the APK before this build can actually handshake.

### Rollback (either host)

```bash
cd /opt/pocvpn/gateway
sudo ./rollback-ft31.sh frankfurt   # or: stockholm
```

Removes the two `b37-ft31` FORWARD accept rules from that host's real
production forwarding path, stops/disables `awg-poc-ft31.service`, deletes
the isolated `inet pocvpn-ft31` NAT table, archives (never deletes
outright) `/etc/amnezia/amneziawg/awg-ft31.conf`. Never touches `awg0`,
`awg-poc.service`, or `inet pocvpn`.

## What this explicitly does NOT do

- Does not touch PR #60/B36, does not merge PR #61.
- Does not change registration/provisioning/activation.
- Does not change Xray/REALITY.
- Does not modify `ProductionGatewayCatalog`, `awg0.conf`, `awg-poc.service`,
  or the production `inet pocvpn` nftables table on either gateway.
- Does not deploy anything server-side by itself - the commands in the task
  report are reported only, per this repository's merge/infra-safety rule.

## PREDEPLOY GATE (senior-review pass, B37 correctness audit) - hard blockers

`provision-ft31.sh` can only prove the LOCAL host firewall/NAT/systemd state
is correct. It cannot see, and does not attempt to fabricate, either
cloud-provider's ingress control plane. **Both of the following must be
confirmed TRUE, on the real host/console, before any real-world test
attempt is meaningful** - until then this field test's status is
**NO-GO**, regardless of what the local script reports:

1. **Frankfurt (Oracle Cloud)** - the VCN security list / NSG attached to
   this instance's subnet must allow inbound **UDP 51821** from `0.0.0.0/0`
   (or at minimum from the field-test device's expected egress range).
   Verify in the OCI console (Networking -> Virtual Cloud Networks -> the
   instance's subnet -> Security Lists/Network Security Groups) - never
   inferred from the host's own `iptables`/`nft` state, which this script
   already verifies separately and which says nothing about the provider's
   own edge firewall.
2. **Stockholm (AWS)** - the EC2 Security Group (and any NACL) attached to
   this instance must allow inbound **UDP 51821** from `0.0.0.0/0` (or the
   expected range). Verify in the EC2 console (Security Groups / Network
   ACLs) - same reasoning as above.

Neither of these can be verified or changed by any script in this
repository, and none should ever be mutated automatically (this repo's own
merge rule: never allocate/change cloud infrastructure without explicit
owner approval). Confirm both manually, then re-state GO/NO-GO explicitly.

### Host-level UDP 51821 INPUT (in addition to the provider gate above)

The local FORWARD-path additions this script makes (see
`lib/ft31_forward_rules.sh`) let traffic that already reached the host be
forwarded into `awg-ft31` - they say nothing about whether inbound UDP
51821 packets are accepted by the host's own INPUT chain in the first
place. Before deploying, separately audit each host's live INPUT
chain/policy (`iptables -S INPUT` on Frankfurt / `nft list chain inet
pocvpn input` or equivalent on Stockholm, read-only) for whether a new
port needs an explicit allow, exactly as already required for the existing
production `51820` listener - add a narrowly-scoped, `b37-ft31`-tagged
INPUT rule only if that audit shows one is actually needed, following the
same fail-closed preflight discipline as the FORWARD rules; do not add one
speculatively, and do not weaken any other INPUT rule/policy.

## Distinguishing a REAL AWG 3.1 block from a mundane reachability/config
## problem (task E1) - read this BEFORE calling a failed attempt "blocked"

The legacy field test used UDP 51820; this one uses **51821 AND** the full
AWG 3.1 parameter set. A failure on this build proves NOTHING about AWG 3.1
specifically unless the server side can show WHERE in the pipeline the
attempt actually stopped. After any real attempt, gather this evidence on
the gateway (read-only, no payload/secret logging):

1. **Did any UDP packet reach port 51821 at all?**
   - Frankfurt: `sudo iptables -L INPUT -v -n | grep 51821` (packet counter
     increasing across attempts) or a brief, bounded
     `sudo timeout 30 tcpdump -ni ens3 udp port 51821 -c 5` (counts/headers
     only - never `-A`/payload capture).
   - Stockholm: `sudo nft list chain inet pocvpn-ft31 postrouting` packet
     counters (add `counter` to the rule first if not already present) or
     the same bounded `tcpdump -ni ens5 udp port 51821 -c 5`.
   - Zero packets ever seen -> **reachability/provider/port-filtering
     problem** (go re-check the PREDEPLOY GATE above first) - NOT evidence
     of protocol detection.
2. **Did packets arrive but no valid AWG handshake completed?**
   - `sudo awg show awg-ft31` on the gateway, before/after an attempt -
     `latest handshake` staying absent/stale despite (1) showing packets
     arriving -> **protocol/config/handshake problem** (verify the profile
     in `config/awg-ft31-profile.env` matches `FieldTestAwg31GatewayCatalog.kt`
     exactly, and that the correct `HeaderProtectionKey` was pasted in).
3. **Did the handshake succeed but the client's own health/data-plane probe
   still failed?**
   - `sudo awg show awg-ft31` shows a fresh handshake, but the client
     report's `outcome` is `FAILED` with `failureCategory=HEALTH_CHECK_FAILED`
     -> **forwarding/NAT/DNS/Internet problem** on the gateway
     (`nft list table inet pocvpn-ft31`, confirm `masquerade` and the two
     `b37-ft31` FORWARD rules are present via
     `iptables -S FORWARD`/`nft list chain inet pocvpn forward`), not a
     protocol-detection result either.

**Only a case that clears (1) and (2) but is then reproducibly blocked
in a way that isn't (3) is any kind of evidence toward "AWG 3.1 was
detected/blocked"** - and even then, a single field test is anecdotal, not
proof.
