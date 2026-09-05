# B36 - exact server-side deployment plan (bootstrap pre-activation tunnel)

**Nothing in this document has been executed. Do not run any command below
against Frankfurt or Stockholm without the repository owner's explicit
go-ahead, per this repository's merge/infra-safety rule.** This plan exists
so that approval, once given, can be carried out mechanically and reviewed
in advance - not to authorize itself.

**Correction (2026-09-05 follow-up):** an earlier version of this document
incorrectly assumed both gateways share one identical firewall/systemd
runtime (both native nftables, both provisioned by `gateway/provision.sh`
end to end). **Verified against each host directly, this is false** -
Frankfurt and Stockholm run genuinely different firewall implementations
for their existing production AWG forwarding/NAT. Everything below is now
runtime-specific; the bootstrap identity and the additive restriction
table's own *shape* remain identical on both (see "One shared design, two
production runtimes" below).

## Phase 1 - verified runtime facts (per host, not assumed)

| Fact | Frankfurt (`152.70.43.1`) | Stockholm (`16.170.208.231`) |
|---|---|---|
| AWG interface | `awg0` | `awg0` |
| AWG listener | UDP `51820` | UDP `51820` |
| Durable AWG config | `/etc/amnezia/amneziawg/awg0.conf` | `/etc/amnezia/amneziawg/awg0.conf` |
| AWG runtime owner (systemd) | **`awg-quick@awg0.service`** | this repository's own `awg-poc.service` (`gateway/systemd/awg-poc.service`) |
| Firewall implementation | **iptables-nft compatibility tables** - `table ip filter`, `table ip nat` | **native nftables** - `table inet pocvpn` (`gateway/nftables/pocvpn.nft.template`) |
| Firewall owner (systemd) | **`awg-firewall.service`** (host-local; NOT tracked in this repository) | none separate - applied directly by `gateway/provision.sh` step 5/6 |
| Egress interface | **`ens3`** | **`ens5`** |
| Existing FORWARD rule | allows `awg0 <-> ens3` | allows `awg0 <-> ens5` (via `pocvpn.nft.template`, interface-scoped, not peer-scoped) |
| Existing NAT | masquerades `10.77.0.0/24` via `ens3` | masquerades `10.77.0.0/24` via `ens5` |
| Repository checkout path | `/opt/pocvpn/gateway` | `/opt/pocvpn/gateway` |
| Peer add/remove tooling | `gateway/scripts/add-peer.sh`/`remove-peer.sh` - **confirmed valid to reuse as-is**, reads/writes the same durable config and live `awg0` state | same, unchanged |

**Neither host's verified facts name an existing INPUT-hook rule** - both
are FORWARD/NAT-only as far as this repository's own knowledge extends
(Stockholm's `pocvpn.nft.template` has no `input` chain at all; Frankfurt's
`awg-firewall.service` is host-local and not tracked, so its INPUT
behavior, if any, is unconfirmed - see the disclosed limitation below).

nginx on both hosts: `listen 443 ssl default_server;` (`gateway/edge/nginx-pocvpn.conf`/
`nginx-pocvpn-stockholm.conf`) - no specific bind IP, unaffected by any of
the above, unchanged by this plan on either host.

## One shared design, two production runtimes

The bootstrap identity, tunnel address, and the additive restriction
table's own **content** are IDENTICAL on both hosts
(`gateway/config/bootstrap.env`, `gateway/nftables/pocvpn-bootstrap.nft.template`)
- what differs is only:

1. **Which production ruleset the pre-flight ordering check reads** -
   Frankfurt's `ip filter` (iptables-nft) vs Stockholm's `inet pocvpn`
   (native nftables).
2. **Which post-apply verification confirms nothing production-owned
   changed** - `ip filter`/`ip nat` + `awg-firewall.service` on Frankfurt,
   `inet pocvpn` on Stockholm.

`gateway/scripts/install-bootstrap-peer.sh`/`uninstall-bootstrap-peer.sh`
now **detect** which of the two shapes a host actually runs (or accept an
explicit `--runtime frankfurt|stockholm` override) and **fail closed** -
refuse to proceed - if neither shape matches unambiguously. Neither script
ever guesses.

## Netfilter hook-priority reasoning (documented, not assumed)

A nftables base chain's dispatch order at a given hook (e.g. `forward`)
for a given packet is determined SOLELY by the registered chains'
priority values for that packet's L3 protocol - enforced by the kernel's
netfilter core hook infrastructure itself, **independent of whether native
`nft` or the `iptables-nft` compatibility layer registered the chain**,
and independent of nftables "family" declaration (`ip` vs `inet`) beyond
which L3 protocols that family covers (`inet` covers IPv4 and IPv6; `ip`
covers IPv4 only - for an IPv4 packet, both are dispatched together in one
strict order). This is standard, documented netfilter/nftables
architecture - the exact mechanism Debian/RHEL rely on for their own
default "iptables-nft coexists with native nftables" backend, not a guess.

Both production FORWARD hooks are confirmed at priority `0`:

- Frankfurt's `ip filter` FORWARD chain: the standard legacy iptables
  default (`NF_IP_PRI_FILTER = 0`), which `iptables-nft` preserves exactly.
- Stockholm's `inet pocvpn` forward chain: `type filter hook forward
  priority filter;` - nftables' own named priority "filter" resolves to
  the same numeric value, `0`.

The bootstrap table's own FORWARD hook uses priority **`-5`**
(`gateway/config/bootstrap.env` `BOOTSTRAP_FORWARD_PRIORITY`) - lower
(earlier) than `0` on both hosts, so its `drop` verdict for the bootstrap
peer's source IP is dispatched, and terminates hook processing for that
packet, **before** either production table's own interface-scoped accept
rule ever runs. `gateway/lib/bootstrap_runtime.sh`'s
`verify_bootstrap_priority_precedes_production` does not trust this
reasoning blindly - it reads the REAL live priority from `nft list table
<family> <table>` on the actual host and refuses to proceed (`die`) unless
it is confirmed strictly greater than `-5`, on every run, before the
bootstrap table is ever applied.

**Table-coexistence (FORWARD):** `iptables-nft`/`iptables-restore`
(Frankfurt's `awg-firewall.service`) only ever touches the specific tables
it owns (`ip filter`, `ip nat`, ...) - it does not issue a global `nft
flush ruleset`, so the separately-named `inet pocvpn_bootstrap` table is
never affected by that service reloading or restarting. This is standard
iptables-nft behavior; it has not been physically confirmed against
Frankfurt's actual (untracked) `awg-firewall.service` unit, so
`install-bootstrap-peer.sh` re-verifies both `ip filter` and `ip nat` are
still present immediately after applying the bootstrap table, and refuses
to declare success if either is missing.

**KNOWN, DISCLOSED LIMITATION (INPUT, Frankfurt only):** if Frankfurt's
real (untracked) `awg-firewall.service` ruleset already ACCEPTs
bootstrap-sourced traffic in its own INPUT chain ahead of the bootstrap
table's `input` chain, that table's "tcp/443 only" restriction may not
execute for already-accepted packets - a no-op in that case, **never a
worsening** of what the host already allowed (the bootstrap table only
ever adds a DROP for non-443 traffic from that one source, never an
ACCEPT). The FORWARD restriction - the actual "no general Internet access"
boundary - is unaffected either way, since FORWARD and INPUT are separate
hook points and Frankfurt's FORWARD shape IS fully confirmed. Given this,
`install-bootstrap-peer.sh` prints a REQUIRED manual read-only check
(`iptables -L INPUT -n` / `nft list ruleset`) for the operator to confirm
before treating the tcp/443-only restriction as a hard guarantee on
Frankfurt specifically. This is disclosed, not guessed past.

## Phase 2 - bootstrap client identity (unchanged from the prior slice)

**One shared bootstrap identity is used on BOTH gateways**, not two - each
gateway's AmneziaWG interface has its own, fully independent peer list, so
one client keypair being a valid peer on two unrelated servers carries no
more risk than a single client already carries by holding two gateway
peers today. A real Curve25519/X25519 keypair (generated locally, RFC 7748
raw encoding - the same shape `awg genkey`/`awg pubkey` produce) is
committed as `net.pocvpn.client.bootstrap.BootstrapIdentity.BOOTSTRAP_PRIVATE_KEY_BASE64`/
`BOOTSTRAP_PUBLIC_KEY_BASE64` (Android source - intentionally public) and
as `BOOTSTRAP_CLIENT_PUBLIC_KEY` in `gateway/config/bootstrap.env` (public
key only). **The private key value is never printed in this document, any
command output, or any report.**

Bootstrap peer's own fixed tunnel address (same on both gateways,
independent subnets): `10.77.0.250`.

## Phase 3 - exact server configuration

All commands below are encapsulated in
`gateway/scripts/install-bootstrap-peer.sh` (install) and
`gateway/scripts/uninstall-bootstrap-peer.sh` (rollback), which
autodetect the runtime (or accept `--runtime frankfurt|stockholm`), read
`gateway/config/bootstrap.env`, and reuse the EXISTING
`add-peer.sh`/`remove-peer.sh` peer-mutation tooling verbatim on BOTH
hosts. The commands shown here are exactly what those scripts run, for
review purposes.

### Frankfurt (`152.70.43.1`) - iptables-nft runtime

```bash
# As root, on Frankfurt, with this repository checked out at /opt/pocvpn/gateway:
cd /opt/pocvpn/gateway
sudo ./scripts/install-bootstrap-peer.sh --runtime frankfurt
```

Which, after verifying `ip filter`'s live FORWARD-hook priority is `0`
(greater than `-5`), performs exactly:

```bash
sudo ./scripts/add-peer.sh I/Kv8Kkebdtb5Rem+vdmkq0N3DK/ojQVbQWtoOFxyFE= 10.77.0.250 bootstrap

sudo bash -c '
sed -e "s/__NFT_TABLE_BOOTSTRAP__/pocvpn_bootstrap/g" \
    -e "s/__BOOTSTRAP_CLIENT_IP__/10.77.0.250/g" \
    -e "s/__BOOTSTRAP_FORWARD_PRIORITY__/-5/g" \
    nftables/pocvpn-bootstrap.nft.template > /etc/nftables.pocvpn-bootstrap.conf
'
sudo chmod 644 /etc/nftables.pocvpn-bootstrap.conf
sudo nft -f /etc/nftables.pocvpn-bootstrap.conf

sudo install -m 0644 systemd/nftables-pocvpn-bootstrap.service /etc/systemd/system/nftables-pocvpn-bootstrap.service
sudo systemctl daemon-reload
sudo systemctl enable --now nftables-pocvpn-bootstrap.service
```

Verification (read-only, no state change):

```bash
sudo awg show awg0 peers                  # bootstrap public key present
sudo nft list table inet pocvpn_bootstrap # both rules present, forward priority -5
sudo nft list table ip filter             # UNCHANGED - byte-for-byte identical to before
sudo nft list table ip nat                # UNCHANGED - byte-for-byte identical to before
sudo systemctl is-active awg-firewall.service   # still active, never touched by this script
# REQUIRED: confirm no existing INPUT rule already accepts 10.77.0.250 ahead of the new table:
sudo iptables -L INPUT -n
sudo nft list ruleset
# from a second host, through a real bootstrap tunnel handshake:
#   https://152.70.43.1/v1/manifest  -> expect the real signed manifest (200)
#   any other destination/port through the tunnel -> expect timeout/refused
```

### Stockholm (`16.170.208.231`) - native nftables runtime

```bash
cd /opt/pocvpn/gateway   # on Stockholm, its own checkout
sudo ./scripts/install-bootstrap-peer.sh --runtime stockholm
```

Which, after verifying `inet pocvpn`'s live FORWARD-hook priority is `0`
(greater than `-5`), performs exactly the same `add-peer.sh`/template-
render/`nft -f`/systemd-enable sequence as Frankfurt above, against
Stockholm's own `awg0` interface.

Verification (read-only, no state change):

```bash
sudo awg show awg0 peers
sudo nft list table inet pocvpn_bootstrap  # both rules present, forward priority -5
sudo nft list table inet pocvpn            # UNCHANGED - byte-for-byte identical to before
```

(Stockholm has no separate firewall-owning service to re-verify - the
`inet pocvpn` table is applied directly by `provision.sh`, unaffected by
this addition.)

### What this explicitly does NOT do, on either host

- Does not modify `/etc/amnezia/amneziawg/awg0.conf`'s existing peer
  entries - `add-peer.sh` only ever appends a new `[Peer]` block.
- Does not modify, re-render, or restart Frankfurt's `ip filter`/`ip nat`
  tables or `awg-firewall.service`.
- Does not modify or re-render Stockholm's `inet pocvpn` table.
- Does not touch `pocvpn-api.service`/`pocvpn-api-ingress.service`, their
  loopback bindings, or any activation store/database, on either host.
- Does not open any new public port - `51820/udp` is already public on
  both hosts; `443/tcp` is already public and already serves
  `/v1/activate`/`/v1/manifest`/`/v1/xray-profile`.
- Does not rotate Frankfurt's or Stockholm's own AWG/REALITY/TLS server
  keys.
- Does not require any AWS/Oracle Cloud security-group change (no new
  port, no port map change).

## Rollback (either host)

```bash
cd /opt/pocvpn/gateway
sudo ./scripts/uninstall-bootstrap-peer.sh --runtime frankfurt   # or --runtime stockholm
```

Which performs exactly:

```bash
sudo systemctl disable --now nftables-pocvpn-bootstrap.service
sudo rm -f /etc/systemd/system/nftables-pocvpn-bootstrap.service
sudo systemctl daemon-reload

sudo nft delete table inet pocvpn_bootstrap
sudo rm -f /etc/nftables.pocvpn-bootstrap.conf

sudo ./scripts/remove-peer.sh I/Kv8Kkebdtb5Rem+vdmkq0N3DK/ojQVbQWtoOFxyFE=
```

Verify with `sudo awg show awg0 peers` (bootstrap public key absent) and,
per host: Frankfurt - `sudo nft list table ip filter` / `sudo nft list
table ip nat` unchanged, `sudo systemctl is-active awg-firewall.service`
still active; Stockholm - `sudo nft list table inet pocvpn` unchanged.

## Rotation (future APK release)

Unchanged from the prior slice's own reasoning: generate a fresh keypair,
add it as an ADDITIONAL peer + a second additive restriction (both hosts,
both runtimes, same install script), ship the new public key in a new APK
release, remove the OLD peer/restriction only once adoption is sufficient
- never a single atomic swap that would strand already-installed APKs.

## Physical validation checklist (after the repository owner approves and applies the above)

1. Run `install-bootstrap-peer.sh --runtime frankfurt` on Frankfurt,
   verify with the read-only commands above, including the REQUIRED
   Frankfurt-only INPUT check.
2. Run `install-bootstrap-peer.sh --runtime stockholm` on Stockholm,
   verify identically (no INPUT caveat there - `pocvpn.nft.template` has
   no existing INPUT hook to race against).
3. From a real Android device (debug build, bootstrap wired), confirm a
   real AmneziaWG handshake against Frankfurt's bootstrap peer.
4. Confirm `/v1/activate` genuinely completes THROUGH that tunnel (not
   directly) and the resulting profile persists; confirm the bootstrap
   tunnel tears down and Home is reached normally.
5. Repeat step 3-4 with Frankfurt's bootstrap peer deliberately blocked
   (e.g. a temporary, reversible higher-priority DROP for
   `10.77.0.250` on Frankfurt only, no production peer touched) to
   confirm real fallback to Stockholm's bootstrap peer.
6. Only then attempt the actual restricted-Russia-network field test.
