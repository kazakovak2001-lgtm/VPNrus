# B36 - exact server-side deployment plan (bootstrap pre-activation tunnel)

**Nothing in this document has been executed. Do not run any command below
against Frankfurt or Stockholm without the repository owner's explicit
go-ahead, per this repository's merge/infra-safety rule.** This plan exists
so that approval, once given, can be carried out mechanically and reviewed
in advance - not to authorize itself.

## Phase 1 findings - exact current server model (from the repository, not assumed)

Both Frankfurt (`152.70.43.1`) and Stockholm (`16.170.208.231`) are
provisioned by the SAME `gateway/provision.sh`/`gateway/config/poc.env`, so
both share the exact same facts:

| Fact | Value | Source |
|---|---|---|
| AWG interface name | `awg0` | `gateway/config/poc.env` `INTERFACE_NAME` |
| systemd service | `awg-poc.service` (`ExecStart=awg-quick up awg0`) | `gateway/systemd/awg-poc.service` |
| Durable config | `/etc/amnezia/amneziawg/awg0.conf` | `poc.env` `CONFIG_DIR`/`CONFIG_FILE` |
| AWG subnet | `10.77.0.0/24` | `poc.env` `AWG_SUBNET_CIDR` |
| Gateway's own tunnel IP | `10.77.0.1` | `poc.env` `GATEWAY_TUNNEL_IP` (confirmed identical on both in `ProductionGatewayCatalog`) |
| Listen port | `51820/udp` (already public on both - B31 port map) | `poc.env` `LISTEN_PORT` |
| Firewall/NAT | **nftables**, one table `inet pocvpn` (`poc.env` `NFT_TABLE`), rendered by `gateway/nftables/pocvpn.nft.template`, applied via `nft -f /etc/nftables.pocvpn.conf` in `provision.sh` step 5/6 - **not iptables** | confirmed directly from `provision.sh`/the template, not assumed |
| Forward chain (existing) | `type filter hook forward priority filter; policy drop;` with `iifname awg0 oifname <egress> accept` (and reverse) - scoped by INTERFACE only, not by peer | `pocvpn.nft.template` |
| NAT (existing) | `postrouting` chain masquerades `ip saddr 10.77.0.0/24` out the egress interface - scoped by SUBNET only, not by peer | `pocvpn.nft.template` |
| nginx | `listen 443 ssl default_server;` - no specific bind IP, so ANY locally-delivered packet to port 443 (any interface, including a hairpinned awg0 packet destined at the box's own public IP) reaches the SAME vhost | `gateway/edge/nginx-pocvpn.conf` / `nginx-pocvpn-stockholm.conf` |
| `pocvpn-api` | Loopback-only (`127.0.0.1:8443` normal role, `8444` ingress role on Stockholm) - **stays loopback-only, never exposed by this plan** | B31 port map |
| Peer add/remove tooling | `gateway/scripts/add-peer.sh <PUBLIC_KEY> <TUNNEL_IP> [label]` / `remove-peer.sh <PUBLIC_KEY>` (locked, idempotent, durable-config-verified, live-converged) | `gateway/scripts/*.sh`, `gateway/lib/peer_mutations.sh` |

**Key implication for restriction (Phase 1 question 5 - how a bootstrap
peer can reach nginx :443 while being denied general forwarding/NAT):** a
packet from an AWG peer destined at the box's OWN public IP is delivered
via the **INPUT** hook (local delivery - the Linux kernel recognizes the
destination as one of the host's own addresses), never the **FORWARD**
hook (which only applies to packets being routed THROUGH the box to some
other destination). The existing `pocvpn` table's `forward`/`postrouting`
chains are therefore irrelevant to this exact path - reaching nginx never
requires forwarding or NAT for this specific destination. General Internet
access, by contrast, DOES require FORWARD+NAT (today granted to every peer
uniformly, by interface/subnet only). This is why the restriction below is
implemented as: an explicit `forward`-hook DROP for the bootstrap peer's
own source IP (denying it the general-Internet FORWARD+NAT path every
other peer gets), plus an `input`-hook rule allowing that same source only
`tcp/443` (the nginx vhost, reached via ordinary local delivery, no new
listener, no DNAT).

## Phase 2 - bootstrap client identity

**One shared bootstrap identity is used on BOTH gateways**, not two. This
is safe under the B36 design specifically because each gateway's AmneziaWG
interface has its own, fully independent peer list - a WireGuard public
key being a valid peer on two unrelated servers carries no more risk than
a single client already carries by being provisioned with two gateway
peers today (exactly what `ProductionGatewayCatalog` already models for
normal per-device production peers, just with one identity shared by every
install instead of one per device). Using two separate bootstrap
identities would double the server-side surface (two peer entries, two
key-rotation schedules) for no corresponding security benefit, since
neither identity is secret in the first place - the restriction, not the
identity split, is what carries the security property. This also keeps the
client-side fallback simple, per the task's own instruction.

A real Curve25519/X25519 keypair was generated locally (Python
`cryptography`, RFC 7748 raw scalar/point encoding - the same wire shape
`awg genkey`/`awg pubkey` produce) and is now committed as
`net.pocvpn.client.bootstrap.BootstrapIdentity.BOOTSTRAP_PRIVATE_KEY_BASE64`/
`BOOTSTRAP_PUBLIC_KEY_BASE64` in the Android source (intentionally public,
per the B36 trust boundary - see that file's own docs), and as
`BOOTSTRAP_CLIENT_PUBLIC_KEY` in `gateway/config/bootstrap.env` (public key
only - the file the server-side scripts below actually read). **The
private key value is never printed in this document or any command
output below** - it lives only in the Android source (where it is meant to
be public/shipped) and in the gitignored local generation artifact
(`gateway/generated/bootstrap/`, never committed).

Bootstrap peer's own fixed tunnel address (same on both gateways,
independent subnets): `10.77.0.250` (`gateway/config/bootstrap.env`
`BOOTSTRAP_CLIENT_TUNNEL_IP`, matching
`BootstrapIdentity.CLIENT_TUNNEL_ADDRESS_CIDR` client-side).

## Phase 3 - exact server configuration

All commands below are already encapsulated in
`gateway/scripts/install-bootstrap-peer.sh` (install) and
`gateway/scripts/uninstall-bootstrap-peer.sh` (rollback), which read
`gateway/config/bootstrap.env` for the exact values above and reuse the
EXISTING `add-peer.sh`/`remove-peer.sh` peer-mutation tooling verbatim -
nothing below invents a second peer-mutation mechanism. The manual
commands shown here are exactly what those scripts run, for review purposes.

### Frankfurt (`152.70.43.1`)

```bash
# As root, with this repository checked out at, e.g., /opt/pocvpn/gateway-src:
cd /opt/pocvpn/gateway-src/gateway
sudo ./scripts/install-bootstrap-peer.sh
```

Which performs exactly:

```bash
sudo ./scripts/add-peer.sh I/Kv8Kkebdtb5Rem+vdmkq0N3DK/ojQVbQWtoOFxyFE= 10.77.0.250 bootstrap

sudo bash -c '
NFT_TABLE_BOOTSTRAP=pocvpn_bootstrap
BOOTSTRAP_CLIENT_IP=10.77.0.250
sed -e "s/__NFT_TABLE_BOOTSTRAP__/$NFT_TABLE_BOOTSTRAP/g" \
    -e "s/__BOOTSTRAP_CLIENT_IP__/$BOOTSTRAP_CLIENT_IP/g" \
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
sudo awg show awg0 peers                       # bootstrap public key present
sudo nft list table inet pocvpn_bootstrap      # both rules present
sudo nft list table inet pocvpn                # UNCHANGED - byte-for-byte identical to before
# from a second host, through a real bootstrap tunnel handshake:
#   https://152.70.43.1/v1/manifest  -> expect the real signed manifest (200)
#   any other destination/port through the tunnel -> expect timeout/refused
```

### Stockholm (`16.170.208.231`)

Identical procedure, same script, same bootstrap identity (Phase 2's own
"one identity, not two" reasoning) - run separately on the Stockholm host:

```bash
cd /opt/pocvpn/gateway-src/gateway   # on Stockholm, its own checkout
sudo ./scripts/install-bootstrap-peer.sh
```

Which performs exactly the same two commands as Frankfurt above (`awg show
awg0 peers`/`nft list table inet pocvpn_bootstrap` verification identical),
against Stockholm's own `awg0` interface and its own `/etc/nftables.pocvpn.conf`
(also left byte-for-byte unchanged).

### What this explicitly does NOT do, on either host

- Does not modify `/etc/amnezia/amneziawg/awg0.conf`'s existing peer
  entries - `add-peer.sh` only ever appends a new `[Peer]` block.
- Does not modify or re-render `/etc/nftables.pocvpn.conf` (the existing
  `pocvpn` table) at all.
- Does not touch `pocvpn-api.service`/`pocvpn-api-ingress.service`, their
  loopback bindings, or any activation store/database.
- Does not open any new public port - `51820/udp` is already public on
  both hosts (B31 port map); `443/tcp` is already public and already
  serves `/v1/activate`/`/v1/manifest`/`/v1/xray-profile`.
- Does not rotate Germany's or Stockholm's own AWG/REALITY/TLS server
  keys.
- Does not require any AWS/Oracle Cloud security-group change (no new
  port).

## Rollback (either host)

```bash
cd /opt/pocvpn/gateway-src/gateway
sudo ./scripts/uninstall-bootstrap-peer.sh
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

Verify with `sudo awg show awg0 peers` (bootstrap public key absent) and
`sudo nft list ruleset` (only the original `pocvpn` table remains).

## Rotation (future APK release)

1. Generate a fresh keypair with the same tooling (Python `cryptography`
   or `awg genkey`/`awg pubkey`).
2. Add the NEW public key as an ADDITIONAL peer (`add-peer.sh <new-pub-key>
   10.77.0.251 bootstrap-v2`, a second, distinct tunnel IP) and a matching
   additional restriction rule (a second `ip saddr` line in the bootstrap
   nftables table, or a second additive table) on both gateways - keep the
   OLD peer/rule live.
3. Ship the new public key in a new APK release.
4. Only once adoption of the new APK is sufficient, remove the OLD peer/
   rule with `remove-peer.sh <old-pub-key>` and the matching nftables
   cleanup - never a single atomic swap that would strand already-
   installed APKs still using the old key.

## Physical validation checklist (after the repository owner approves and applies the above)

1. Run `install-bootstrap-peer.sh` on Frankfurt, verify with the read-only
   commands above.
2. Run `install-bootstrap-peer.sh` on Stockholm, verify identically.
3. From a real Android device (debug build, bootstrap wired), confirm a
   real AmneziaWG handshake against Frankfurt's bootstrap peer.
4. Confirm `/v1/activate` genuinely completes THROUGH that tunnel (not
   directly) and the resulting profile persists; confirm the bootstrap
   tunnel tears down and Home is reached normally.
5. Repeat step 3-4 with Frankfurt's bootstrap peer deliberately blocked
   (e.g. a temporary `iif "awg0" ip saddr 10.77.0.250 drop` at higher
   priority, reversible, no production peer touched) to confirm real
   fallback to Stockholm's bootstrap peer.
6. Only then attempt the actual restricted-Russia-network field test.
