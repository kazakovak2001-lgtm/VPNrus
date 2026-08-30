# B10 - DNS / IPv4 / IPv6 leak validation, and B9's external-IP claim

Reproducible verification runbook, not a script - reuses EXISTING tooling
only (the app's own debug diagnostics dialog, `gateway/scripts/status.sh`,
and standard OS/curl commands). No new transport, routing, or leak-
protection behavior is introduced by this document. Requires a physical
Android device with the app installed (debug build, for the diagnostics
dialog) and real connectivity to the live gateway - **this session has
neither**, so this document is the plan plus the one precondition check
that could be safely run without them (§1), not the completed B9/B10
verification itself. See §5 for exactly what remains UNVERIFIED and why.

## What this reuses (no new tooling invented)

- **App diagnostics dialog** (`net.pocvpn.client.ui.screens.DiagnosticsDialog`,
  debug builds only) already reports, live: transport state, tunnel IP,
  gateway endpoint, configured DNS servers, current transport, handshake
  age. No new client-side instrumentation is needed for this plan.
- **`gateway/scripts/status.sh`** (existing, read-only) - `awg show`,
  listening UDP port, the live `nftables` table, peer count - run on the
  gateway itself to correlate server-side state with what the client
  observed.
- **Standard, no-install-needed checks**: a public IP-echo endpoint (any
  neutral one not owned by pocvpn, e.g. `https://icanhazip.com` /
  `https://ifconfig.me`), a public multi-resolver DNS-leak-test service,
  and an IPv6-only echo endpoint (e.g. `https://ipv6.icanhazip.com`) - all
  standard, widely-used verification methods, not anything project-specific.

## §1. Precondition check - executed this session, read-only, no tunnel involved

Confirms the gateway itself is real and reachable before anyone attempts
a device-level test - NOT B9/B10 evidence on its own (no client connected
through it), just removes "is the gateway even up" as a variable.

```bash
curl -s -o /dev/null -w "HTTP status: %{http_code}\nRemote IP: %{remote_ip}\n" -m 8 https://152.70.43.1/
```

**Result, this session:** `HTTP status: 404`, `Remote IP: 152.70.43.1` -
matches `gateway/edge/nginx-pocvpn.conf`'s own `location / { return 404; }`
fail-closed default exactly, and the TLS handshake succeeded with NO
`-k`/insecure flag needed:

```
Issuer: C=US, O=Let's Encrypt, CN=YE1
Expire Date: 2026-09-04 10:21:00 GMT
```

A genuine, publicly-trusted certificate, not self-signed - confirms the
gateway is live and its edge config matches this repository's own
`nginx-pocvpn.conf` template.

## §2. Baseline capture (BEFORE connecting) - device-side, real evidence required

On the Android device, VPN disconnected, real mobile/Wi-Fi network:

1. `curl -s https://icanhazip.com` (or open it in a browser) - record the
   device's REAL, pre-tunnel public IPv4. This is the value B9's claim
   must differ from.
2. Note the device's current DNS behavior is whatever the carrier/Wi-Fi
   normally provides (no specific command needed - this is just the "before"
   state for contrast with §4).

## §3. Connect and capture live diagnostics - device-side, real evidence required

1. Connect through the app (Smart Connect / AWG, and separately with AWG
   made to fail so Xray fallback engages - reusing the EXACT physical
   reproduction steps that already produced the B8I8 evidence: remove
   the device's AWG peer server-side via `gateway/scripts/remove-peer.sh`,
   confirm AWG fails, confirm automatic Xray fallback).
2. Open the debug diagnostics dialog. Record, verbatim, for EACH
   transport tested (AMNEZIA_WG and XRAY_REALITY):
   - `State` (must be `Connected`)
   - `Gateway` / `Client tunnel IP`
   - `DNS servers` (expected: `1.1.1.1, 1.0.0.1` per `VpnDnsPolicy.servers`
     - see `android/app/src/main/java/net/pocvpn/client/vpn/config/VpnLeakProtectionPolicy.kt`)
   - `IPv6 policy` (expected: `blocked/fail-closed` per `VpnIpv6Policy.current`)
   - `Current transport`, `Transport health`, `Restriction class`
3. On the gateway (SSH), run `gateway/scripts/status.sh` at the same
   moment - record `awg show`'s handshake/transfer counters and the
   `nftables` table output, to correlate server-side state with what the
   device showed.

## §4. The three B10 leak checks - device-side, real evidence required, WHILE connected

1. **External public IP (B9's own claim)**: `curl -s https://icanhazip.com`
   from the device again. **PASS** iff this now equals the gateway's own
   public IP (`152.70.43.1`) and differs from §2's baseline value. This is
   exactly what `gateway/nftables/pocvpn.nft.template`'s `postrouting`
   chain (`ip saddr $AWG_SUBNET oifname $EGRESS_IFACE masquerade`) is
   designed to produce - this step is what actually proves it happens in
   practice, on the real host, not just that the rule is correctly written.

2. **DNS leak**: run a public multi-resolver DNS-leak-test (any standard
   one - they all work the same way: the device makes several DNS queries
   to per-test-unique subdomains, and the test reports which resolver
   IP(s) actually answered). **PASS** iff every reported resolver is
   `1.1.1.1`/`1.0.0.1` (Cloudflare) or an anycast IP Cloudflare's own docs
   attribute to those addresses - **FAIL** if the carrier/Wi-Fi's own
   resolver (or anything not traceable to Cloudflare) shows up, since that
   would mean a DNS query left the tunnel.

3. **IPv6 leak**: `curl -6 -s --max-time 8 https://ipv6.icanhazip.com`
   (forces an IPv6-only request) from the device. Per `Ipv6LeakPolicy.FAIL_CLOSED`'s
   own documented design (an `::/0` route IS present inside the tunnel per
   `AwgPeer`'s default AllowedIps, capturing IPv6 traffic, but the gateway
   does not forward IPv6 anywhere - see `gateway/nftables/pocvpn.nft.template`,
   which has no `ip6` NAT/forward rule), the CORRECT/PASSING result is that
   this request **times out or fails** - it must NOT return the device's
   real ISP IPv6 address (that would be a leak) and cannot succeed via the
   tunnel either (no IPv6 forwarding exists yet). A successful response
   showing the device's real ISP-assigned IPv6 is the one specific failure
   this check exists to catch.

## §5. What remains UNVERIFIED after this session, and why

**Nothing in `docs/ROADMAP.md`'s "Current verification status" table is
changed by this document.** §1 is the only step actually executed this
session (this environment has no Android device, no AmneziaWG/Xray client,
and no root-level network access to establish a real tunnel itself -
confirmed: `wg`/`awg-quick` are not installed here, and installing VPN
client tooling or creating a system network interface without the user's
explicit authorization is exactly the kind of system-level change this
session should not take unilaterally). §2-4 require a human with the
physical device and gateway SSH access - the same shape of execution the
existing B8I8 physical AWG->Xray failover evidence already came from.

Per `docs/ROADMAP.md`'s own stated discipline ("must not be asserted as
true until [proven with real evidence]... the same way B8A did for the
local handshake"), `External public IP change through the tunnel`, `DNS
leak protection`, and `IPv4/IPv6 leak protection` all correctly REMAIN
`UNVERIFIED` until someone executes §2-4 and records the actual results
here (or in a follow-up to this document) - a good plan is not evidence.
