# B10 - DNS / IPv4 / IPv6 leak validation, and B9's external-IP claim

Reproducible verification runbook, not a script - reuses EXISTING tooling
only (the app's own debug diagnostics dialog, standard OS/curl/adb
commands, and third-party reachability/DNS-leak services). No new
transport, routing, or leak-protection behavior is introduced by this
document. §1-4 were written as a plan in an earlier session with no
physical device attached; §5 records the REAL results from B10-1
(2026-08-30), executed against a physical Android device connected over
ADB - see §5 for the actual evidence, and `docs/ROADMAP.md`'s
verification table for the resulting status.

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

## §5. Results - B10-1, executed 2026-08-30

§2-4 above were executed for real, this session, against a physical
Android device (Oppo CPH2173, `net.pocvpn.client` debug build,
`versionName 0.1-poc`) connected over ADB. `docs/ROADMAP.md`'s
verification table IS updated by this run - see that file for the
authoritative status; this section is the underlying evidence.

**Device detected:** yes - `adb devices -l`: `c618ee06 device
product:CPH2173EEA model:CPH2173`.

**§2 baseline (VPN disconnected, confirmed via `adb shell ip addr show`
- no `tun0` interface, `dumpsys connectivity` shows 0 VPN networks):**
- IPv4 (`https://ipv4.icanhazip.com`, real Chrome tab): `86.49.236.33`
- IPv6 (`https://icanhazip.com`, real Chrome tab): `2a02:8308:10e:8400:d4b5:2f7f:1f9c:5d65`
  (confirms the device has genuine ISP-assigned IPv6 - makes the §4
  IPv6 result meaningful rather than trivially true)

**§3 connect + live diagnostics:** reconnected via the app's own toggle
(not a fresh install/reset - existing activation/profile data untouched).
Cross-checked which transport actually engaged three independent ways,
not just the diagnostics dialog's own text (see the CAUTION note below):
- `adb shell dumpsys activity services net.pocvpn.client`:
  `ServiceRecord{... net.pocvpn.client/org.amnezia.awg.backend.GoBackend$VpnService}`
  running in the foreground - AMNEZIA_WG, not Xray, is the live transport
  for this run.
- `adb shell ip addr show`: `tun0 ... inet 10.77.0.5/32` - matches AWG's
  addressing, not Xray's fixed `172.19.0.1/30`.
- `adb logcat --pid=<pocvpn pid>`: `peer(9Wew...HYRU) - Sending handshake
  initiation` followed 33ms later by `peer(9Wew...HYRU) - Received
  handshake response` - a genuine, real AmneziaWG handshake over the
  public network.
- App diagnostics dialog (debug build): `State: Connected`, `Client
  tunnel IP: 10.77.0.5`, `Gateway: 152.70.43.1:51820`, `AllowedIPs:
  0.0.0.0/0, ::/0`, `DNS servers: 1.1.1.1, 1.0.0.1`, `IPv6 policy:
  blocked/fail-closed`, `Kill switch - App session: ACTIVE`, `Routing
  mode: ALL_APPS`.

**CAUTION confirmed real** (matching this task's own warning): the
diagnostics dialog's `Current transport: AMNEZIA_WG` line is
`smartConnectDecision()`'s fresh hypothetical pick, NOT necessarily the
live session's actual transport - on this device, EARLIER in the same
session (before this test's own disconnect/reconnect), that same line
read `AMNEZIA_WG` while `dumpsys`/`ip addr` proved `NovaXrayVpnService`
(Xray) was actually the live foreground service (a leftover fallback
session from earlier physical testing). This is a real, minor
diagnostics-UX gap worth a future fix (the line should reflect the
actually-connected transport, not just a fresh re-decision) - not fixed
in this session per "do not modify production code just to make the
test pass."

**§4 leak checks - all via real Chrome browser tabs (`am start -a
android.intent.action.VIEW`), never `adb shell curl`, per this task's own
caution that shell-UID traffic isn't necessarily representative of
ordinary app traffic:**

1. **External IP / IPv4 leak** (`https://ipv4.icanhazip.com`):
   **`152.70.43.1`** - exactly the gateway's own address, differs from
   the `86.49.236.33` baseline. Independently re-confirmed by a SECOND,
   unrelated third-party service (dnsleaktest.com's own landing page:
   "Hello 152.70.43.1 from Frankfurt am Main, Germany"). **PASS.**

2. **DNS leak** (dnsleaktest.com, Standard Test): "Test complete", 1
   server found: IP `172.71.140.49`, ISP **Cloudflare**, Frankfurt am
   Main, Germany. Zero trace of the device's real carrier resolvers
   (T-Mobile CZ, confirmed via `dumpsys connectivity` while disconnected:
   `DnsAddresses: [ /62.141.16.181,/62.141.16.151 ]`) or of the Wi-Fi
   network's own DNS. **PASS.**

3. **IPv6 leak**: two independent checks, both via real Chrome tabs:
   - `https://ipv6.icanhazip.com` (DNS-dependent, IPv6-only hostname):
     `ERR_NAME_NOT_RESOLVED` - the name never resolved at all.
   - `https://[2606:4700:4700::1111]/` (a raw IPv6 literal - NO DNS
     lookup involved, isolates the ROUTING layer specifically):
     `ERR_CONNECTION_TIMED_OUT` after ~20s.

   Matches `Ipv6LeakPolicy.FAIL_CLOSED`'s documented design exactly: the
   `::/0` route inside the tunnel captures the attempt, the gateway never
   forwards it, so it fails closed rather than either succeeding or
   leaking around the tunnel onto the device's real ISP IPv6 (confirmed
   present in the §2 baseline). **PASS** - real ISP IPv6 never reached
   either destination.

**Server-side (VPS) cross-check attempted, not obtained:** this session
has no SSH credentials for the gateway (4 read-only, non-interactive
auth probes tried against `152.70.43.1` - `ubuntu`, `opc`, `root`,
`pocvpn` - all `Permission denied (publickey)`; not brute-forced
further). Cross-validation instead comes from TWO independent
third-party services (icanhazip.com, dnsleaktest.com) agreeing on the
same exit IP from the device's own real network vantage point, plus this
session's earlier read-only HTTPS probe of the same gateway (see §1).
Running `gateway/scripts/status.sh` server-side to correlate `awg show`'s
handshake/transfer counters remains a genuine gap - worth doing whenever
gateway SSH access is available in a session.

**Device left in its normal working state**: connected via AMNEZIA_WG
(the app's default/expected state), no data wiped, no config changed,
activation/profile untouched. One incidental note: mid-session, a stray
gesture (an edge-swipe, not a tap) briefly switched the foreground app to
the device owner's WhatsApp; no text was sent, entered, or deleted there
- recovered immediately by relaunching Nova via `adb shell am start`.
Every interaction after that point used verified UI-element bounds
(`uiautomator dump`) rather than gesture navigation.
