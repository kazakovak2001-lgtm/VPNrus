# Field test runbook (Russia / restricted networks)

The debug build contains a **Field test** (Diagnostics dialog -> "Field test
(all gateways x transports)"). It turns one tester session into one
shareable report. It is a measurement tool: a passing run on one network is
evidence for that network only (see the B54 and Field-Validation Truth
Boundary rows in `docs/ROADMAP.md`). Nothing here claims Russia works.

## What one run does (about 15-25 minutes)

1. **Network context** - operator name and MCC/MNC, network and SIM country,
   roaming, Wi-Fi/cellular, validated, IPv4/IPv6, Private DNS, MTU.
   Not recorded: phone number, IMSI/IMEI, SSID, local addresses, ISP
   resolver addresses, the device's own public IP.
2. **Direct probes (VPN off)** - DNS for our and foreign hostnames; HTTPS to a
   control (Google 204), services commonly blocked in RU (YouTube, Telegram,
   Instagram), domestic controls (ya.ru, vk.com); Cloudflare trace (country
   and edge only) and a 256 KB Cloudflare download (throttling check); TCP
   connect to every TCP port in the signed manifest; HTTPS to each gateway's
   control plane (`/v1/tunnel-probe`) and to the CDN edge.
3. **VPN runs** - every gateway (GERMANY, STOCKHOLM) x every transport
   (AMNEZIA_WG, XRAY_REALITY, TLS_TCP, XRAY_XHTTP, SHADOWSOCKS_2022,
   HYSTERIA2), then Smart Connect (Auto). Each run uses the normal connect
   path with the debug transport pin. Bindings the signed manifest does not
   offer for that gateway are SKIPPED. A connected run measures (bound to
   the VPN network): DNS, Google 204, Telegram, YouTube, Cloudflare trace
   (exit IP and edge), a 1 MB download with stall detection, and the same
   again after a 20 s hold.
4. The original gateway / transport selection is restored; the VPN ends
   disconnected.

Mobile data used: about 10-12 MB per full run.

## Run outcomes

| Outcome | Meaning |
|---|---|
| `DATA_PLANE_OK` | Connected, exit = this gateway, 1 MB download completed |
| `DATA_PLANE_DEGRADED` | Small probes worked, bulk download incomplete |
| `DATA_PLANE_STALL_SUSPECTED` | A flow froze after 8-64 KB (reported TLS throttling pattern) |
| `CONNECTED_NO_DATA` | Tunnel up, nothing answered through it |
| `EXIT_MISMATCH` | Traffic left through another address |
| `HANDSHAKE_FAILED` / `CONNECT_FAILED` / `CONNECT_TIMEOUT` | Did not connect |
| `UNAVAILABLE` | The app refused the attempt (no profile/credential/binary/binding) |
| `SKIPPED` | Not offered by the manifest, or gateway not activated on this device |

## Procedure

1. **In CZ, before travel** (owner): issue the activation credential, activate
   the device on BOTH gateways, then connect once with every transport
   (Diagnostics -> Force ... -> connect) so every profile (Xray REALITY /
   TLS / XHTTP, Hysteria2, Shadowsocks, ingress) is stored. Activation and
   profile fetches go to foreign IPs and may fail inside RU.
2. **CZ baseline**: run the field test on Wi-Fi and on cellular; share both
   reports. Every transport should be `DATA_PLANE_OK` here - anything else is
   a bug to fix before travel, not RU evidence.
3. **In RU**: run on each available network separately (home Wi-Fi, each
   mobile operator, at different times of day). Never merge networks. Note
   anything the app cannot see (city, mobile-internet restrictions announced
   for that day, VPN-blocking notices).
4. Share each report with "Share report (JSON)" (and "Share summary" for a
   quick look). "Save report locally" keeps a copy in the app's private
   storage (`files/support-diagnostics/field-test-<time>.json`, debug only).

## Build

Debug build from `main` with the same local, gitignored inputs as the CZ test
build: `android/app/gateway-dev.properties`, `android/app/libs/*.aar`, and
the pinned native binaries in `android/app/src/main/jniLibs/arm64-v8a/`
(`libnovahysteriachild.so` / `libnovatun2sockschild.so` per
`third_party/*/README.md`, `libsslocal.so` = upstream pinned `333eafee...`).
Without the native binaries SHADOWSOCKS_2022 and HYSTERIA2 report
`UNAVAILABLE`. HYSTERIA2 remains under legal review (B46 G1); a test build is
not a release.
