# Field test runbook (Russia / restricted networks)

The app contains a **Field test**. In the debug build open it from
Diagnostics -> "Field test (all gateways x transports)"; in the release
build only the quick check exists, under Settings -> "Network check". It
turns one tester session into one shareable report. It is a measurement
tool: a result on one network is evidence for that network at that time
only (see the B54 and Field-Validation Truth Boundary rows in
`docs/ROADMAP.md`). Nothing here claims Russia works.

## Modes

| Mode | Build | Duration | What it does |
|---|---|---|---|
| Full field test | debug | 15-30 min | everything below |
| Quick network check | debug + release | 2-4 min | context, direct probes, censorship analysis, API checks, crashes, logs - no VPN cycling. A connected session is paused and reconnected afterwards |
| Monitor 30 min / 2 h | debug | as chosen | keeps the user's normal connection up, probes every 30 s, 256 KB download every 5 min, records every state/health/transport/network change |

The screen stays on while a test runs. Keep the app in the foreground.

## What a full run measures

1. **Network context** - operator name and MCC/MNC, network and SIM country,
   roaming, Wi-Fi/cellular, validated, IPv4/IPv6, Private DNS, MTU. Not
   recorded: phone number, IMSI/IMEI, SSID, local addresses, the device's own
   public IP.
2. **Direct probes (VPN off)** - DNS; HTTPS to a control (Google 204),
   commonly blocked services, domestic controls; Cloudflare trace (country
   and edge only) and a 256 KB download (throttling); TCP to every TCP port
   in the signed manifest; each gateway's control plane and the CDN edge;
   the DNS resolver identity (`whoami.akamai.net`).
3. **Censorship analysis (VPN off)** - for 18 targets (commonly blocked
   foreign services, a classic registry-blocked site, foreign and domestic
   controls, Nova's own hostnames):

   | Verdict | Meaning |
   |---|---|
   | `DNS_BLOCKED` | system resolver fails, DNS-over-HTTPS answers |
   | `DNS_TAMPERED_BOGON` | system resolver returns a private/loopback address |
   | `DNS_DIFFERS_FROM_DOH` | different addresses (weak: CDNs answer per region) |
   | `IP_BLOCKED_DROP` / `IP_BLOCKED_RESET` | TCP to the real address times out / is reset |
   | `SNI_FILTERED` | TLS with the real name fails, with a neutral name succeeds (same address) |
   | `TLS_BLOCKED` | TLS fails with both names |
   | `THROTTLED_STALL` | the HTTPS download freezes after 8-64 KB |
   | `HTTPS_INTERFERENCE` | TLS works but the HTTPS request gets no answer |
   | `HTTP_BLOCK_PAGE` | plain HTTP returns an ISP block page / redirect |
   | `OK` | works |

   Network verdicts: `WHITELIST_MODE_SUSPECTED` (domestic sites work, foreign
   controls do not), `UDP53_TO_FOREIGN_RESOLVERS_BLOCKED`, `DOH_BLOCKED`,
   `NOVA_HOST_UNREACHABLE <host>`, `COMMONLY_BLOCKED_SERVICES_AFFECTED n/m`,
   and `MECHANISMS ...` (how often each mechanism was seen).
4. **API checks (VPN off)** - `POST /v1/activate` and `/v1/xray-profile` with
   an intentionally invalid key on every gateway and `control.aknova.pp.ua`
   (the server rejects it before any credential or store access, so there is
   no side effect), `GET /v1/manifest`, and the app's own signed manifest
   refresh. `API_REACHABLE` = activation would work from this network.
5. **VPN runs** - every gateway x every transport, then one forced run per
   relay ingress in the manifest (`RELAY via stockholm-ingress-1` = REALITY
   relay, `RELAY via stockholm-xhttp-ingress-1` = Cloudflare CDN XHTTP), then
   Smart Connect. Each run uses the normal connect path (debug transport pin
   / debug path override). Connected runs measure DNS, Google 204, Telegram,
   YouTube, exit IP, a 1 MB download with stall detection, stability after
   20 s and **leaks** (DNS resolver through the VPN vs without it; IPv6
   egress while connected - our exits have no IPv6).
6. **Crashes and logs** - Android's history of why the app process ended
   (Android 11+, e.g. `EXIT_SELF`, `CRASH_NATIVE`, ANR traces), locally
   recorded JVM crashes, and the app's own log buffer (Kotlin, AWG/Xray,
   Hysteria2/sslocal output) with UUIDs, keys, tokens, credentials and
   e-mail addresses removed.
7. The original gateway/transport selection is restored.

Mobile data: about 12-15 MB per full run; monitor about 3 MB per hour.

## Run outcomes

| Outcome | Meaning |
|---|---|
| `DATA_PLANE_OK` | Connected, exit = this gateway, 1 MB download completed |
| `DATA_PLANE_CORE_CONFIRMED` | Xray-family path (REALITY, TLS, XHTTP, relays): the app is excluded from the Xray tunnel by design, so the Xray core measured through it (latency to Google 204, the exit gateway, Telegram, YouTube). No bulk download, exit IP or leak check |
| `CONNECTED_APP_EXCLUDED` | Connected and confirmed by the transport (e.g. Hysteria2), but the VPN excludes the Nova app - not measurable from the app; check with a browser |
| `DATA_PLANE_DEGRADED` | Small probes worked, bulk download incomplete |
| `DATA_PLANE_STALL_SUSPECTED` | A flow froze after 8-64 KB (reported TLS throttling pattern) |
| `CONNECTED_NO_DATA` | Tunnel up, nothing answered through it |
| `EXIT_MISMATCH` | Traffic left through another address |
| `HANDSHAKE_FAILED` / `CONNECT_FAILED` / `CONNECT_TIMEOUT` | Did not connect |
| `UNAVAILABLE` | The app refused the attempt (no profile/credential/binary/binding/relay candidate) |
| `SKIPPED` | Not offered by the manifest, or gateway not activated on this device |

## Procedure

1. **In CZ, before travel** (owner): issue the activation credential,
   activate the device on BOTH gateways and the relay ingresses, then connect
   once with every transport and once per forced relay path so every profile
   is stored. Activation and profile fetches go to foreign IPs and may fail
   inside RU.
2. **CZ baseline**: full test on Wi-Fi and on cellular; share both reports.
   Every offered transport/path should be `DATA_PLANE_OK` and the censorship
   analysis should show `OK` for foreign targets. Anything else is a bug to
   fix before travel, not RU evidence.
3. **In RU**: full test on each network separately (home Wi-Fi, each mobile
   operator, different times of day), plus a 2 h monitor on the network
   that will really be used. Never merge networks. Note what the app cannot
   see (city, announced mobile-internet restrictions).
4. Share every report ("Share report (JSON)" sends a `nova-field-test-<time>.json`
   FILE through the share sheet - a full report is larger than Android's
   ~1 MB intent limit, so it is never sent as text; "Share summary" for a
   quick look). Debug builds can also save a copy locally
   (`files/support-diagnostics/field-test-<time>.json`) - app-private, only
   reachable with adb, not from the phone's file manager.

## Server-side correlation (optional, owner-approved per session)

Agree a time window with the tester, then on each gateway:

```bash
sudo /opt/pocvpn/gateway/tools/field_test_capture.sh --minutes 30 --client-net <tester IP or /24>
```

It records packet headers only (96 bytes, no payload) on Nova's
client-facing ports, `awg show` handshakes before/after and the journal of
the Nova units for that window, plus a per-port in/out summary, into
`/var/tmp/nova-fieldtest/<UTC>/` (root, 0700). No reload, restart or
configuration change. `--client-net` keeps everyone else's traffic out of
the capture. Delete the directory after analysis. `--dry-run` prints what
it would do.

## Build

Debug build from `main` with the same local, gitignored inputs as the CZ test
build: `android/app/gateway-dev.properties`, `android/app/libs/*.aar`, and
the pinned native binaries in `android/app/src/main/jniLibs/arm64-v8a/`
(`libnovahysteriachild.so` / `libnovatun2sockschild.so` per
`third_party/*/README.md`, `libsslocal.so` = upstream pinned `333eafee...`).
Without them SHADOWSOCKS_2022 and HYSTERIA2 report `UNAVAILABLE`. HYSTERIA2
remains under legal review (B46 G1); a test build is not a release.
