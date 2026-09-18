# B46-1: QUIC / HTTP3 Feasibility and Architecture Research

**Status of this document: RESEARCH ONLY. No production code, native binary,
server daemon, gateway/nginx/firewall/DNS config, or routing/scoring/selection
change was made as part of this task. `TransportRegistry`,
`SmartConnectDecisionEngine`, `AutoGatewaySelector`, `TransportOrchestrator`,
`VpnController`, `MainViewModel`, and `VpnService` are all unmodified by this
work. See `docs/ROADMAP.md`'s B46 row for the authoritative status this
document supports.**

Baseline: `main` at `6051aacea2080278791b67cf9e90cfb80f178657` (PR #85 merge,
B45B-4). Research branch: `claude/b46-quic-http3-research-0z90ql`.

**In-session architecture-review substitution notice (CLAUDE.md rule 7):**
this environment has no Agent/Task tool, so the `vpn-architecture` reviewer
persona (`.claude/agents/vpn-architecture.md`) could not be dispatched as a
real isolated subagent. Its rules were instead applied directly in-session:
`PROJECT_ARCHITECTURE.md`, the relevant `docs/ROADMAP.md` rows (P0 table,
B45/B46 rows), and this document's own proposed Section 19 architecture were
read and self-checked against the persona's boundaries (single scoring
authority, Manual-mode transport-only Smart Connect, no gateway hardcoding,
device-identity invariant, debug/release boundary, infrastructure-safety
rules) before finalizing. See Section 20 for the resulting self-check.

## 1. Scope

Research whether any QUIC/HTTP3-family transport deserves a future
implementation slice for Nova VPN, and if so, exactly how it would fit the
existing `VpnTransport`/`TransportOrchestrator`/Smart-Connect/reachability
architecture without creating a second routing, scoring, failover, or
diagnostics authority. No implementation, no dependency, no wiring into
`TransportRegistry`/`SmartConnectDecisionEngine`/`AutoGatewaySelector`/
`TransportOrchestrator`/`VpnController`/`MainViewModel`/`VpnService`, and no
gateway/nginx/firewall/DNS change is in scope. PR #86 (Shadowsocks physical
validation) and B45B-4P/B45B-5 are explicitly out of scope and untouched.
Russia/restricted-network field evidence is not produced by this task and
stays UNVERIFIED for every candidate, exactly as B45's research document
established for Shadowsocks/OpenVPN.

## 2. Repository audit (code-verified, not memory-derived)

### 2.1 What already exists for `TransportKind.QUIC` today

- `TransportKind.QUIC` is an existing enum value
  (`android/app/src/main/java/net/pocvpn/client/transport/TransportKind.kt`),
  named for exactly the same reason `SHADOWSOCKS_2022` is: "so the
  architecture ... has somewhere truthful to point at 'not implemented yet',
  never a fake success."
- `TransportRegistry` registers it as `TransportStatus.NOT_IMPLEMENTED` with
  `TransportCapabilities.notImplemented()` (`TransportRegistry.kt:58-61`) -
  no factory, no adapter shell, no `VpnTransport` implementation exists.
- `SmartConnectDecisionEngine.PREFERRED_ORDER` already lists `QUIC` second
  (`AMNEZIA_WG, QUIC, XRAY_REALITY, ...`) - this is a static preference-order
  placeholder, not a claim of eligibility; `TransportRegistry`'s
  `NOT_IMPLEMENTED` status is what actually excludes it from any real
  candidate list, the same gate that excludes `XRAY_XHTTP`/`SHADOWSOCKS_2022`
  today.
- `NetworkProfile` (`android/.../network/NetworkProfile.kt`) already carries
  a `quicReachability: ProbeSignal = ProbeSignal.Unknown` field, explicitly
  documented as "a future reachability/restrictiveness signal Smart Connect
  could one day use... No probe for any of these exists yet." This is a
  placeholder type slot, not a working probe - it is the natural home for a
  future bounded QUIC/UDP-443 reachability signal (Section 13).
- `MainViewModel.connectManual` (Private Gateway mode) and
  `PrivateGatewayConfig` both document themselves as structurally AWG-only
  ("architecture constraint: no Xray/REALITY/TLS/QUIC") - Private Gateway
  mode is out of scope for any future QUIC transport unless that constraint
  is deliberately revisited in its own slice.
- `PROJECT_ARCHITECTURE.md:2383` repeats the same AWG-only Private-Gateway
  scope boundary.

### 2.2 Xray's own QUIC/HTTP3 surface (the load-bearing finding of this audit)

The pinned Xray-core build is `v26.7.28` (`docs/B8K0_RUNTIME_AUDIT.md:46`,
commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, MPL-2.0). Nova's own code
already encodes a hard architectural fact about that pinned version's QUIC
support:

`android/app/src/main/java/net/pocvpn/client/vpn/xray/CdnXhttpRuntimeConfigResolver.kt`
defines `CdnXhttpRuntimeFailure.HTTP3_DIAL_NOT_BOUNDED` and rejects any
signed CDN provider profile whose ALPN is `h3`:

```kotlin
// The current Nova patch bounds TCP/TLS/REALITY establishment through
// dialContext. Xray's H3 path uses a separate QUIC Dial callback and is
// therefore not covered by that 5s bound yet.
if (provider.tls.alpn.single() == "h3") {
    return CdnXhttpRuntimeResolution.Rejected(
        CdnXhttpRuntimeFailure.HTTP3_DIAL_NOT_BOUNDED,
    )
}
```

`docs/CDN_PROVIDER_PROFILE.md:72` confirms: "H3 is rejected until its QUIC
establishment [is bounded]." This means: **Xray XHTTP in this codebase can
already speak HTTP/3 at the protocol level (the config schema accepts an h3
ALPN), but Nova's own runtime resolver deliberately refuses to execute it**
because the pinned core's QUIC dial path bypasses the same connect-timeout
bounding (`dialContext`) that TCP/TLS/REALITY get, and because - per the same
architecture principle B33 already established for the relay-health
watchdog - a socket Nova cannot bound/observe the same way as its other
sockets is not something Nova will silently execute against censorship-risk
production traffic. This is a real, already-encoded architectural decision,
not a hypothetical concern this document invents.

### 2.3 External confirmation: standalone QUIC transport is gone from Xray-core

External research (XTLS/Xray-core release notes and community docs,
2026-09) confirms Nova's pinned-version reality matches upstream: the
standalone `quic` transport type was removed from Xray-core entirely (build
error if configured), and QUIC-capable traffic in current Xray-core is
reached only via XHTTP/SplitHTTP's HTTP/3 mode
([XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases),
[Xray transport tutorial](https://core-tutorial.argsment.com/xray/transport),
[amnezia-xray-core DeepWiki QUIC section](https://deepwiki.com/amnezia-vpn/amnezia-xray-core/5.5-quic-and-other-transports)).
WebSocket, HttpUpgrade and gRPC transports are deprecated in favor of XHTTP
with HTTP/2 or HTTP/3. **Conclusion: there is no separate "Xray QUIC
transport" to independently evaluate any more - "QUIC via Xray" reduces
entirely to "XHTTP's h3 ALPN mode," which Section 2.2 shows Nova already
built and already, correctly, refuses to execute.** Any future Nova QUIC
work that stays inside Xray is therefore bounded to: (a) closing the
`HTTP3_DIAL_NOT_BOUNDED` gap for XHTTP-h3 specifically (a narrower, XHTTP-CDN-
scoped slice, not a new `TransportKind`), or (b) building a wholly
independent QUIC runtime outside Xray (Section 4), which is what actually
answers "does using Xray for QUIC undermine transport-diversity goals" - it
does, for the same reason B45's research document already rejected routing
Shadowsocks through Xray's own module: a second protocol executed inside the
SAME runtime process is not an independent failure domain from the Xray core
itself (crash, library bug, or upstream removal of the feature take down
every Xray-hosted transport together).

## 3. What "QUIC/HTTP3 transport" can mean - and what actually carries a VPN data plane

| Layer | What it is | Carries a full TCP+UDP VPN data plane? |
|---|---|---|
| Raw QUIC (RFC 9000) | A transport protocol over UDP: streams + (optionally) unreliable datagrams (RFC 9221), connection IDs, 1-RTT/0-RTT handshake on TLS 1.3. | Not by itself - it is a substrate. A proxy protocol has to be built on top (Hysteria2, TUIC, a custom Xray outbound, MASQUE). |
| HTTP/3 (RFC 9114) | HTTP semantics over QUIC. | No - it's a request/response web protocol; carrying arbitrary VPN traffic over it needs an extension (below). |
| HTTP Datagrams (RFC 9297) | An HTTP/3 extension frame type for unreliable, connection-associated datagrams, using QUIC DATAGRAM frames under the hood. | No - a building block MASQUE uses. |
| CONNECT-UDP / MASQUE (RFC 9298, `draft-ietf-masque-quic-proxy`) | Extended HTTP CONNECT method + HTTP Datagrams to proxy a single UDP 5-tuple through an HTTP/3 (or HTTP/2) server. RFC 9484 extends this to raw IP ("Proxying IP in HTTP"), which is what turns an HTTP/3 endpoint into a real VPN gateway (this is the mechanism behind iCloud Private Relay and Cloudflare WARP's MASQUE mode) ([RFC 9298](https://ietf-wg-masque.github.io/draft-ietf-masque-connect-udp/draft-ietf-masque-connect-udp.html), [MASQUE explained](https://http.dev/masque)). | **Yes, RFC 9484 (CONNECT-IP) can** - this is the one HTTP/3-family mechanism that is actually a VPN protocol, not merely QUIC-flavored web traffic. CONNECT-UDP alone (RFC 9298) only proxies UDP, not TCP - not sufficient alone for a full tunnel unless paired with a second TCP-proxy mechanism. |
| WebTransport | A browser/JS-facing API for bidirectional streams+datagrams over HTTP/3 (or HTTP/2 fallback). | Not directly relevant server-to-native-client; it's aimed at web apps, not native VPN clients, and has no IP-layer semantics of its own. |
| Proxy-over-QUIC protocols (Hysteria2, TUIC, Juicity) | Purpose-built proxy protocols that use raw QUIC (not HTTP/3) as their substrate, each with its own auth/framing on top. | **Yes** - these are designed specifically to relay arbitrary TCP+UDP traffic, closer in spirit to Shadowsocks-over-QUIC than to "web browsing over HTTP/3." |
| Ordinary HTTP/3 web traffic / CDN HTTP/3 | A CDN or origin serving normal HTTPS content over HTTP/3 to browsers. | No - this is what Q9 addresses: an owned/authorized CDN's HTTP/3 termination is a web-serving capability, not automatically a channel Nova's own arbitrary VPN protocol can ride without the CDN also proxying MASQUE/CONNECT-IP specifically (most CDNs do not expose that to arbitrary customer backends). |

**Conclusion for Q1:** the two families that could plausibly become a real
Nova `TransportKind` are (a) an independent QUIC-substrate proxy protocol
(Hysteria2/TUIC-class) and (b) CONNECT-IP/MASQUE if Nova ever ran or fronted
its own MASQUE-capable HTTP/3 endpoint. HTTP/3 web traffic, WebTransport, and
CONNECT-UDP alone are not, by themselves, full VPN data-plane mechanisms.

## 4. Independent QUIC transport candidates

### 4.1 Hysteria2 (apernet/hysteria)

- **Protocol model**: purpose-built QUIC-substrate proxy (not HTTP/3), UDP
  hop-by-hop obfuscated via Salamander, "Brutal" congestion control tuned for
  lossy/high-latency links, built-in bandwidth-aware handshake, optional
  Gecko packet-fragmentation obfuscation (added v2.9.2, May 2026 per search
  results) that fragments QUIC long-header packets specifically to resist
  QUIC fingerprinting.
- **Maintenance**: active as of 2026-09 (quic-go dependency bumped to
  v0.60.0 in recent releases); MIT license
  ([apernet/hysteria](https://github.com/apernet/hysteria)).
- **Language/toolchain**: Go, built on `quic-go`. Go is already a live
  toolchain dependency in this repo (Xray-core, AndroidLibXrayLite AAR via
  gomobile) - reusing the same cross-compile/gomobile pattern is plausible,
  but a Hysteria2 client would be a SEPARATE Go binary/library from Xray's,
  not a mode of the existing one (Section 2.3's "independent runtime"
  requirement).
- **Android/ABI**: no official first-party Android SDK/AAR observed in this
  research pass; third-party Android clients (Husi, NekoBox, Excalve) wrap
  the Go core, typically via `gomobile`. `arm64-v8a`-only is the pragmatic
  first-ABI choice, mirroring B45B's own Shadowsocks-rust ABI decision.
- **Known Android instability**: search results surface an open, long-
  standing (6+ months as of the search) issue of Hysteria2 dropping idle/
  screen-locked connections on Android across multiple third-party clients
  ([apernet/hysteria#1510](https://github.com/apernet/hysteria/issues/1510)).
  This is directly relevant to Doze/foreground-service interaction (Q5) and
  is an UNRESOLVED upstream problem, not solved by adopting Hysteria2.
- **Full-tunnel TCP+UDP**: yes, by design (general-purpose SOCKS5/TUN proxy
  use cases already exist in the ecosystem).
- **Fingerprint**: QUIC's own wire format is somewhat distinctive versus
  plain TLS/TCP (long-header packet shapes, UDP/443 usage itself is a
  signal in networks that block/throttle non-QUIC UDP); Gecko obfuscation is
  an explicit upstream attempt to counter QUIC fingerprinting specifically,
  which is itself evidence that QUIC fingerprinting is a live, real concern
  upstream takes seriously - not evidence that Gecko defeats it (full audit
  deferred to B47 per task scope).

### 4.2 TUIC

- **Protocol model**: 0-RTT-focused proxy protocol over raw QUIC, deliberately
  minimal framing.
- **Maintenance/governance risk**: the original author (EAimTY) stepped back
  from sole authorship in 2025 and restarted the project under a
  community-driven model
  ([EAimTY's own blog post](https://www.eaimty.com/2025/restart-developing-tuic-but-not-as-the-author/)).
  Multiple forks/successors exist with varying activity (`Itsusinn/tuic`,
  `iwayproxy/iway`), which is a real supply-chain signal: no single
  canonical, unambiguously-maintained upstream exists the way Hysteria2 or
  Shadowsocks-rust have.
- **License**: GPLv3
  ([tuic-protocol/tuic LICENSE](https://github.com/EAimTY/tuic/blob/dev/LICENSE)).
  This is materially stronger copyleft than MIT/MPL-2.0/Xray's own MPL-2.0 -
  the SAME class of concern B45's research document already flagged for
  `ics-openvpn` (GPLv2) and explicitly called out as needing "formal legal
  review" before any linkage decision. A native TUIC dependency inside a
  proprietary-adjacent Android app would need the identical legal review
  before this candidate could move past research.
- **Language**: Rust.
- **Android/ABI**: no first-party Android SDK/AAR identified in this
  research pass; third-party Android integration precedent exists (TUIC
  client support appears in general-purpose multi-protocol Android proxy
  clients in the same ecosystem as Hysteria2's own third-party wrappers -
  Section 4.1), but Nova has no TUIC-specific Android/`VpnService`/physical
  feasibility evidence of its own. A future Nova adapter would still need
  its own JNI wrapper, comparable in shape to the Shadowsocks-rust
  `local-tun` work, with no existing B45A-equivalent spike proving Android
  feasibility for TUIC specifically.

### 4.3 General QUIC libraries (quiche, quinn, s2n-quic)

These are NOT proxy protocols - they are QUIC transport-layer libraries a
future Nova-built protocol (e.g. a from-scratch MASQUE/CONNECT-IP client, or
a custom framing) would be built on top of, not a drop-in transport
themselves.

- **quiche** (Cloudflare, BSD-2-Clause, C API/Rust): explicit
  `cargo ndk`-based Android `arm64-v8a` build path exists and is used in
  production elsewhere (Android's own system DNS-over-HTTP/3 resolver uses
  quiche) ([quiche GitHub](https://github.com/cloudflare/quiche)) - the
  strongest Android-provenance evidence of the three.
- **quinn** (community, MIT/Apache-2.0, pure Rust): general-purpose,
  async-friendly; Android support is achievable via standard Rust
  cross-compilation but has less documented production Android precedent
  than quiche in this research pass
  ([quinn-rs/quinn](https://github.com/quinn-rs/quinn)).
- **s2n-quic** (AWS, Apache-2.0, Rust): explicitly documented for
  Linux/macOS/Windows with a Linux-kernel-5.0+ requirement; no Android
  support surfaced in this research pass - treat as **not evidenced for
  Android** rather than assumed absent.
- Any of these would require Nova to design and implement its own
  proxy/auth/framing protocol on top (effectively building a bespoke
  Hysteria2/TUIC-equivalent) - a materially larger, higher-risk undertaking
  than adopting an existing purpose-built protocol, and one that invents new
  cryptographic/protocol design the task's scope explicitly excludes ("No
  new cryptography is in scope" per this task and B45's own precedent).

### 4.4 Cronet

- Google's Chromium network stack packaged as an Android library; QUIC/
  HTTP/3 enabled by default, with documented connection-migration
  configuration
  ([Android Cronet docs](https://developer.android.com/develop/connectivity/cronet)).
- **Not a VPN transport candidate by itself**: Cronet is an HTTP(S) client
  library (`CronetEngine`/`UrlRequest`) for making HTTP requests, not a
  generic UDP/TCP tunneling primitive. It has no CONNECT-IP/MASQUE client
  implementation surfaced in official docs in this research pass. It could
  theoretically serve as the HTTP/3 transport underneath a future MASQUE
  client Nova builds itself, but that is "build a MASQUE client using
  Cronet's QUIC stack as a library," not "adopt Cronet as a transport" - a
  much larger scope than adopting Hysteria2/TUIC.
- License: BSD-3-Clause (Chromium), large binary size (Chromium-derived
  native library), non-trivial footprint for a narrow use case.

### 4.5 MASQUE (`quic-go/masque-go`) as a from-scratch build

`quic-go/masque-go` implements RFC 9298 CONNECT-UDP in Go
([quic-go/masque-go](https://github.com/quic-go/masque-go)). A Nova-built
MASQUE/CONNECT-IP client would be closer to "build a new transport from an
IETF spec and a reference library" than "adopt a maintained proxy protocol" -
higher engineering cost and no existing Android-proven client, but the most
standards-aligned option (production precedent: iCloud Private Relay,
Cloudflare WARP). This is the most credible "future, not next" option and is
flagged as such in Section 19, not proposed for near-term adoption.

## 5. Xray/XHTTP diversity concern (Q2, expanded)

Per Section 2.2/2.3, using Xray's own XHTTP-h3 path for "QUIC support" would
NOT give Nova an independent failure domain from the existing Xray-based
transports (`XRAY_REALITY`, `TLS_TCP`, `XRAY_XHTTP`) - it is the same
`XrayCoreController`/`NovaXrayVpnService` runtime, the same pinned binary,
the same upstream release cadence. This directly undermines the stated
purpose of transport diversity (independent failure characteristics), the
same conclusion B45's research reached for "Shadowsocks routed through
Xray's own module" (marked "REJECT FOR NOW as a diversity claim" in
`docs/ROADMAP.md`'s B45 row). **A credible QUIC transport for diversity
purposes must be an independent runtime outside Xray** (Section 4's
Hysteria2/TUIC/custom-MASQUE candidates), mirroring B45A's own
"independent `shadowsocks-rust` runtime, never routed through Xray's own
module" precedent exactly.

## 6. UDP/443 coexistence with existing gateway infrastructure (research only)

No gateway/nginx/firewall change was made or is proposed here. Observed
facts from the existing deployment docs (`gateway/DEPLOYMENT.md`,
`gateway/README.md`):

- The control-plane (`pocvpn-api`) is TCP-only by systemd hardening
  (`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, "the service only
  ever needs a TCP listen socket") - a future QUIC data-plane listener would
  be a materially different process/service, not an extension of
  `pocvpn-api`.
- AWG already uses UDP (port 51820) on both gateways; REALITY/TLS use TCP on
  2053/2083. A QUIC data-plane on UDP/443 would be a THIRD distinct
  listening surface, sharing UDP/443 (or a Nova-chosen alternate UDP port)
  with nothing existing today - port 443 is currently TCP-only (TLS/REALITY
  inbounds), so a UDP/443 listener does not collide at the port-number level
  with the existing TCP/443 inbounds (UDP and TCP are independent port
  spaces), but it DOES add a new firewall allow-rule, a new health-probe
  target, and a new nginx-vs-native-listener decision (nginx does not
  natively terminate raw QUIC/UDP the way it does HTTP/TLS on TCP; an
  `ngx_http_v3_module`-based HTTP/3 listener is a DIFFERENT nginx
  capability than proxying an arbitrary QUIC-substrate protocol like
  Hysteria2/TUIC, which would need its own standalone UDP listener process,
  not nginx).
- **This document does not propose any specific port, firewall rule, or
  nginx config** - it only records that such a change would be a genuinely
  new deployment surface, evaluated against `gateway/DEPLOYMENT.md`'s
  existing hardening discipline (least-privilege systemd units, explicit
  `AF_*` restriction, no new management port) whenever a real implementation
  slice is proposed.

## 7. Android `VpnService` integration requirements vs. existing lessons

Compared against AWG/Xray/Shadowsocks lessons already recorded in this repo:

| Requirement | AWG (`GoBackend$VpnService`) | Xray (`NovaXrayVpnService`) | Shadowsocks (B45A/B45B) | QUIC candidate implication |
|---|---|---|---|---|
| TUN ownership | Own AAR-owned `VpnService` | Nova's own `VpnService` | Nova's own `VpnService`, `SCM_RIGHTS` fd handoff | A QUIC transport needs its own `VpnService` (pattern (a) from B45's audit) unless it somehow runs inside the Xray process (rejected, Section 5) - "a new native core needs its own `VpnService`" is explicitly established as non-unprecedented in this codebase (`docs/B45_TRANSPORT_DIVERSITY_RESEARCH.md` §2.3). |
| TCP+UDP handling | UDP only | TCP only (both current Xray inbounds) | Both real (B45A proved 3/3 exact UDP + TCP round-trips) | A QUIC-substrate proxy protocol tunnels BOTH TCP and UDP payloads over one QUIC connection - the TUN-to-proxy translation layer (tun2socks-equivalent) has to demux both, same shape as Shadowsocks's proven design, not a new problem class. |
| `protect()` | Yes (native) | Yes (native) | Yes (`protect(fd)`, B45A physically proved) | The QUIC socket itself (the UDP socket the QUIC library opens to the gateway) MUST be protected exactly like Shadowsocks's outbound UDP/TCP sockets, or the app's own tunnel recursively captures its own VPN traffic - identical requirement, already proven solvable in this codebase for a Rust-JNI runtime. |
| DNS | Tunnel-scoped resolver | Tunnel-scoped resolver | Same pattern reused | No new DNS design needed - reuse the existing tunnel-DNS pattern; QUIC introduces no new DNS semantics for this layer. |
| IPv4/IPv6 | IPv4 handshake proven; IPv6 fail-closed by design across the whole app | Same fail-closed IPv6 discipline | Same | No change - IPv6 stays fail-closed until a dedicated slice addresses it app-wide, unaffected by transport choice. |
| MTU/PMTU | Standard WireGuard MTU handling | Standard | Standard | QUIC's own packetization (typically targeting ~1200-1350 byte UDP payloads to avoid fragmentation) needs the SAME TUN MTU discipline the existing transports already apply; no evidence yet that this needs different handling, but unverified until physically tested. |
| Network changes / reconnect | `AndroidReconnectManager`'s real underlying-network callback fix (the B30B `registerNetworkCallback`+`NET_CAPABILITY_NOT_VPN` fix, `docs/ROADMAP.md` P0 row) | Same shared fix | Q7 (handover) explicitly BLOCKED/UNVERIFIED for B45A | QUIC's own connection migration (Section 15) is a DIFFERENT layer than `AndroidReconnectManager`'s job: QUIC migration can keep the QUIC session itself alive across a network change WITHOUT tearing down the VPN session, which is a genuinely different capability than the existing "detect loss, `RESTART_SESSION`" reconnect model - but it does not replace `AndroidReconnectManager`; the app-level VpnService/TUN interface itself still needs the SAME underlying-network-change detection to decide whether to hand the new network to the QUIC library (`quic-go`/quiche support explicit path-migration APIs the JNI/Go wrapper would need to call) or fall back to `RESTART_SESSION`. This is real, additive engineering, not free. |
| Doze/foreground-service | Existing foreground-service discipline applies uniformly | Same | Same | Hysteria2's OWN documented idle/screen-locked disconnect bug (Section 4.1) is a live, unresolved upstream risk specific to this candidate family, independent of Nova's own foreground-service correctness. |
| Reconnect ownership | `VpnController`/`ReconnectManager`, never transport-owned | Same | Same (would be, once wired) | A QUIC transport's `VpnTransport.observeState()`/health confirmation MUST follow the SAME rule B45's doc already states for any non-Xray-wrapped runtime: "needs its OWN positive-confirmation and post-connect health-check implementation... never bolted onto `XrayCoreController`, and never a second, parallel health authority outside `TransportHealth`." |
| Process lifecycle / battery / radio | N/A per-transport, app-wide constraints | Same | Same | QUIC's per-packet AEAD framing (vs. WireGuard's simpler framing) and userspace crypto in a JNI/Go runtime carry the SAME "own thread pool / native runtime lifecycle" concerns B45B already designed around (`ShadowsocksRuntime`); no new lifecycle model needed, but real CPU/battery measurement is unverified (Section 16). |

**Conclusion: a QUIC transport fits the existing `VpnTransport` ownership
model (pattern (a): own `VpnService` subclass, own runtime, `protect()`'d
sockets, `TransportState` Flow, own health confirmation) without requiring
any change to that model.** Nothing here proves the model impossible for
QUIC - the opposite: every seam B45's audit already mapped (Section 2.2 of
that document, reused verbatim above) applies unchanged.

## 8. Network handover: reality vs. marketing (Q6)

What QUIC actually provides, per RFC 9000 and the IETF QUIC WG's own
materials:

- **Connection IDs** decouple a QUIC connection from any specific 4-tuple -
  a peer can present a new source IP/port (e.g. after a Wi-Fi->cellular
  switch or a NAT rebind) and the connection continues, subject to **path
  validation** (a PATH_CHALLENGE/PATH_RESPONSE exchange) before the new path
  is trusted for anything beyond a small amount of data
  ([http.dev QUIC explainer](https://http.dev/quic)).
- This is a real, standards-level capability distinct from TCP (which
  requires a brand-new connection on any IP/port change) - not marketing.
- **What is required to actually get this benefit**: the QUIC
  implementation must call its own migration APIs when the underlying
  network changes (most implementations do NOT migrate automatically on
  every network change without the application driving it - `quic-go`'s own
  docs describe connection migration as something the application config/
  API enables and, in some paths, initiates explicitly:
  [quic-go connection-migration docs](https://quic-go.net/docs/quic/connection-migration/)).
  **This means QUIC's handover benefit is NOT free just by choosing a QUIC-
  based transport** - the Android integration layer must detect the
  underlying network change (the SAME `AndroidReconnectManager`/
  `registerNetworkCallback` signal this codebase already fixed for B30B) and
  explicitly hand the new network/socket to the QUIC library's migration
  path, and the library binding used (whichever JNI/Go wrapper Nova builds)
  must actually expose that API - not all "QUIC support" claims in a proxy
  protocol's marketing mean "handover is wired end to end for our exact
  usage," which is why multipath/migration remains an active IETF draft
  area (`draft-deconinck-quic-multipath`) rather than a fully solved,
  uniform problem.
- **Interaction with `AndroidReconnectManager`**: a correctly-integrated
  QUIC transport could, in principle, use `IN_PLACE`
  `UnderlyingNetworkRecovery` (survive a network change without tearing the
  VPN session, unlike today's `RESTART_SESSION`-only transports) - but this
  is a claim that requires the SAME kind of physical proof B45A demanded for
  Shadowsocks's own UDP claim, never assumed from protocol theory. Until
  physically proven, any future QUIC adapter shell must default to
  `RESTART_SESSION` and report `supportsRoaming = false`, exactly like every
  other adapter-shell factory in `TransportCapabilities.kt` does before its
  own physical evidence exists.

## 9. Blocking/censorship characteristics - evidence-based only

No claim of undetectability or of bypassing Russian filtering/whitelists is
made or implied anywhere in this document, consistent with
`docs/ROADMAP.md`'s stated architecture principle ("Nothing in this product
may claim 'untraceable,' a guaranteed censorship bypass, or a guaranteed
hard-whitelist bypass") and B45's own precedent ("Russia/restricted-network
field evidence is not produced by this task - it remains UNVERIFIED"). What
IS publicly documented and cited:

- UDP/443 (or any UDP-based transport) is a KNOWN, common target of DPI/QoS
  policies in restrictive networks generally - this is a well-known
  industry pattern (many networks throttle or drop non-standard UDP,
  including QUIC itself, precisely because it's harder to inspect than
  TCP/TLS) but this document makes no claim about any specific network,
  including Russia's, without field evidence (B54 territory).
- Hysteria2's own upstream added Gecko obfuscation specifically to resist
  QUIC fingerprinting (Section 4.1) - upstream's own investment in this is
  evidence that QUIC fingerprinting resistance is NOT solved merely by
  "using QUIC," it is an ongoing arms-race the protocol's own maintainers
  are still actively working on.
- Nothing here claims AWG/REALITY/TLS_TCP's existing UDP-filtering or
  hard-whitelist evasion characteristics are inferior or superior to a
  future QUIC transport - both remain UNVERIFIED in the field per this
  repo's existing discipline until B54 actually runs.

## 10. Traffic fingerprint characteristics per candidate (survey only, full audit deferred to B47)

No forged fingerprints of unrelated services and no unauthorized domain
fronting are proposed anywhere in this document.

- **Hysteria2**: raw QUIC wire format by default (long-header Initial
  packets are visible as QUIC even before decryption); Salamander
  obfuscation XORs a shared-secret-derived keystream over the whole UDP
  payload including QUIC headers, aiming to make the traffic look like
  unstructured UDP rather than recognizably-QUIC; Gecko (2026) further
  fragments long-header packets. None of this is evaluated for effectiveness
  here - that is explicitly B47's job.
- **TUIC**: raw QUIC, no obfuscation layer surfaced as a standard/default
  feature in this research pass (would need confirmation from its current
  spec if this candidate is pursued further).
- **CONNECT-IP/MASQUE over HTTP/3**: wire format is indistinguishable from
  ordinary HTTP/3 traffic to the SAME extent any HTTP/3 CDN traffic is -
  this is the theoretical fingerprint advantage of the MASQUE family (it
  rides inside a real, standards-conformant HTTP/3 session, the same shape
  legitimate CDN/web traffic uses), but only if Nova's own MASQUE endpoint
  is genuinely indistinguishable at the TLS/ALPN/H3-frame level from real
  web traffic to that host - unverified without a real implementation and
  audit.
- **Xray XHTTP-h3** (if the `HTTP3_DIAL_NOT_BOUNDED` gap were ever closed):
  inherits whatever fingerprint properties Xray's own H3 implementation has
  - not independently evaluated here since Section 5 already establishes it
  is not a diversity-relevant candidate regardless of its fingerprint.

## 11. CDN/HTTP3 relay usability (Q9)

No CDN configuration is proposed or made in this slice. Distinguishing the
four things this question asks to distinguish:

1. **CDN termination of ordinary HTTPS/HTTP3** (what `docs/CDN_PROVIDER_PROFILE.md`'s
   existing XHTTP work already uses, minus the h3 ALPN which Nova rejects) -
   this is a CDN serving/relaying HTTP requests to an origin, nothing more.
2. **End-to-end QUIC** (client QUIC session terminates at Nova's own
   gateway, no intermediary) - what a self-hosted Hysteria2/TUIC deployment
   would be; no CDN involvement at all.
3. **CONNECT-UDP/MASQUE via a CDN** - requires the CDN to specifically
   support proxying MASQUE CONNECT-UDP/CONNECT-IP requests to an arbitrary
   backend on Nova's behalf, which is a materially different, much rarer CDN
   product feature than "serves HTTP/3 to browsers." Whether Nova's
   currently-used CDN provider (per `docs/CDN_PROVIDER_PROFILE.md`) exposes
   this is UNVERIFIED and not researched in this pass (out of scope: no CDN
   configuration or provider-specific claim is made).
4. **Ordinary HTTP/3 web traffic** - not usable to relay an arbitrary VPN
   QUIC protocol at all; it's the CDN's OWN web-serving HTTP/3, unrelated to
   whatever protocol Nova's data plane speaks underneath.

**Conclusion: an owned/authorized CDN's HTTP/3 support for web content does
NOT automatically mean it can relay an arbitrary Nova-defined QUIC/VPN
protocol.** That requires the CDN to specifically support MASQUE/CONNECT-IP
proxying (item 3) or Nova bypassing the CDN entirely for the QUIC data plane
(item 2, self-hosted). This is a real architectural fork any future slice
must resolve explicitly, not assume.

## 12. Security (Q10)

- **TLS 1.3**: QUIC mandates TLS 1.3 for its handshake (RFC 9001) - this is
  already the minimum-version floor Nova's own signed CDN provider profiles
  enforce (`CdnMinimumTlsVersion`), so no regression versus existing
  invariants.
- **Cert auth / PSK / 0-RTT**: QUIC's 0-RTT (like TLS 1.3's) has the SAME
  well-known replay risk as any 0-RTT mechanism - early data can be
  replayed by a network attacker unless the application layer explicitly
  guards against replay-sensitive operations in 0-RTT data. Any future
  Nova QUIC transport must treat 0-RTT identically to how a careful TLS 1.3
  deployment would: either disable it for anything not idempotent, or
  explicitly design replay-safe framing. This is a real design requirement
  for a future slice, not solved by "QUIC has TLS 1.3."
- **Session tickets / key rotation**: standard TLS 1.3 session-resumption
  mechanics apply; a future design must specify ticket lifetime/rotation
  the same way REALITY/TLS_TCP's own signed TLS policy fields
  (`CdnMinimumTlsVersion`, ALPN, fingerprint) are already modeled, not
  invent a parallel credential-freshness model.
- **Credential storage**: any future QUIC candidate's client credential
  (PSK, cert, or protocol-specific auth token e.g. Hysteria2's shared
  password/TUIC's UUID+password) MUST live in an endpoint-scoped encrypted
  credential repository following the EXACT pattern
  `XrayProfileRepository`/`XrayTlsProfileRepository`/(future)
  `Shadowsocks2022CredentialRepository` already establish - never inline in
  a signed manifest field, never in `ProductionGatewayCatalog`, never in
  plain SharedPreferences. This document proposes no new storage
  abstraction; it reuses the existing one.
- **Secrets**: no secret, key, credential, or token of any kind appears
  anywhere in this document or would ever appear in a future signed
  transport profile (Section 13) - both per this task's explicit
  instruction and per this repo's existing B42 discipline.

## 13. B42 Signed Transport Profile compatibility (Q11 - design only, no implementation)

Following the exact pattern B23's `ingressKind()` and B44's
`operationalState()` used to extend `SignedTransportProfile`/
`EndpointTransportBinding.metadata` without a re-signing ceremony
(`docs/B45_TRANSPORT_DIVERSITY_RESEARCH.md` §2.2), a future
`SignedTransportProfile.Quic*` (or metadata-map entries under a
`TransportKind.QUIC`/new `TransportKind` value) would need ONLY non-secret,
public connection facts:

- `host`, `port` (already generic `EndpointTransportBinding` fields).
- `protocolVariant` (e.g. `"hysteria2"` / `"tuic-v5"` / `"masque-connect-ip"`)
  - a public wire-protocol identifier, not a secret.
- `alpn` (already modeled for TLS-based transports; QUIC-substrate
  protocols that don't use ALPN in the TLS sense would omit it).
- `minTlsVersion` (reuse `CdnMinimumTlsVersion`'s existing type).
- `congestionControlHint` (e.g. Hysteria2's declared bandwidth-negotiation
  mode) - public protocol-tuning metadata, not a secret.
- `obfuscationVariant` (e.g. `"salamander"` / `"gecko"` / `"none"`) - a
  public capability flag, mirroring how REALITY's camouflage `dest`/
  `serverName` are already public signed facts.
- **Explicitly NOT included**: any PSK, password, UUID/auth-token, private
  key, or session ticket - these belong in a new endpoint-scoped encrypted
  credential repository (Section 12), exactly like every existing
  credential-bearing transport.

This is a design sketch only - no `SignedTransportProfile` type, no manifest
schema change, and no signing-key ceremony is performed or proposed by this
task.

## 14. Mapping onto `TransportCapabilities` (Q12 - using actual repo names)

Using the real fields from `TransportCapabilities.kt`:

| Field | Hysteria2/TUIC-class (design intent) | Notes |
|---|---|---|
| `usesUdp` | `true` | QUIC is UDP-substrate by definition. |
| `usesTcp` | `false` | The QUIC session itself never opens a raw TCP socket (unlike XHTTP/TLS_TCP); TCP payload relaying happens INSIDE the QUIC streams, same conceptual shape as how AWG's `usesUdp=true`/`usesTcp=false` already describes a transport that can still carry arbitrary IP payload once tunneled. |
| `supportsPort443` | `true` (design intent) - UDP/443 is the common convention for QUIC-based proxies specifically to blend with HTTP/3 traffic, unverified until a real deployment decision is made. |
| `supportsObfuscation` | Protocol-dependent (`true` for Hysteria2 w/ Salamander/Gecko, unresolved for TUIC) - must reflect REAL configured behavior once implemented, never assumed. |
| `suitableForRestrictiveNetworks` | `false` until real evidence exists - same discipline as every existing NOT_IMPLEMENTED/EXPERIMENTAL factory in this file. |
| `supportsRoaming` | `false` until a REAL physical Wi-Fi<->cellular handover proof exists (Section 8) - QUIC's theoretical migration capability is not sufficient evidence by itself. |
| `supportsFullTunnel` | `true` once physically proven (design intent - both TCP and UDP payload relaying are architecturally intended). |
| `supportsSplitRouting` | `false` initially (mirrors every current adapter-shell's ALL_APPS-only starting point). |
| `supportsIpv6` | `false` (fail-closed by omission, matching every existing transport's IPv6 posture). |
| `supportsTrafficStatistics` | `false` initially. |
| `supportsProbing` | `false` initially, pending a real bounded probe design (Section 15). |
| `maturity` | `NOT_IMPLEMENTED` until code exists; the model has no intermediate state for "protocol researched, no code" (same gap B45B-1 already noted for Shadowsocks - `TransportMaturity` genuinely lacks a "researched" rung). |

**Gap identified, not fixed**: `TransportCapabilities` has no explicit
`requiresUdp` (as distinct from `usesUdp`), `supportsNetworkMigration`, or
`reachability` field the task's own research-question wording assumed exist
- they do not exist in this codebase today. `usesUdp` already serves the
"requires UDP" signal implicitly (nothing currently models "prefers but
doesn't require" UDP). `supportsRoaming` is the closest existing analog to
"network migration," and `EndpointReachability`
(`android/.../reachability/`, not `TransportCapabilities` itself) is where
reachability facts actually live, per-endpoint rather than per-transport-
type - so a future QUIC reachability signal belongs on `NetworkProfile`'s
existing `quicReachability: ProbeSignal` field (Section 2.1) and/or a new
per-(endpoint, QUIC-kind) `EndpointReachability` entry, NOT a new
`TransportCapabilities` field. This document notes these gaps; it does not
modify the model.

## 15. Smart Connect / auto-selection design sketch (Q13 - no wiring)

Any future QUIC eligibility/scoring MUST go through the existing evidence
pipeline, never a hardcoded rule:

- **Eligibility gate**: identical shape to B45B-4's `SHADOWSOCKS_2022`
  gating (`docs/ROADMAP.md` B45 row: "gated fail-closed on THREE narrow
  facts") - a future QUIC transport would need its own narrow, explicit,
  AND-ed eligibility facts (e.g.: endpoint has a signed QUIC transport
  binding AND a valid endpoint-scoped credential exists AND device ABI has
  a packaged runtime), never a country/provider/OS-version rule.
- **UDP failure and eligibility**: `NetworkProfile.udpReachability`
  (already-modeled `ProbeSignal`) and the new `quicReachability` slot
  (Section 2.1) are the natural inputs - a network where UDP/AWG is already
  observed blocked (existing `POSSIBLE_UDP_OR_AWG_FILTERING` signal per
  `RestrictionClassifier`) is prior evidence a QUIC-substrate transport is
  ALSO likely to fail (same UDP-blocking cause), and `PathScorer`/
  `AutoGatewaySelector` should be able to fold that in as a scoring/
  eligibility signal exactly the way `AutoGatewaySelectorTest`'s existing
  "fresh AWG UNREACHABLE... reorders" cases already prove the pattern for
  AWG today - no new decision authority, reuse of the SAME
  `PathScorer.eligible`/`ineligibilityReason` mechanism.
- **Bounded probing fitting `ReachabilityEngine`**: a QUIC reachability
  probe (e.g. a bounded-timeout QUIC handshake attempt to the target
  endpoint's QUIC port, analogous to the existing HTTPS control-plane
  probe) would populate `quicReachability`/a new endpoint-specific
  reachability entry through `ReachabilityEngine`'s EXISTING bounded-probe
  discipline (the same "this endpoint, this transport, this network" model
  `EndpointReachability` already implements per B11/B12) - never a new,
  unbounded, or blocking probe path, and never conflated with the
  control-plane HTTPS probe (`controlPlaneReachable` stays distinct from
  `endpointSpecificReachable`, per the existing explicit non-collapsing
  rule in `docs/ROADMAP.md`'s Gateway Health row).
- Manual mode's `SmartConnectDecisionEngine.decideAuto` would gain QUIC in
  `PREFERRED_ORDER` only once `TransportRegistry` genuinely reports it
  AVAILABLE (mirroring how it's already LISTED but excluded today) - never
  before real code/credentials/ABI packaging exist, per this repo's
  standing "no fake success" discipline.

## 16. Failure taxonomy mapping (Q14)

Mapped onto the project's existing typed-failure philosophy
(`DiagnosticFailureMapping`/`SupportDiagnosticsRecorder`, B29):

| Generic category | Existing precedent | QUIC-specific LEAF cause (proposed name only, not implemented) |
|---|---|---|
| NETWORK_UNAVAILABLE | Existing, transport-agnostic | Reused as-is. |
| GATEWAY_UNREACHABLE | Existing | Reused as-is (endpoint-level, not protocol-specific). |
| UDP blocked | `POSSIBLE_UDP_OR_AWG_FILTERING` (RestrictionClassifier) | `QUIC_UDP_HANDSHAKE_TIMEOUT` - distinct from AWG's own UDP-blocked signal so evidence doesn't conflate two different UDP protocols' independent failure (architecture principle: never collapse distinct evidence). |
| Auth failure | Xray REALITY key-validation-bug precedent (B8I8), Shadowsocks credential-repository gating | `QUIC_AUTH_REJECTED` (PSK/token rejected by gateway). |
| TLS/cert failure | Existing TLS_TCP-family diagnostics | `QUIC_TLS_HANDSHAKE_FAILED` (TLS 1.3-over-QUIC handshake failure, distinguishable from a TCP-TLS failure since it's a materially different code path). |
| Runtime/process failure | Shadowsocks's own `SS2022_HANDSHAKE_FAILED`-class precedent, B45A's `SCM_RIGHTS`/fdsan lessons | `QUIC_RUNTIME_START_FAILED` (native/Go/Rust QUIC runtime failed to initialize - e.g. JNI load failure, socket bind failure). |
| Config/profile invalid | Existing `RENDER_CONFIG_INVALID`-class (CdnXhttpRuntimeConfigResolver precedent) | `QUIC_PROFILE_INVALID`. |
| Timeout | Existing `dialContext`-bounded pattern (Section 2.2's own precedent, and its EXPLICIT current gap for Xray's own H3 dial) | `QUIC_DIAL_TIMEOUT` - and this LEAF cause is exactly why Section 2.2's finding matters: whatever bounded-dial mechanism a future QUIC adapter uses must be verified to actually bound the QUIC library's own connect call, the same defect Nova's own resolver already caught once for Xray's H3 path. |
| Local VpnService failure | Existing generic `VpnService` failure diagnostics | Reused as-is - a QUIC `VpnService` subclass reports through the SAME generic `TransportState`/diagnostics path every other transport does. |

**Gap identified, not implemented**: none of these LEAF causes exist in
`DiagnosticFailureMapping` today (confirmed: no QUIC-specific failure
literal appears anywhere in `android/app/src/main/java/net/pocvpn/client/`
per the Section 2 grep). This is expected - no QUIC runtime exists yet to
produce these failures - and is recorded here purely as the shape a future
implementation slice would need to add, following the SAME vocabulary
discipline (never inferring a failure kind from an exception message
string) the rest of the codebase already enforces.

## 17. Fallback/coexistence with existing transports (Q15)

A future QUIC transport must participate in the SAME `PathScorer`/
`AutoGatewaySelector`/`TransportHealth` scoring-and-health architecture as
every other transport - never a hardcoded cascade (e.g. "always try QUIC
first," "always fall back AWG->QUIC->REALITY"). Concretely:

- **When attempting QUIC would be harmful**: (a) a network with fresh
  `UNREACHABLE` `udpReachability`/`quicReachability` evidence - attempting a
  QUIC handshake there wastes the SAME bounded connect-timeout budget
  `AwgXrayFailoverPolicy`'s own AWG->Xray fallback already has to respect,
  directly costing user-visible startup latency for a path already known
  unlikely to succeed; (b) a network where AWG (also UDP) is ALREADY known
  `UNREACHABLE`/`DEGRADED` - strong correlated-failure evidence UDP itself
  is filtered, not merely one protocol.
- **How existing evidence avoids this**: `PathScorer.isEligible`'s existing
  "fresh UNREACHABLE ineligible regardless of health... endpoint REACHABLE
  overriding transport-wide UNREACHABLE" precedent (already unit-proven per
  `docs/ROADMAP.md`'s Gateway Health row) is the exact mechanism that would
  need to apply to a QUIC candidate too - no new precedence rule, reuse of
  the one that already exists, keyed off `quicReachability`/UDP-correlated
  evidence rather than inventing a QUIC-specific scoring path.
- Coexistence with `AWG`/`XRAY_REALITY`/`TLS_TCP`/`XRAY_XHTTP`/
  `SHADOWSOCKS_2022` in `SmartConnectDecisionEngine.PREFERRED_ORDER` is
  purely additive (one more entry, `TransportRegistry` availability still
  the real gate) - no reordering of existing entries is implied or
  proposed by this document.

## 18. Performance (Q16 - theory vs. benchmarks vs. Nova measurements)

- **Protocol theory** (IETF spec-level, not vendor-specific): QUIC's 1-RTT
  (and optional 0-RTT) handshake combines transport+TLS negotiation in
  fewer round trips than TCP+TLS's traditional separate handshakes;
  per-stream flow control removes head-of-line blocking BETWEEN independent
  streams (though a single stream, or the QUIC UDP packet loss itself, can
  still stall); congestion control is pluggable (Hysteria2's own "Brutal"
  algorithm is a vendor-specific, non-standard congestion controller tuned
  for lossy/bandwidth-known links, not an IETF-standardized algorithm).
- **Upstream benchmark claims** (vendor-reported, not independently
  verified by this task): Hysteria2's own marketing emphasizes performance
  on lossy/high-latency links via Brutal CC - this document does not adopt
  or repeat specific numeric claims from vendor benchmarks as fact, per the
  task's instruction not to rely on memory alone and to distinguish claims
  from verification.
- **Nova measurements**: **NONE EXIST.** No handshake-RTT, throughput,
  CPU/memory/battery, or binary-size measurement for any QUIC candidate has
  been performed against Nova's actual gateways or devices. This is
  identical in kind to B45A's own discipline (real device evidence required
  before any capability claim) - Section 19 names this as a required
  pre-implementation step, not something this research task could or should
  fabricate.
- **Gateway resource use**: unmeasured; a QUIC-substrate proxy server
  process (Hysteria2/TUIC server) would be a new process on the gateway VPS
  with its own CPU/memory footprint, distinct from `pocvpn-api`/`nova-xray`/
  `awg-firewall`/`nginx` - no measurement exists.

## 19. Proposed smallest credible future B46 architecture (design only, no implementation)

This is the "if a future implementation slice happens" sketch, explicitly
NOT proposed for immediate execution:

1. **What runtime executes it**: an independent native runtime (Go via
   gomobile, mirroring Hysteria2's own upstream language, OR Rust/JNI
   mirroring B45A's proven Shadowsocks-rust pattern) - never inside the
   existing `XrayCoreController` process (Section 5).
2. **Who owns the TUN**: a new `VpnService` subclass following
   `NovaXrayVpnService`'s established pattern (self-UID exclusion via
   `addDisallowedApplication`, `TransportState` Flow emission, `EXTRA_*`
   intent-extra config threading) - one more coexisting-but-never-
   concurrent `VpnService`, the same shape B45's audit already established
   as non-unprecedented.
3. **How TUN packets reach the runtime**: the SAME `SCM_RIGHTS` real-fd
   handoff pattern B45A/B45B physically proved (not `ParcelFileDescriptor.
   adoptFd`, per B45B3P's own documented fdsan-ownership-conflict lesson) -
   reuse, don't reinvent.
4. **How runtime sockets avoid recursive VPN capture**: `protect(fd)` on
   the QUIC library's own outbound UDP socket, exactly like every existing
   transport, verified BEFORE any traffic proof is claimed (B45A's own Q-
   numbered verification discipline).
5. **How credentials/endpoint metadata are provided**: public facts via
   `EndpointTransportBinding`/a future `SignedTransportProfile.Quic*`
   (Section 13); secret credentials via a NEW endpoint-scoped encrypted
   repository mirroring `Shadowsocks2022CredentialRepository`'s own design
   (never inline in the signed manifest).
6. **How lifecycle maps to `TransportState`**: standard
   `Connecting -> Connected -> Disconnecting -> Disconnected`/`Error` Flow
   emission, with an OWN positive-confirmation step (post-handshake,
   application-level proof of live traffic - not merely "process started")
   before ever reporting `Connected`, per B33's precedent.
7. **Stop/cleanup**: mirrors B45B3P's own found-and-fixed lesson (a normal-
   stop Unix-domain-socket cleanup bug was found and fixed there) - a
   future QUIC runtime needs the SAME explicit teardown discipline
   physically verified, not assumed correct from code review alone.
8. **Reconnect ownership**: `VpnController`/`ReconnectManager`, never
   transport-owned (Section 7's table) - `UnderlyingNetworkRecovery`
   defaults to `RESTART_SESSION` until a REAL physical handover proof
   justifies `IN_PLACE` (Section 8).
9. **How reachability is measured**: a new bounded QUIC-handshake probe
   feeding `NetworkProfile.quicReachability`/a per-endpoint
   `EndpointReachability` entry through the EXISTING `ReachabilityEngine`
   (Section 15) - never a new, parallel reachability authority.
10. **How selection is gated**: `TransportRegistry` `NOT_IMPLEMENTED` until
    real code+credentials+ABI packaging exist (mirroring `SHADOWSOCKS_2022`'s
    own B45B-4 gating discipline exactly) - `PathScorer`/
    `AutoGatewaySelector` reused verbatim, no second scorer.
11. **How the gateway would be deployed**: a new, narrowly-scoped systemd
    unit (mirroring `pocvpn-api`'s own hardening: explicit `AF_*`
    restriction, no new management port, least-privilege) running the
    chosen proxy-server binary, with its own firewall allow-rule - a
    genuinely new deployment surface (Section 6), requiring explicit
    operator action and NEVER a purchased/allocated cloud resource without
    owner approval (CLAUDE.md's infrastructure-safety rule).
12. **What must be physically proven before any implementation slice**:
    (a) an Android feasibility spike proving real `VpnService` TUN
    ownership + `SCM_RIGHTS` handoff + `protect()` + real end-to-end TCP AND
    UDP data-plane traffic through the chosen QUIC library on a real device
    (the exact B45A-equivalent bar); (b) a real Wi-Fi<->cellular handover
    physical test before `supportsRoaming`/`IN_PLACE` is ever claimed; (c)
    real CPU/memory/battery measurement on a real device before any
    performance claim; (d) a real gateway-side deployment + firewall/health-
    probe integration proof; (e) formal legal review of the chosen
    candidate's license (immediately required for TUIC given its GPLv3
    licensing, per Section 4.2) BEFORE any code from it is linked into this
    app.

## 20. Architecture self-check against `vpn-architecture` invariants

Applying the persona's boundaries (Section "Architectural boundaries to
preserve" in `.claude/agents/vpn-architecture.md`) to Section 19's sketch:

- **Single scoring authority**: preserved - Section 15/17/19 reuse
  `PathScorer`/`AutoGatewaySelector` verbatim, propose no second scorer.
- **Smart Connect transport-only, never gateway**: preserved - nothing in
  this design lets a QUIC transport choice imply or drive gateway
  selection; `SmartConnectDecisionEngine` stays within the manually
  selected endpoint exactly as today.
- **Provider names stay diagnostics-only**: not affected by this document
  (no gateway/provider-facing UI change proposed).
- **Whitelist-vs-DPI conflation**: Section 9 explicitly avoids this,
  treating UDP-blocking evidence as UDP-blocking evidence, never inferring
  a specific censor mechanism.
- **No impersonation of unrelated trusted services**: Section 10 explicitly
  states no forged fingerprints/unauthorized domain fronting are proposed;
  fingerprint work itself is deferred to B47 by design.
- **Device-identity invariant** (`ClientTunnelIdentityStore`, never
  hardcoded): not affected - Section 13/19 propose credential storage
  mirroring existing endpoint-scoped repositories, never gateway-catalog
  hardcoding.
- **Infrastructure safety** (no paid-resource allocation, no destructive
  changes without approval): Section 6/19 explicitly defer any real gateway
  deployment to a future slice requiring explicit operator action.
- **Debug/release boundary**: not affected (no debug tooling proposed by
  this research document).
- **ROADMAP discipline**: this document's own companion `docs/ROADMAP.md`
  edit is a minimal, status-only line (RESEARCH -> "B46-1 research
  complete, in review"), not a capability-status inflation.

**No blocker identified against these invariants** - because no code,
config, or wiring exists yet to violate them. This self-check exists to
verify the PROPOSED Section 19 design does not describe an architecture
that WOULD violate them once implemented, which it does not.

## 20.5. Prior B21 / PR #35 QUIC experiment reconciliation

**PR #35, "B21: QUIC Transport/Fallback (real XHTTP/HTTP-3) - Foundation"**
(`feature/b21-quic-transport`, head `dc5228406fc350656c330f40d917465a9ef1a6a9`,
base `main` at `4b540c780983225b13a0d70b1637a0ca0fb66a58`) is **OPEN and
UNMERGED** as of this research pass. It was read in full (PR body, all 7
commit messages, both PR comments, and `docs/B21_QUIC_TRANSPORT_AUDIT.md` as
committed on its branch) via the GitHub API - not modified, merged,
continued, cherry-picked, or closed by this task, per instruction. It is
treated below as EXPERIMENTAL, UNMERGED prior evidence, not current
production truth; `main` (this document's actual baseline) remains
authoritative for current architecture.

### What PR #35 attempted

Phase A of the PR independently reached the SAME conclusion Section 2.2/2.3
of this document reaches from the currently-checked-out `main`: the pinned
`xray-core v26.7.28`'s standalone `"quic"` `streamSettings.network` value is
a hard config-load error
(`errors.PrintRemovedFeatureError("QUIC transport...", "XHTTP stream-one H3")`,
cited directly from the pinned tag's `infra/conf/transport_internet.go`),
and the real, currently-supported QUIC/HTTP-3 path is XHTTP with
`mode: "stream-one"`, `security: "tls"`, ALPN `h3`, backed by a genuine
`quic-go`/`quic-go/http3` client. PR #35's own audit doc
(`docs/B21_QUIC_TRANSPORT_AUDIT.md`) independently confirms this document's
Section 2.3 external-search finding, from primary source (the pinned tag's
own Go source, not a web search) - this is a second, independent
confirmation of the same fact via a different method, which strengthens
rather than contradicts this document's conclusion.

The PR then built a full, real, wired-in adapter: `TransportKind.QUIC`
reusing `NovaXrayVpnService`/`XrayCoreController` (no second VpnService),
`XrayVlessQuicConfig`/renderer/validator, `VlessQuicTransport`, an
endpoint-scoped `XrayQuicProfileRepository`/provisioner, a third gateway
`vless` inbound (`xhttp`/`stream-one`/ALPN h3) reusing the shared
revocation-aware identity store, `AutoGatewaySelector` gaining one additive
always-defaults-to-unavailable parameter, and 13+16 new Android unit tests
plus 15 gateway pytest tests (all green, full suites green: 933/933 Android
by the final commit). Local `xray run -test` validated both the client
outbound shape and the real three-inbound server config against the exact
pinned binary (`Configuration OK.` both times) - this is real, not claimed
from JSON-reading alone.

### What was actually physically demonstrated vs. what failed

With **explicit operator approval** (per the PR's own commit message,
independent of this task), Frankfurt had `2087/udp` opened and the QUIC/XHTTP
inbound deployed through the existing `xray_reconcile.py` stage/validate/
publish path; all four listeners (REALITY/TLS_TCP/QUIC/AWG) were confirmed
live, and `POST /v1/xray-profile` was confirmed to accept
`{"transport":"quic"}`. **This document does not verify, re-check, alter, or
assume the current live state of that port/inbound** - CLAUDE.md and this
task's own instructions forbid touching Frankfurt or any server/port config
in this slice; whatever state PR #35 left it in is unverified-as-of-today by
this document.

A real wiring bug was found and fixed (`NovaXrayVpnService` never actually
passed a `quicRepository` into its real `XrayCoreController` construction -
the parameter existed with a safe default but the one production call site
was never updated).

After that fix, physical on-device testing produced a **confirmed false
positive**: the app reported `Protected`/`Current transport: QUIC` after a
real activation and `connect()`, but Frankfurt's own `2087/udp` firewall
packet counter stayed at exactly 0 across every attempt, and real browser
traffic through the tunnel failed (`DNS_PROBE_FINISHED_NO_INTERNET`) - the
Android client never sent a single UDP packet to the server, yet the UI
showed a fully connected state. Per the coordinator's instruction, this
physical "Protected" UI state is explicitly NOT treated as evidence of a
working implementation anywhere in this document.

### Confirmed root cause (architectural gap) vs. unconfirmed root cause (why the packet never left)

Two DISTINCT issues were uncovered, and PR #35's own commits are careful to
keep them separate - this document preserves that distinction:

1. **CONFIRMED, general, and the more important finding**: no Xray-family
   transport (`XRAY_REALITY`, `TLS_TCP`, and now `QUIC`) verified any
   data-plane handshake before reporting `Connected`/`Protected` - unlike
   AWG's `awaitFreshHandshake`, `XrayCoreController.requestStart` returning
   `Started` only ever meant "the Go runtime's goroutines launched without
   throwing," never "a real proxied session succeeded." This is a genuine,
   previously-undocumented architectural gap across the WHOLE Xray transport
   family, not a QUIC-specific defect - it was simply QUIC's total, obvious
   failure that surfaced it, because REALITY/TLS_TCP happened to have
   independent prior physical proof of real traffic masking the same
   theoretical gap in their own `Started`-reporting code path. PR #35 fixed
   this generally: it added `XrayDataPlaneReadinessCheck` (using the AAR's
   existing `measureDelay(...)` API) and gated `Started` on real readiness
   for all three Xray-family transports, then physically re-verified REALITY
   and TLS_TCP still worked correctly with the new gate (readiness succeeded,
   real traffic passed, exit IP confirmed) - this is a legitimately valuable,
   reusable finding and fix, independent of whether QUIC itself ever ships.
   **As of `main` (this document's baseline), this readiness gate is NOT
   present** - it exists only on the unmerged `feature/b21-quic-transport`
   branch. This is a real, currently-true gap in the CURRENT production
   REALITY/TLS_TCP code path that this research document is flagging as a
   reusable finding for a future, SEPARATE slice (not B46-scoped - it applies
   to already-shipping transports, not a new one), regardless of what happens
   with QUIC.
2. **NOT CONFIRMED - the actual reason port 2087 packets never reached the
   server.** PR #35 pursued this methodically across its final three commits:
   AndroidLibXrayLite's native binary was confirmed (via JNI symbol
   inspection) to actually CONTAIN XHTTP/H3/quic-go code - ruling out
   "AAR built without QUIC support" as the cause. A debug-only outbound-
   isolation harness (bypassing VpnService/TUN entirely) and a raised log
   level then recovered the real underlying xray-core error:
   `"timeout: no recent network activity"` - quic-go's own idle-timeout,
   identical on Wi-Fi and cellular, identical inside/outside VpnService. A
   final, separate, non-Xray diagnostic (a raw `java.net.DatagramSocket`
   sending an unrelated marker packet, no xray-core involved at all) proved
   raw UDP to Frankfurt's ALREADY-open `51820/udp` (AWG) genuinely reached
   the server (firewall counter incremented as expected) while byte-for-byte
   the same mechanism to `2087/udp` produced **zero** firewall counter
   movement on the same host/device/session. **This rules out a general
   device/OS UDP send-path defect and localizes the failure specifically to
   port-2087 delivery** - but PR #35 explicitly stops there: it does not
   claim to know WHY port 2087 specifically drops packets (leading
   hypotheses left open, none confirmed, in the PR's own words: a gap
   between the pinned commit's official Linux server binary and the
   AndroidLibXrayLite gomobile AAR built from the same commit; a carrier/
   network-level mid-path filter specific to that port; or a
   server/firewall-side detail specific to that one listener). **This
   document does not resolve that open question either** - it was not
   re-investigated in this research pass (no device, no server access, and
   out of this task's explicit no-server-touching scope).

### Reusable lessons vs. must-reject ideas

**Reusable, and directly relevant to a future implementation slice
regardless of which QUIC candidate is chosen:**
- The data-plane-readiness-before-`Connected` gap (finding 1 above) and its
  fix shape (`measureDelay`-based readiness check before ever reporting
  `Started`/`Connected`) is exactly the "own positive-confirmation" pattern
  Section 7/19 of this document already independently derives from B33's
  precedent - PR #35 is direct physical proof this pattern is necessary, not
  merely theoretically prudent.
- The raw-UDP-vs-through-Xray isolation methodology (send an unrelated
  control packet to a KNOWN-working port on the same host, compare against
  the port under test) is a reusable diagnostic technique for any future
  UDP-based transport's own bring-up, independent of protocol choice.
- The outbound-isolation harness pattern (run the runtime with no TUN/
  inbound at all, to separate "does the protocol work at all" from "does it
  work through our VpnService/TUN routing") is a reusable debugging
  technique for any future non-Xray QUIC runtime's own bring-up too.

**Must be rejected or treated with caution, not reused as-is:**
- PR #35's core design choice - implementing `TransportKind.QUIC` AS Xray
  XHTTP-h3, inside the SAME `XrayCoreController`/`NovaXrayVpnService` runtime
  REALITY/TLS_TCP already use - is exactly the "shares Xray's runtime/binary/
  lifecycle/config-engine/upstream-project" outcome Section 5/21 of this
  document flags as NOT a genuine transport-diversity win, regardless of
  whether the port-2087 delivery defect is ever fixed. A working XHTTP-h3
  would still fail together with REALITY/TLS_TCP on any Xray-core-wide bug,
  AndroidLibXrayLite AAR defect, or upstream xray-core removal - PR #35's own
  finding 1 (a bug that silently affected REALITY/TLS_TCP too, just
  unnoticed) is itself a live demonstration of exactly this shared-fate risk.
- Nova's own runtime resolver (`CdnXhttpRuntimeConfigResolver`, Section 2.2)
  independently and more conservatively REJECTS the h3 ALPN path today
  specifically because the QUIC dial isn't bounded through the same
  `dialContext` timeout REALITY/TLS/TCP get - this is a narrower, CDN-
  fronted-XHTTP-specific version of the same underlying "Xray's H3 path is a
  different, less-observed code path than its TCP paths" theme PR #35's
  finding 1 hit from a different angle (data-plane readiness, not dial
  timeout-boundedness). Both independently point at the same conclusion:
  Xray's H3/QUIC code path is less mature/less observable in THIS codebase's
  own integration than its TCP paths, on two separate axes, found by two
  separate investigations. Any future work resurrecting XHTTP-h3 must close
  BOTH gaps, not just the one PR #35 already fixed.
- The experimentally-opened `2087/udp` on Frankfurt and the deployed QUIC/
  XHTTP inbound are NOT verified, touched, or assumed current by this
  document - whatever state they were left in by PR #35 remains exactly
  that PR's own responsibility to report accurately, not this document's to
  re-certify.

### Why B21/PR #35 was never merged

Every one of PR #35's 7 commits ends with an explicit "Do not merge" and the
PR's own body states "Kept at FOUNDATION, not IMPLEMENTED" and "**Do not
merge** - implementation/validation only, per repository policy." The
substantive reason: no real, completed, non-false-positive QUIC proxied
session was ever achieved - the confirmed false-positive `Protected` state
(the exact evidence class this task's coordinator flagged as insufficient)
is the terminal state of that PR's physical validation, with the actual
packet-delivery root cause left genuinely unconfirmed. This is a legitimate,
honest "not ready" outcome, not an oversight or a blocked-on-approval
situation - the work itself proved the feature does not yet function.

### Which B21 findings remain valid vs. stale/superseded

- **Still valid, confirmed independently by this document too**: standalone
  Xray QUIC transport is removed in the pinned version; XHTTP-h3 is the only
  QUIC-capable path inside Xray-core today (Section 2.2/2.3).
  Data-plane-readiness-before-Connected is a real, still-unfixed-on-`main`
  gap across the whole Xray transport family.
- **Stale/superseded by this document's broader scope**: PR #35 scoped
  itself to "no Hysteria/sing-box/TUIC/second native core considered further
  than a documentation check" - this document's Section 4/21 goes materially
  further and concludes (Section 5, reinforced by PR #35's own shared-fate
  evidence above) that staying inside Xray does not actually achieve
  transport-diversity, which is a stronger, more specific conclusion than
  PR #35 reached or needed to reach for its own narrower FOUNDATION-only
  goal.
- **Unconfirmed, still open**: the actual port-2087 packet-delivery root
  cause. Any future work must either re-open that investigation or start
  fresh with a different candidate (Section 4) where this specific defect
  is moot.

### Should any B21 work be salvaged, and should PR #35 be closed?

**Do not close PR #35 now** (per explicit instruction) - it remains valuable
as a primary evidentiary record (the false-positive discovery, the
data-plane-readiness fix design, and the isolation-diagnostic methodology
are all genuinely reusable). Recommended disposition, for the repository
owner to decide, not enacted by this document: PR #35 should stay open and
unmerged until a future slice either (a) resurrects the XHTTP-h3 path with
BOTH the readiness gate AND `HTTP3_DIAL_NOT_BOUNDED`-class dial-bounding
fixed, and the port-2087-class delivery defect actually root-caused and
fixed, and even then re-evaluates whether shipping it is worth its
non-independent-failure-domain trade-off against an independent-runtime
candidate (Section 4) - or (b) B46 concludes an independent-runtime
candidate is the better direction, at which point PR #35 would be
superseded (not merged) and could be closed with a comment pointing at
whatever future PR supersedes it, once that replacement direction is
actually established - not before, and not by this document.

### Answering the coordinator's explicit comparison (A vs. B vs. C)

- **A. Xray XHTTP/H3** (what PR #35 built): lowest integration cost (reuses
  100% of the existing Xray runtime/identity/dispatch machinery), but -
  confirmed twice now, independently, by two different investigations
  (PR #35's readiness-gate finding and this document's own
  `HTTP3_DIAL_NOT_BOUNDED` finding) - it does **not** achieve genuine
  transport-diversity: it shares runtime, binary, lifecycle, config-engine,
  and upstream-project fate with `XRAY_REALITY`/`TLS_TCP`/`XRAY_XHTTP`,
  meaning a defect or upstream regression in Xray-core/AndroidLibXrayLite
  can take down every Xray-hosted transport together, which is exactly the
  independent-failure-domain property transport diversity exists to provide
  (Section 5). It may still give real protocol-level and fingerprint-level
  diversity (a QUIC/H3 wire shape genuinely differs from TCP/TLS/REALITY on
  the wire) without giving failure-domain diversity - both things are true
  at once, and this document treats them as separate axes rather than
  collapsing "protocol looks different" into "independently resilient."
- **B. Independent QUIC transport (Hysteria2/TUIC/etc.)**: genuine
  failure-domain independence from Xray (Section 4/5), but zero Nova-specific
  Android physical-feasibility evidence exists for any candidate in this
  family (unlike Shadowsocks, which has a real B45A spike) - the entire
  Android/`VpnService`/`protect()`/data-plane bring-up PR #35 had to do FOR
  Xray-QUIC would need to be redone from scratch for a new native runtime,
  with its own new risk (Hysteria2's documented Android idle-disconnect bug,
  TUIC's licensing/governance risk).
- **C. Direct lower-level QUIC library (quiche/quinn/s2n-quic) as a build-
  it-yourself substrate**: the most failure-domain-independent AND the
  highest-effort option - no existing proxy protocol to adopt, Nova would
  need to design its own framing/auth (explicitly out of scope: "no new
  cryptography," and a bespoke protocol has no external security review),
  or build a standards-based MASQUE/CONNECT-IP client (Section 4.5) which is
  more defensible but still has no existing Android implementation
  precedent identified anywhere in this research pass.

**Recommendation carried into Section 21/22's overall conclusion**: B46
should treat option A (Xray XHTTP/H3) as effectively researched-out for the
transport-diversity goal specifically (real, but not diversity-relevant,
per two independent findings) and prioritize evaluating option B
(independent QUIC transport) as the next research/spike target if B46
continues, with option C noted as the long-term standards-aligned fallback
if no option-B candidate proves out - exactly the ordering Section 21's
comparison matrix already reflects, now corroborated by PR #35's own
physical evidence rather than by this document's analysis alone.

## 21. Candidate comparison matrix (Q18 - factual, no arbitrary scores)

| | Hysteria2 | TUIC | Custom MASQUE/CONNECT-IP (quic-go/quiche-based) | Xray XHTTP-h3 |
|---|---|---|---|---|
| Independent failure domain from Xray | Yes | Yes | Yes | **No** (Section 5) |
| License | MIT | **GPLv3** (needs legal review) | Depends on library (quiche BSD-2, quinn MIT/Apache-2.0, s2n-quic Apache-2.0, quic-go MIT) | MPL-2.0 (already accepted) |
| Upstream governance stability | Active, single canonical org (apernet) | Recently restarted, multiple forks, less canonical | N/A (Nova would own the protocol code) | Already pinned/tracked in this repo |
| Known Android runtime precedent | Third-party wrappers exist (Husi/NekoBox/Excalve), no official AAR | No first-party SDK/AAR identified in this research pass; third-party Android integration precedent exists (general-purpose multi-protocol Android proxy clients), but no Nova-specific evidence | None (would be from-scratch) | Already running in production (`NovaXrayVpnService`) |
| Known Android-specific issues | Documented idle/lock disconnect bug (open, unresolved) | Not surveyed in depth (less community deployment data found) | Unknown (unbuilt) | Already solved for existing Xray transports; H3 specifically blocked by Nova's own `HTTP3_DIAL_NOT_BOUNDED` gate |
| Full TCP+UDP tunnel design intent | Yes | Yes | Yes (RFC 9484 CONNECT-IP specifically) | Only via closing the H3-dial-bounding gap, and still shares Xray's runtime |
| Obfuscation vs QUIC fingerprinting | Active upstream investment (Salamander, Gecko) | Not found as a standard feature in this pass | Rides real HTTP/3 semantics (fingerprint audit deferred to B47) | Inherits Xray's own H3 fingerprint, not independently evaluated |
| Nearest existing Nova precedent | B45A (independent Rust/Go runtime, JNI, own VpnService) | Same shape as Hysteria2, minus any B45A-equivalent spike | Would need its own B45A-equivalent spike from zero | Already-built, already-rejected-at-runtime gap (Section 2.2) |
| Physical Android feasibility proof today | **None** | **None** | **None** | N/A (not a new runtime) |

**No clear winner is declared.** Hysteria2 has the strongest upstream
governance/license/Android-precedent profile of the independent-runtime
candidates, but carries a known, unresolved Android stability bug and zero
Nova-specific physical proof. TUIC's GPLv3 licensing and governance churn
make it the weakest candidate for near-term adoption without a dedicated
legal review. A from-scratch MASQUE/CONNECT-IP client is the most
standards-aligned long-term option but the largest engineering lift with no
existing Android implementation precedent identified in this research pass.
Xray XHTTP-h3 is not a genuine diversity
candidate regardless of its lower integration cost.

## 22. Summary / MERGE READY statement

This document adds no production code, no dependency, no gateway config, and
no wiring into any selection/scoring/orchestration authority - it is a
research artifact plus a minimal, status-only `docs/ROADMAP.md` line. Per
CLAUDE.md's merge rule, merging always requires the repository owner's
explicit approval given directly; this document does not request or imply
merge authorization.

**MERGE READY** (as a research-only, docs-only PR): implementation-tests do
not apply (no code changed); no build is affected (no source files under
`android/`, `gateway/`, or CI config were touched); no architectural blocker
was found against the `vpn-architecture` invariants (Section 20); ROADMAP
truth is consistent (a minimal, accurate status line was added, no
capability-status inflation). The repository owner's explicit approval is
still required before this branch is merged, per CLAUDE.md.

This document's conclusions were independently corroborated, not
contradicted, by reading OPEN/UNMERGED PR #35's full physical-validation
history (Section 20.5): Xray XHTTP-h3 is real and reachable in the pinned
core, but PR #35's own physical evidence (a confirmed false-positive
`Protected` state, an unresolved port-level UDP delivery defect, and a
newly-discovered data-plane-readiness gap shared with already-shipping
REALITY/TLS_TCP) reinforces rather than undermines this document's
Section 5/21 conclusion that Xray-hosted QUIC does not deliver genuine
transport-diversity, independent of whether its remaining defects are ever
fixed.

**Key open items for whoever picks up implementation next** (not blockers to
THIS doc, but prerequisites to any B46 code slice): (1) formal legal review
before touching any GPLv3 QUIC candidate; (2) a B45A-equivalent Android
physical feasibility spike for whichever candidate is chosen, including a
real network-migration test; (3) resolving the CDN/MASQUE question
(Section 11) if the CDN-relay path is ever pursued instead of/alongside a
self-hosted gateway listener; (4) a real gateway-side deployment design
(new systemd unit, firewall rule, health probe) reviewed against
`gateway/DEPLOYMENT.md`'s existing hardening discipline before any
production infrastructure change.

## Sources cited (external)

- [XTLS/Xray-core GitHub](https://github.com/XTLS/Xray-core)
- [XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases)
- [Xray-core transport tutorial (SplitHTTP/XHTTP)](https://core-tutorial.argsment.com/xray/transport)
- [amnezia-xray-core DeepWiki - QUIC and Other Transports](https://deepwiki.com/amnezia-vpn/amnezia-xray-core/5.5-quic-and-other-transports)
- [apernet/hysteria (Hysteria2)](https://github.com/apernet/hysteria)
- [apernet/hysteria issue #1510 - Android idle disconnect](https://github.com/apernet/hysteria/issues/1510)
- [tuic-protocol/tuic](https://github.com/tuic-protocol/tuic)
- [EAimTY/tuic LICENSE (GPLv3)](https://github.com/EAimTY/tuic/blob/dev/LICENSE)
- [EAimTY - restart of TUIC development, governance change](https://www.eaimty.com/2025/restart-developing-tuic-but-not-as-the-author/)
- [quinn-rs/quinn](https://github.com/quinn-rs/quinn)
- [quiche (Cloudflare)](https://github.com/cloudflare/quiche)
- [s2n-quic (AWS) on lib.rs](https://lib.rs/crates/s2n-quic)
- [RFC 9298 - Proxying UDP in HTTP (CONNECT-UDP)](https://ietf-wg-masque.github.io/draft-ietf-masque-connect-udp/draft-ietf-masque-connect-udp.html)
- [MASQUE explained (http.dev)](https://http.dev/masque)
- [QUIC explained (http.dev)](https://http.dev/quic)
- [quic-go/masque-go](https://github.com/quic-go/masque-go)
- [quic-go connection migration docs](https://quic-go.net/docs/quic/connection-migration/)
- [draft-deconinck-quic-multipath (Multipath Extensions for QUIC)](https://datatracker.ietf.org/doc/html/draft-deconinck-quic-multipath-02)
- [Android Cronet developer docs](https://developer.android.com/develop/connectivity/cronet)
- [Android Cronet integration with other libraries](https://developer.android.com/develop/connectivity/cronet/integration)

## Internal prior evidence cited

- [PR #35 - "B21: QUIC Transport/Fallback (real XHTTP/HTTP-3) - Foundation"](https://github.com/kazakovak2001-lgtm/VPNrus/pull/35) (`feature/b21-quic-transport`, OPEN, UNMERGED, head `dc5228406fc350656c330f40d917465a9ef1a6a9`) - see Section 20.5.
- `docs/B21_QUIC_TRANSPORT_AUDIT.md` as committed on `feature/b21-quic-transport` (not present on `main`).
