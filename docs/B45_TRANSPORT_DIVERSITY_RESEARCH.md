# B45 Transport Diversity Research

**Status of this document: RESEARCH ONLY. No production code, native binary, server
daemon, or routing/scoring change was made as part of this task. See ROADMAP.md's
B45 row for the authoritative status this document supports.**

Baseline: `main` at `cc7c3f33a172d222554787441ad1c1dc4413b64b` (PR #78 merge).
Research branch: `research/b45-transport-diversity` (local only, not pushed).

**Correction pass (post-initial-draft, still docs-only, still no
implementation):** two factual corrections were made to the initial draft
and are marked inline where they occur - (1) `shadowsocks-rust` ships its
own `local-tun` Android-targeted TUN client mode; the initial draft
overstated that it always needs an external tun2socks/tun2proxy layer, and
(2) OpenVPN3's core library license is dual AGPLv3/MPL-2.0 with a documented
OpenSSL exception for the AGPLv3 option; the initial draft incorrectly left
this "UNKNOWN". Neither correction changes the "no implementation yet"
posture of this document; see Section 4 (Android implementations, Full-tunnel
integration) and Section 5 (Supply chain/licensing) for the corrected text,
and Section 13 for the resulting B45A acceptance matrix.

## 1. Scope

Research whether Shadowsocks 2022 (AEAD-2022) and OpenVPN 2.6 `tls-crypt-v2`
deserve a future implementation slice, and if so, exactly how each would fit
into the existing VPNrus transport/reachability/Smart-Connect architecture
without creating a second routing, scoring, failover, or diagnostics
authority. Plain WireGuard and IKEv2 are explicitly out of scope per the
ROADMAP entry. No new cryptography is in scope. Russia/restricted-network
field evidence is not produced by this task - it remains UNVERIFIED for every
transport, existing or candidate, until B54 (Restricted-Network Field
Validation Matrix) actually runs one.

## 2. Current VPNrus transport architecture (Phase 1 audit)

This is a code-verified map of the extension points a new transport would
have to use. Read directly from source, not from memory or docs alone.

### 2.1 Pipeline (fixed order, per `PROJECT_ARCHITECTURE.md`)

```
NetworkProfiler
  -> RestrictionClassifier
  -> ReachabilityEngine
  -> PathCandidateBuilder / PathScorer   (single scoring authority, manual + auto)
  -> SmartConnectDecisionEngine / AutoGatewaySelector   (pick TRANSPORT + GATEWAY)
  -> TransportOrchestrator.resolve()      (candidate -> real VpnTransport instance)
  -> VpnTransport.connect()               (real data-plane, one Android VpnService)
  -> post-connect confirmation (measureDelay / relay health watchdog)
  -> ReconnectManager / VpnController     (network-change recovery)
  -> SupportDiagnosticsRecorder / PathHistoryStore   (typed outcome recording)
```

### 2.2 The concrete extension points a new transport uses

- **`TransportKind`** (`android/.../transport/TransportKind.kt`) - a closed
  enum: `AMNEZIA_WG`, `XRAY_REALITY`, `QUIC`, `TLS_TCP`, `XRAY_XHTTP`. A new
  transport adds one enum value here. Nothing else about the enum's shape
  needs to change.
- **`TransportCapabilities`** (`android/.../transport/TransportCapabilities.kt`) -
  a typed, honest capability record (`usesUdp`/`usesTcp`/`supportsPort443`/
  `supportsObfuscation`/`suitableForRestrictiveNetworks`/`supportsRoaming`/
  `supportsFullTunnel`/`supportsSplitRouting`/`supportsIpv6`/
  `supportsTrafficStatistics`/`supportsProbing`/`maturity`). A new transport
  adds one factory function here (mirroring `xrayXhttpAdapterShell()`), and it
  must start at `TransportMaturity.NOT_IMPLEMENTED` or `EXPERIMENTAL` -
  claiming `suitableForRestrictiveNetworks = true` requires the same kind of
  real evidence B35/B36/B37 required for XHTTP, not an assumption from
  reading the protocol's marketing.
- **`VpnTransport`** (`android/.../vpn/VpnTransport.kt`) - the interface every
  transport implements: `kind`, `capabilities`, `underlyingNetworkRecovery`
  (`IN_PLACE` or `RESTART_SESSION`), `preparePermissionIntent()`,
  `connect(config)`, `disconnect()`, `observeState(): Flow<TransportState>`,
  optional `probe()`/`stats()`. This is the ONLY seam a new transport needs -
  no other class needs to know the transport exists beyond registering it.
- **`TransportRegistry`** - maps `TransportKind` to a constructible
  `VpnTransport`; `TransportOrchestrator.resolve()` is a pure executor that
  turns an already-made `TransportSelectionDecision` into a real instance via
  the registry, and never re-derives its own transport choice (architecture
  principle 11 - "no second scorer").
- **`TransportConfig`** (`android/.../vpn/config/TransportConfig.kt`) - the
  sealed per-transport connection payload (`Awg`, `Xray`, `XrayTls`, ...). A
  new transport adds one sealed subtype carrying only what it needs
  (host/port/credential references, never raw secrets inline where an
  existing encrypted store pattern - `XrayProfileRepository`/
  `XrayTlsProfileRepository` - already exists).
- **`EndpointTransportBinding`** (`android/.../reachability/Endpoint.kt`) -
  the signed, public per-endpoint fact: `kind: TransportKind`, `host: String`,
  `port: Int`, `metadata: Map<String, String>`. This is the ONLY place a new
  transport's public connection facts (SNI, ALPN, method identifier, protocol
  version) can live in the signed manifest, and it already round-trips
  arbitrary string pairs without a re-signing ceremony (exactly how B23's
  `ingressKind()`/B44's `operationalState()` were added - see
  `SignedTransportProfile.kt`, B42). No credential-bearing material is ever
  placed here - existing per-endpoint encrypted profile stores are the
  pattern to reuse for actual secrets.
- **`RelayIngressResolver`** (B24/B25, `android/.../relay/`) - the seam for a
  transport used as a client<->INGRESS hop distinct from INGRESS<->EXIT; it
  returns `Resolved(transport: VpnTransport, kind)` and never becomes a
  second VPN execution authority. A future Shadowsocks/OpenVPN ingress hop
  would plug in here exactly as a hypothetical native Xray ingress would.

### 2.3 Ownership / lifecycle facts already true today (not hypothetical)

- **Two Android `VpnService` implementations already coexist**, coordinated
  (never run concurrently) by `VpnController`/`TransportOrchestrator`/
  `ReconnectManager`: `org.amnezia.awg.backend.GoBackend$VpnService` (AWG's
  own AAR-owned service, JNI to the upstream Go WireGuard core) and
  `net.pocvpn.client.vpn.xray.NovaXrayVpnService` (Nova's own service,
  wrapping the pinned AndroidLibXrayLite AAR). This means "a new native core
  needs its own VpnService" is **not** an unprecedented architectural shape
  in this codebase - the existing invariant is "one ACTIVE VpnService at a
  time, one connection controller (`VpnController`)," not "exactly one
  VpnService class ever." A new transport can either (a) own a third
  `VpnService` subclass following the `NovaXrayVpnService` pattern
  (self-UID exclusion via `addDisallowedApplication`, `TransportState` Flow
  emission, `EXTRA_*` Intent-extra config threading) or (b) run inside the
  existing Xray runtime as another Xray outbound protocol if the underlying
  library already speaks it (see 4.6/5.6 below for why this second option
  changes NOTHING about runtime diversity even though it looks like a new
  transport).
- **`UnderlyingNetworkRecovery`** is a real, already-modeled per-transport
  fact (`IN_PLACE` vs `RESTART_SESSION`) that `VpnController`'s
  network-change handling already branches on. A new transport must honestly
  report which one its underlying core actually supports (verified against
  its real socket/interface-rebinding behavior, not assumed).
- **`XrayCoreController`'s post-`Started` remote confirmation and the B33
  relay-health watchdog are Xray-specific**, not part of the generic
  `VpnTransport` contract. A transport with an independent runtime (i.e. not
  wrapped in Xray) needs its OWN positive-confirmation and post-connect
  health-check implementation, following the same principle B33 established
  (local process start != healthy connection) but wired through its own
  `VpnTransport.connect()`/`observeState()` - never bolted onto
  `XrayCoreController` itself, and never a second, parallel health authority
  outside `TransportHealth`.
- **Diagnostics**: `DiagnosticFailureMapping`/`SupportDiagnosticsRecorder`
  (B29) already enumerate typed failure categories per layer (DNS, TLS,
  transport, ingress, relay, exit, data-plane). A new transport contributes
  new LEAF causes within this SAME typed vocabulary (e.g.
  `SS2022_HANDSHAKE_FAILED`, `OVPN_TLS_CRYPT_V2_KEY_REJECTED`), never a
  parallel diagnostics authority, and never infers a failure kind from an
  exception message string (architecture principle 9, and the R3 truth-table
  discipline already established for XHTTP/CDN causes).
- **`PathScorer`/`AutoGatewaySelector` are transport-agnostic** - they score
  `(gateway, transport)` pairs via `TransportHealth`/`ReachabilityEngine`/
  `PathHistoryStore`, none of which contain protocol-specific logic. Adding a
  `TransportKind` value does not require touching the scorer itself, only
  registering the new kind's health/reachability the same way existing ones
  are.

## 3. Evidence methodology

Every substantive claim below is tagged with one of:

- **UPSTREAM-DOCUMENTED** - stated by the protocol's own spec/maintainers.
- **CODE-VERIFIED** - confirmed by reading VPNrus's own source in this repo.
- **SECURITY-RESEARCH** - peer-reviewed or reputable independent security
  analysis.
- **FIELD-MEASURED** - a real, reproducible measurement (this repo's own, or
  a cited third party's).
- **COMMUNITY-ANECDOTAL** - forum/user reports; explicitly not proof.
- **INFERENCE** - a reasoned conclusion this document draws from the above,
  not itself a fact independently observed.
- **UNKNOWN** - not established by available evidence; do not act on it.

Web research access was available for this task; sources are listed in
Section 14. Two important limits: no benchmark was run against these
protocols on a real VPNrus device or gateway (Section 9 marks all
performance numbers UNKNOWN/TO BE MEASURED accordingly), and Russia/GFW-class
field evidence for these specific candidates in 2026, on VPNrus's own
infrastructure, does not exist and cannot exist without B45E-G actually being
executed - anything cited here about censorship resistance is about the
*protocol in general*, observed by outside researchers, not about VPNrus's
own deployment.

## 4. Shadowsocks 2022

### Protocol/security

- Shadowsocks 2022 (AEAD-2022 / SIP022) is a real, documented revision of the
  original Shadowsocks AEAD design, published as `SIP022` and in the
  `Shadowsocks-NET/shadowsocks-specs` repository. It mandates full replay
  protection, drops legacy/weak ciphers, and overhauls UDP relay with a
  per-session ID and packet-counter header to prevent the packet-reuse
  attacks the pre-2022 AEAD design had. **UPSTREAM-DOCUMENTED.**
- TCP and UDP are both specified and both implemented in `shadowsocks-rust`
  (`2022-blake3-aes-256-gcm` is the flagship AEAD-2022 cipher; a chacha20
  variant also exists for non-AES-NI hardware). Multiplexing UDP-over-TCP is
  the *recommended* deployment shape specifically because bare UDP is more
  passively fingerprintable - this is a deployment recommendation, not a
  protocol requirement. **UPSTREAM-DOCUMENTED.**
- Multi-user/server support exists via "Extensible Identity Headers" in the
  2022 spec, letting one server key space serve multiple identities without a
  separate connection per user config. **UPSTREAM-DOCUMENTED.**
- Cryptographic ownership: the AEAD-2022 construction is specified upstream
  (AEAD with a pre-shared symmetric key, BLAKE3/AES-GCM or ChaCha20-Poly1305)
  and implemented in `shadowsocks-rust`. VPNrus would consume an existing,
  maintained implementation; **no protocol-level cryptography would need to
  be invented or modified** to integrate it, satisfying the ROADMAP's "no new
  cryptography" constraint. **UPSTREAM-DOCUMENTED / INFERENCE** (about fit,
  not about the crypto itself).

### Android implementations

**Correction (post-initial-draft):** the first version of this section stated
too categorically that `shadowsocks-rust`'s bare core has no TUN path and
always needs a separate tun2socks layer. That is wrong about upstream
protocol capability. Re-checked directly against the current
`shadowsocks/shadowsocks-rust` repository (PR #586, the `local-tun` feature
flag, `sslocal --protocol tun` CLI docs, and open Android-specific issues
#856/#1432/#1644): `shadowsocks-rust` has shipped a real `local-tun`
client-mode feature since PR #586, which brings up a TUN interface itself
(no external tun2socks/tun2proxy process) and relays both TCP and UDP
through it, and the project's own build docs list Android as a supported
target for this feature (conditionally compiled, `IFF_NO_PI` handled
specially for Android's TUN driver quirk). **UPSTREAM-DOCUMENTED.** This is a
materially different, and more favorable, starting point than "always needs
a separate tun2socks" - but it does **not** by itself prove clean
integration with VPNrus's own Android `VpnService`/`ParcelFileDescriptor`
model, and the same upstream issue tracker that documents the feature also
records real, unresolved Android-specific build/runtime friction (issue
#856, "在android下运行tun遇到的问题" - TUN-on-Android runtime problems; issue
#1644, routing/default-route configuration questions for `local-tun`). The
correct, non-overclaimed framing has four distinct layers, which B45A exists
specifically to walk through in order:

**A. Protocol capability (UPSTREAM-DOCUMENTED, resolved by this correction).**
`shadowsocks-rust` genuinely has a TUN-capable local client mode
(`sslocal --protocol tun`), supporting both TCP and UDP, with Android listed
among its documented build targets. This is a real upstream capability, not
a plan or a roadmap item on their side.

**B. Android build/runtime feasibility in OUR toolchain (UNKNOWN, needs an
isolated proof).** "Android is a supported build target upstream" is not the
same as "cross-compiles cleanly and runs correctly inside VPNrus's own
Gradle/NDK toolchain and API-level/ABI matrix." The open, Android-specific
issues found in the upstream tracker (TUN-on-Android runtime problems,
default-route/DNS configuration questions for `local-tun`) are evidence real
integrators have hit real friction here, not evidence the feature is broken
- but they are also evidence this is not a solved, drop-in path. This is
exactly what B45A's build-and-run spike (question 1 of the acceptance matrix
below) exists to answer, not to assume in either direction.

**C. VPNrus `VpnService` integration (UNKNOWN until B45A proves it).** Even
once `local-tun` runs standalone, VPNrus's actual model requires answering,
with a real build on a real device, not by inference from upstream docs:
who owns the `ParcelFileDescriptor` the Android `VpnService.Builder.establish()`
call returns (Nova's own `VpnService`, handing the fd to `local-tun`'s
process/thread, mirroring how `NovaXrayVpnService` already hands its TUN fd
to the Xray core - or does `local-tun` need to open/own the interface itself,
which Android's permission model may not allow from a non-`VpnService`
process); how the shadowsocks-rust process's own outbound socket to the real
server is protected from being recursively captured by the VPN interface
(the same class of problem `NovaXrayVpnService.addDisallowedApplication`/
`VpnService.protect()` already solves for Nova's own process - `local-tun`
would need an equivalent, and whether its Rust code exposes a hook for
Android's `protect()` FD-based mechanism specifically was **not verified in
this session**); and how routes/DNS/UDP are actually threaded through
(`local-tun`'s own CLI flags reference an `--outbound-bind-interface` concept
that has NOT been confirmed compatible with Android's `VpnService.protect()`
model specifically - CODE/DOC-VERIFIED only for its existence, UNKNOWN for
Android-specific compatibility). None of this is answered by upstream
documentation alone; it is only answered by B45A physically building and
instrumenting it.

**D. Alternative architecture (still available, not mandatory).** A separate
external tun2socks/tun2proxy layer paired with `shadowsocks-rust`'s
non-TUN (SOCKS5/HTTP local-proxy) modes remains a valid fallback architecture
if B45A finds `local-tun`'s Android integration unsafe or impractical - but
per this correction, it is an ALTERNATIVE to evaluate if native `local-tun`
integration fails, not something automatically required as this document's
first draft implied. **INFERENCE**, drawn from A-C above, not a claim of
either path's superiority.

Three realistic embedding routes were identified overall; none was assumed
suitable without checking:

1. **`shadowsocks-rust` core (Rust), invoked as a subprocess or via JNI,
   using its own `local-tun` feature (see A-D above) or the SOCKS5/HTTP
   local-proxy modes paired with an external tun2socks layer.**
   MIT-licensed (permissive, redistribution-compatible). Actively released
   (tagged releases on GitHub; AEAD-2022 ciphers already shipped and
   documented in its own README/issue tracker). Cross-compiles to
   `aarch64-linux-android` and `x86_64-linux-android` (standard Rust Android
   targets - the repo's own CI/release artifacts target these). Would need a
   thin Kotlin/JNI or subprocess wrapper written by VPNrus, since it ships as
   a CLI binary/library, not an Android SDK. **UPSTREAM-DOCUMENTED (license,
   ciphers, local-tun existence) / UNKNOWN (Android build/runtime/VpnService
   integration - see B/C above, not yet attempted).**
2. **sing-box (Go, GPLv3), compiled to a `libbox` AAR.** Actively maintained,
   ships native Android AAR builds, and natively supports Shadowsocks
   including AEAD-2022 methods. **However it is GPLv3-licensed**, which is a
   real supply-chain/licensing constraint for a proprietary or
   differently-licensed APK - "strict GPLv3 preservation" is called out by
   the project's own downstream integrators. This must be resolved (a
   separate GPLv3-compatible distribution, or avoiding sing-box) before any
   implementation slice, not glossed over. **UPSTREAM-DOCUMENTED.**
3. **Outline Client / `outline-sdk` (Jigsaw/Google-backed).** Actively
   maintained, ships Android support, uses Shadowsocks as its core transport
   and interoperates with any standard Shadowsocks server. Whether the
   currently-published Outline stack has already rolled forward to AEAD-2022
   specifically (vs. legacy AEAD ciphers) was **not conclusively confirmed**
   by available search results in this session - **UNKNOWN, verify against
   the `outline-sdk` changelog directly before relying on it.**

For every candidate: startup/shutdown lifecycle, crash behavior, and logging
behavior under Android's process-lifecycle constraints (Doze, background
execution limits) were **not measured** in this session - **UNKNOWN / TO BE
MEASURED**, and binary size was not measured - **UNKNOWN / TO BE MEASURED**.
Security-advisory history for `shadowsocks-rust` specifically (CVE
database/GHSA) was not exhaustively queried in this session - **UNKNOWN, a
future slice must check the advisory database directly before pinning a
version.**

### Server implementations

`shadowsocks-rust`'s server component (`ssserver`) is the natural choice for
VPNrus's own authorized VPS infrastructure: Linux amd64/arm64 support,
`systemd` unit patterns already documented and used elsewhere in the
ecosystem (Arch Wiki, distro packaging), JSON config format, multi-user via
Extensible Identity Headers, TCP+UDP, and MIT license (no GPL contamination
for a server-side daemon VPNrus operates itself - though server-side
licensing is a materially smaller concern than client redistribution).
DNS/IPv6/config-reload/rolling-rotation behavior for `ssserver` specifically
was **not verified in this session - UNKNOWN**, and should be checked against
its actual CLI/config docs before B45D. **UPSTREAM-DOCUMENTED (packaging
shape) / UNKNOWN (operational specifics).**

### Full-tunnel integration (the critical architectural question)

**Correction:** the base Shadowsocks protocol is a SOCKS5/proxy protocol, not
itself a tun-capable VPN transport - but `shadowsocks-rust` specifically now
ships its own `local-tun` client mode (see "Android implementations" A-D
above), which brings up and relays a TUN interface directly, without a
separate external tun2socks/tun2proxy process. Whether that native TUN path
can be safely integrated with Android's specific `VpnService`/
`ParcelFileDescriptor`/`protect()` model is UNKNOWN until B45A proves it
(layer C above) - it is a real, currently-open engineering question, not a
solved detail and not a blocked one. An external tun2socks/tun2proxy layer
paired with `shadowsocks-rust`'s SOCKS5/HTTP local-proxy modes remains a
fallback if `local-tun`'s Android integration turns out to be unsafe.
sing-box's own `libbox` bundles an equivalent TUN-handling chain internally
regardless, so this specific question does not apply to the sing-box route.

- **Who owns the TUN interface?** In VPNrus's current model, `VpnController`/
  the transport's own `VpnService` owns it (via `Builder.establish()`). A
  Shadowsocks integration would still have Nova's own `VpnService` establish
  the TUN (exactly like `NovaXrayVpnService` does today) and hand the fd
  either to `local-tun`'s process/thread or to a separate tun2socks layer
  feeding the Shadowsocks client core's outbound connection - this is
  architecturally compatible with the existing one-`VpnService`-per-attempt
  model, NOT a second VPN owner, in either shape. Exactly which of the two
  shapes actually works safely on Android is what B45A must determine (see
  the "Android implementations" section, layer C).
- **sing-box specifically already bundles this whole chain** (TUN handling +
  tun2socks-equivalent + protocol clients) behind one Go library boundary -
  meaning if sing-box were chosen, VPNrus would NOT need to separately adopt
  a tun2socks library or evaluate `local-tun`'s Android fitness at all; if
  `shadowsocks-rust` were chosen instead, `local-tun`'s own Android
  integration (preferred, pending B45A proof) or a separate tun2socks/
  tun2proxy dependency (fallback) is required.
- **This is genuine protocol diversity, not merely another Xray profile** -
  Shadowsocks 2022 does NOT depend on the Xray core at all, whichever
  Android embedding route is chosen. This is an important distinction from a
  hypothetical "Shadowsocks via Xray" shortcut (Xray/Xray-core does have a
  Shadowsocks inbound/outbound module) - using Xray's own Shadowsocks support
  would be materially EASIER to integrate (same runtime, same
  `NovaXrayVpnService`, same config renderer pattern) but would give **zero
  additional runtime/core failure-domain diversity** versus XRAY_REALITY/
  XRAY_XHTTP - it would still be one Xray process, one Xray crash domain, one
  Xray CVE surface. **This distinction must drive the actual implementation
  choice** (see Section 6/13): "Shadowsocks via Xray's own module" and
  "Shadowsocks via an independent core (shadowsocks-rust/sing-box)" are two
  materially different B45 slices with very different diversity payoffs and
  very different integration costs, and this document does not recommend
  collapsing them.

### Censorship evidence

This is the section the roadmap most explicitly warns not to overclaim.
Preserved evidence discipline (unchanged by the corrections in this pass):
AEAD-2022 is a real improvement to protocol security and replay resistance;
that improvement does NOT establish invisibility to traffic classifiers;
independent research shows fully-encrypted-looking traffic (which AEAD-2022
traffic still is) has been detected and blocked by real, deployed censorship
systems; and VPNrus's own Russia/hard-whitelist behavior remains UNVERIFIED
regardless of anything in this section.

- **Cryptographic security (AEAD-2022) is a real, documented improvement**
  over legacy Shadowsocks AEAD: mandatory replay protection, no legacy weak
  ciphers, better UDP session/key hygiene. **UPSTREAM-DOCUMENTED.**
- **This does NOT make Shadowsocks traffic invisible to DPI.** The
  authoritative, peer-reviewed measurement here is "How China Detects and
  Blocks Shadowsocks" (ACM IMC 2020, gfw.report/USENIX-adjacent authors):
  the Great Firewall identified probable Shadowsocks connections using
  first-packet length/entropy heuristics, then actively re-probed the
  server with 7 distinct probe types across multiple stages to confirm
  before blocking - a real, deployed, large-scale active-probing
  infrastructure (over 50,000 probes from over 12,000 China-geolocated IPs
  against studied servers). **SECURITY-RESEARCH.**
- **A materially worse escalation for the whole "fully encrypted proxy"
  category, which Shadowsocks 2022 remains a member of**: per the same
  research lineage (USENIX Security 2023, "How the Great Firewall of China
  Detects and Blocks Fully Encrypted Traffic"), since November 2021 the GFW
  can block fully-encrypted-looking proxy protocols **in real time, based on
  passive traffic analysis alone** (no active probing needed first). Since
  AEAD-2022 traffic is, by design, still a high-entropy, protocol-agnostic
  byte stream (same "looks like random noise" property that made original
  Shadowsocks attractive), it falls squarely inside the traffic SHAPE that
  this later GFW capability targets - the 2022 protocol's cryptographic
  hardening does not change this passive-entropy signature.
  **SECURITY-RESEARCH; the two papers together are the load-bearing citation
  for this whole subsection - do not cite only the 2020 paper, since the
  2021+ passive-blocking escalation is the more current and more severe
  threat model.**
- **Replay protection and active-probing resistance are different
  properties.** AEAD-2022's mandatory replay protection defeats one class of
  active probe (replay-based confirmation), but the GFW's probing toolkit in
  the 2020 study used multiple, DIFFERENT probe strategies, and the 2021+
  passive-only capability does not need any probe at all. **INFERENCE**
  (combining the two cited papers) - do not claim AEAD-2022 "solves" active
  probing; it closes one specific historical vector.
- **This research context is China-specific (GFW), not Russia-specific.**
  Russia's blocking apparatus (TSPU / Roskomnadzor infrastructure) is a
  DIFFERENT deployed system with different, less publicly documented
  detection heuristics. No field evidence in this document establishes
  whether Russia's DPI performs the same passive fully-encrypted-traffic
  classification the GFW does. **UNKNOWN - do not extrapolate GFW behavior
  onto Russia; this is exactly the kind of unproven inference architecture
  principle 16 (real field evidence required) forbids treating as fact.**
- **SNI/domain dependence**: Shadowsocks (any edition) has no TLS SNI/domain
  layer at all in its base form - it is not a TLS-mimicking protocol, so it
  carries none of REALITY/XHTTP's SNI-based blocking/allowlisting surface,
  but also none of their "looks like ordinary HTTPS to a passive observer"
  cover. It is a materially different threat-model bet than the existing
  XRAY_REALITY/XRAY_XHTTP transports: those try to look like real
  legitimate-looking encrypted traffic; Shadowsocks 2022 tries to look like
  ordinary encrypted noise while resisting active fingerprinting. Given the
  2021+ GFW capability above, "looks like noise" is not a strictly weaker or
  stronger bet than "looks like HTTPS" - they fail differently, which is
  itself a legitimate diversity argument (Section 6), but neither is proven
  against Russia specifically. **INFERENCE.**
- **IP/server-address blocking, throttling, mobile-carrier-specific
  behavior**: no field evidence found for VPNrus-relevant deployments;
  server IP blocklisting is an infrastructure-operations concern
  (Section 6/13) orthogonal to the protocol's own detectability. **UNKNOWN.**

### Lifecycle/handover (Phase 7 requirement, answered per candidate)

- Whichever Android core is chosen, its socket-level survival across Android
  network changes (Wi-Fi<->cellular) depends on that core's own connection
  model - `shadowsocks-rust`'s and sing-box's underlying TCP connections to
  the server do NOT automatically survive an underlying-network switch
  (ordinary TCP socket semantics; no MASQUE/QUIC-style connection migration
  exists in Shadowsocks-2022 the way it might in a QUIC-based transport -
  B46's own separate research track). This means a Shadowsocks-2022
  transport realistically needs `UnderlyingNetworkRecovery.RESTART_SESSION`,
  the SAME category AWG already uses today - not a new lifecycle category,
  just a different transport claiming an existing one. **INFERENCE, grounded
  in ordinary TCP/UDP socket semantics** - this was not measured on a real
  device in this session (no implementation exists yet) - **UNKNOWN/TO BE
  MEASURED** whether the actual chosen library exposes a rebind primitive
  that could make `IN_PLACE` viable instead.
- Total-loss -> restore and explicit-connect/disconnect-during-recovery
  behavior would need to follow the SAME `ReconnectManager`/
  `VpnController.handleNetworkLost` contract every other `RESTART_SESSION`
  transport already follows - no new state machine required if this
  category is claimed honestly (architecture principle 11).

### Supply chain/licensing

| Candidate | License | Redistribution risk |
|---|---|---|
| `shadowsocks-rust` | MIT | Low - permissive, standard attribution only |
| sing-box (`libbox`) | GPLv3 | Real - strict copyleft; must be resolved (isolation, separate distribution channel, or avoided) before APK inclusion |
| Outline / `outline-sdk` | Predominantly Apache-2.0 in Jigsaw's own repos (not independently re-verified line-by-line in this session) | Likely low, but **UNKNOWN - verify directly, do not assume** |

No CVE/security-advisory database query was run against any of these three in
this session - **UNKNOWN, mandatory before B45C/B45D** (Phase 5 requirement;
this document does not certify any of them clean).

### VPNrus architecture fit

- Fits `VpnTransport`/`TransportKind`/`TransportCapabilities`/
  `TransportRegistry` cleanly as a new, independent-core transport (Section
  2.2), IF a non-Xray core is chosen. Fits as "just another Xray profile"
  trivially if Xray's own Shadowsocks module is chosen instead - but per
  Section 4, that choice sacrifices the entire runtime-diversity argument
  (Section 6).
- Signed public metadata fits `EndpointTransportBinding.metadata` without a
  schema change (Section 7 detail).
- Genuinely independent-core Shadowsocks 2022 is the ONLY candidate in this
  research pass that could add real core/runtime diversity beyond "another
  Xray outbound profile" - this is the single most important finding of this
  document (see Section 6/11).

## 5. OpenVPN 2.6 tls-crypt-v2

### Protocol/security

- `tls-crypt-v2` is a real OpenVPN 2.6-line feature: it lets a server issue
  each client its OWN wrapped tls-crypt key (rather than one shared
  tls-crypt/tls-auth key for the whole deployment), so large
  multi-tenant/VPN-provider deployments get the same pre-TLS-handshake
  DoS/stack-hardening protection tls-auth/tls-crypt already gave small
  single-key deployments, without a shared-secret blast radius. Per-client
  keys means the server can also selectively deny an individual client's
  key. **UPSTREAM-DOCUMENTED.**
- It protects the **control channel** (the TLS handshake used to negotiate
  session keys), not the data channel's own cipher choice - data-channel
  encryption is governed separately by the negotiated cipher (AES-GCM/
  ChaCha20-Poly1305 in a modern config), unaffected by tls-crypt-v2 itself.
  **UPSTREAM-DOCUMENTED.**
- tls-crypt-v2 clients need OpenVPN 2.6+ specifically (the client must resend
  its wrapped key material on completing the handshake) - a server can
  choose whether to also accept older non-v2 clients. **UPSTREAM-DOCUMENTED.**
- **Security history is real and non-trivial**: multiple CVEs directly in
  tls-crypt-v2 packet handling were found and fixed in the 2.6 line (memory
  leaks in client-key handling and in tls-crypt-v2 packet reception that
  could exhaust server memory and crash it) - this is evidence of an actively
  audited, actively fixed feature, but also evidence it is NOT a trivially
  simple, risk-free addition; a VPNrus-operated server on an old 2.6.x point
  release would be exposed to these until patched. **SECURITY-RESEARCH
  (CVE record), UPSTREAM-DOCUMENTED (changelog entries).**
- TCP and UDP transport are both supported (OpenVPN's long-standing dual-mode
  design; tls-crypt-v2 does not change this). Roaming/reconnect: OpenVPN 2.6
  itself doesn't provide QUIC/MASQUE-style seamless migration; typical
  behavior on a network change is a fresh TLS renegotiation/reconnect, not an
  in-place socket rebind (verify against the specific client library chosen -
  Section 5.2). **UPSTREAM-DOCUMENTED / UNKNOWN (exact reconnect timing for a
  given client).**
- **tls-crypt-v2 is control-channel obfuscation/hardening, not traffic-shape
  camouflage.** It does not change OpenVPN's packet framing, its
  characteristic handshake sequence, or its port/protocol conventions in any
  way that would defeat protocol fingerprinting (Section 5.5). This
  distinction is explicit and must not be blurred in any future
  implementation slice's marketing or internal claims.

### Android feasibility

- **`ics-openvpn` (schwabe/ics-openvpn)** is the long-standing, actively
  maintained open-source "OpenVPN for Android" app/library, GPLv2-licensed.
  Its own README is explicit that it is "not about creating a library to be
  used in other projects" and that anything built on top of it must publish
  source under GPL - a hard licensing constraint for embedding inside a
  differently-licensed VPNrus APK, not merely a preference. Whether its
  bundled OpenVPN 2.x core (or its own OpenVPN3-based variant) has actually
  wired up tls-crypt-v2 end-to-end in its Android UI/config plumbing was
  **found to be an open community question as of the most recent GitHub
  issue found in this session** ("is tls-crypt-v2 supported... ?", still
  open) - **UNKNOWN, do not assume UI/config parity even if the underlying
  core theoretically supports it.**
- **OpenVPN3 core library** (`OpenVPN/openvpn3`) is C++, protocol-compatible
  with the 2.x line, and its own source tree contains `tls_crypt_v2.hpp` -
  i.e. the core-library-level primitive genuinely exists. **CODE-VERIFIED
  (file exists in the upstream repo, confirmed via web search of the repo
  tree) / UNKNOWN (exact behavioral completeness/parity with server-side 2.6
  was not independently verified against the spec in this session).**
- **Official OpenVPN Connect for Android** is closed-source and not something
  VPNrus can embed or fork - relevant only as evidence that a fully-capable
  client exists commercially, not as an integration candidate.
- JNI/native-process integration complexity for either `ics-openvpn`'s core
  or a from-scratch OpenVPN3-based JNI wrapper was **not measured** in this
  session - **UNKNOWN/TO BE MEASURED**, but should be assumed materially
  higher than a Shadowsocks JNI wrapper: OpenVPN's control-channel TLS
  handshake, certificate/PKI handling, and config-file semantics are a much
  larger surface than a single-shared-key AEAD proxy protocol.
- Binary size, startup/shutdown lifecycle, crash behavior, credentials
  handling, and network-change handling for a from-scratch Android
  integration are all **UNKNOWN/TO BE MEASURED** - no implementation exists.

### Server feasibility

- Standard `openvpn` 2.6.x packaging exists for common Linux distributions
  (the project ships its own release/ChangeLog for the 2.6 branch actively,
  including recent point releases with the CVE fixes above - evidence of
  live maintenance). `systemd` unit support is a long-standing, ordinary
  packaging pattern for OpenVPN server daemons (not independently
  re-verified for the exact target distro in this session -
  **UNKNOWN/verify at deploy time**).
- tls-crypt-v2 key generation/distribution requires the `easyrsa`/OpenVPN
  tooling's own `--tls-crypt-v2` machinery to mint a per-client wrapped key
  from the server's own tls-crypt-v2 server key - this is a NEW piece of
  per-device provisioning state VPNrus's control plane does not have an
  analogous concept for today (unlike XRAY_REALITY's per-device
  activation-issued profile, which already has a real provisioning story -
  see B15/B30). Revocation of an individual client's tls-crypt-v2 key is
  supported at the protocol level (the whole point of "per-client keys") but
  requires VPNrus to build real key-issuance/revocation tooling - **this is
  real new server-side control-plane work, not a config toggle.**
  **UPSTREAM-DOCUMENTED (capability exists) / INFERENCE (integration
  effort).**
- Client-certificate requirement vs. alternative auth modes, IPv4/IPv6, DNS,
  observability, and graceful config reload for a VPNrus-operated OpenVPN 2.6
  server were **not independently verified in this session** -
  **UNKNOWN/TO BE MEASURED at B45D time.**

### Censorship value

Preserved evidence discipline (unchanged by the corrections in this pass):
`tls-crypt-v2` protects/authenticates the control channel's metadata; it
does NOT thereby establish resistance to protocol fingerprinting, and
VPNrus's own Russia/hard-whitelist behavior remains UNVERIFIED regardless of
anything in this section.

- **`tls-crypt-v2` != DPI invisibility, and this must never be stated
  otherwise.** It authenticates/encrypts the CONTROL channel; it does not
  alter OpenVPN's packet structure, opcode framing, or handshake timing in a
  way that defeats protocol fingerprinting.
- **The load-bearing citation here is "OpenVPN is Open to VPN
  Fingerprinting"** (Xue, Ramesh, Jain et al.; published via Censored
  Planet / ACM, cited by CyberInsider/HackerNoon coverage): OpenVPN traffic,
  including with tls-auth/tls-crypt-family obfuscation, remains
  fingerprintable via protocol-structure and behavioral heuristics distinct
  from payload content, and the paper's own framing is that active DPI
  vendors and state censors can realistically build detectors from these
  fingerprints at scale. **SECURITY-RESEARCH.**
- **Field reports specifically cite standard OpenVPN as actively DPI-blocked
  or throttled on major Russian ISPs** (Rostelecom, MTS, Beeline, Megafon) on
  default configurations, per Russia-focused commentary found in this
  session's search (a VPN-industry blog, not a peer-reviewed source - treat
  as lower-confidence than the Censored Planet paper, but directionally
  consistent with it). **COMMUNITY-ANECDOTAL / lower-confidence
  SECURITY-ADJACENT** - do not promote this single blog-style source to
  "verified Russia field evidence"; it is exactly the kind of claim
  architecture principle 16 requires VPNrus's own real field evidence to
  confirm before acting on, not a third party's blog post.
- **tls-crypt-v2's actual, real contribution is control-channel DoS/stack
  hardening and per-client key isolation** (reduced blast radius if one
  client's key leaks) - a genuine security property, but a different
  property from "defeats active censorship," and this document does not
  conflate the two.
- Active-probing implications for OpenVPN specifically (whether a censor can
  send crafted packets to an OpenVPN port to confirm it's OpenVPN, the way
  the GFW active-probes Shadowsocks) were not directly evidenced by sources
  found in this session - **UNKNOWN.**

### Lifecycle/handover

- OpenVPN's control-channel/TLS session model means an underlying-network
  change (Wi-Fi<->cellular) most naturally maps to `RESTART_SESSION` unless a
  specific client stack implements session-resumption/roaming logic
  (`float`/peer-id continuity exists in the protocol for some deployments,
  but whether the chosen Android integration route actually implements and
  exposes it was **not verified - UNKNOWN**). Treat as `RESTART_SESSION` by
  default, verify before claiming `IN_PLACE`.
- Same requirement as Shadowsocks 2022: total-loss -> restore, explicit
  connect/disconnect-during-recovery must route through the EXISTING
  `ReconnectManager`/`VpnController` contract, never a bespoke OpenVPN-only
  reconnect loop (architecture principle 11).

### Supply chain/licensing

- `ics-openvpn`: **GPLv2**. Embedding it (or code derived from it) inside
  VPNrus's APK would obligate VPNrus to release the combined work's source
  under GPL terms unless VPNrus obtains its stated alternative paid license
  for UI code, or unless VPNrus writes an independent client against the
  separately-licensed OpenVPN3 core instead. This is a real, binding
  constraint, not a formality.
- **`OpenVPN/openvpn3` core library license (correction - re-read directly
  from the upstream repository's `LICENSE.md`, replacing the earlier
  "UNKNOWN" placeholder).** OpenVPN3 is **dual-licensed**: a licensee may
  choose either (a) **GNU Affero General Public License v3 (AGPLv3)**, with
  an explicit additional permission granted by the project to link the
  resulting work with OpenSSL (or a modified OpenSSL) despite AGPLv3's own
  copyleft terms - the upstream text notes this OpenSSL exception is only
  *needed* for OpenSSL versions older than 3.0, since OpenSSL 3.0+ itself
  moved to Apache-2.0 (a license already GPL/AGPL-compatible without a
  special exception); or (b) **Mozilla Public License 2.0 (MPL-2.0)**.
  **UPSTREAM-DOCUMENTED**, confirmed against the current `LICENSE.md` in the
  `OpenVPN/openvpn3` repository.

  **This does not by itself make embedding acceptable** - which of the two
  license paths actually fits VPNrus's intended use, and what it would
  obligate, is a real, separate analysis, not resolved by the license's mere
  identity:

  - **AGPLv3 path.** AGPLv3's defining, and for a mobile client
    provider-operated-service context most consequential, term is its
    network-use clause: distributing a *combined/modified* work that
    incorporates AGPLv3-licensed code obligates offering that combined
    work's corresponding source to users who interact with it - including,
    under AGPLv3's own language, over a network. For a compiled Android APK
    distributed to end users (not merely a server VPNrus alone operates),
    this reads as at minimum a source-availability obligation for the parts
    of the app that are a "combined work" with the AGPLv3 code, and
    plausibly (this is the part needing formal review, not a default
    resolvable from license text alone) for more of the app depending on
    how tightly the OpenVPN3 code is linked/integrated. The OpenSSL
    exception is irrelevant to VPNrus's own choice of TLS library unless
    VPNrus's build actually links OpenSSL <3.0 through this code path -
    **UNKNOWN, depends on the actual build (verify which TLS backend the
    chosen OpenVPN3 build configuration uses before assuming the exception
    is even relevant).**
  - **MPL-2.0 path.** MPL-2.0's copyleft is explicitly **file-level, not
    whole-program**: only the MPL-2.0-licensed *files themselves* (and
    modifications to them) must remain available under MPL-2.0 terms; files
    VPNrus writes that merely call into or link against the MPL-2.0 code
    (a "Larger Work" in MPL-2.0's own terminology) are NOT required to be
    released under MPL-2.0 or any copyleft license. This is the
    materially more permissive of the two paths for a mixed-license
    proprietary-adjacent APK, PROVIDED VPNrus (a) does not modify the
    MPL-2.0-licensed OpenVPN3 files themselves without being willing to
    republish those specific modified files' source, and (b) satisfies
    MPL-2.0's own attribution/notice requirements (preserving the license
    text and copyright notices for the covered files, and providing a
    mechanism - e.g. an in-app or repository-hosted NOTICE/licenses page,
    the same pattern already needed for the AmneziaWG/Xray/other pinned
    third-party dependencies this codebase already carries - for a
    recipient to obtain the MPL-2.0 source of those specific files).
  - **JNI/linkage question (explicitly asked for, not yet answered here).**
    Whether calling OpenVPN3 via JNI counts as a "Larger Work" boundary
    under MPL-2.0 (favorable - JNI is a natural boundary between VPNrus's
    own Kotlin/Java code and the separately-distributed native library) or
    whether static-linking the C++ core directly into VPNrus's own native
    module blurs that boundary is a genuine legal interpretation question
    that this document does NOT resolve. **UNKNOWN - the underlying LICENSE
    text and linkage mechanics are now correctly identified above, but
    whether VPNrus's specific proposed integration shape (JNI wrapper vs.
    static link vs. dynamic `.so` loading) satisfies either license's terms
    is marked here as needing FORMAL LEGAL REVIEW before any B45A/B45B code
    is written against OpenVPN3, not resolved by this research document.**
  - **NOTICE/source-distribution obligations, either path.** At minimum:
    preserve copyright/license notices for the OpenVPN3 files used; make the
    corresponding source of those files (as used/modified) available to
    recipients of the APK. Under the AGPLv3 path specifically, this could
    extend further per the network-use clause above - the exact boundary is
    the open legal question, not the existence of SOME obligation, which is
    clear either way.
- Server-side `openvpn` daemon: GPLv2, standard for operating (not
  redistributing inside a proprietary client) - materially lower risk than
  the Android client-embedding question above, and unaffected by the
  OpenVPN3 core library's own separate dual-license terms (the server-side
  `openvpn` 2.6.x daemon and the client-side `openvpn3` core library are
  different codebases with different license histories - do not conflate
  them).

### VPNrus architecture fit

- Fits the same `VpnTransport`/`TransportKind`/`TransportRegistry` seam as
  any other transport, IF a viable, license-compatible Android integration
  is actually built - which is the single biggest open unknown for this
  candidate (Section 5.2's licensing and tls-crypt-v2-UI-support gaps).
  Materially higher integration and licensing cost than Shadowsocks 2022.
  Genuine independent-core diversity (OpenVPN's core is unrelated to Xray's
  or AmneziaWG's), IF a workable non-viral-license integration path is
  actually found.

## 6. Failure-domain comparison (Phase 4)

| Dimension | AMNEZIA_WG (current) | XRAY_REALITY (current) | TLS_TCP (current) | XRAY_XHTTP (current) | Shadowsocks 2022 (independent core) | Shadowsocks 2022 (via Xray module) | OpenVPN 2.6 tls-crypt-v2 |
|---|---|---|---|---|---|---|---|
| Protocol family | WireGuard-derived | VLESS/Xray | Xray TLS | VLESS/Xray XHTTP | Shadowsocks AEAD-2022 | Shadowsocks AEAD-2022 | OpenVPN 2.x |
| Crypto implementation | upstream AmneziaWG Go core | Xray-core | Xray-core | Xray-core | shadowsocks-rust/sing-box (own AEAD-2022 impl) | Xray-core's SS module | OpenSSL/mbedTLS via OpenVPN core |
| Userspace core/runtime | AmneziaWG GoBackend (own process/JNI) | Xray-core (shared) | Xray-core (shared) | Xray-core (shared) | INDEPENDENT (shadowsocks-rust or sing-box) | Xray-core (shared) | INDEPENDENT (OpenVPN2/3 core) |
| TUN owner | `GoBackend$VpnService` | `NovaXrayVpnService` | `NovaXrayVpnService` | `NovaXrayVpnService` | new `VpnService` (own or shared pattern) | `NovaXrayVpnService` (unchanged) | new `VpnService` |
| Android service/process | AWG's own | Nova's own (shared with other Xray kinds) | shared | shared | new, independent | shared (no new process) | new, independent |
| Server daemon | none (kernel/Go WG peer) | Xray | Xray | Xray | ssserver/sing-box (new daemon) | Xray (unchanged) | openvpn (new daemon) |
| TCP/UDP | UDP only | TCP | TCP | TCP (HTTP/2-3 style) | both (UDP-over-TCP recommended) | both, inherits Xray SS module's shape | both |
| TLS dependency | none | REALITY (TLS-mimicking) | real TLS | TLS (CDN-fronted) | none (not a TLS mimic) | none | TLS-based control channel |
| HTTP dependency | none | none | none | yes (XHTTP) | none | none | none |
| CDN dependency | none | none | none | yes | none | none | none |
| DNS dependency | manifest-resolved host, no per-connection DNS reliance | same | same | CDN hostname resolution | server host resolution (same shape as others) | same | server host resolution |
| Endpoint/IP dependency | pinned gateway | pinned gateway | pinned gateway | CDN-fronted (less direct-IP dependence) | pinned server (direct-IP unless CDN-fronted, not designed) | pinned gateway | pinned server |
| Control-plane dependency | signed manifest | signed manifest + Xray profile store | signed manifest + Xray profile store | signed manifest + Xray profile store | signed manifest (new metadata) + new key-issuance | signed manifest, unchanged shape | signed manifest + NEW per-client key issuance |
| Provisioning dependency | `ClientTunnelIdentityStore` | `XrayProfileRepository`/activation | `XrayTlsProfileRepository`/activation | activation + CDN profile | NEW per-device credential store | unchanged Xray provisioning | NEW per-device tls-crypt-v2 key store |
| Reconnect behavior | `RESTART_SESSION`(verify) | Xray-specific confirm+watchdog | Xray-specific confirm | Xray-specific confirm | likely `RESTART_SESSION` (unverified) | Xray-specific confirm (unchanged) | likely `RESTART_SESSION` (unverified) |
| Signed-profile suitability | yes (today) | yes (today) | yes (today) | yes (B42 CdnXhttp profile) | yes - fits `EndpointTransportBinding.metadata` (Section 7) | yes, unchanged | yes - fits same metadata pattern, but needs a NEW secret-issuance channel outside the manifest |

**Key finding (Phase 4 conclusion)**: only an **independent-core Shadowsocks
2022** integration and a **genuine OpenVPN 2.6** integration would add real
runtime/core failure-domain diversity beyond today's set - today's three
Xray-backed kinds (`XRAY_REALITY`/`TLS_TCP`/`XRAY_XHTTP`) already share one
process, one crash domain, and one CVE surface, and "Shadowsocks via Xray's
own module" would simply become a FOURTH member of that same shared-runtime
family - genuinely useful protocol/traffic-shape diversity, but explicitly
**not** runtime diversity, and must never be marketed or counted as such
internally.

## 7. B42 signed-profile compatibility (Phase 6)

B42 (`SignedTransportProfile`, `FOUNDATION`, not live execution authority) is
already a typed, endpoint-bound view over `EndpointTransportBinding`'s
existing signed `metadata: Map<String, String>` field - the SAME mechanism
B23's `ingressKind()` and B44's `operationalState()` use, requiring zero
re-signing ceremony for either candidate.

**Public/non-secret metadata a future B45 transport profile could carry**
(mirroring `CdnProviderCapabilityProfile`'s existing shape for XHTTP):

- endpoint id (already exists - `EndpointDescriptor.id`)
- transport kind (already exists - a new `TransportKind` enum value)
- host/port (already exist - `EndpointTransportBinding.host`/`port`)
- for Shadowsocks 2022: AEAD-2022 method/cipher identifier (e.g.
  `"2022-blake3-aes-256-gcm"`), protocol/spec version identifier, whether UDP
  relay is enabled for this endpoint
- for OpenVPN 2.6: negotiated data-channel cipher identifier, TLS
  version/cipher-suite floor, protocol mode (TCP/UDP), a
  tls-crypt-v2-server-key VERSION/fingerprint identifier (never the key
  material itself)
- capability/spec-version identifier for forward compatibility (mirrors
  `CdnProviderProfileReadResult.UnsupportedVersion`'s existing fail-closed
  pattern for an unrecognized future version)

**What must NEVER enter the signed public manifest** (both candidates):

- Shadowsocks: the pre-shared symmetric key/password itself
- OpenVPN: the per-client tls-crypt-v2 wrapped key, any client certificate
  private key, or any bearer/reusable credential
- Any reusable secret that would let manifest-fetch access alone (which is
  intentionally public/unauthenticated per B17/B20's own trust model)
  substitute for real per-device provisioning

**Where the real secret material must live instead**: a NEW per-device,
per-endpoint encrypted local store, following the EXACT existing pattern
`XrayProfileRepository`/`XrayTlsProfileRepository` already establish for
Xray's own client keys/certificates - populated only through a real
control-plane activation flow (mirroring `/v1/activate`), never hand-edited,
never derived from the public manifest alone. For OpenVPN specifically, this
store must also hold the whole per-client tls-crypt-v2 wrapped key (a
meaningfully larger artifact than a symmetric password), and the control
plane needs new key-issuance/revocation logic that does not exist today (see
Section 5.3) - this is real net-new server-side work, independent of the
Android integration effort.

**This document does not propose activating B42 live consumption** - it only
maps where each candidate's public facts would live if/when B42 becomes a
live execution authority, per this task's explicit Phase 6 boundary.

## 8. Diagnostic/failure taxonomy implications

Both candidates need new LEAF failure causes inside the EXISTING typed
per-layer vocabulary (`DiagnosticFailureMapping`/B29/R3 truth-table
discipline) - never a new diagnostics authority, never inferred from
exception-message text (architecture principle 9):

- **Shadowsocks 2022** (independent core): `SS2022_HANDSHAKE_FAILED`
  (transport layer - malformed/incompatible AEAD negotiation), `SS2022_AUTH_REJECTED`
  (server rejected the pre-shared key/identity - only distinguishable from
  generic connection failure if the underlying core surfaces it as a typed
  result, which must be verified per chosen library, not assumed),
  `SS2022_UDP_RELAY_UNAVAILABLE` (relay layer, only relevant if UDP-over-TCP
  multiplexing is not negotiated). All of these are NEW leaves under the
  EXISTING `transport`/`relay` layer categories B29 already defines, not new
  layers.
- **OpenVPN 2.6 tls-crypt-v2**: `OVPN_TLS_CRYPT_V2_KEY_REJECTED` (server
  rejected this client's wrapped key - could mean revocation, corruption, or
  version mismatch; the underlying library's real, typed return value must
  be traced before this leaf can be trusted the way B37's R3 audit traced
  Xray's actual exception types), `OVPN_CONTROL_CHANNEL_TLS_FAILED` (TLS
  layer), `OVPN_DATA_CHANNEL_NEGOTIATION_FAILED` (transport layer). Same
  discipline: only emit a leaf the chosen library can genuinely, typedly
  distinguish - never guess from a generic exception.
- Neither candidate changes Auto failover eligibility/sequencing rules by
  itself - a new `TransportKind`'s failures plug into the EXISTING
  `AutoGatewayFailoverPolicy.isEligibleForNextCandidate` categories
  (handshake timeout / backend start failure) the same way XRAY_XHTTP's
  failures already do, per architecture principle 11.

## 9. Mobile/performance implications (Phase 8)

No benchmark was run in this session - nothing here is a measured number.

| Metric | Shadowsocks 2022 | OpenVPN 2.6 tls-crypt-v2 |
|---|---|---|
| APK size impact | UNKNOWN / TO BE MEASURED (shadowsocks-rust core + optional tun2socks vs. sing-box's bundled libbox AAR will differ materially - not estimated here) | UNKNOWN / TO BE MEASURED (OpenVPN3 core is a substantial C++ dependency; larger than a single-purpose AEAD proxy core, by INFERENCE from its broader feature scope, not measured) |
| Memory/CPU | UNKNOWN / TO BE MEASURED | UNKNOWN / TO BE MEASURED |
| Battery | UNKNOWN / TO BE MEASURED | UNKNOWN / TO BE MEASURED |
| Startup/handshake latency | UNKNOWN / TO BE MEASURED (AEAD handshake is a single round trip by design - INFERENCE from protocol shape, not measured) | UNKNOWN / TO BE MEASURED (full TLS handshake is inherently more round trips than a pre-shared-key AEAD handshake - INFERENCE from protocol shape, not measured) |
| Throughput | UNKNOWN / TO BE MEASURED | UNKNOWN / TO BE MEASURED |
| TCP-over-TCP risk | Real, if UDP-over-TCP multiplexing is used for all traffic including TCP app traffic tunneled over a TCP transport - same class of risk XRAY_XHTTP/TLS_TCP already accept today, not a new risk category | Real if TCP mode is chosen; UDP mode avoids it, same tradeoff every other transport here already faces |
| UDP support | Yes (native) | Yes (native) |
| MTU considerations | UNKNOWN / TO BE MEASURED - additional AEAD framing overhead exists by protocol design (INFERENCE), exact MTU budget not computed | UNKNOWN / TO BE MEASURED - OpenVPN's own framing overhead is well-documented upstream but not computed against VPNrus's specific TUN/MTU setup here |
| Mobile handover cost | Likely `RESTART_SESSION`-class cost (Section 4/5), same order of magnitude as AWG's existing reconnect cost - INFERENCE, not measured | Likely `RESTART_SESSION`-class cost, likely HIGHER than Shadowsocks due to full TLS renegotiation - INFERENCE, not measured |

## 10. Decision matrix (Phase 10)

| Criterion | Shadowsocks 2022 (independent core) | OpenVPN 2.6 tls-crypt-v2 | Current transport set (baseline) |
|---|---|---|---|
| Actual Android support | SUPPORTED (shadowsocks-rust JNI/subprocess, or sing-box AAR - GPLv3 caveat) | PARTIAL (OpenVPN3 core exists; GPLv2 `ics-openvpn` not directly embeddable; tls-crypt-v2 UI/config completeness in any Android client UNVERIFIED) | SUPPORTED (proven, physically verified) |
| Actual Linux server support | SUPPORTED (`shadowsocks-rust`/`ssserver`, actively maintained) | SUPPORTED (`openvpn` 2.6.x actively maintained, real CVE-fix cadence) | SUPPORTED (proven) |
| Maintained implementation availability | SUPPORTED (shadowsocks-rust, sing-box, both active) | PARTIAL (core library active; Android client/licensing path unresolved) | SUPPORTED |
| Independent runtime/core diversity | SUPPORTED, if independent core chosen; UNSUPPORTED (zero credit) if routed through Xray's own module | SUPPORTED, if a workable non-GPL-conflicting integration is built | N/A (baseline - three of four current kinds already share Xray's runtime) |
| TCP availability | SUPPORTED | SUPPORTED | SUPPORTED (existing kinds) |
| UDP availability | SUPPORTED | SUPPORTED | PARTIAL (only AWG today) |
| Full-tunnel feasibility | SUPPORTED, needs a tun2socks-equivalent (bundled in sing-box, separate for shadowsocks-rust) | SUPPORTED, native to the protocol design | SUPPORTED (proven) |
| Mobile handover feasibility | PARTIAL - architecturally fits `RESTART_SESSION`, unverified in practice | PARTIAL - same, likely costlier | SUPPORTED (AWG/Xray both physically verified) |
| Signed-profile compatibility | SUPPORTED (fits `EndpointTransportBinding.metadata`, no schema change) | SUPPORTED (same mechanism), but needs a NEW secret-issuance channel outside the manifest | SUPPORTED (proven, B42 foundation exists) |
| Provisioning complexity | PARTIAL - new per-device credential store needed, but conceptually simple (one pre-shared key/identity per device) | UNSUPPORTED-simple / PARTIAL - genuinely new key-issuance+revocation control-plane logic, larger artifacts, larger operational surface | SUPPORTED (proven activation flow exists) |
| Operational complexity | PARTIAL - new daemon, new monitoring, but a single well-understood service | PARTIAL-to-harder - new daemon, PKI/key lifecycle management, generally regarded as more operationally involved than a symmetric-key proxy | SUPPORTED (proven) |
| Dependency/supply-chain risk | PARTIAL - MIT (shadowsocks-rust) is low-risk; GPLv3 (sing-box) is a real constraint; CVE history not queried this session | PARTIAL - GPLv2 (`ics-openvpn`) is a real constraint; OpenVPN core has a real, actively-patched CVE history (evidence of scrutiny, not evidence of safety) | Known (existing pinned AARs/cores already vetted per their own ROADMAP history) |
| Licensing | PARTIAL (MIT viable path exists; GPLv3 path does not, for a proprietary APK) | PARTIAL (GPLv2 `ics-openvpn` path likely blocked; OpenVPN3 core is dual AGPLv3/MPL-2.0 - MPL-2.0's file-level copyleft is a plausible viable path, but which path VPNrus's actual integration shape falls under needs FORMAL LEGAL REVIEW, not further research) | Known/accepted |
| APK impact | UNKNOWN | UNKNOWN, likely larger (INFERENCE from broader protocol/PKI surface) | Known (current build) |
| Typed diagnostics feasibility | SUPPORTED in principle (fits B29's existing per-layer taxonomy), needs the chosen library to actually expose typed errors (UNVERIFIED per library) | SUPPORTED in principle, same caveat | SUPPORTED (proven, R3 audit) |
| End-to-end proof feasibility | SUPPORTED in principle (same `measureDelay`-style pattern *could* apply if the endpoint serves an equivalent unauthenticated probe target - not yet designed) | SUPPORTED in principle, same caveat | SUPPORTED (proven, B33) |
| Evidence of restricted-network utility | UNKNOWN for VPNrus specifically; general research shows real active-probing AND passive fully-encrypted-traffic detection risk (Section 4.5) | UNKNOWN for VPNrus specifically; general research shows real fingerprinting risk, tls-crypt-v2 does not close it (Section 5.5) | UNVERIFIED (ROADMAP's own standing caveat - this is true for the WHOLE existing transport set too, not a comparative weakness unique to the candidates) |
| Known censorship weaknesses | Active probing (2019-era, partially mitigated by AEAD-2022's replay protection) AND passive fully-encrypted-traffic classification (2021+, NOT mitigated by AEAD-2022) | Protocol/behavioral fingerprinting independent of tls-crypt-v2; reported (lower-confidence) active blocking on major Russian ISPs | Documented per-transport in ROADMAP (e.g. REALITY/XHTTP's own SNI/CDN-dependence caveats) |
| Security maturity | Real, spec-reviewed, actively maintained; no independent CVE-database query performed this session | Real, long-lived protocol with an active CVE-fix cadence specifically in tls-crypt-v2 code (evidence of real scrutiny) | Proven in this codebase's own physical validation history |
| Amount of custom code required | LOW-to-MEDIUM (a JNI/subprocess wrapper + `VpnTransport` adapter + new diagnostics leaves; a tun2socks layer if not using sing-box) | MEDIUM-to-HIGH (JNI wrapper around a much larger core, new PKI/key-issuance control-plane logic, new diagnostics leaves, licensing resolution) | N/A (already built) |

## 11. Candidate classifications (Phase 11)

- **Shadowsocks 2022, independent `shadowsocks-rust` runtime (i.e. NOT via
  Xray's own module): EXPERIMENTAL SPIKE ONLY, conditional on B45A.** The
  protocol/crypto story is genuinely solid and upstream-documented, a
  permissively-licensed maintained implementation (`shadowsocks-rust`, with
  its own `local-tun` client mode) exists, and this is the ONLY candidate
  that COULD add real runtime/core diversity beyond today's Xray-dominated
  set - but that diversity credit is conditional, not yet earned: it holds
  only if B45A's acceptance matrix (Section 13) is actually satisfied on a
  real Android build/device. Android `VpnService`/`ParcelFileDescriptor`/
  socket-protection integration of `local-tun`, lifecycle/handover behavior,
  diagnostics typing, and licensing-path choice (MIT `shadowsocks-rust` core
  vs. GPLv3 sing-box) are all unverified in practice - exactly the profile of
  "worth an isolated lab prototype before committing a reviewed
  implementation slice," not yet an implementation candidate, and NOT yet a
  confirmed diversity win.
- **Shadowsocks 2022 via Xray's own Shadowsocks module: REJECT FOR NOW**, as
  a claimed diversity improvement - kept explicitly SEPARATE from the row
  above, never collapsed into one "Shadowsocks 2022" verdict. It may still
  be a reasonable, LOW-COST additional protocol/traffic-shape option
  (genuinely different wire fingerprint than REALITY/XHTTP), but must never
  be counted as runtime-diversity progress regardless of what B45A finds for
  the independent-runtime path, and this document does not classify it as
  worth a dedicated B45 slice on diversity grounds alone; if pursued, it
  should be scoped and named honestly as "another Xray-backed protocol
  profile," not as B45's answer to runtime diversity.
- **OpenVPN 2.6 tls-crypt-v2: RESEARCH CONTINUES.** The protocol feature
  itself is real, upstream-documented, and reasonably mature (with a real,
  actively-patched CVE history proving active scrutiny) - but the Android
  integration path is unresolved (the most maintained open Android
  client, `ics-openvpn`, is GPLv2 and its own community has an open question
  about tls-crypt-v2 UI/config completeness; a from-scratch integration
  against the OpenVPN3 core library is no longer blocked by an unknown
  license - it is dual AGPLv3/MPL-2.0, and MPL-2.0's file-level copyleft is a
  plausible path for a from-scratch client - but which path VPNrus's actual
  JNI/static/dynamic integration shape would fall under, and what NOTICE/
  source obligations follow, needs FORMAL LEGAL REVIEW before it can be
  called feasible on acceptable terms), the server-side per-client key
  issuance/revocation control-plane does not exist yet and is real new work,
  and the censorship-value evidence is explicitly negative-to-neutral
  (control-channel hardening, not fingerprint resistance). Too many
  foundational unknowns (Phase 12) remain to call this even an experimental
  spike candidate yet - the next step is answering Section 12's licensing
  and tls-crypt-v2-completeness questions definitively, not writing code.

## 12. Unknowns (consolidated)

- Whether Outline/`outline-sdk`'s current Android stack has actually adopted
  AEAD-2022 ciphers (vs. legacy AEAD only).
- `shadowsocks-rust`'s and sing-box's CVE/security-advisory history (no
  database query performed).
- Real APK size, memory, CPU, battery, and latency cost of any candidate on
  an actual VPNrus build/device.
- Whether either candidate's chosen library actually exposes a typed,
  distinguishable error for handshake/auth failure (required before any
  diagnostics leaf can be trusted per B29/R3 discipline) - a repeat of the
  exact kind of audit R3 already did for Xray/CDN causes, not yet done here.
- Exact `UnderlyingNetworkRecovery` behavior (`IN_PLACE` vs
  `RESTART_SESSION`) for any real chosen library, only inferred here from
  generic TCP/UDP/TLS socket semantics.
- OpenVPN3 core library's license identity is now resolved (AGPLv3/MPL-2.0
  dual license, confirmed against its own `LICENSE.md` - see Section 5's
  corrected Supply chain/licensing subsection). What remains genuinely
  unresolved is a LEGAL, not a factual, question: which of the two license
  paths VPNrus's specific proposed integration shape (JNI wrapper, static
  link, or dynamic `.so` loading) would actually fall under, and what that
  implies for source-availability/NOTICE obligations - marked as needing
  formal legal review before any OpenVPN3 code is written, not an unresolved
  research fact.
- Whether `ics-openvpn`'s or any other maintained Android OpenVPN client
  actually has complete tls-crypt-v2 support in its config/UI layer today
  (an open, unresolved community question as of this session's search).
- Any real Russia/hard-whitelist field evidence for either candidate - none
  exists, and none was claimed to exist.
- Exact operational cost of building new per-client tls-crypt-v2 key
  issuance/revocation control-plane tooling.
- Whether a safe, real end-to-end confirmation probe target (mirroring
  Direct's `measureDelay`/`/v1/manifest` pattern) could exist for either
  candidate's server daemon without adding a new HTTP surface that itself
  becomes a distinguishing fingerprint.

## 13. Proposed future implementation slices

Derived from the actual architecture audited in Section 2, not a generic
template. None of these are started by this task.

- **B45A - Independent `shadowsocks-rust` AEAD-2022 runtime feasibility
  spike (NOT a VPN transport implementation).** Preferred first candidate
  per this corrected research, conditional on its own findings (Section 11).
  Scope: a standalone (non-Nova-APK) Android test harness answering the
  bounded feasibility questions below - not a `VpnTransport` integration,
  not a production credential, not a Smart Connect wiring. Failure
  conditions: any question below cannot be answered with a real, observed
  result on a physical device within the spike's bounded time box.
  Rollback: delete the spike branch/harness; nothing production-facing
  exists to roll back. Evidence requirement: real device logs, real
  server-side access log correlation, no simulated/assumed answers.

  **B45A acceptance matrix - every question is answered with an observed
  result, not an assumption, before this slice is considered complete:**

  1. **Build.** Can a maintained `shadowsocks-rust` client be built for
     Android arm64 with an AEAD-2022 method (e.g. `2022-blake3-aes-256-gcm`)
     enabled, using the project's own current release/build instructions,
     without unofficial patches to the crypto path?
  2. **Runtime shape.** Can it run in-process/JNI, or as an app-owned native
     executable (subprocess), entirely without the Xray runtime/core -
     confirmed by process/library inspection on the test device, not by
     assumption from the build succeeding?
  3. **TUN integration.** Can `shadowsocks-rust`'s own `local-tun` client
     mode be integrated with Android's `VpnService`/`ParcelFileDescriptor`
     model safely (per Section 4's Android-implementations A-D framing) -
     or does it require falling back to an external tun2socks/tun2proxy
     layer paired with `local-tun`'s SOCKS5/HTTP modes instead? Record which
     shape actually worked, not which was hoped for.
  4. **Socket protection.** Can the shadowsocks-rust process's own outbound
     socket to the real server be protected from being recursively captured
     by the just-established VPN interface (the same class of problem
     `NovaXrayVpnService.addDisallowedApplication`/`VpnService.protect()`
     already solves for Nova's own process)?
  5. **TCP + UDP.** Do both TCP and UDP application traffic actually pass
     through the intended path end to end, verified with real traffic, not
     inferred from the protocol spec supporting both?
  6. **Deterministic lifecycle.** Can the runtime be started and stopped
     deterministically, with no orphaned process, no leaked TUN fd, and no
     stuck state, across repeated connect/disconnect cycles on a real
     device?
  7. **Network handover.** Does a Wi-Fi -> cellular (and reverse) transition
     require a full session restart (`RESTART_SESSION`), or can the
     underlying socket/session genuinely migrate in place (`IN_PLACE`) -
     answered by observing real behavior on a real device, not inferred
     from generic TCP/UDP socket semantics as Section 4 necessarily did
     ahead of this spike?
  8. **Authority isolation.** Can all of the above be done WITHOUT touching
     or duplicating `SmartConnectDecisionEngine`/`AutoGatewaySelector`/
     `PathScorer`/`RoutingDecisionEngine`/`ReconnectManager` - i.e. does the
     spike harness stay entirely outside those authorities, proving the
     eventual `VpnTransport` adapter (B45B/B45C) can plug in without
     creating a second decision/failover/routing authority (architecture
     principle 11)?
  9. **Cost.** What APK-size delta and runtime (memory/CPU/battery/startup
     latency) cost does the built artifact actually add, measured on the
     test harness - not estimated?
  10. **Supply-chain artifacts.** What exact license/supply-chain artifacts
      would enter the app as a result (crate versions, their individual
      licenses beyond `shadowsocks-rust`'s own MIT license - e.g. any
      transitive dependency with a different license - and whether a
      `local-tun`-capable build pulls in additional platform-specific
      crates with their own terms)?

  None of these ten questions is answered by this research document itself
  - they are the acceptance criteria B45A must produce real, observed
  answers to before B45B (typed adapter) is scoped.
- **B45B - Typed transport adapter (`VpnTransport`/`TransportKind`/
  `TransportCapabilities` for Shadowsocks 2022).** Scope: add
  `TransportKind.SHADOWSOCKS_2022`, a truthful `TransportCapabilities`
  factory (maturity `NOT_IMPLEMENTED` until B45C proves otherwise), a sealed
  `TransportConfig.Shadowsocks2022` payload, and new B29-taxonomy leaves per
  Section 8 - no live wiring into Smart Connect yet (same FOUNDATION
  discipline B42 itself follows). Tests: unit tests for the new
  capability/config types only. Non-goals: no registry registration as
  AVAILABLE yet.
- **B45C - Local Android integration (tun2socks + TUN ownership).** Scope: a
  real `VpnService` (or shared `NovaXrayVpnService`-pattern) implementation
  wiring the JNI/subprocess core from B45A behind a tun2socks-equivalent
  layer, self-UID exclusion, `TransportState` Flow emission, positive
  post-connect confirmation (B33-style, adapted to whatever real
  unauthenticated probe target the server can safely offer - a new open
  question, see Section 12). Failure conditions: cannot reliably rebind/
  restart the session across a real network change. Acceptance gate: a
  physical device reaches a genuinely confirmed Connected state and passes
  real HTTPS/DNS traffic, matching the same evidentiary bar B10/B33 already
  set for AWG/Xray.
- **B45D - Owned server integration.** Scope: real `ssserver` deployment on
  authorized VPNrus infrastructure, per-device credential issuance wired
  into the existing control-plane activation pattern (mirroring `/v1/activate`,
  never a parallel credential system), `EndpointTransportBinding.metadata`
  extension per Section 7 (no re-signing ceremony required). Failure
  conditions: cannot avoid introducing a second credential-issuance
  authority alongside the existing Xray activation flow. Acceptance gate:
  a real signed manifest entry resolves to a real, working server-side
  endpoint.
- **B45E - Diagnostics / data-plane proof.** Scope: extend B29's typed
  vocabulary with the leaves designed in Section 8, prove each is reachable
  from a real, distinguishable underlying error (repeat R3's own audit
  discipline for this transport specifically) - never inferred from generic
  exception text.
- **B45F - Controlled physical unrestricted-network validation.** Scope:
  exactly the same evidentiary bar B35's XHTTP proof already met (real
  device, real unrestricted network, full data-plane proof, Wi-Fi<->cellular
  handover). Acceptance gate: matches B35/B10's own physical-validation
  format.
- **B45G - Restricted-network field validation.** Scope: real, authorized
  testing from an actually restricted network (Russia or another verified
  restrictive network), following B54's eventual matrix format - this is the
  ONLY slice that could ever justify writing "Russia/hard-whitelist"
  language for this transport, per architecture principle 16. Explicit
  non-goal: never simulate this and call it field evidence.

The equivalent slice sequence for OpenVPN 2.6 tls-crypt-v2 would be
structurally identical (A-G), but B45A/B45B cannot responsibly start until
the licensing question (GPLv2 `ics-openvpn` vs. a from-scratch OpenVPN3
integration) and the tls-crypt-v2 Android-completeness question (Section 12)
are answered directly against upstream sources - this document classifies
OpenVPN as RESEARCH CONTINUES specifically because starting B45A today would
mean building on an unresolved licensing/completeness foundation.

## 14. Sources

- [SIP022 AEAD-2022 Ciphers - Shadowsocks](https://shadowsocks.org/doc/sip022.html) - Shadowsocks project - AEAD-2022 protocol specification (methods, replay protection, UDP session/packet-ID design). Accessed 2026-09-18.
- [shadowsocks-specs/2022-1-shadowsocks-2022-edition.md](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md) - Shadowsocks-NET - full Shadowsocks 2022 edition spec. Accessed 2026-09-18.
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) and its [LICENSE](https://github.com/shadowsocks/shadowsocks-rust/blob/master/LICENSE) - shadowsocks-rust project - MIT license, AEAD-2022 cipher support, release cadence. Accessed 2026-09-18.
- [Shadowsocks - sing-box manual](https://sing-box.sagernet.org/manual/proxy-protocol/shadowsocks/) and [sing-box Change Log](https://sing-box.sagernet.org/changelog/) - SagerNet - sing-box Shadowsocks support, Android build notes, GPLv3 licensing discipline. Accessed 2026-09-18.
- [Outline Client (outline-vpn/outline-client)](https://github.com/outline-vpn/outline-client) - Jigsaw - Outline's Android/Shadowsocks support and maintenance signal. Accessed 2026-09-18.
- [How China Detects and Blocks Shadowsocks (ACM IMC 2020)](https://dl.acm.org/doi/10.1145/3419394.3423644) and [gfw.report paper PDF](https://gfw.report/publications/imc20/data/paper/shadowsocks.pdf) - active-probing detection/blocking of Shadowsocks. Accessed 2026-09-18.
- [How the GFW Detects and Blocks Fully Encrypted Traffic (USENIX Security 2023)](https://www.usenix.org/system/files/sec23fall-prepub-234-wu-mingshi.pdf) - passive, real-time blocking of fully-encrypted proxy traffic since Nov 2021, relevant to any AEAD-2022 deployment's traffic shape. Accessed 2026-09-18.
- [OpenVPN/openvpn ChangeLog (release/2.6 branch)](https://github.com/OpenVPN/openvpn/blob/release/2.6/ChangeLog) and [Changes.rst](https://raw.githubusercontent.com/OpenVPN/openvpn/release/2.6/Changes.rst) - OpenVPN project - tls-crypt-v2 feature description, CVE fixes (memory leaks in tls-crypt-v2 handling). Accessed 2026-09-18.
- [ChangesInOpenVPN26 - community wiki](https://community.openvpn.net/Changelogs/ChangesInOpenVPN26) - OpenVPN community - 2.6 feature summary including tls-crypt-v2. Accessed 2026-09-18.
- [OpenVPN/openvpn3 - tls_crypt_v2.hpp](https://github.com/OpenVPN/openvpn3/blob/master/openvpn/crypto/tls_crypt_v2.hpp) - confirms tls-crypt-v2 primitive exists in the OpenVPN3 core library source tree. Accessed 2026-09-18.
- [schwabe/ics-openvpn](https://github.com/schwabe/ics-openvpn), [its LICENSE](https://github.com/schwabe/ics-openvpn/blob/master/doc/LICENSE.txt), and [GitHub issue #1625 - "is tls-crypt-v2 supported in OpenVPN for Android 0.7.46?"](https://github.com/schwabe/ics-openvpn/issues/1625) - GPLv2 licensing terms and an open community question on tls-crypt-v2 UI/config completeness. Accessed 2026-09-18.
- [OpenVPN is Open to VPN Fingerprinting (arXiv / Censored Planet)](https://arxiv.org/pdf/2403.03998) and [ACM Communications version](https://dl.acm.org/doi/full/10.1145/3618117) - protocol/behavioral fingerprintability of OpenVPN independent of tls-auth/tls-crypt obfuscation. Accessed 2026-09-18.
- Russia-specific OpenVPN DPI-blocking commentary (VPN-industry blog, lower-confidence, cited only as COMMUNITY-ANECDOTAL, not independently verified) - accessed via web search 2026-09-18; treat as directionally suggestive only, not field-verified for VPNrus.
- This repository's own `PROJECT_ARCHITECTURE.md` and `docs/ROADMAP.md` (B16-B44 sections) and source files cited inline in Section 2 (`TransportKind.kt`, `TransportCapabilities.kt`, `VpnTransport.kt`, `TransportOrchestrator.kt`, `Endpoint.kt`, `SignedTransportProfile.kt`) - CODE-VERIFIED, read directly in this session at commit `cc7c3f33a172d222554787441ad1c1dc4413b64b`.
