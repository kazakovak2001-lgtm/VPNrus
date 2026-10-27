# Nova VPN (VPNrus) - architecture summary

Compact, factual reference for STABLE invariants and CURRENT runtime boundaries only.
This is not a history and not a replacement for `docs/ROADMAP.md` - it exists so a
slice touching one part of the system doesn't require re-reading the whole repo or
the whole ROADMAP. Update it only when stable architecture actually changes (a new
boundary, a new gateway, a genuinely cross-cutting refactor) - not for every slice,
and not for ROADMAP status-only edits.

## Detailed sections (moved verbatim to `docs/architecture/`)

Read the linked file only when a slice touches that area. Each one is the
unchanged former section of this file, including its `###` review follow-ups.
Older references to "PROJECT_ARCHITECTURE.md's Bxx section" (code comments,
docs) resolve through this list.

- [Reachability / Smart Connect pipeline (fixed order, do not reorder or bypass)](docs/architecture/reachability-smart-connect-pipeline.md) - fixed order `NetworkProfiler -> RestrictionClassifier -> ReachabilityEngine -> PathCandidateBuilder/PathScorer -> SmartConnectDecisionEngine (picks a TRANSPORT, never a gateway) -> TransportOrchestrator`; never reorder or bypass a stage.
- [Xray/TLS Connected confirmation (hard invariant, B33)](docs/architecture/xray-tls-connected-confirmation.md) - A real physical Oppo CPH2173 test (client's ordinary DIRECT ports deliberately blocked server-side) found the app reporting Protected/Connected for an XRAY_REALITY session whose real remote handshake never completed - `NovaXrayVpnService`'s local `coreRuntime.startLoop(...)` returning without throwing was, by itself, being treated as sufficient proof of a healthy tunnel.
- [Field-test zero-touch enrollment (B67.4, Russia field test) - bounded, opt-in, FOUNDATION/PARTIAL until physically validated](docs/architecture/field-test-zero-touch-enrollment-bounded-opt-in-foundation-p.md) - A separate, additive enrollment PATH onto the SAME `/v1/activate` entitlement model - never a second authorization system, and never a replacement for B67.3's contract (see that section's own docs): the credential this mints IS the same live legacy `ActivationCredential` server-side authorization artifact, minted a different way.
- [Restricted-Network / Whitelist Bridge Runtime Foundation (B23) - FOUNDATION](docs/architecture/restricted-network-whitelist-bridge-runtime-foundation-found.md) - Turns the B11 `PathCandidate.Relayed` (client -> INGRESS -> EXIT) model from observational-only into a real, evidence-scored EXECUTABLE CANDIDATE MODEL - still **FOUNDATION**, not IMPLEMENTED, and deliberately **not described as decision-integrated**: no real RU ingress is deployed, client->ingress-
- [Real Ingress Runtime / Server-Side Relay Execution Foundation (B24) - FOUNDATION](docs/architecture/real-ingress-runtime-server-side-relay-execution-foundation.md) - Turns B23's relay CANDIDATE model into a real execution contract on both sides - client execution wiring AND a real server-side ingress runtime - still **FOUNDATION**, not IMPLEMENTED: no real RU ingress is deployed, so none of this has been physically exercised end to end.
- [Relay Readiness / Protected Gating + Ingress Provisioning Control Plane (B25) - FOUNDATION](docs/architecture/relay-readiness-protected-gating-ingress-provisioning-contro.md) - Closes every remaining CLIENT/control-plane blocker B24 named - still **FOUNDATION**, no real RU ingress deployed, **Russia hard-whitelist bypass remains UNVERIFIED**.
- [First Real DIRECT_IP Ingress Deployment Readiness (B26) - software/repo side only](docs/architecture/first-real-direct-ip-ingress-deployment-readiness-software-r.md) - Closes B25's remaining named client/server prerequisites for a real DIRECT_IP ingress deployment.
- [CDN_FRONTED Ingress Support (B27) - FOUNDATION](docs/architecture/cdn-fronted-ingress-support-foundation.md) - The CDN provider capability profile is a typed, versioned description in the existing signed `EndpointTransportBinding.metadata` map (`cdnProviderProfile`).
- [Restricted-Network Decision Authority (B28) - FOUNDATION](docs/architecture/restricted-network-decision-authority-foundation.md) - Architecture principle: `RestrictionClass` (B18/B23) becomes decision-driving for the first time - real restriction evidence now influences automatic DIRECT vs RELAY path ranking, without a second decision authority, without country/provider hardcoding, and without physically validating a real restrictive network.
- [Field Diagnostics / Support Bundle (B29) - FOUNDATION](docs/architecture/field-diagnostics-support-bundle-foundation.md) - Architecture goal: a connection/support incident produces ONE bounded, sanitized, structured diagnostic bundle a non-technical tester can export/ share with one tap - captured AUTOMATICALLY during the real connect flow, never requiring developer mode/ADB/logcat.
- [Resilient Activation & Control-Plane Access (B30) - FOUNDATION](docs/architecture/resilient-activation-control-plane-access-foundation.md) - activation, manifest and profile fetches go through trusted control-plane origins (`TrustedOriginRequestExecutor`) with bounded fallback; includes the PR #44 review fixes.
- [Config resolution atomicity](docs/architecture/config-resolution-atomicity.md) - `SelectedProductionGatewaySource.snapshot()` resolves the selected gateway id exactly once per `GatewayConfigurationRepository.get()` call - a concurrent selection change mid-resolution can never combine one gateway's host with a different gateway's key/ identity/profile.
- [B67/B63 recovery boundary (2026-09-26, ROADMAP-only re-scoping, no code change)](docs/architecture/b67-b63-recovery-boundary.md) - ROADMAP-only re-scoping of B67/B63 (2026-09-26), no code change.
- [B67.6 - entitlement -> eligible-gateway mapping (2026-09-27)](docs/architecture/b67-6-entitlement-eligible-gateway-mapping.md) - Resolves the one architecture question the B67.6 task left open: how an `ActivationEnvelope`'s entitlement maps to which gateway(s) a device may activate against, without turning the envelope into network authority.
- [B67.7 - Smart Connect integration of B67.6 eligibility (2026-09-27)](docs/architecture/b67-7-smart-connect-integration-of-b67-6-eligibility.md) - Technical integration only - wires the B67.6 eligible-gateway set into the EXISTING `AutoGatewaySelector`/`TransportOrchestrator` candidate pipeline.
- [B-WL (Whitelist / Restricted-Network Adaptation) recovery boundary (2026-09-26)](docs/architecture/b-wl-recovery-boundary.md) - recovery boundary for the whitelist / restricted-network adaptation track (2026-09-26).
- [B-WL1/B-WL5 behavior-evidence pipeline (2026-09-27, IMPLEMENTED)](docs/architecture/b-wl1-b-wl5-behavior-evidence-pipeline.md) - Real code, not a proposal - implements the pipeline this file's Reachability/ Smart Connect section already names as fixed and unmodified by this addition: `NetworkProfiler -> RestrictionClassifier -> ReachabilityEngine -> PathCandidateBuilder/PathScorer -> SmartConnectDecisionEngine/ AutoGatewaySelector -> TransportOrchestrator`.

## Health-aware Auto ranking (B19)

- `AutoGatewaySelector`/`PathScorer` remain the SINGLE decision authority for
  automatic gateway+transport ranking (unchanged architecture, B16) - B19 only
  fixes/extends what feeds that one scorer, never adds a second one.
  `SmartConnectDecisionEngine.decideAuto` (Manual-gateway-mode's own transport
  picker) deliberately still ignores `TransportHealth` - the two authorities
  are never merged (architecture principle 1).
- **Diversity bonus fix**: `PathScorer.score`'s `diverseProviderOrAsnSeenElsewhere`
  is now a genuine PER-CANDIDATE signal computed by `AutoGatewaySelector` (a
  pre-pass identifies provider/ASN keys with fresh negative evidence in the
  current batch; only a candidate on a different, non-troubled provider/ASN
  gets the bonus, and only when a troubled alternative actually exists) -
  never an identical batch-wide Boolean (the B12-era bug this replaces).
- **Bounded failure cooldown**: `PathHistoryEntry.consecutiveFailures` (the
  RECENT streak, distinct from the lifetime `failureCount`) drives a capped,
  time-decaying penalty in `PathScorer.score` (`FAILURE_COOLDOWN_WINDOW_MILLIS`) -
  resets to 0 on the next success, expires on its own after the window, never
  a permanent blacklist, never a second persistence system (same
  `FilePathHistoryStore` file, format version bumped 1->2).
- **Evidence from every remote-confirmed Direct attempt (RU field test fix)**:
  `ConnectionOutcomeStore`/`PathHistoryStore` get one record per Direct
  attempt for AWG (synchronous handshake check) AND for XRAY_REALITY/TLS_TCP/
  XRAY_XHTTP/HYSTERIA2 (`VpnController.pendingStateOutcome`: the transport's
  first Connected = success, first Error = failure; user disconnect = no
  record). SHADOWSOCKS_2022 is excluded (its Connected is local-only).
  Relayed attempts stay with `recordRelayOutcome`. `restrictionClass()`'s
  `awgHandshakeFresh` reads the newest AMNEZIA_WG outcome only.
- **Xray session ids**: REALITY/TLS/XHTTP transports share
  `XrayRuntimeState.nextSessionId()` (one counter) - never per-class
  counters, which let one transport adopt another's replayed `Failed`
  event. Ids only grow, also across main-process restarts and wall-clock
  rollback: `XraySessionIdAllocator` covers every id by a persisted ceiling
  (`XraySessionIdCeilingFile`, no-backup, atomic move) before handing it out.
- **Signed binding is the transport address authority**: for Direct
  HYSTERIA2/SHADOWSOCKS_2022 (host+port) and XRAY_REALITY (port; the
  per-device profile must match the binding host or the attempt fails
  closed) the pinned signed manifest binding wins over stored profiles, so
  a port move is a manifest change, not a re-activation. Relayed attempts
  keep their own ingress/relay profiles.
- **Hysteria2 obfuscation**: the signed `hysteria2Profile.obfuscationMode`
  (`NONE`/`SALAMANDER`) is authoritative; the provisioned credential must
  agree (provisioner + `Hysteria2VpnService` fail closed). Salamander is one
  SHARED listener-level secret per server (gateway
  `POCVPN_API_HYSTERIA2_OBFS_PASSWORD_FILE`), never per device; per-device
  access stays the HTTP-auth `auth_secret`. Activation codes are never
  stored, so a mode change needs re-activation of that gateway.
- **Typed reasons**: `PathScorer.Reason` (`ENDPOINT_REACHABLE`/`TRANSPORT_HEALTHY`/
  `FAILURE_COOLDOWN`/`DIVERSITY_BONUS`/etc) are appended to `PathScoreResult
  .reasons` alongside the pre-existing free-text summaries - never replacing
  them, so no pre-B19 reader breaks.
- Precedence (unchanged, B11-established, re-verified this pass): fresh
  endpoint-specific reachability > transport-wide health > this-network
  history > capability maturity > small latency/failure/cooldown/diversity
  adjustments - enforced by `PathScorer`'s own order-of-magnitude tiering,
  never a flat weighted sum.
- **Eligibility (B19-3, a separate concern from ranking, checked first in
  `PathScorer.isEligible`/`ineligibilityReason` - the ONE place, never a
  second filtering layer in `AutoGatewaySelector`/`MainViewModel`/
  `TransportOrchestrator`)**: fresh endpoint-specific `ReachabilityState
  .UNREACHABLE` -> ineligible regardless of transport health (the strongest,
  most specific signal); `TransportHealthState.NOT_IMPLEMENTED` ->
  ineligible; transport-wide `TransportHealthState.UNREACHABLE` ->
  ineligible UNLESS some hop is fresh-confirmed `REACHABLE` (fresh
  endpoint-specific evidence is never overridden by a coarser transport-wide
  claim); `DEGRADED`/`UNKNOWN` on either signal remain eligible, penalized
  only by scoring. Stale evidence never needs a second freshness check here -
  `ReachabilityEngine.assess` already decays it to `UNKNOWN` before
  `PathScorer` ever sees it. An ineligible `PathScoreResult` (`score =
  Long.MIN_VALUE`) never becomes an executable `GatewayAttemptCandidate` -
  `AutoGatewaySelector` already only promotes `eligible == true` results, so
  an ineligible candidate structurally never consumes a `MAX_ATTEMPTS` slot.
- **Physically verified end to end (2026-09-01)**: on the real test device,
  in real Auto mode, two real `FAILURE` outcomes for Frankfurt AWG (written
  via a minimal debug-only Diagnostics button - `MainViewModel
  .debugRecordConnectionFailure` - through the EXACT SAME `ConnectionOutcomeStore`/
  `FilePathHistoryStore` a real failed attempt already writes to, no server
  config touched) demoted Frankfurt AWG to last place
  (`ENDPOINT_UNREACHABLE`/`TRANSPORT_UNREACHABLE`/`FAILURE_COOLDOWN`,
  score=-1080) and promoted Frankfurt XRAY_REALITY to first
  (score=2020000); connecting genuinely executed XRAY_REALITY and reached
  `Protected`. A real-shaped `SUCCESS` write plus a real (non-simulated) AWG
  connection restored AWG to first place
  (`RECENT_SUCCESS_THIS_NETWORK`, score=3030975) and executed AWG again.
  Transport preference stayed `Auto` throughout - the reordering came
  entirely from ranking evidence, never from `AwgXrayFailoverPolicy` or a
  manual override. Device left clean (Auto/Auto, no fault, `Protected`).

## Routing decision vs transport/gateway selection (hard invariant, B18)

- `RoutingDecisionEngine.decideAdaptiveRoute` (`smartconnect/RoutingDecisionEngine.kt`)
  is the ONE live authority for DIRECT vs VPN at the destination-route level -
  never merged with `SmartConnectDecisionEngine` (transport) or
  `AutoGatewaySelector` (gateway). Input: a top-level, persisted, device-local
  `RoutingMode` (`FULL_VPN`/`ADAPTIVE`/`APPS`, default `FULL_VPN`,
  `vpn/policy/RoutingMode.kt`), a route-prefix-only `DestinationClass`
  (`LOCAL_PRIVATE` - RFC1918/loopback/link-local, computed by the
  provably-correct `Ipv4RouteExclusion` CIDR-subtraction utility - vs
  `PROTECTED`, everything else; never per-packet/hostname/domain
  inspection), and `RestrictionClass` (`RestrictionClassifier`'s output,
  wired into a routing decision for the first time here). Conservative by
  construction: only `RestrictionClass.NO_NETWORK` ever changes the
  outcome (-> `Block`); every "possible filtering" class NEVER routes
  `PROTECTED` traffic DIRECT - no hard-whitelist bypass exists or is
  claimed.
- Precedence rule: `AppRoutingPolicy` (B8H, unchanged) decides WHICH APPS'
  traffic reaches the VPN interface at all; `RoutingMode`/
  `RoutingDecisionEngine` decides, only for traffic that does, whether its
  destination goes DIRECT or through the tunnel. `RoutingMode.APPS` is
  byte-for-byte identical to `FULL_VPN` at the destination-route layer -
  Adaptive mode can never broaden which apps bypass the VPN.
  `routingModeStore` is read fresh only at the start of a real `connect()`
  attempt (`VpnController.appliedRoutingMode`) - same "no live mid-session
  rebuild, reconnect to apply" discipline as `AppRoutingPolicy`.
- Live enforcement is consistent across every currently-live transport
  (B18-2). `VpnController.resolveAdaptiveAllowedIps` (AWG) and
  `net.pocvpn.client.vpn.xray.buildXrayVpnPlan` (XRAY_REALITY/TLS_TCP) both
  resolve their IPv4 route list through the ONE shared
  `RoutingDecisionEngine.resolveIpv4Routes` function - never a second CIDR
  computation, never a parallel routing decision. `RoutingMode` reaches the
  Xray/TLS path via `TransportConfig.Xray/XrayTls.routingMode` ->
  `NovaXrayVpnService.EXTRA_ROUTING_MODE` (same intent-extra pattern as
  `EXTRA_TRANSPORT_KIND`/`EXTRA_ENDPOINT_ID`), defaulting to `FULL_VPN` at
  every hop so every pre-B18-2 call site is byte-for-byte unaffected. Only
  the IPv4 entries are ever touched: AWG's AllowedIPs keeps its `::/0` entry
  verbatim in every mode; `XrayVpnBuilderPlan` structurally has no IPv6
  field at all (unchanged) - IPv6 stays fail-closed on every transport, in
  every `RoutingMode`. `RestrictionClass` is NOT live-threaded into the
  Xray/TLS path (defaults `UNKNOWN`) - a documented, safe simplification:
  only `RestrictionClass.NO_NETWORK` changes `resolveIpv4Routes`'s output,
  and `UNKNOWN` yields the identical route set AWG yields for every other
  class, so both transports' ADAPTIVE route sets are provably identical for
  every reachable live case. **Physically verified end to end (2026-09-01) -
  IMPLEMENTED**: a real device's live `dumpsys connectivity` route table for
  `tun0` was checked directly before/after switching `RoutingMode` - Full
  VPN shows plain `0.0.0.0/0`/`::/0`; Adaptive shows the exact
  `Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES` complement. **Xray/TLS
  consistency is physically proven**: a genuinely minimal debug-only
  trigger (`MainViewModel.debugSetTransportPreference`, one button in the
  existing `isDebugBuild`-gated Diagnostics dialog) pins
  `UserTransportPreference.Manual(XRAY_REALITY)` for the next `connect()` -
  a real mechanism `SmartConnectDecisionEngine`/`AutoGatewaySelector`
  already read but no product UI could reach - driving the REAL connect
  path end to end (never a second Xray connection path). The resulting live
  Xray `tun0` session's route table matched AWG's Adaptive session
  entry-for-entry, with `::/0 unreachable` confirming IPv6 fail-closed at
  the OS level for Xray specifically.
  **Live AWG traffic/DNS - root-caused and fixed.** `tun0` RX stuck at zero
  bytes (TX climbing normally, identically on WiFi and cellular) was
  diagnosed via read-only SSH to the Frankfurt gateway: server-side data
  plane (forwarding/NAT/FORWARD chain) was fully healthy throughout - the
  defect was a stale `ClientTunnelIdentityStore[GERMANY]` value on this one
  test device (`10.77.0.2`) that no longer matched the server's actual peer
  registration for this device's public key (`10.77.0.5/32`, uniquely
  assigned - `10.77.0.2` had since been reassigned to a different, active
  peer). WireGuard's cryptokey routing silently drops decrypted packets
  whose source doesn't match the peer's AllowedIPs, inside the kernel WG
  module, before netfilter - exactly matching the symptom. Fixed by
  re-provisioning through the REAL control-plane flow (a fresh activation
  credential issued via the gateway's own operator tool, submitted through
  the unmodified `MainViewModel.activateDevice`/`/v1/activate` path - never
  a hand-edited store), reached via one more minimal debug-only Diagnostics
  button ("Re-activate Germany") that opens the existing `ActivationScreen`
  for an already-provisioned gateway (mirrors B15's own mechanism for an
  unprovisioned one). After re-provisioning: `tun0` RX climbs normally, a
  real request to `cdn-cgi/trace` returned `ip=152.70.43.1`/`loc=DE` in both
  Full VPN and Adaptive modes - conclusive proof public/protected traffic
  genuinely exits through the Frankfurt gateway in both modes, with DNS
  validated through the tunnel (`ValidatedPrivateDnsAddresses`) and IPv6
  unaffected. Device restored to Full VPN/Auto preference/clean afterward.

## Per-device identity (hard invariant)

- Client tunnel IP is per-device, per-endpoint, PROVISIONED identity - lives only in
  `ClientTunnelIdentityStore`. Never hardcoded into `ProductionGatewayCatalog`.
- Missing identity for an endpoint -> fail closed. Never borrow another endpoint's
  identity, never guess, never mark that endpoint usable anyway.
- A control-plane response (live activation or legacy persisted profile) is mapped to
  a gateway id via `ProductionGatewayCatalog.matchGatewayId` (host+port+key+
  gatewayTunnelIp together, never host alone, never inferred from current UI
  selection). A response matching no known gateway, or a DIFFERENT gateway than the
  one requested, is rejected outright - never accepted-but-ignored.
- **Managed AWG identity binding (hard invariant, Phase B).** A stored tunnel IP
  alone NEVER authorizes managed AWG. `ManagedAwgBindingStore` keeps a per-gateway
  map `ProductionGatewayId -> fingerprint` (SHA-256 of the raw managed public key,
  first 16 hex), written ONLY by the activation commit - never by startup,
  migration, recovery or connect (no adoption). Managed AWG for a gateway is
  allowed only when that gateway's binding equals the fingerprint of the public
  key DERIVED from the existing private key the tunnel will use
  (`ClientKeyRepository.getExistingPrivateKeyForTunnel`, never creates a key).
  Missing/unreadable/stale binding, missing/corrupt key or a mismatched key pair
  fails closed; PRIVATE, Xray and Hysteria2 are not gated.
- **Single enforcement point**: `VpnController.buildTransportConfig` (managed
  `AMNEZIA_WG` branch) runs `ManagedAwgIdentityGuard.requireEligiblePrivateKeyLocked`
  and builds the AwgConfig in the same critical section. It also re-reads the
  gateway's CURRENT tunnel IP (`ClientTunnelIdentityStore`) and refuses
  (`TUNNEL_IDENTITY_CHANGED`) if it is missing or differs from the config's
  `clientTunnelIp` (the config may have been snapshotted before the lock).
  A refusal records `ConfigurationMappingFailure("MANAGED_AWG_<reason>")` and no
  outcome/path history. Only `REACTIVATION_REQUIRED` is failover-eligible
  (`ManagedAwgEligibility.isReactivationRefusal`, used by both
  `AwgXrayFailoverPolicy` and `AutoGatewayFailoverPolicy`); a pinned/forced AWG
  and every other refusal reason stop with no fallback.
- **Activation commit** (`MainViewModel.commitManagedActivationLocally`, HTTP
  request outside the lock, short `NonCancellable` local section): key used by
  the request must still be current, else no local write; then the gateway's OLD
  binding is removed (abort on failure), then profile + tunnel IP, then the new
  binding LAST. No server/local atomicity: any failure leaves that gateway
  unbound until a successful activation. Existing installs therefore need a new
  activation (and, with `max_devices=1`, a new credential) before managed AWG.
- **Identity mutation** (debug regeneration) only via
  `VpnController.runManagedIdentityMutation`: refused unless that controller is
  idle (`Disconnected`, no cached config); all bindings are deleted BEFORE the key
  is replaced, and the key is untouched if that fails.
- **Lock order**: `connectMutex` (per `VpnController`) -> L
  (`ManagedIdentityLifecycle`, inside `ManagedAwgIdentityGuard`) -> binding-store
  lock -> managed key repository mutex; code holding L never takes
  `connectMutex`. The guard is built per `MainViewModel.Factory.create()` call,
  which runs once per main process (see VPN session ownership below), so these
  locks serialize the one controller that every `MainActivity` shares.

## VPN session ownership (hard invariant)

- **One owner per main process.** `NovaVpnApplication` is a
  `ViewModelStoreOwner`; `MainActivity.sessionViewModel` takes `MainViewModel`
  from that store, never from the Activity's own. So there is exactly one
  `MainViewModel` -> one `VpnController` -> one set of transports (one
  `GoBackend`) per main process. The store is never cleared in production, so
  `MainViewModel.onCleared`/`VpnController.shutdown` run only in tests.
- **UI state source.** Every `MainActivity` renders `MainViewModel.transportState`
  (= `VpnController.state`) of that one instance. A second instance (explicit
  intent, App Link) or one created after the previous finished (Back) reads the
  controller that owns the running session, not a new one starting
  `Disconnected`. The controller still has no "adopt a tunnel it did not start"
  path: what it shows is only what this process' controller started.
- **Process end.** The owner ends with the main process. AWG
  (`GoBackend$VpnService`), Shadowsocks and Hysteria2 services run in that
  process; `NovaXrayVpnService` runs in `:xray`, and an `:xray` left by a dead
  main process is stopped at the next main-process start
  (`XrayProcessBridge.stopOrphanedXrayProcess`).
- `MainActivity` keeps the default launch mode, so several instances can still
  exist in a task; they share one session owner. Each instance has its own
  Compose UI collecting `MainViewModel.events`.
- Proof: `SessionViewModelOwnerTest` (JVM, fake transport) and
  `ActivityRecreationInstrumentedTest` (device/emulator: two concurrent
  instances and finish+relaunch share one `MainViewModel`).

## Combined Auto attempt fairness and terminal teardown (hard invariant, B34)

A real physical Oppo CPH2173 test (PR #53's own CHAIN_DIRECT validation,
2026-09-04) found two separate defects in the same Auto terminal-attempt
lifecycle, surfaced together once B33 made every failed Direct Xray attempt
correctly take its full bounded confirmation window instead of falsely
succeeding instantly: with 4 ranked Direct candidates (2 gateways x 2
transports) all outranking a real, eligible Relayed `stockholm-ingress-1`
candidate, the entire shared `AutoGatewaySelector.MAX_ATTEMPTS` budget was
consumed by Direct failures before the Relayed candidate was ever tried -
Auto reported "Automatic gateway candidates exhausted" despite a genuinely
viable path existing - and once exhausted, the device was left with a
stale, non-functional VPN interface and NO working Internet at all (worse
than the "Connection failed" UI communicated) until the app process was
force-stopped.

- **`MAX_ATTEMPTS` semantics (unchanged, now precisely documented)**: it
  bounds attempts CONSUMED at runtime (`attemptedKeys.size >= MAX_ATTEMPTS`
  in `nextCombinedAttempt`), never an admission cap on how many candidates
  `buildCombinedAttempts` may return - the full ranked list can be (and
  routinely is) longer than `MAX_ATTEMPTS`; `nextCombinedAttempt` simply
  stops advancing once that many have genuinely been tried.
- **Attempt fairness, never re-scoring**: `AutoGatewaySelector.applyRelayFairness`
  (called from inside `buildCombinedAttempts`, right after the existing
  score sort - `nextCombinedAttempt` itself is completely unchanged) finds
  the single highest-ranked `RelayedAttempt` and, ONLY if it would otherwise
  fall outside the first `MAX_ATTEMPTS` positions, moves it to exactly
  position `MAX_ATTEMPTS` (the last slot the budget allows) - never earlier,
  never re-scored, never preferred over a higher-ranked Direct candidate.
  Every Direct candidate that genuinely outranks the relay keeps its earlier
  turn; only the single lowest-ranked Direct candidate that would have
  occupied that last slot is displaced past the budget instead. A no-op
  when the top Relayed candidate already earns a slot on pure merit, when
  there is no Relayed candidate at all, or when there is no Direct candidate
  to be fair against. Multiple Relayed candidates: only the single
  highest-ranked one is ever guaranteed a slot. The total bounded attempt
  count never changes.
- **Terminal-exhaustion teardown**: `MainViewModel.attemptCombined`'s
  genuine-exhaustion branch (reached only after at least one real candidate
  in the SAME sequence was actually dialed) now calls
  `VpnController.abandonAttemptWithTerminalError(error, message)` instead of
  `rejectPreflight` - the latter is a DIFFERENT, pre-existing function built
  for "reject before this controller was ever touched" (still correctly
  used by `connectAuto()`'s own separate zero-candidate check, where nothing
  was ever touched) and never tears down a transport/tun a real prior
  attempt already brought up. `abandonAttemptWithTerminalError` shares the
  EXACT SAME extracted teardown (`teardownActiveAttemptLocked` - cancels any
  reconnect, cancels the active-transport observer job BEFORE calling
  `disconnect()` to prevent that collector's own async re-forwarding of the
  transport's post-disconnect state from racing/clobbering the terminal
  error, clears every per-attempt pinned field) `abandonAttemptForFailover`
  (B25) already used, then records the typed error and sets a genuine
  `TransportState.Error(message)` - never silently falling back to plain
  `Disconnected`, which the UI/diagnostics could not distinguish from an
  ordinary user-initiated stop. `abandonAttemptForFailover`'s own pre-existing
  behavior (ends at `Disconnected`, used mid-sequence when Auto is about to
  try the next candidate) is unaffected - it shares the extracted helper but
  still sets its own terminal state itself. Never duplicates disconnect
  logic - both public functions call the one private helper.

## Control-plane vs data-plane

- `gateway/api/*.py` (`pocvpn-api`) is fully env-var-driven per instance - zero
  gateway-specific hardcoding in the Python code itself. A second gateway's
  control-plane is a pure deployment action (see `gateway/DEPLOYMENT.md`'s "Deploying
  a second gateway" section), not a code change.
- Client-side: `ProvisioningClient.activate/fetchXrayProfile/fetchXrayTlsProfile` have
  endpoint-aware overloads that POST to the REQUESTED gateway's own edge
  (`ProductionGatewayCatalog.<GATEWAY>.awg.endpointHost`).
  `MainViewModel.activateDevice(credential, targetGatewayId)` routes to that
  gateway's own activation client and its own `XrayProfileProvisioner`/
  `XrayTlsProfileProvisioner` pair, writing only that gateway's
  `ClientTunnelIdentityStore` entry and only that gateway's own endpoint-scoped
  `XrayProfileRepository`/`XrayTlsProfileRepository`.
- Xray/TLS availability (`buildTransportRegistry`) is per-endpoint
  (`xrayAvailableEndpoints`/`xrayTlsAvailableEndpoints`, `Set<EndpointId>`) - one
  endpoint's profile can never make a different endpoint appear available.

## Current gateway state (verify against `docs/ROADMAP.md`'s Gateway Pool row before
relying on this for anything user-facing - this table is a snapshot, ROADMAP is truth)

| | Germany / Frankfurt | Stockholm / Sweden |
|---|---|---|
| Provider | Oracle Cloud | AWS eu-north-1 |
| AWG data plane | physically validated | physically validated |
| REALITY / TLS data plane | physically validated | physically validated (operator/debug-provisioned credentials) |
| Self-service control-plane (`/v1/activate`) | deployed, live | deployed, live (B15) - 443 edge externally reachable (security-group fix applied by operator), real physical-device activation completed successfully |
| AWG client identity provisioning | real, self-service | real, self-service (B15) - physically verified: real device activation, real AWG handshake, exit IP `16.170.208.231` |
| Public IP addressing | stable | AWS auto-assigned, NOT durable/reserved |

Gateway Pool remains **FOUNDATION** (see ROADMAP's own Gateway Pool row for
why - Stockholm's non-durable IPv4 addressing is unrelated to and unresolved
by B16). Automatic multi-gateway selection/failover is now **IMPLEMENTED**
(real candidate construction/ranking/bounded failover, unit-proven AND
physically validated on a real device 2026-09-01: real Auto connect to
Germany, a real on-device fault excluding Germany, real Auto failover to
Stockholm with a confirmed real `16.170.208.231` data-plane connection,
restore, confirmed normal reconnect) - see ROADMAP's own B16 row for the
exact scope, including its one honest caveat (a genuine mid-connect()
AWG-handshake-timeout retry trigger remains unit-test-only, not physically
reproduced - root/server access would be required).

## Private Gateway Mode (B22) - a third, explicit gateway-selection authority

Architecture principle 9: a user may connect through the managed gateway
network *or* their own compatible VPS running the same pinned AmneziaWG
gateway (`gateway/provision.sh`). `GatewaySelectionMode`
(`AUTO`/`MANUAL_MANAGED`/`PRIVATE`, `vpn/config/GatewaySelectionMode.kt`) is
the one explicit authority `MainViewModel.connect()` dispatches on -
`AUTO`/`MANUAL_MANAGED` call the exact pre-B22 `connectAuto()`/
`connectManual()` functions unchanged; `PRIVATE` is the one new branch
(`connectPrivate()`), AWG-only, single candidate, no `smartConnectDecision`/
`AwgXrayFailoverPolicy` - resolving ONLY from `PrivateGatewayStore`, never
`ProductionGatewayCatalog` or the signed manifest (`PrivateGatewayConfig` has
no conversion function to either type - structurally incapable of entering
them). The legacy `GatewayAutoModeStore` boolean is kept in lockstep both
  directions (`selectGatewaySelectionMode`/`setGatewayAutoMode`), and an accepted
  `selectGateway()` call also enters `MANUAL_MANAGED` (including from `PRIVATE`).
  `PRIVATE` can only be selected explicitly through the new store (the boolean
  has no way to express it).

**Client private key never touches ordinary config (architecture constraint
1)**: `PrivateGatewayConfig` has no private-key field at all - the keypair
lives in a SEPARATE `ClientKeyRepository` instance
(`PrivateGatewayKeyRepositoryFactory`, reusing `AwgClientKeyRepository`/
`FileIdentityStore`/`AndroidKeystoreAesGcmEncryptor` byte-for-byte unchanged,
only the backing file name/AndroidKeyStore alias differ from the
managed-network `ClientKeyRepositoryFactory`) - a genuinely distinct identity
from the managed network's, never the same keypair linking both. Threaded
into the real connect path via one new, additive field on the EXISTING B16
pinning mechanism: `TransportOrchestrator.Resolution.Resolved.privateKeyRepository`
(null for every AUTO/MANUAL_MANAGED resolution) -> `VpnController`'s
`pendingConnectPrivateKeyRepository` (mirrors `pendingConnectConfig`'s own
lifecycle exactly) -> consulted instead of the constructor-owned
`clientKeyRepository` only in `buildTransportConfig`'s `AMNEZIA_WG` branch.
`PrivateGatewayConfig.toGatewayConfigSnapshot()` converges into the SAME
`GatewayConfigSnapshot`/`GatewayConfigSnapshotValidator`/`AwgConfigMapper`/
`AmneziaWgTransport` pipeline every other AWG gateway already uses - no
second execution stack.

Fails closed on anything malformed (`PrivateGatewayConfigValidator`, reusing
the existing `Ipv4Format`/`WgKeyFormat` validators verbatim) - the four AWG
magic-header obfuscation fields are required (a real handshake blocker
against `gateway/provision.sh` if mismatched, per `PocAwgProfile`'s own
documented distinction). `PrivateGatewayDialog` also exposes `AwgProfile`'s
full junk-packet profile (`Jc`/`Jmin`/`Jmax`/`S1`-`S4`) - added after physical
validation against a real Stockholm peer proved matching only the four
headers was NOT sufficient against this exact `gateway/provision.sh` build
(see `docs/ROADMAP.md`'s B22 physical-validation history). These seven remain
optional (blank -> `null`, never a hardcoded/invented value - a different
user's own VPS may need different values or none), validated when present
(non-negative, min/max not inverted) via a dedicated
`INVALID_JUNK_PACKET_PARAMETERS` reason, and persisted by
`FilePrivateGatewayStore` exactly like every other field (a legacy file from
before they existed reads back with them correctly `null`, never invented).
`FilePrivateGatewayStore` re-validates on every read, never trusting a
corrupted/hand-edited file as "configured".

First-slice scope: exactly one private gateway, add/edit/remove UI
(`PrivateGatewayDialog`, a real production dialog reached from
`GatewayPickerDialog`'s new "Private Gateway" row - not debug-only), no
Smart Connect/Auto ranking/`ReachabilityEngine`/`PathScorer` integration, no
Xray/REALITY/TLS/QUIC. **IMPLEMENTED** - physically validated end to end
against a real, independently-provisioned isolated peer on the Stockholm
gateway (real handshake, real bidirectional data plane, distinct exit IP,
DNS/IPv6 invariants held, managed identity/state completely unaffected - see
`docs/ROADMAP.md`'s B22 row for the full evidence).

## Signed manifest transport-kind compatibility (hard invariant, 2026-10-09)

- The signed manifest encodes `TransportKind` by **ordinal**
  (`ManifestCanonicalizer`, and `kindOrdinal` in `gateway/tools/manifest_signing.py`
  JSON). `TransportKind` is therefore **append-only**: never reorder, remove
  or insert in the middle (pinned by `ManifestForwardCompatibilityTest`).
- A binding whose ordinal this build does not know (a kind a newer server
  added) is decoded into `EndpointDescriptor.opaqueTransports`
  (`OpaqueTransportBinding`), never `transports`: it is re-emitted in
  ordinal order so `ManifestVerifier`'s re-canonicalization still matches the
  signed bytes, and it is never a candidate, never dialed. Before this, one
  unknown ordinal rejected the whole manifest (older APKs stayed on their
  last-known-good copy until it expired - e.g. pre-HYSTERIA2 builds vs v6/v7).
- Unknown `EndpointRole` ordinals still reject the manifest (unchanged).
- Supersedes draft #113's schema-2 approach: no wire-format or server change.

## Production vs debug boundary

- `XrayDiagnosticsActivity` (and any future manual/debug provisioning helper) lives in
  the `debug` Gradle source set only - must stay absent from the release manifest.
- Normal product UI (picker/LocationCard/Home) shows geography only - no provider/ASN
  names. Provider metadata is diagnostics/debug-only.

## Release native library packaging (B45B, 2026-09-18)

`android/app/build.gradle.kts`'s `androidComponents.onVariants` sets
`packaging.jniLibs.useLegacyPackaging = true` for BOTH the `debug` and `release`
variants (two separate blocks, same Variant API shape) - release native libraries
(Xray's `libgojni.so`, AWG's `libwg*.so`, and any future pinned executable such as
`libsslocal.so`) are extracted to `nativeLibraryDir` at install time, never
mmap'd directly from the APK. This is module-wide by construction - AGP exposes no
per-file granularity for this setting, confirmed by direct investigation, not
assumed. Physically proven end to end on real hardware for both AMNEZIA_WG and
XRAY_REALITY (real connect/data-plane/disconnect, no crash) - see `docs/ROADMAP.md`'s
B45 row for the full evidence trail. A pinned production binary placed under
`android/app/src/main/jniLibs/<abi>/` must be gitignored, never committed (see
`.gitignore`'s own B45B entries) and its provenance hash recorded against BOTH the
pre-build pinned value and the post-`stripReleaseDebugSymbols` shipped value (AGP
strips this specific binary's ELF section headers during release packaging) - see
ROADMAP for the current pinned `sslocal` example.

## Infrastructure safety

Never allocate/purchase paid cloud resources (including Elastic IPs) or make
destructive production changes without explicit owner approval - this applies to any
change, not just gateway-related ones.

## Activation Import Layer (2026-09-27, source-adapter boundary, no new trust root)

- **`ActivationInput`/`ActivationInputResolution`/`ActivationInputResolver`**
  (`net.pocvpn.client.activation.ActivationInput.kt`) is a pure-JVM,
  zero-crypto normalization layer sitting IN FRONT OF the existing
  `ActivationPackageImporter`/`ActivationPackageRedeemer` pipeline
  (unchanged) - it turns a raw source (pasted text, a SAF-picked file's UTF-8
  content, a scanned QR payload, an incoming HTTPS App Link) into either a
  `Ready(ActivationPackageInput.Text)` (which `MainViewModel.submitActivationInput`
  forwards to the SAME `importActivationPackage()` the paste path already
  calls), a `NeedsHandoff(token)` (an App Link/QR-URL resolved to a
  well-formed one-time token, but no backend endpoint exists yet to exchange
  it for a package - surfaced as "not yet supported", NEVER treated as
  trusted), or a `Rejected(reason)` (the raw input's own shape was unusable -
  before the crypto pipeline is ever reached).
- **No new trust root, no new verifier, no duplicated signature/issuer/
  expiry/replay/eligibility logic** - every adapter's only job ends at
  producing plain text for the EXISTING `ActivationPackageInput.Text`.
- **File import** (`ACTION_OPEN_DOCUMENT`, `MainActivity`) and **App Link**
  plumbing (`AndroidManifest.xml`'s `MainActivity` intent-filter,
  `android:autoVerify="true"`, exact host+pathPrefix literals - never a
  wildcard) are real and wired. **QR camera capture and the one-time
  handoff backend endpoint are NOT implemented** - see
  `docs/ACTIVATION_HANDOFF_CONTRACT.md` for the full design contract, exact
  host TODO, and `assetlinks.json` template. `ActivationScreen`'s manual
  paste field remains the fallback/admin/recovery path, unchanged in
  behavior; the relayed-ingress `ActivationScreen` reuse (a different bearer
  credential, never a `NovaActivationPackage`) is untouched.

## Hysteria2 gateway route + Android client (B46-4P.1-.3, B46-4A; live on Stockholm since 2026-09-28)

- `POST /v1/hysteria-profile` (`gateway/api/handler.py` ->
  `hysteria_provisioning.provision_hysteria_identity`) uses the SAME
  activation credential + device binding as `/v1/xray-profile`
  (`activations.py`, `per_activation_lock` outermost; the Hysteria store lock
  is separate and inner). No second activation authority, no crypto of its own.
- Per-device wire secret: fresh 256-bit value per call (rotation), only a
  salted hash at rest (`hysteria_store.py`), returned once in the response,
  never logged. `verify_hysteria_auth` re-checks LIVE activation state and is
  the auth backend's only authority.
- Auth backend (B46-4P.2): `hysteria_auth_server.py` serves `POST /auth` on
  the hard-coded `127.0.0.1` only (no host setting), port
  `POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT` (0 = refuses to start; must differ
  from `API_PORT`). Every failure path denies with the same body; logs never
  carry the secret. Runs as `pocvpn-hysteria-auth.service` on Stockholm.
- Fail-closed: `503 hysteria_not_configured` unless the all-or-nothing
  `POCVPN_API_HYSTERIA2_{STORE_PATH,LOCK_PATH,SERVER_PORT,SNI}` group is set
  (blank by default). Public only through the Stockholm edge location below.
- Deployment (B46-4P.3 artifacts, live on Stockholm): topology is public
  UDP 443 -> `nova-hysteria.service` (non-root, `CAP_NET_BIND_SERVICE` only)
  -> `http://127.0.0.1:8446/auth` -> `pocvpn-hysteria-auth.service`. Server
  config is rendered from the same `POCVPN_API_HYSTERIA2_*` values the API
  advertises (`hysteria_server_config.py`); its ACL rejects loopback/private/
  link-local destinations. SNI `origin-sthlm.aknova.pp.ua` (DNS-only, never a
  Cloudflare-proxied name). nginx is not in the data path and must never add
  a QUIC listener on 443. 8446 is never public.
- Android client (B46-4A completion, ported from #111): `vpn/hysteria/*`
  keeps the three-process boundary (app/VpnService -> tun2socks child ->
  Hysteria2 child, SCM_RIGHTS TUN handoff, protect bridge); no Go runtime
  for Hysteria/tun2socks in the app process. The tun2socks -> Hysteria2 hop
  is a local SOCKS5 on an ephemeral `127.0.0.1` port with per-session
  credentials, and every UDP association is pinned to the client's declared
  loopback address on both sides; the two child ELFs ship only as a pair
  (sources/build records `third_party/{hysteria2,tun2socks}-child/`;
  physically verified on device 2026-10-02; not released, not production
  deployed). Secrets only from the
  endpoint-scoped `Hysteria2CredentialRepository`, never via Intent.
  HYSTERIA2 (ordinal 6) is AVAILABLE only with a trusted signed
  `hysteria2Profile` binding + stored credential + arm64-v8a binaries;
  last in `PREFERRED_ORDER`; never offered by `AutoGatewaySelector`.
  Provisioning goes through the Stockholm edge `location =
  /v1/hysteria-profile` (POST -> 127.0.0.1:8443); the client rejects a
  response whose server/port/SNI/obfuscation differ from the binding.
- Connected = child QUIC + server auth (before `SOCKS5_LISTENING`) AND
  `Hysteria2TunnelProbe` (B33 counterpart): verified HTTPS GET of the
  binding host's `/v1/tunnel-probe` through the child's loopback SOCKS5,
  bounded 6 s, before tun2socks starts. Failure publishes FAILED with
  `Hysteria2RuntimeError.RemoteUnconfirmed`. This probe never touches the
  TUN -> tun2socks leg (the app UID is excluded from its own VPN).
- Protected (H2-GATE): Connected maps to `VpnSessionHealth.DataPlaneVerifying`
  (`requiresDataPlaneProof`, HYSTERIA2 only), never `DirectProtected`, until a
  fresh B-WL7 `VERIFIED` for that same session and reconnect generation.
  Evidence is the tun2socks child's own TUN<->SOCKS payload counters
  (`novasocks5` conns after the handshake + decoded UDP payload, no ACKs):
  after an ack with `"stats": true` the child streams one counters-only
  JSON line per second on a third connection to the same app-private
  control socket; `Hysteria2DataPlaneStatsTracker` binds it to the acked
  pid and fails closed (wrong pid, non-increasing seq, falling counters,
  stream end -> `Unsupported`; >3.5 s quiet -> `Unavailable`, no sample).
  `Hysteria2VpnService.dataPlaneCounters(sessionId)` serves only the
  RUNNING session. A child without the marker can never reach Protected.
  Other transports' Protected semantics are unchanged.
- Hysteria2 data-plane monitor (H2-GATE Gap A, `vpn/Hysteria2DataPlaneMonitor.kt`
  driven by `VpnController.runHysteria2DataPlaneMonitor`, one long-lived
  sampler per session/generation; Gap B relaunches it after an automatic
  reconnect). Promotion (initial and after a revoke) = `evaluate` VERIFIED
  over the current epoch's samples AND an rx advance in the newest sample;
  the first sample of an epoch is a baseline. No S1 probe runs before the
  first promotion; S1 (`VpnTransport.confirmSessionDataPath`, session-scoped
  `Hysteria2VpnService.probeTarget`) never promotes. While Protected: tx
  without rx for the 10 s verification window revokes at once; 60 s without
  an rx advance or S1 success starts one IDLE probe whose success keeps
  Protected only with live counters; `Unavailable` revokes; `Unsupported`
  revokes and stops the monitor (session stays non-Protected, no teardown).
  A revoke starts a new epoch and a recovery episode (<= 3 serialized
  probes, 120 s - both provisional); successes never restore, two
  consecutive failures or a failed last probe at the episode end tear down
  through `failDeadDataPlane`, otherwise the session holds non-Protected.
  The existing NO_PAYLOAD/STALLED verdict still tears down. Every
  promote/revoke/teardown checks one ownership predicate (monitor job,
  reconnect generation, `connectedEpoch`, transport, Connected) under
  `connectMutex` -> `reconnectOwnershipLock`; `setState` runs under
  `reconnectOwnershipLock`, so every `_state` writer serializes with it.
- Live (2026-09-28): Stockholm runs both units (official pinned v2.12.3);
  manifest v6 (`prod-manifest-key-2026-09-14`) carries the only HYSTERIA2
  binding, `16.170.208.231:443`, SNI `origin-sthlm.aknova.pp.ua`, `NONE`;
  physically verified on a device (B46-4A G5/G6). The official server binary
  statically links GPL-3.0-or-later `sing`/`sing-tun` - licence decision
  open (legal review). Record: `docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md`.

## Control-plane loopback edge (B57-5A/5D/5E; Stockholm STAGING live since 2026-10-03)

- Stockholm nginx serves the loopback template (B57-5D version, commit
  `7fbabaf`) on `127.0.0.1:8081`
  ONLY (never `0.0.0.0`/`[::]`), additive to the existing vhosts and reusing
  their `$pocvpn_ingress_profile_backend` map (defined once, in the existing
  vhost). Its only external path: `cp-staging.aknova.pp.ua` -> Cloudflare ->
  Tunnel `8290ff1b-...` -> systemd `cloudflared` (`--token-file`, metrics on
  `127.0.0.1:20241`) -> 8081 -> loopback API. Staging only: no app client and
  no production hostname uses it.
- nginx owns Cache-Control there (B57-5A C1-C4); the Cloudflare Cache Rules
  for `cp-staging` only narrow caching (anonymous `/v1/manifest` eligible,
  any `Authorization` bypassed via `has_key(http.request.headers, ...)`).
  `CF-Connecting-IP` is trusted only from 127.0.0.1 and keys nginx's
  per-client zones; any local process can set it.
- B57-5D (deployed and runtime verified on Stockholm STAGING 2026-10-03,
  commit `7fbabaf`): server-level `X-Forwarded-Proto != "https"` -> 403
  with a server-level `Cache-Control: private, no-store`, before any
  location, so rejected requests never reach the API. Through the Tunnel,
  Cloudflare sets `X-Forwarded-Proto` from the real edge scheme (a
  client-sent `https` over plain HTTP arrives as `http`). Defense in depth,
  not a boundary. Frankfurt variant: not deployed.
- The cp listener's nginx zones key on `$binary_remote_addr`, the client
  address resolved from `CF-Connecting-IP`; on a real mobile CGNAT
  network it resolved to the carrier's public IPv4 (`78.80.113.26`,
  B57-5E 11.9), so all subscribers behind one CGNAT address share one
  per-IP bucket.
- One `pocvpn-api` process on 8443 serves both the staging listener and
  the production 443 vhosts. Deployed on both gateways since 2026-10-04
  (Stockholm: all three API roles; Frankfurt: `pocvpn-api`) and in the
  repository (B57), replacing the old single process-wide 60 req/10 s
  limiter: `api/admission.py` admits per client ->
  edge (cp-loopback ceiling) -> endpoint class -> unchanged global
  ceiling, right after the endpoint's config check and before any
  validation, store read or lock; a rejected request never spends a later
  layer. Client = nginx-set `X-Real-IP` (/32, IPv6 /64) + constant
  `X-Pocvpn-Edge` (`api/client_identity.py`), never `Host` or
  `X-Forwarded-For`; unusable values map to one still-limited
  `unattributed` client. Per-token is per device (credential + public
  key) plus a per-credential cap. The global ceiling is the one shared
  safety ceiling; class/edge ceilings are separate, unaligned fixed
  windows, so no global share is reserved for activation. All limiter
  state is process-local and resets on restart.
- In-tunnel probes (Xray connect confirmation, relayed-session watchdog)
  originate in the Nova app inside the user's own tunnel and reach the
  gateway's nginx from the gateway's own address - indistinguishable from
  other user traffic at the HTTP layer. They therefore target
  `/v1/tunnel-probe` (`XrayCoreController.TUNNEL_PROBE_PATH`), answered by
  nginx itself: static 200, never proxied to pocvpn-api, no limit zone, no
  client input. Never point a probe at a rate-limited or API path. The
  address-based `gateway-self` bootstrap scope (`GATEWAY_SELF_ADDRESSES`)
  exists only for pre-B57 builds that still probe `/v1/manifest`; it is
  not a trusted identity.
- Deployed edge state (2026-10-04, both public gateways): the static
  `/v1/tunnel-probe` location and `proxy_set_header X-Pocvpn-Edge
  "public-443"` on the existing public API locations are live (Frankfurt
  `pocvpn`; Stockholm `pocvpn-stockholm`, all three 443 server blocks).
  Not yet given the edge header: Frankfurt `/v1/relay-health`, the
  Stockholm cp-loopback listener (edge `unknown`, so its edge ceiling is
  inactive), the CDN-origin `edge-sthlm` route (also no `X-Real-IP`, so
  one shared `unattributed` client).
- Deployed API limiter (2026-10-04, both gateways): Stockholm runs the
  B57 API (`main` `3c7429b` files) with `GATEWAY_SELF_ADDRESSES=16.170.208.231`;
  Frankfurt runs the whole `gateway/api` of `main` `20280f0` with
  `GATEWAY_SELF_ADDRESSES=152.70.43.1` (each in `api.env` only). It is a
  compatibility rate-limit scope for pre-B57 `/v1/manifest` probes, NOT an
  authentication, authorization or edge-trust boundary. On Frankfurt the
  B67.4 field-enrollment and B46 Hysteria2 code is present but inactive
  (no env, no nginx route).
- Production control plane is unchanged: raw IPs and `control.aknova.pp.ua`
  (DNS-only -> `16.170.208.231`). Records: `docs/B57_5E_STAGING_VERIFICATION.md`,
  `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md`.

## Exit Target ACL / SSRF boundary (hard invariant, 2026-09-27; Xray exit layer live on Stockholm since 2026-09-28 and Frankfurt since 2026-10-04; AWG nftables layer live on Stockholm since 2026-10-04, blocked on Frankfurt)

- A VPN exit is an Internet proxy, never a proxy into the gateway host, its
  VPC, cloud metadata, or special-purpose space. ONE canonical list:
  `gateway/api/exit_target_policy.py` (IPv4 + IPv6 CIDRs). Never add
  `::ffff:0:0/96` (Go treats it as 0.0.0.0/0); IPv4-mapped space is judged
  by the IPv4 list.
- Xray exit: `xray_config_renderer.render_server_config` enforces it twice:
  a routing field rule (`domainStrategy: AsIs` - never resolves public
  domains) sends literal blocked IPs to the `exit-acl-block` blackhole
  outbound, and `freedom.settings.finalRules` blocks at dial time on the
  RESOLVED IP (hostname destinations included). `direct` stays the first
  (default) outbound. Xray ingress configs have no freedom outbound.
- AWG exit: `gateway/nftables/pocvpn.nft.template` sets `exit_blocked_v4/v6`
  must equal the Python policy (test-enforced); forward chain order is
  `ct established,related accept` -> tunnel-ingress reject to the sets ->
  tunnel<->egress accept; masquerade (postrouting) unchanged and after it.
  Match only `iifname <awg>` so return traffic and ICMP errors (PMTUD) pass.
  Live on Stockholm (`nftables.service` includes `/etc/nftables.pocvpn.conf`).
  Frankfurt's AWG firewall is iptables-nft (`netfilter-persistent`,
  `awg-firewall.sh`, Oracle rules, `awg-ft31`); provision.sh step 5
  (`enable --now nftables`, whose config starts with `flush ruleset`) does
  not fit it - no AWG ACL there until a compatible design exists.
- Hysteria2 (B46-4P.3) keeps its own application-layer ACL for the same
  classes. Defense in depth: application ACL -> host/network ACL; neither
  replaces the other.
- Not covered: tunnel -> gateway INPUT path (host's own listeners).

## Entitlement enforcement on the data plane (hard invariant, B47 T1/T2; API/render enforcement live on Stockholm since 2026-09-28 and Frankfurt since 2026-10-04 - its first render dropped 8 expired Xray identities; Stockholm reconcile service units + first manual run 2026-10-04, timers for AWG / Xray exit / `ingress-xhttp` active since 2026-10-04 (REALITY `@ingress` timer not enabled); Frankfurt: reconcile code + one manual AWG reconcile 2026-10-04, no units or timers)

- ONE predicate: `gateway/api/activations.py` `entitlement_state(record, now)`
  -> ACTIVE / REVOKED / EXPIRED (`status != ACTIVE` -> REVOKED; `expires_at`
  None -> no expiry; `now >= expires_at` -> EXPIRED). `now` must be tz-aware;
  a naive/unparseable `expires_at` is store corruption (`parse_store` rejects
  it) - never an active entitlement. Never decide on `status == ACTIVE` alone.
- Users: `decide_and_bind` (activate / field enroll / ingress self-bind),
  Xray eligibility (`xray_provisioning`), Xray rendering
  (`xray_config_renderer._active_clients`, shared by the ingress renderer,
  evaluated at an explicit `now`), and the AWG reconcile planner.
  Hysteria (`hysteria_provisioning.py`) still has its own copy - follow-up.
- AWG: `awg0.conf` is reconciled to the stores by
  `gateway/scripts/reconcile-peers.sh` (root, `pocvpn-awg-reconcile.service`
  + `.timer` ~5 min, plus a best-effort `systemctl start --no-block` from
  `activation_tokens.py revoke`). It holds `.provision.lock` across planning
  (`gateway/tools/awg_reconcile.py`, read-only) AND mutation
  (`mutate_remove_peer_if_present`). Removes only keys bound exclusively to
  revoked/expired activations or REVOKED legacy tokens; peers unknown to every
  store are reported, never removed; any store problem, or an `awg0.conf`
  that fails structural validation (`migrate_peer_markers.parse_marked_conf`:
  markers, sections, one canonical PublicKey per `[Peer]`, peer boundaries
  identical to `mutate_remove_peer`'s), aborts with exit 3 before any
  mutation or reload. The API gains NO removal privilege (sudoers unchanged).
  Lock order: `.provision.lock` -> store shared locks; the reconcile never
  takes a per-activation lock (the API holds per-activation -> waits on
  `.provision.lock`), so no cycle.
- Live convergence (provisioning AND reconcile) goes through
  `converge_live_state`, which reloads `$SERVICE_NAME`. `SERVICE_NAME` is
  per host: `config/poc.env` default `awg-poc`, overridable ONLY by
  `/etc/pocvpn/awg-host.env` (parsed, never sourced; `SERVICE_NAME` is the
  sole accepted key; Frankfurt: `awg-quick@awg0`, tracked in
  `gateway/hosts/frankfurt/`). "Service inactive" is success only when
  `$INTERFACE_NAME` is really down (`awg show interfaces`); interface up +
  service inactive, or an unqueryable interface list, dies - a wrong
  `SERVICE_NAME` can never again report durable-only changes as converged.
- Per-host systemd path differences are tracked drop-ins under
  `gateway/hosts/<host>/` (reset + exact list), never widened base units.
- Xray: the existing render -> hash compare -> `nova-xray-reload` path, run
  periodically by `nova-xray-reconcile.timer` /
  `nova-xray-ingress-reconcile@<env>.timer`; expiry changes the render, so
  the hash changes and the existing reload drops the client. A store error
  leaves the running config untouched (no staging write, no reload).
- Relay `static_clients` (ingress -> exit infra identity) are NOT user
  entitlements and are never filtered by this predicate.
- Deployed state (2026-10-04): Stockholm has the three reconcile SERVICE
  units installed, each run once by hand, and the timers
  `pocvpn-awg-reconcile.timer`, `nova-xray-reconcile.timer`,
  `nova-xray-ingress-reconcile@ingress-xhttp.timer` enabled and active
  (every 5 min; first automatic runs were no-ops). Expiry/revocation is
  thus enforced automatically on Stockholm for AWG, Xray exit and XHTTP
  ingress. `nova-xray-ingress-reconcile@ingress.timer` (REALITY ingress)
  is NOT enabled, so that role converges only on a render. Frankfurt has
  no reconcile unit or timer. With
  the AWG service unit installed, `activation_tokens.py revoke`'s
  best-effort `systemctl start --no-block pocvpn-awg-reconcile.service`
  now resolves to a real unit on Stockholm (from code; not yet exercised).
  Frankfurt (2026-10-04): reconcile code, `awg-host.env`
  (`awg-quick@awg0`) and one manual AWG reconcile deployed; no reconcile
  units or timers yet, so no automatic expiry there.

## Field test (measurement tool, 2026-10-06)

- `diagnostics/fieldtest/`: `FieldTestRunner` drives the EXISTING
  `connect()`/`disconnect()`, gateway selection, debug transport pin and
  debug path override through the narrow `FieldTestHost` (implemented in
  `MainViewModel`) - no second connection path, no selection or scoring
  change. It saves and restores the user's selection (also on cancel).
- `DebugPathOverride` is build-type-scoped (src/debug real, src/release
  no-op): it only filters the attempt list connectAuto already built to
  the Relayed attempts (optionally one ingress), fail-closed.
- In-tunnel probes bind to the VPN `Network`; direct and censorship probes
  run only while disconnected. The device's own public IP is never stored;
  log lines pass `LogSanitizer`; reports leave the device only via the
  user's share action.
- UI: FULL/MONITOR only from the `isDebugBuild`-gated Diagnostics dialog;
  release exposes only QUICK (Settings -> Network check). Local save is a
  no-op in release. `CrashRecorder` (installed in NovaVpnApplication) keeps
  the newest 5 sanitized JVM crash records in app-private storage.
- Every rendered Xray config disables the access log (`"access": "none"`):
  per-connection destination records never reach logcat or a report
  (`LogSanitizer.isConnectionRecord` drops any that still appear).
- Measurement only: a report is B54 evidence for one network, never a
  reachability claim by itself.

## Process boundary: Xray runs in `:xray` (hard invariant, 2026-10-06)

- ONE Go runtime per process. AmneziaWG (`libwg-go`, GoBackend in the main
  process) and Xray (`libgojni`) in one process crash it (`E/Go: SIGSEGV`,
  ApplicationExitInfo `EXIT_SELF status=2` - the B57 "unexplained" exits),
  reproduced 3/3 by the field test when an Xray session followed an AWG
  session. `NovaXrayVpnService` therefore runs with `android:process=":xray"`;
  nothing in `:xray` may load `libwg-go` (NovaVpnApplication returns early
  there) and nothing in the main process may load `libgojni`.
- The only cross-process state is `XrayProcessBridge`: `XrayRuntimeEvent`s
  as an app-private broadcast (setPackage + RECEIVER_NOT_EXPORTED) re-published
  into the main process' `XrayRuntimeState` (transports unchanged);
  `:xray` death during a Started session -> `XrayRuntimeEvent.Failed`
  (zero-flag bind + linkToDeath; onBindingDied too) - at once when the main
  process did not ask that session to stop (Android has already removed
  the VPN interface), after the 2 s grace only for a stop it requested
  (`stopSession` marks it before ACTION_STOP). START/STOP/revoke run in
  intent order on one `XrayLifecycleQueue`; ACTION_STOP carries the session
  id and never tears down a different running session. Session work stops
  the service only via `stopSelf(startId)` while no newer START/STOP/revoke
  exists (`XrayServiceStopGate`); `onDestroy`'s unscoped teardown is the
  only one left. Teardown reports the
  session whose core it actually stopped (`NovaXrayServiceLifecycleCoordinator
  .stopSession`, tracked under the lifecycle mutex), never the latest
  ACTION_START id. `XrayProcessCore` owns the one `LibXrayCoreRuntime`
  (one native `libv2ray.CoreController`) and the one `XrayCoreStopState` of
  the `:xray` process - never per service instance, so a recreated service
  drives the same core. A stop counts as confirmed only when the runtime
  reports `isRunning == false` after `stopLoop()` (at most one retry);
  otherwise it is StopUnconfirmed: teardown publishes `Failed`, never
  `Stopped`, and every START on that process returns `StopUnconfirmed`
  (no tun, no `startLoop()` - the pinned wrapper's `StartLoop` silently
  succeeds while its core still runs) until a later stop or the runtime
  reports the core down, or the process dies. `isRunning == false` is the
  wrapper's flag only: its shutdown logs and swallows a `Close()` error,
  so it does NOT prove every native resource was released. Xray
  transports' `disconnect()` from `Error` sends a best-effort ACTION_STOP so
  an unconfirmed stop is retried. Under one lock with each broadcast, `:xray` keeps an
  app-private record (`XrayTerminalJournal`/`XrayTerminalRecord`, atomic
  move) of the first terminal event of the session it last started;
  Started clears it. A death that beats the broadcast therefore yields the
  real event of THAT session (Stopped after a system revoke, a typed relay
  Failed), and a record of any other session or run is never read. The main mirror takes at most one terminal event per session
  and nothing from an older session (`acceptInMain`); the watcher ends
  only on its own session's events; an orphaned `:xray` tunnel is stopped when
  a new main process starts; field-test core measurements
  (`ACTION_MEASURE` -> Xray `measureDelay`); B-WL7 tunnel byte totals
  (`ACTION_QUERY_TRAFFIC` -> session id + two counts, asked only while the
  main mirror shows that session Started).
- Secrets never cross Intent/Binder: the XHTTP session config (VLESS uuid)
  is handed over as an Android-Keystore AES-GCM encrypted app-private file
  (`XhttpSessionConfigStore`), consumed once and deleted; stale files swept.
- Xray (and Hysteria2) sessions exclude the Nova app from their tunnel by
  design, so app sockets cannot probe through them (EPERM); the field test
  measures Xray through the core and reports Hysteria2 as
  CONNECTED_APP_EXCLUDED.
- Xray transports' `disconnect()` is a no-op when already Disconnected and
  falls back to Disconnected after a bounded wait (same rule as
  Shadowsocks/Hysteria2) - an idle transport can no longer wedge the
  controller in Disconnecting.

## GeoData datasets (Settings -> GeoData, 2026-10-26)

- Layout under `noBackupFilesDir/xray-assets`: `geo-<id>/` (`geoip.dat`, `geosite.dat`, `.geo-dataset.json` marker; `<id>` = SHA-256-derived, content-addressed,
  never rewritten in place), `.geo-active.json` (atomic pointer: active + previous id), `.geo-effective` (dataset id the `:xray` core was last pointed at),
  `.geo-staging.lock` / `.geo-update.lock`, `.geo-download/` (temp). Old downloaded datasets are pruned except the active, the previous and the `.geo-effective` one;
  the bundled dataset, quarantine dirs, foreign dirs and symlinks are never touched.
- `LibXrayCoreRuntime.ensureCoreEnvInitialized` (`:xray`) gives `initCoreEnv` the verified active downloaded dataset, else the bundled one, else the plain root
  (= pre-feature behavior). It never fails a start because of geo data. A changed pointer is re-applied only while the core is NOT running (no hot reload).
  There is no automatic rollback to the previous download: the fallback is the bundled databases.
- Updates run in the MAIN process (`GeoDataViewModel`/`GeoDataUpdater`); the core runs in `:xray`; cross-process safety is file locks + the atomic pointer.
- Downloads bypass the VPN (the app is `addDisallowedApplication`'d) and are https-only; the renderer, TUN, routing and `RoutingMode` are untouched.
