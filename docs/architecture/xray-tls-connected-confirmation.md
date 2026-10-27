# Xray/TLS Connected confirmation (hard invariant, B33)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

A real physical Oppo CPH2173 test (client's ordinary DIRECT ports
deliberately blocked server-side) found the app reporting Protected/Connected
for an XRAY_REALITY session whose real remote handshake never completed -
`NovaXrayVpnService`'s local `coreRuntime.startLoop(...)` returning without
throwing was, by itself, being treated as sufficient proof of a healthy
tunnel. It is not: `startLoop()` only proves the LOCAL core/tun exist: real
HTTPS/DNS through the tunnel timed out the entire time, and the combined Auto
sequence never advanced past the falsely-"successful" attempt.

- **Local process start != healthy connection.** `XrayCoreController.requestStart`
  now runs a bounded, real, positive confirmation
  (`confirmRemoteConnectivity`, `REMOTE_CONFIRM_TIMEOUT_MS = 6s`) AFTER
  `coreRuntime.startLoop(...)` succeeds and BEFORE ever returning
  `XrayCoreStartOutcome.Started` - a real `measureDelay(url)` round trip
  (the pinned AndroidLibXrayLite AAR's own native `CoreController.measureDelay`,
  the exact primitive v2rayNG's own "test configuration" feature uses -
  see `XrayCoreRuntime.measureDelay`'s own docs) through the JUST-STARTED
  core's own configured outbound/routing, targeting THIS attempt's own real
  gateway's already-deployed, unauthenticated `/v1/manifest` endpoint on port
  443 - never a third-party public-IP service, never "process alive"/"tun
  exists", never a fixed sleep, never a debug-only signal. On failure, the
  loop is stopped and the tun released BEFORE returning
  `XrayCoreStartOutcome.RemoteUnconfirmed(reason)` - a genuinely distinct
  outcome from `CoreStartFailed` (that means `startLoop()` itself threw, an
  earlier failure) - never left half-up, and the lifecycle gate is never
  marked running for an unconfirmed attempt (a fresh retry can always
  proceed). `NovaXrayVpnService` publishes the SAME `XrayRuntimeEvent.Failed`
  either way, so `VlessRealityTransport`/`VlessTlsTransport`'s own
  `xrayTransportStateFor` mapping (unchanged) only ever reports
  `TransportState.Connected` after this real confirmation.
- **Auto-progression fix, the other half of the same bug**: even with the
  above, a real terminal Xray failure only arrives asynchronously (via
  `XrayRuntimeState` -> the transport's own `observeState()`), well after
  `VpnController.doConnectAttempt`'s Xray branch has already returned - the
  SAME branch, unchanged, still trusts whatever state the transport
  genuinely reports rather than fabricating one (see that branch's own
  docs). `VpnController.switchActiveTransport`'s existing active-transport
  collector now records `VpnError.HandshakeTimeout` - the SAME typed
  category `AutoGatewayFailoverPolicy.isEligibleForNextCandidate` already
  treats as eligible for AWG - the instant it observes a
  `TransportState.Error` from an XRAY_REALITY/TLS_TCP transport, BEFORE
  `setState` runs, so a concurrently-attached `armFailoverWatch` always sees
  the correct typed error already in place. AWG's own `HandshakeFailed`
  recording (`doConnectAttempt`'s own `awaitFreshHandshake` branch) is
  completely unaffected - this only ever fires for an XRAY_REALITY/TLS_TCP
  transport's own `Error` state. At the time of this original fix, no relay/
  CHAIN_DIRECT-specific code existed anywhere in it - health code only ever
  reported a failure; `attemptCombined`/`AutoGatewaySelector` remained the
  sole authority deciding what is tried next (never called directly from
  here). **This is no longer true for the confirmation step itself - see the
  "B33 relay follow-up" subsection below, which found that same generic
  probe target unsound specifically for a Relayed attempt.**
- **What did NOT change**: `awaitFreshHandshake`/`HANDSHAKE_TIMEOUT_MS`
  (AWG's own cheap local-stats poll, a different signal with a different
  cost shape) is untouched - Xray's confirmation is a one-shot bounded probe
  inside `XrayCoreController`, not a repeated poll, since a real network
  round trip is far more expensive than AWG's local counter read.
  `handleNetworkLost`/B30B reconnect semantics, `xrayTransportStateFor`'s
  `Started`/`Stopped` mappings, and every AWG connect/handshake/reconnect
  path are all byte-for-byte unchanged.
- **Round 2 review fix - the timeout must isolate the BLOCKING native call,
  never merely wrap it.** `XrayCoreRuntime.measureDelay` is an ordinary
  blocking JNI method with no suspension point - an earlier version of
  `confirmRemoteConnectivity` wrapped the blocking call DIRECTLY in
  `withTimeoutOrNull`, which does not bound it at all: the very coroutine
  running that block IS the thread stuck inside the blocking call, so there
  is no separate execution path left for the timeout to fire on (coroutine
  cancellation only takes effect at a suspension point, which a raw
  blocking call never reaches). Fixed by giving the blocking call its own,
  independent coroutine on a dedicated `probeScope` (constructor-injected,
  defaults to a real `CoroutineScope(SupervisorJob() + Dispatchers.IO)` in
  production - `NovaXrayVpnService` passes its own supervisorJob-backed
  `scope` explicitly, so an abandoned probe is cancelled for real when the
  service is destroyed) - deliberately NOT a structured child of the
  calling coroutine. `withTimeoutOrNull` now bounds only the SUSPENDING
  `CompletableDeferred.await()`, which genuinely can be abandoned; the
  underlying native call keeps running independently until it naturally
  returns/throws, at which point it completes a `CompletableDeferred` that
  is fresh and LOCAL to that one `confirmRemoteConnectivity` call - never
  instance-level shared state - so a late completion after timeout has
  nothing left reading it, can never publish `Started` after the timeout
  branch already committed to `RemoteUnconfirmed`, and can never affect a
  later, independent attempt's own outcome. Bounded resource growth: each
  timed-out probe leaves at most one coroutine on `probeScope` (backed by
  `Dispatchers.IO`'s own bounded elastic pool) until the native call's own
  OS-level socket timeout eventually resolves it (the pinned AAR exposes no
  configurable timeout parameter for `measureDelay`, confirmed against its
  decompiled native method signature) - never literally unbounded, since
  the number of concurrently-abandoned probes per connect() sequence is
  capped by the same `AutoGatewaySelector.MAX_ATTEMPTS` bound already
  governing the whole combined attempt sequence.
  `NovaXrayServiceLifecycleCoordinatorTest`'s own `buildController` test
  helper now must pass `probeScope = this` (the enclosing `runTest`'s own
  `TestScope`) explicitly - mixing the production default (real
  `Dispatchers.IO`) into a `kotlinx-coroutines-test` virtual-time test would
  reintroduce the exact same class of flakiness the original
  `withContext(Dispatchers.IO)` mistake already caused once, since
  `runCurrent()`/`advanceUntilIdle()` cannot wait for a real background
  thread to finish.
- **Probe target verified for real, without a certificate bypass.** Both
  production gateways (`152.70.43.1`, `16.170.208.231`) were checked
  directly (read-only SSH) dialing `https://<own-public-IP>/v1/manifest`:
  both present a real Let's Encrypt certificate with an IP-address SAN
  (`subjectAltName: host "..." matched cert's IP address!`,
  `SSL certificate verify ok`) - `measureDelay`'s dial-by-IP probe target
  performs genuine TLS verification with no `-k`/bypass required on either
  host, so a healthy tunnel cannot be mistaken for a broken one due to a
  hostname/certificate mismatch.

### B33 relay follow-up: the generic probe target is unsound for Relayed attempts

A real physical combined-PR pre-merge integration test (PR #55 + PR #53,
Stockholm relay black-hole scenario) proved the CHAIN_DIRECT relay tunnel
genuinely worked end to end (real DNS/HTTPS traffic confirmed server-side in
the ingress's own access log, under the activated device identity) while the
ORIGINAL B33 confirmation above kept reporting `RemoteUnconfirmed` for it and
tearing the working tunnel down every attempt.

- **Root cause (proved from the deployed rendered config, not guessed).**
  The client's rendered Xray config has exactly one outbound and no routing
  rules (`XrayConfigRenderer`), so `confirmRemoteConnectivity`'s generic
  `/v1/manifest` probe against `resolution.config.server` is dialed through
  that one outbound regardless of destination - for a Relayed attempt, that
  outbound IS the ingress. The ingress's own server-side routing (read
  directly from the deployed `/etc/nova-xray-ingress/config.json`) has
  exactly one rule: every destination from the client inbound is
  unconditionally forwarded to its fixed relay-upstream hop, with no
  exception for the ingress's own address. So the probe never tests "is the
  client<->ingress hop alive" - it accidentally asks the exit hop to dial
  back to the ingress's own control-plane over the public internet, a
  fragile, self-referential detour unrelated to genuine relay health.
- **Fix: a context-aware confirmation strategy, not a second health
  authority.** `XrayCoreController.requestStart` now takes a
  `RemoteConfirmationContext` (`Direct`/`Relayed(confirm: suspend () ->
  Boolean)`), defaulting to `Direct` so every pre-existing call site is
  byte-for-byte unaffected. `XrayCoreController` itself stays free of any
  `relay`-package dependency and never hardcodes an ingress id - it only
  ever executes whichever action the caller supplies.
- **Threading, reusing the existing endpointId/routingMode extra pattern.**
  `VpnController`'s existing `VpnAttemptContext.Relayed` (already pinned per
  attempt) now also sets `TransportConfig.Xray/XrayTls.isRelayed`, threaded
  through `VlessRealityTransport`/`VlessTlsTransport` into a new
  `NovaXrayVpnService.EXTRA_IS_RELAYED` Intent extra - the exact same
  mechanism `EXTRA_ENDPOINT_ID`/`EXTRA_ROUTING_MODE` already use.
- **The real Relayed confirmation action reuses the existing
  `HttpRelayEndToEndProbe` - never a fabricated/local check.**
  `NovaXrayVpnService` loads the already-persisted `IngressClientProfile`
  for the attempt's endpoint (the SAME `IngressProfileStore`
  `RelayIngressResolverImpl` already matched moments earlier) and probes it
  via a new `HttpRelayEndToEndProbe.probeProfile(profile)` - the narrower
  half of the SAME `probe(plan, profile)` method `armFailoverWatch` already
  calls later (after `Connected`) for the fuller, plan-scoped end-to-end
  proof; both share one HTTP-calling implementation. `probeProfile` skips
  only the `historyPathId` echo check (no `RelayedExecutionPlan` is in scope
  yet at this earlier layer) - it is still the SAME real, bearer-
  authenticated HTTPS round trip through client -> ingress -> exit, never a
  "TCP/Reality handshake accepted == healthy" shortcut. No persisted profile
  for the endpoint (should not happen - the attempt was only marked relayed
  because a profile already resolved successfully moments earlier) fails
  closed immediately, the same shape `NotConfiguredRelayEndToEndProbe`
  already uses.
- **What did NOT change.** Direct's own confirmation (the generic
  `/v1/manifest` round trip above) is byte-for-byte unchanged.
  `armFailoverWatch`'s later, plan-scoped `HttpRelayEndToEndProbe.probe()`
  call is unchanged - still the sole authority for
  `RelayAttemptOutcome.Success`/`RelayReadinessStage.END_TO_END_DATA_PLANE_OK`.
  `PathScorer`, `AutoGatewaySelector`, attempt budgets, B34 fairness/
  advancement, and AWG are all untouched.

### B33 relay follow-up, round 2 - the replacement probe was ALSO not in-tunnel proof; fixed with an empirically-verified Xray-native target

A further physical CHAIN_DIRECT integration test kept reporting a false
negative (genuine relay data plane working, app UI still ending in
`Connection failed`) even with the round-1 fix above deployed. Root cause,
traced to actual sockets/routing (not inferred from names):

- **Nova's own app process is excluded from its own VPN** -
  `NovaXrayVpnService.establishInterface` always calls
  `builder.addDisallowedApplication(novaPackageId)` (recursion prevention -
  see that function's own docs). This exclusion applies to EVERY socket
  Nova's process opens, with no exception for a "diagnostic" HTTP call.
- **`HttpRelayEndToEndProbe.probe()`/`.probeProfile()` were ordinary
  `java.net.URL.openConnection()` calls made from that SAME excluded
  process** (`NovaXrayVpnService` for the pre-`Started` gate,
  `MainViewModel`'s `armFailoverWatch` for the post-`Connected` end-to-end
  check). Both therefore ran over the device's ordinary default network,
  never through the just-established client->ingress->exit tunnel,
  regardless of that tunnel's actual health. `VpnService.protect()` cannot
  fix this - `protect(socket)` explicitly EXCLUDES a socket from the VPN,
  the opposite of what would be needed.
- **The probe target (`IngressClientProfile.endToEndProbeUrl` /
  `GET /v1/relay-health`) made this concrete, not just theoretical.**
  Traced through `gateway/api/handler.py`: `probe_url` is minted as
  `https://{ingress_exit_probe_host}/v1/relay-health` - the EXIT gateway's
  own public control-plane host, the SAME publicly-reachable address its
  `/v1/manifest` is served from. A request from Nova's excluded process
  reached this host DIRECTLY over ordinary internet, entirely bypassing the
  ingress - a 200/401 there proved only "this device's credential is valid
  and the exit's control-plane API is reachable right now", independent of
  whether the Xray tunnel itself worked.

**Fix: reuse Direct's own `measureDelay`/`/v1/manifest` primitive, dialed
against the EXIT's host instead of the client's own dial target.**
`XrayCoreRuntime.measureDelay(url)` is not itself excluded from the VPN - it
dials through the JUST-STARTED core's own outbound/routing (the native
primitive, not an app-process socket). `RemoteConfirmationContext.Relayed`
now carries `exitProbeHost` (the EXIT endpoint's plaintext host, from
`RelayedExecutionPlan.exitBinding.host` - threaded via a new
`TransportConfig.Xray/XrayTls.relayExitProbeHost` field, `NovaXrayVpnService
.EXTRA_RELAY_EXIT_PROBE_HOST`), and `confirmRemoteConnectivity` dials
`https://$exitProbeHost/v1/manifest` - the SAME unauthenticated,
already-served-by-every-gateway endpoint Direct already trusts, just
targeting the EXIT rather than the ingress. This sidesteps the
`measureDelay`-has-no-header-support problem entirely (no bearer token
needed) and is architecturally distinct from the round-1 bug: round 1 dialed
the INGRESS's own address (which the ingress's blanket forwarding rule
bounced back out to the exit and beyond - a genuinely unrelated public round
trip); this dials the EXIT's address, which the SAME forwarding rule
delivers TO the exit, which serves it locally.

**Empirically verified safe, read-only, against the real deployed Stockholm
ingress / Frankfurt exit pair (2026-09-04)** - not guessed:
- Traced both rendered configs directly: the ingress
  (`/etc/nova-xray-ingress/config.json`) has exactly one unconditional
  routing rule forwarding every destination from the client inbound to its
  `nova-relay-upstream-out` VLESS outbound (dialing the exit's own
  `nova-vless-reality-in` inbound at `152.70.43.1:2053` directly); the exit
  (`/etc/nova-xray/config.json`) has NO routing rules at all beyond its
  single `freedom`/`direct` outbound, which dials whatever destination the
  proxied connection names.
- Confirmed via direct read-only SSH to both hosts: (a) the exit's own
  public IP self-TCP-connects on 443; (b) `curl https://152.70.43.1/v1/manifest`
  issued FROM the exit itself completes a real TLS 1.3 handshake with
  certificate verification (`SSL certificate verify ok`, IP-SAN match, no
  `-k`) and returns HTTP 200 with genuine signed-manifest bytes served by
  the same nginx Direct's own confirmation already trusts; (c) the identical
  request works when issued from the Stockholm ingress host toward the
  Frankfurt exit's public IP (79ms round trip).
- Conclusion: a client dialing `152.70.43.1:443` through the real Stockholm
  ingress genuinely arrives at the Frankfurt exit, which dials
  `152.70.43.1:443` AS ITSELF - a real, working self-connect (not a
  guess) - never leaving the exit machine a second time. Safe to use as the
  authoritative in-tunnel Relayed confirmation target.

- **`HttpRelayEndToEndProbe` is not removed** - still real and useful as an
  OUT-OF-BAND control-plane/credential diagnostic (a 401 is genuine proof
  the token/HMAC binding is broken) and for `historyPathId`
  attribution/replay-binding, but is no longer wired as a gate that can
  overturn a genuine Xray-native `Connected` state:
  `XrayCoreController.requestStart`'s pre-`Started` gate now uses only the
  Xray-native EXIT-manifest `measureDelay` check (never
  `HttpRelayEndToEndProbe`); `MainViewModel.armFailoverWatch`'s
  post-`Connected` branch, for an XRAY_REALITY/TLS_TCP-resolved relayed
  attempt (the only kinds any real `RelayIngressResolver` implementation
  constructs today - AWG upstream chaining remains not implemented, see the
  B24 "Real supported relay transport matrix" section above), now trusts that already-proven Connected state directly
  and fires `HttpRelayEndToEndProbe.probe()` fire-and-forget, diagnostic-only,
  afterward - its result can no longer tear down or advance past a
  genuinely-Connected relayed session. For any OTHER resolved kind
  (defensive - `RelayIngressResolver` is a general interface, never assumed
  Xray-backed), the pre-round-2 probe-gated behavior is unchanged, so this
  fix does not weaken the resolver-agnostic safety net the B25 tests
  originally established.

### B33 relay follow-up, round 3 - stale-Protected relay failure (post-Connected health watchdog)

A further physical test proved a SEPARATE defect from rounds 1/2, on top of
the round-2 fix: a genuinely healthy CHAIN_DIRECT session (Android ->
Stockholm ingress `16.170.208.231:2093` -> Germany exit `152.70.43.1`, real
Protected/HTTPS/DNS) had ONLY its relay-upstream link (Stockholm -> Germany)
black-holed server-side. For 6+ minutes: the client<->ingress link stayed
healthy (`ss -tno` showed zero failed keepalive probes to `:2093`), the data
plane was genuinely dead (`HTTP=000`), `tun0` stayed up, Xray kept running,
and the UI stayed falsely `Protected` - no detection, no teardown, no
recovery, confirmed via direct on-device observation (screenshots + `adb
shell`), not inferred.

- **Root cause**: `MainViewModel.armFailoverWatch` cancels its own
  `controller.state` observer the moment a Relayed attempt first reaches
  genuine success (see that function's own docs) - a deliberate one-shot
  design for the CONNECT-time decision, never intended as ongoing health
  monitoring. `VpnController.handleNetworkLost`/`reconnectLoop` only fire on
  an OS-level network-loss callback, never on a data-plane failure with the
  underlying network (and the client<->ingress link) still healthy - exactly
  this scenario. No other mechanism in the codebase re-checks a relayed
  session's data-plane health after Connected.
- **Fix: a bounded post-Connected relay-health watchdog, owned by
  `XrayCoreController`** (`startRelayHealthWatchdog`) - started only for a
  genuinely Connected `RemoteConfirmationContext.Relayed` session (never
  Direct, never AWG - AWG has no code path through this class at all).
  Reuses the EXACT SAME Xray-native EXIT-manifest primitive round 2 already
  proved safe (`boundedMeasureDelay`, extracted from `confirmRemoteConnectivity`
  so both share one implementation) - never the out-of-band Nova-process
  `HttpURLConnection` check. Polls every `RELAY_HEALTH_PROBE_INTERVAL_MS`
  (20s - no existing "ongoing session health" cadence constant was found to
  reuse; `ReconnectManager`'s backoff and `VpnController.HANDSHAKE_TIMEOUT_MS`
  both govern different concerns, see that constant's own docs). A single
  transient miss is never terminal - only `RELAY_HEALTH_FAILURE_THRESHOLD`
  (2) *consecutive* failures (reset by any intervening success) declare the
  session unhealthy.
- **Teardown ordering closes the "ownerless tun" risk by construction, not a
  new ack primitive.** On reaching the threshold, the watchdog hands its
  stop to `NovaXrayServiceLifecycleCoordinator` (`relayHealthStop`), which
  runs it under the SAME lifecycle mutex as every START/STOP: it stops only
  the watchdog's own session (`stopSessionLocked` refuses while a different
  session runs, so a newer session's core and tun are never touched) and
  invokes the caller's `onRelayHealthLost` callback, still under that lock,
  only when that stop actually tore the session down. The watchdog never
  calls `requestStop()` outside the coordinator in production (that direct
  path remains only for controller-level tests). `NovaXrayVpnService` wires that callback to
  the SAME `XrayRuntimeEvent.Failed` + `stopSelf()` shape every other Xray
  failure already uses, so `VlessRealityTransport`/`VlessTlsTransport`'s
  existing `observeState()` mapping (never a new one) carries it into
  `TransportState.Error` - `VpnController.switchActiveTransport`'s existing
  collector records `VpnError.HandshakeTimeout` and updates `_state`, moving
  the UI off `Protected` - through machinery that already existed, wired to
  a new trigger.
- **Lifecycle**: cancelled by `requestStop()` (covers explicit disconnect,
  and an endpoint switch - `NovaXrayServiceLifecycleCoordinator.selectControllerLocked`
  already tears down the OLD endpoint's controller before building a new
  one) and defensively at the top of every `requestStart()`.
  `relayHealthWatchdogJob` is this controller's own single field (a
  watchdog clears it only while it still holds its own job); a watchdog
  that already passed its threshold is bounded by the coordinator's
  session-id check above, not by cancellation.
- **Known, explicitly out-of-scope boundary**: this fix makes the app
  correctly LEAVE `Protected` and fully tear down on a relay-upstream
  failure - it does NOT re-attempt a different candidate automatically
  (`PathScorer`/`AutoGatewaySelector`/`MAX_ATTEMPTS`/`attemptCombined` are
  untouched, per this follow-up's own scope). A user must reconnect
  manually after this failure, same as any other terminal Xray error today.
