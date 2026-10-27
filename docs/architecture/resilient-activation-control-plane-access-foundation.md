# Resilient Activation & Control-Plane Access (B30) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

**PR #44 review fix, round 2 (2026-09-03) - origin-discarding blocker
fixed.** The round-1 fix wired `activateDevice()`/Xray/TLS profile fetch
through `TrustedOriginRequestExecutor`/`fetchThroughTrustedOrigins`
structurally, but every actual per-origin network callback still discarded
the `ControlPlaneOrigin` it was handed and re-dialed the SAME pre-bound
host every time - a 2-origin executor iterating the SAME request twice
(retry, not failover). Fixed by making every gateway-scoped network seam
genuinely **origin-aware**:

- `MainViewModel.activationClient`/`stockholmActivationClient` changed
  from `(publicKey, activationCredential) -> ProvisioningResult` to
  `(origin: ControlPlaneOrigin, publicKey, activationCredential) -> ProvisioningResult`,
  both now sharing the SAME origin-driven default -
  `{ origin, pk, cred -> ProvisioningClient.activate(pk, cred, origin.host) }`
  - no gateway-specific hardcoded host needed anymore, since
    `origin.host` already carries whichever gateway's real host
    `ControlPlaneOriginSetBuilder.forGateway` resolved it from.
  - `activateDevice`'s `callActivate = { origin, pk, cred -> client(origin, pk, cred) }`
    now genuinely forwards `origin` instead of discarding it.
- `XrayProfileProvisioner.fetchXrayProfile`/`XrayTlsProfileProvisioner.fetchXrayTlsProfile`
  changed the same way - `(origin, publicKey, activationCredential) -> XrayProfileResult`/
  `XrayTlsProfileResult`, defaulting to
  `{ origin, pk, cred -> ProvisioningClient.fetchXrayProfile(pk, cred, origin.host) }`
  (and the TLS equivalent). `gatewayId` on both classes changed from
  nullable (opt-in origin routing) to non-null, defaulting to `GERMANY`
  (this codebase's own existing "Germany-default" convention) - `provision()`
  now ALWAYS routes through `fetchThroughTrustedOrigins`, never a second,
  parallel non-origin-aware code path that could silently diverge from the
  real one. The Stockholm-specific `fetchXrayProfile`/`fetchXrayTlsProfile`
  overrides in `MainViewModel.Factory.create` (previously hand-building the
  Stockholm host) were removed entirely - the new default, combined with
  `gatewayId = STOCKHOLM`, already resolves the correct host via
  `ControlPlaneOriginSetBuilder`.
- Every pre-existing test call site supplying a 2-arg
  `activationClient`/`stockholmActivationClient`/`fetchXrayProfile`/
  `fetchXrayTlsProfile` lambda was updated to the new 3-arg (origin-first)
  shape - mechanical, behavior-preserving for tests that don't care about
  origin (they just add a leading `_`).
- **New tests directly prove host-level routing** (not just call count):
  `MainViewModelActivationGatewayIdentityTest` gained
  `primaryOrigin`/`secondaryOrigin` fixtures with real, distinct hostnames
  (`"primary.example"`/`"secondary.example"`) and a fake `activationClient`
  that branches ON `origin.host` and records every host it was actually
  called with - asserting the exact sequence
  `["primary.example", "secondary.example"]` for the fallback case and
  `["primary.example"]` only for the authorization-rejection-stops-early
  case. This is the proof a synthetic 2-origin executor could otherwise
  silently dial the same host twice without any test catching it.

**PR #44 review fix, round 1 (2026-09-03)** - two blockers fixed:

1. **`MainViewModel.activateDevice()`'s real network call now genuinely
   routes through `ActivationResilienceCoordinator`** (it did not before -
   the coordinator previously existed only as tested-but-unused
   foundation code). `activateDevice` builds `origins` via a new
   `controlPlaneOriginsForActivation` constructor seam (defaults to
   `ControlPlaneOriginSetBuilder::forGateway`, the real production
   builder), calls `activationResilienceCoordinator.activate(...)` with
   `hasValidLocalActivation = { false }` (this is an explicit,
   user-triggered action - it must always actually attempt the network,
   never silently skip because some prior local state happens to exist),
   and unwraps the resulting `Outcome` back into the SAME `ProvisioningResult`
   every pre-existing downstream line already branches on
   (`Outcome.Success.result`/`Outcome.Rejected.result`/
   `Outcome.AllOriginsExhausted.lastResult`) - the ~250-line success/
   persistence block (gateway-identity `matchGatewayId` cross-check,
   `gatewayConfigOverride.apply`/`profileStore.write`/
   `clientTunnelIdentityStore.write`, Xray/TLS provisioning chain,
   `reconcileSelectedGatewayIfNeeded`) is untouched, byte-for-byte the same
   code, now fed a `result` that may have come from a later origin instead
   of only ever the first. `retryActivation()` already called
   `activateDevice` verbatim, so Retry automatically reuses the same
   resilient path - no bypass. `Outcome.AllOriginsExhausted` gained a
   `lastResult: ProvisioningResult` field specifically so this unwrapping
   is possible without losing per-status UI fidelity (`ServiceUnavailable`/
   `MalformedResponse`/`NetworkError` still map to their pre-existing
   `ProvisioningUiState.Error` variants when only one real origin exists,
   today's actual production case). Manual `recordActivationStarted`/
   `recordActivationSucceeded`/`recordActivationFailed` calls in
   `activateDevice` were removed (the coordinator now records these
   itself) except one narrow addition: a client-side gateway-identity
   mismatch (a wire-level Success that `matchGatewayId` then rejects) is
   recorded as an additional `TRUST_VALIDATION_REJECTED` failure, since the
   coordinator's own narrow view already recorded `ACTIVATION_SUCCEEDED`
   for the wire response alone.
2. **Trusted-origin audit, performed rather than assumed**: decoded the
   embedded signed bootstrap manifest's canonical bytes directly (see
   `EmbeddedBootstrapManifest.kt`) - each of Germany's and Stockholm's
   `EndpointDescriptor`s carries exactly ONE host across all three
   transport bindings (AWG/51820, a second VPN-transport port/2053,
   TLS/2083 - different PORTS/PROTOCOLS on the SAME IP, not alternate
   hosts, and none of them an HTTP activation-API port anyway). Audited
   `gateway/api/activations.py`: activation state is a durable JSON store
   **local to each gateway's own VPS filesystem** - Germany and Stockholm
   run fully independent `pocvpn-api` processes with independent
   credential-digest-keyed stores; a credential valid on one has no
   meaning to the other (confirmed independently by
   `ProductionGatewayCatalog.matchGatewayId`'s own full-fact,
   never-guessed-at matching). **Conclusion: no genuine second trusted
   control-plane origin exists today, for either gateway** - the two
   production gateways are NOT interchangeable activation backends, and
   there is no alternate edge/host for either one's own control plane in
   any compiled or signed trusted data. Per the review's own accepted
   alternative ("report the architecture blocker instead of fabricating
   failover"), `ControlPlaneOriginSetBuilder.forGateway()` was left
   unchanged (still exactly one real origin per gateway) - inventing a
   second host would violate the "never accept/invent an untrusted origin"
   invariant this same slice exists to enforce. Provisioning a genuine
   second edge (e.g. a load balancer/CDN edge sharing the SAME backend
   store) is real infrastructure work requiring explicit owner approval per
   this repo's own rules, out of scope for a client-only PR.
   `controlPlaneOriginsForActivation` (see point 1) makes the FALLBACK
   MECHANISM itself verifiable today anyway: a new
   `MainViewModelActivationGatewayIdentityTest` integration test injects a
   synthetic two-origin list through this real seam and proves
   `activateDevice()` genuinely retries and persists a later origin's
   success - the mechanism is proven correct through the real production
   code path even though real production data cannot yet exercise it with
   two DIFFERENT physical hosts.
3. **Xray/TLS profile fetch now also genuinely routed through the executor**
   (review's own "verify all profile retrieval endpoints... are actually
   wired through it, not only instrumented"): `XrayProfileProvisioner`/
   `XrayTlsProfileProvisioner` gained additive nullable `gatewayId`/
   `diagnosticsRecorder` params (both null preserves the exact old
   single-call behavior for every pre-B30 test/call site); when
   `gatewayId` is set (now true for all four Factory-constructed
   instances - Germany and Stockholm, REALITY and TLS), `provision()`
   routes its fetch through the new `fetchThroughTrustedOrigins` helper
   (`controlplane/TrustedOriginProfileFetch.kt`) - the SAME
   `TrustedOriginRequestExecutor`/`ControlPlaneOriginSetBuilder`
   activation uses, generalized for any gateway-scoped fetch.
   `IngressProfileProvisioner` (relay/ingress profile fetch) deliberately
   stays diagnostics-instrumented only, NOT routed through this same
   mechanism: an ingress endpoint is `EndpointId`-scoped, not
   `ProductionGatewayId`-scoped (need not be one of the two production
   gateways at all), so forcing it into the gateway-identified origin
   model would misrepresent what is actually trusted for it - its own
   single, already-pinned `ingressBinding.host` is the ONLY origin that
   could ever be correct for that specific ingress.
- **New tests**: `TrustedOriginProfileFetchTest` (executor reuse for
  profile fetch, `classifyXrayProfileResultFailure`/
  `classifyXrayTlsProfileResultFailure` exhaustive mapping),
  `MainViewModelActivationGatewayIdentityTest` additions (primary-fails/
  secondary-succeeds applied+persisted through the REAL activateDevice
  flow; malformed primary response leaves no partial state and the
  secondary's success is what persists; all-origins-exhausted produces
  the required friendly message with no host/exception leakage;
  authorization rejection stops fallback with the secondary never
  attempted), `MainViewModelSupportDiagnosticsTest` addition (activateDevice's
  real diagnostics carry no origin host/IP/URL/credential). All new + full
  existing suite green (1190 total, the same one pre-existing unrelated
  `EffectiveConfigDiffTest` failure); `compileDebugKotlin`/
  `testDebugUnitTest`/`assembleDebug` all re-verified green after these
  fixes.

Architecture goal: activation/profile-retrieval network calls (POST
`/v1/activate`/`/v1/xray-profile`/`/v1/ingress-profile` via
`ProvisioningClient`) become bounded, typed, and origin-list-driven rather
than a single hardcoded call with undifferentiated failure and
default-follow-redirect behavior - without creating a second trust system
alongside B11/B12/B20's signed-manifest/bootstrap/LKG architecture.
**FOUNDATION only** - not yet physically validated on a restrictive
network; does NOT prove Russia hard-whitelist bypass, which remains
UNVERIFIED.

- **Trusted origin model (task 1/2, `controlplane/ControlPlaneOrigin.kt`)**:
  `ControlPlaneOrigin(gatewayId: ProductionGatewayId, host: String)`,
  built ONLY by `ControlPlaneOriginSetBuilder.forGateway(gatewayId)` from
  `ProductionGatewayCatalog` - the same compiled-at-build-time, trusted
  gateway facts every other gateway-identity check in this codebase already
  uses (never a second, independently-maintained origin list; never a
  parameter through which a caller-supplied/arbitrary URL could enter -
  task 2's "never accept arbitrary user-supplied activation URLs" holds
  structurally, not by convention). Today's compiled catalog carries
  exactly one physical origin per gateway (Germany/Stockholm - see that
  catalog's own docs), so this returns a single-element list per gateway;
  the list SHAPE (not a bare host string) is what makes the executor below
  genuinely N-origin-capable the moment ops adds a second trusted origin
  (e.g. a CDN-fronted control-plane edge, mirroring B27's CDN-fronted
  ingress binding) - no call site changes when that happens, only this one
  builder. TLS downgrade/redirect-based origin substitution is structurally
  impossible here: nothing in this file ever performs I/O or inspects a
  response.
- **Generic executor (task 4, `controlplane/TrustedOriginRequestExecutor.kt`)**:
  pure and synchronous - no networking, no coroutines. Tries each origin in
  `origins` (an ordered `List<ControlPlaneOrigin>`) AT MOST ONCE, in order
  (bounded by construction - `origins.size` attempts, never a retry loop,
  never unbounded); the caller supplies `callPerOrigin` (already reduced to
  a typed `OriginCallResult.Success`/`Failure(ControlPlaneFailureReason)`),
  so the bounded/typed-failure/no-infinite-retry discipline is unit-testable
  with fake origins and fake results, never a live HTTPS connection. Stops
  early on `AUTHORIZATION_REJECTED` (default `stopOnReasons`) - a rejected
  credential is evidence about the credential, not about which origin was
  reachable, so it is never retried against a different origin (also
  satisfies task 10's "never forward credentials to another host
  automatically": each origin gets a fresh `callPerOrigin` invocation from
  whatever closure the caller built, no shared connection/header state
  crosses origins). ONE executor, reused by
  `controlplane/ActivationResilienceCoordinator.kt` (activation) and
  `relay/IngressProfileProvisioner.kt` (ingress-profile diagnostics/
  classification) - task 4's own "do not create transport-specific copies
  of control-plane retry logic".
- **Failure taxonomy (task 9, `controlplane/ControlPlaneFailureReason.kt`)**:
  `DNS_RESOLUTION_FAILED`/`CONNECT_TIMEOUT`/`TLS_TRUST_FAILED`/
  `HTTP_UNAVAILABLE`/`AUTHORIZATION_REJECTED`/`MALFORMED_RESPONSE`/
  `TRUST_VALIDATION_REJECTED`/`UNTRUSTED_REDIRECT_REJECTED`/
  `ALL_ORIGINS_EXHAUSTED` - a closed, support-bundle-safe vocabulary,
  distinct from (never replacing) the richer `ProvisioningResult`/
  `IngressProfileResult` types callers still branch on, the same
  "re-label, never replace" discipline B29's `DiagnosticFailureReason`
  mappers already use. `classifyControlPlaneIoException`/
  `classifyNetworkErrorMessage` (`internal`, unit-tested) map a raw
  exception type or `ProvisioningClient`'s own deterministic
  `"${exceptionClass}: ..."` message prefix into this taxonomy - never the
  rest of an exception message, which is never inspected or logged.
- **Redirect lock-down (task 10, `provisioning/ProvisioningClient.kt`)**:
  `executeGeneric` (the ONE shared low-level call every endpoint -
  peers/activate/xray-profile/xray-tls-profile/ingress-profile - already
  goes through) now sets `connection.instanceFollowRedirects = false`
  before connecting. Audit finding: `HttpsURLConnection` follows redirects
  TRANSPARENTLY by default, before any status-code branch in this file ever
  ran - every endpoint here carries a bearer credential, so an auto-followed
  redirect would have silently resent `Authorization` to whatever host a
  response named. A 3xx now surfaces as a real status code, already
  rejected by every `mapResponse` function's own `else -> NetworkError(...)`
  catch-all - never followed, never treated as success. One-line fix,
  applies to all five endpoints at once, zero API changes.
- **Activation resilience (task 3/5/11/12, `controlplane/ActivationResilienceCoordinator.kt`)**:
  wraps the SAME per-gateway `ProvisioningClient.activate(...)` call this
  codebase already has with the executor's bounded/typed discipline.
  `hasValidLocalActivation` (a caller-supplied pure check, task 3) skips the
  network entirely when already valid. Idempotent by construction (task
  11): never generates/rotates identity itself - `publicKey` is always the
  caller's already-get-or-created device key, so a Retry always presents
  the SAME public key + credential, exactly what the server's own
  activation endpoint (idempotent by credential digest -
  `gateway/api/activations.py`) needs to treat a retry as the SAME logical
  activation, never a new device identity. Never applies/persists anything
  itself (task 12 - "no half-written activation credentials"): returns the
  raw `ProvisioningResult.Success` on success, leaving
  `gatewayConfigOverride`/`profileStore`/`clientTunnelIdentityStore` writes
  to the caller, unchanged from `MainViewModel.activateDevice`'s own
  existing "only after full validation, never partial" ordering.
  **PR #44 review fix**: `MainViewModel.activateDevice`'s primary network
  call now genuinely routes through this coordinator (see this section's
  own "PR #44 review fix" note at the top for the full detail) - the
  scope-limited "foundation only, not wired in" state described in the
  original B30 slice no longer holds.
- **First-run failure UX / Retry (task 6/7, `provisioning/ActivationFailureMessage.kt`,
  `MainViewModel.activationFailureMessage`/`retryActivation`)**:
  `activationFailureMessage: StateFlow<String?>` is a pure DERIVED
  projection of the existing `provisioningState` (never a second state
  machine, never mutates it) - `friendlyActivationFailureMessage` collapses
  every failure variant to ONE fixed, non-technical sentence (task 6's own
  required copy for the generic case: "VPN setup could not be completed on
  this network. Try another network or send diagnostics.") - a FIXED string
  literal per branch, never interpolating `ProvisioningUiState.Error`'s own
  raw exception/hostname/malformed-reason text, which is what makes "never
  leaks a raw exception" true by construction. `retryActivation(...)`
  reuses `activateDevice(...)` verbatim - no manual endpoint entry, same
  idempotent identity.
- **Profile-fetch resilience (task 4/5/8, `relay/IngressProfileProvisioner.kt`)**:
  gained an additive nullable `diagnosticsRecorder: SupportDiagnosticsRecorder?`
  (wired from the SAME recorder instance `MainViewModel.Factory.create`
  already builds for B29, via `RelayCompositionFactory.build`'s new
  optional param - never a second, independently-constructed recorder).
  `provision()` now records `PROFILE_FETCH_STARTED`/`_FAILED`/`_SUCCEEDED`,
  classifying every existing outcome branch (Unauthorized/Revoked/Expired/
  DeviceNotBound/ServiceUnavailable/MalformedResponse/NetworkError, plus
  the three pre-existing pinned-fact mismatch checks - ingress id/host+port/
  ingress-kind - now tagged `TRUST_VALIDATION_REJECTED`) through
  `ControlPlaneFailureReason`, never inventing new persistence/network
  behavior. `ensureFreshProfile`'s pre-existing `stillGood` branch (a
  still-valid, unexpired, pinned-fact-matching stored profile, reused with
  ZERO network calls) now also records `OFFLINE_STATE_REUSED` - task 5's
  real, already-existing offline-resilience point, not new logic.
- **Diagnostics integration (task 8, `diagnostics/support/DiagnosticTypes.kt`/
  `SupportDiagnosticsRecorder.kt`/`DiagnosticFailureMapping.kt`)**: ten new
  `DiagnosticEventType` values (`ACTIVATION_STARTED`/`CONTROL_ORIGIN_ATTEMPT`/
  `CONTROL_ORIGIN_FAILED`/`CONTROL_ORIGIN_SUCCEEDED`/`ACTIVATION_SUCCEEDED`/
  `ACTIVATION_FAILED`/`PROFILE_FETCH_STARTED`/`PROFILE_FETCH_FAILED`/
  `PROFILE_FETCH_SUCCEEDED`/`OFFLINE_STATE_REUSED`) and eight new
  `DiagnosticFailureReason` values (the `CONTROL_PLANE_*` finer-grained
  set, mapped 1:1 from `ControlPlaneFailureReason` via
  `mapControlPlaneFailureReasonToFailureReason`). Every new `record*`
  function takes only closed enums/ints - `ProductionGatewayId`, an origin
  ORDINAL INDEX (never the origin's own host), `ControlPlaneFailureReason` -
  continuing B29's structural "zero raw String parameters on any `record*`
  function" invariant (DiagnosticTypesTest's reflection check covers these
  automatically, no exception added). `PROFILE_FETCH_*`/`OFFLINE_STATE_REUSED`
  intentionally carry no gateway/endpoint tag at all - they are shared by
  both `ProductionGatewayId`-scoped (activation-time Xray/TLS) and
  `EndpointId`-scoped (ingress) callers, and no single closed identity model
  fits both without misrepresenting one of them.
- **Tests**: `TrustedOriginRequestExecutorTest` (primary-fails/secondary-
  succeeds, timeout fallthrough, TLS-failure fallthrough, untrusted-redirect
  rejection, bounded attempt count, authorization-rejection stops early,
  per-origin independence, empty-origin-list rejected), `ControlPlaneOriginTest`
  (origins only ever come from `ProductionGatewayCatalog`, never leak a
  different gateway's host, exception/message classification),
  `ActivationResilienceCoordinatorTest` (primary-fails/secondary-succeeds,
  all-origins-exhausted, authorization-rejection is terminal, already-valid
  short-circuits with zero network calls, Retry reuses the same public
  key/credential - never a new logical identity, diagnostics carry typed
  origin-attempt results but no host/IP/URL/credential/UUID),
  `ActivationFailureMessageTest` (every failure variant collapses to the
  required non-technical sentence, `classifyProvisioningResultFailure`'s
  own exhaustive mapping), `IngressProfileProvisionerTest` additions
  (offline reuse records `OFFLINE_STATE_REUSED` with zero network calls, a
  malformed response is never persisted, a pinned-fact mismatch is recorded
  as `CONTROL_PLANE_TRUST_REJECTED` and never persisted, a successful fetch
  carries no host/UUID/token in any diagnostic tag, an expired profile whose
  refresh itself then fails closes rather than silently extending the stale
  profile), and one new `MainViewModelTest` case (an already-activated user,
  `GatewayConfiguration.Configured`, connects successfully while a REAL,
  wired manifest-refresh control-plane call is failing - proving requirement
  5 against genuine failure, not merely an omitted collaborator). All new +
  full existing suite green (1180 total tests, one pre-existing failure
  unrelated to this slice - `EffectiveConfigDiffTest` needs a gitignored,
  developer-local `gateway-dev.properties` this sandbox does not have);
  `compileDebugKotlin`/`assembleDebug` green. No gateway/Python code
  touched this slice (server-side idempotent activation, confirmed via
  `gateway/api/activations.py`'s existing credential-digest locking, was
  sufficient - no server change needed).
- **Not done this slice**: production `ProductionGatewayCatalog`/signed
  manifest data currently carries only one physical origin per gateway
  (audited, see this section's "PR #44 review fix" note - Germany and
  Stockholm are confirmed NOT interchangeable activation backends, and no
  alternate edge/host exists for either one's own control plane), so even
  though `activateDevice` now genuinely routes through
  `ActivationResilienceCoordinator`, real production traffic cannot yet
  exercise cross-HOST fallback - the executor's own N-origin capability is
  proven correct through the real `activateDevice()` code path via an
  injected test seam (`controlPlaneOriginsForActivation`), not live
  redundant infrastructure; provisioning a genuine second edge is real
  infrastructure work requiring explicit owner approval, out of scope
  here. `IngressProfileProvisioner` (relay/ingress profile fetch) is not
  routed through the same gateway-scoped executor (see this section's own
  reasoning for why that would misrepresent its `EndpointId`-scoped
  trust). No live-HTTPS integration test proves the redirect lock-down
  against a real 3xx response (no mock HTTPS server in this test setup -
  covered by code-level review plus a unit-level executor test asserting a
  redirect-classified failure is never treated as success); this does NOT
  prove Russia hard-whitelist bypass, which remains UNVERIFIED.

### Multi-Path Activation Discovery (B67.2) - FOUNDATION/PARTIAL, extends B30, no new engine

**SOFTWARE COMPOSITION: DONE. PRODUCTION CHAIN PATH AVAILABILITY: NOT
IMPLEMENTED (no trusted CHAIN_DIRECT/CHAIN_CDN control-plane origin is
deployed or audited). REAL PRODUCTION ACTIVATION: DIRECT-ONLY TODAY.** This
section describes a composition MECHANISM, not a deployed three-path
system - see the callouts below for exactly where the line sits.

`ActivationPathKind` (`DIRECT`/`CHAIN_DIRECT`/`CHAIN_CDN`,
`controlplane/ActivationPathCandidate.kt`) is the ACTIVATION/CONTROL-PLANE
path-shape vocabulary - never conflated with the DATA-PLANE
`PathCandidate.Direct`/`PathCandidate.Relayed` (`reachability/PathCandidate.kt`)
`PathScorer`/`AutoGatewaySelector` already rank; the two answer different
questions ("how does the client reach `/v1/activate`" vs "how does traffic
reach the Internet") and share no type. `ActivationPathCandidateBuilder`'s
PRODUCTION entry point, `forGateway(gatewayId)`, takes no origin/host
parameter at all - it composes an ordered `List<ActivationPathCandidate>`
per gateway purely from `ControlPlaneOriginSetBuilder` (DIRECT, unchanged
B30) and `TrustedChainControlPlaneOriginCatalog.chainDirect`/`chainCdn`
(CHAIN_DIRECT/CHAIN_CDN) - **both return `emptyList()` today: no trusted
HTTP-capable relay/CDN front for the control plane is deployed or audited;
the one real B25/B31 Stockholm ingress relays DATA-PLANE VLESS traffic and
is never reused as a control-plane front.** `forGateway` delegates to a
separate, `internal` (module-visible-only - a compile-time/Kotlin-visibility
mechanism, not a runtime security boundary) `forGatewayFromOrigins`
composition seam, but ONLY ever with origins it already resolved itself from
those trusted production catalogs; `ActivationPathCandidateTest` calls that
same internal seam directly, with synthetic test origins, to exercise the
composition mechanism deterministically. No PRODUCTION caller (i.e.
`forGateway`, the only one that exists) supplies a raw caller-supplied host
to it - MainViewModel only ever calls `forGateway`. Fixed DIRECT->CHAIN_DIRECT->CHAIN_CDN
declaration order, deliberately not a score (no per-gateway `Long` weight,
no `PathScorer` tiering reused) - there is no control-plane-specific
evidence to rank against, so this is the "no useful evidence -> stable
deterministic order" the architecture calls for, not an invented
preference. A path shape with zero trusted origins contributes no
candidate. `ActivationPathOriginSetBuilder.forGateway` flattens those
candidates into the same `List<ControlPlaneOrigin>` shape
`ActivationResilienceCoordinator.activate`'s `origins` parameter already
accepted - the ONE integration seam (`MainViewModel`'s existing
`controlPlaneOriginsForActivation` constructor seam is repointed to it).
`TrustedOriginRequestExecutor`/`ActivationResilienceCoordinator` are
completely unmodified: the flat multi-path origin list already gives
per-origin-once bounded execution in path order, with
`AUTHORIZATION_REJECTED` on any origin (any path shape) terminal for the
whole call - the B30 invariant, unchanged (this part of the mechanism is
real and tested; it is simply exercised today with exactly one trusted
origin, since that is all that exists in production). Since both chain
catalogs are empty in production, `ActivationPathOriginSetBuilder.forGateway`
is byte-for-byte `ControlPlaneOriginSetBuilder.forGateway` today; **real
activation traffic remains DIRECT-only** until ops deploys and audits a
trusted CHAIN_DIRECT/CHAIN_CDN control-plane origin - that deployment/audit
work is explicitly NOT part of this slice. `ActivationPathCandidateTest`'s
15 deterministic tests (synthetic trusted origins via the internal test
seam) prove the composition/fallback mechanism works correctly once such
origins exist; they are not evidence that any do. See `docs/ROADMAP.md`'s
B67.2 row for the full test list and status wording.
