# Real Ingress Runtime / Server-Side Relay Execution Foundation (B24) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Turns B23's relay CANDIDATE model into a real execution contract on both
sides - client execution wiring AND a real server-side ingress runtime -
still **FOUNDATION**, not IMPLEMENTED: no real RU ingress is deployed, so
none of this has been physically exercised end to end. **Russia
hard-whitelist bypass remains UNVERIFIED** until tested on an actually
restricted Russian network.

**Real supported relay transport matrix** - client<->ingress and
ingress<->exit are INDEPENDENT (never collapsed to one shared
`TransportKind` - B23's own PR #37 fix, reused verbatim here):

| Client -> INGRESS | INGRESS -> EXIT | Status |
|---|---|---|
| XRAY_REALITY | XRAY_REALITY or TLS_TCP | server config real (`xray_ingress_config_renderer`), client dial not provisioned |
| TLS_TCP | XRAY_REALITY or TLS_TCP | server config real, client dial not provisioned |
| AMNEZIA_WG (client<->ingress) | any | capability-not-implemented this slice - AWG upstream chaining was not attempted (task's own "if AWG upstream is significantly harder to implement safely, do not fake it") |

**Client execution wiring** (`android/.../relay/RelayExecution.kt`,
`smartconnect/AutoGatewaySelector.kt`, `MainViewModel.kt`):

- `RelayedExecutionPlan` - the real, immutable per-attempt contract, built
  ONLY via `.from(RelayAttemptCandidate)` - copies `ingressEndpointId`/
  `ingressBinding`/`ingressTransport`/`exitEndpointId`/`exitBinding`/
  `exitTransport`/`historyPathId` straight off the already-ranked
  candidate, never re-resolving from the manifest/catalog mid-attempt (task
  requirement 2).
- `RelayReadinessStage` (`INGRESS_REACHABLE`/`INGRESS_HANDSHAKE_OK`/
  `UPSTREAM_EXIT_HANDSHAKE_OK`/`END_TO_END_DATA_PLANE_OK`) and
  `RelayFailureCategory` (`INGRESS_UNREACHABLE`/`INGRESS_HANDSHAKE_FAILED`/
  `UPSTREAM_EXIT_UNREACHABLE`/`UPSTREAM_EXIT_HANDSHAKE_FAILED`/
  `RELAY_AUTH_FAILED`/`END_TO_END_DATA_PLANE_FAILED`/
  `EXECUTION_NOT_IMPLEMENTED`) are the typed vocabulary task requirements
  10/12 asked for. `RelayAttemptOutcome.Success` is constructible ONLY at
  `END_TO_END_DATA_PLANE_OK` - fail-closed by TYPE CONSTRUCTION (a `Failure`
  literally cannot claim that stage - `init{}` enforces it), not by
  convention.
- **`RelayIngressResolver` - a PREPARATION boundary, never a second VPN
  execution/state owner (PR #38 review fix, round 3).** An earlier version
  of this had `RelayIngressDialer.dial()` itself return the TERMINAL
  attempt outcome (including a `Success` case) - meaning a real
  implementation would have had to independently drive a tunnel to
  `END_TO_END_DATA_PLANE_OK` and report back, becoming a SECOND VPN
  execution authority beside `TransportOrchestrator`/`VpnController`/the
  real `VpnService` (violating "one Android VpnService owner, no second
  connection controller"). Fixed before any real implementation was built
  on the wrong seam: `RelayIngressResolver.resolve(plan)` now returns a
  `RelayIngressResolution` - either `Resolved(transport, kind)` (a real,
  already-constructed `VpnTransport` for the client<->ingress hop, reusing
  the EXISTING Xray transport/service stack - task requirement 4/7, never a
  bespoke networking path) or `NotProvisioned(category, detail)` (no real
  credential exists to prepare one). `RelayIngressResolution` carries NO
  state of its own - existing purely as data, never starting anything.
  `MainViewModel.attemptRelayedAttempt` is what feeds a `Resolved` result
  into the SAME `TransportOrchestrator.resolve`/`VpnController.connect`/
  `PendingFailoverAttempt`/`armFailoverWatch` path a Direct candidate
  already goes through - a fresh per-attempt `TransportRegistry` naming
  only the resolved transport/kind, exactly mirroring how Direct already
  builds a fresh registry per candidate. `PendingFailoverAttempt.relayPlan`
  (non-null only for a relayed attempt) lets `armFailoverWatch`'s SAME real
  `controller.state` observation - never this attempt's own belief, never
  a resolver return value - govern both what gets recorded and whether the
  combined sequence advances (task requirement 8). Critically: even when
  `controller.state` genuinely reaches `TransportState.Connected` for the
  resolved ingress transport (a REAL handshake, not faked), this branch
  NEVER constructs `RelayAttemptOutcome.Success` - a client<->ingress
  handshake alone only proves `RelayReadinessStage.INGRESS_HANDSHAKE_OK`,
  never `UPSTREAM_EXIT_HANDSHAKE_OK`/`END_TO_END_DATA_PLANE_OK` (no
  server-side upstream readiness signal channel exists yet - see that
  enum's own docs), so it is recorded as a `Failure` instead, every time,
  by construction (`RelayAttemptOutcome.Failure` cannot even represent
  `END_TO_END_DATA_PLANE_OK` - its own `init{}` forbids it).
  `NotProvisionedRelayIngressResolver` is the ONLY implementation wired
  into production today: it reports `NotProvisioned(EXECUTION_NOT_IMPLEMENTED)`
  for every plan, honestly, because preparing a real ingress transport over
  XRAY_REALITY/TLS_TCP needs a real per-ingress-provisioned Xray client
  profile that cannot exist without a real ingress and a real per-device
  activation against it (out of scope - "no new infrastructure"). **Known,
  named remaining gap** (explicitly not closed by this fix, since closing
  it would mean redesigning shared, Direct-affecting `VpnController`/UI
  code well beyond this task's narrow scope): `VpnController`'s OWN
  pre-existing generic `recordPathHistory` also fires for a resolved
  relay's `controller.connect()` call, writing a real but SEPARATE,
  single-hop record keyed by the bare ingress endpoint id (never the
  composite `historyPathId` relay scoring actually reads - harmless to
  scoring, but see `MainViewModelRelayAttemptTest`'s own note). More
  importantly, `TransportState.Connected` still drives the generic
  `"Protected"` UI text application-wide (`ProductFlowPresentation
  .toHomeStatusText`) with no awareness that an attempt was relayed - so a
  FUTURE real `RelayIngressResolver` reaching genuine ingress-handshake
  `Connected` would show "Protected" in the UI even though this codebase's
  own relay-outcome bookkeeping correctly refuses to call it healthy. Since
  `NotProvisionedRelayIngressResolver` never reaches that branch, this has
  no production impact today - but a future slice wiring a real resolver
  MUST also teach `VpnController`/the UI layer to distinguish a relayed
  attempt before claiming "Protected" for one.
- `AutoGatewaySelector.AutoConnectAttempt` (sealed `DirectAttempt`/
  `RelayedAttempt`) + `buildCombinedAttempts`/`nextCombinedAttempt` - ONE
  combined, real, ranked attempt list built from `buildCandidates` +
  `buildRelayedCandidates` together (task requirement 4), sharing ONE
  `MAX_ATTEMPTS` budget across both types. `MainViewModel.connectAuto()`
  picks its winner from this combined list via `attemptCombined` - the ONE
  bounded-progression authority for the whole request. A **Direct** winner
  is DIALED through the completely unchanged `TransportOrchestrator`/
  `VpnController`/`PendingFailoverAttempt` machinery - the same pinned
  `GatewayAttemptCandidate.configSnapshot`, the same AWG->Xray intra-gateway
  failover, byte-for-byte (task requirement 7/8: no duplicated Direct
  execution logic, no second connection controller). A **Relayed** winner is
  resolved via `attemptRelayedAttempt`/`relayIngressResolver`, and on
  `Resolved` is ALSO dialed through that SAME `TransportOrchestrator`/
  `VpnController` path (see the `RelayIngressResolver` bullet above); its
  outcome is recorded under the FULL `historyPathId` (task requirement 11 -
  never poisons either hop's own Direct history). **PR #38 review fix**: on
  EITHER shape's terminal failure - `attemptAutoCandidate`'s own
  `NotSelectable` branch, `armFailoverWatch`'s async observation of a real
  Direct OR relayed failure, or `attemptRelayedAttempt`'s own
  `NotProvisioned`/`NotSelectable` branches - control returns to
  `attemptCombined` with the SAME `(attempts, attemptedKeys)` state, so the
  VERY NEXT globally-ranked unattempted candidate is chosen regardless of
  shape. An earlier version of this row wrongly had a Direct winner
  delegate to a REORDERED DIRECT-ONLY LIST that then owned the rest of the
  Direct sub-sequence on its own - silently skipping any higher-ranked
  Relayed candidate ranked in between, and defeating the shared
  `MAX_ATTEMPTS` budget the row already (incorrectly) claimed. Fixed before
  merge, never shipped to `main`: `PendingAutoGatewayContext` now carries
  the combined `(attempts, attemptedKeys)` shape instead of a Direct-only
  one, and `attemptAutoCandidate` takes exactly ONE candidate to dial (never
  a list to "own"). One candidate consumes exactly one combined attempt
  slot, added to `attemptedKeys` the moment `attemptCombined` chooses it -
  never re-chosen. `AutoGatewayDiagnostics` itself stays Direct-only (its
  existing public shape is unchanged - every pre-B24 reader is unaffected);
  a Relayed attempt is currently reflected there only via
  `lastFailureReason` once it
  fails.

**Server-side ingress runtime** (`gateway/api/xray_ingress_config_renderer.py`)
- reuses the EXISTING Xray server machinery (task requirement 7 - no new
daemon, no sing-box/Hysteria):

- Client-facing inbound rendering (REALITY/TLS) and client authorization
  are the SAME functions `xray_config_renderer` already uses for a real
  gateway (`_active_clients`/`_render_reality_inbound`/`_render_tls_inbound`,
  imported and called verbatim, never duplicated) - an ingress has NO
  second/parallel identity system (task requirement 8); a revoked/expired
  activation is excluded here exactly as it already is for a real gateway.
- The genuinely NEW piece is the OUTBOUND: instead of `freedom` (what every
  existing gateway config renders - direct to the open Internet), the
  ingress's outbound is a real, authenticated VLESS connection
  (`UpstreamExitConfig` - REALITY or TLS, independently chosen from the
  client-facing inbound's own transport) to the pinned EXIT, carrying its
  own dedicated relay UUID credential (task requirement 9 - "do not assume
  source IP == trusted ingress"; never a shared/global plaintext
  credential, never committed to this repository - always caller-supplied
  at render time). Routing rules bind EVERY client-facing inbound
  EXCLUSIVELY to that one upstream outbound, and no `direct`/`freedom`
  outbound exists in the rendered config AT ALL - an ingress rendered this
  way is structurally incapable of becoming an open relay or the public
  Internet exit by accident (task requirement 6/L), not merely by
  convention. `render_ingress_server_config_redacted` never serializes the
  ingress's own REALITY private key or the upstream relay UUID (task
  requirement 9/M).
- Malformed upstream inputs (bad UUID, blank host, unsupported transport,
  malformed REALITY key/short-id) fail closed with `IngressConfigRenderError`
  rather than rendering a config that would silently misroute.
- **Not done this slice**: no systemd unit/deployment script for an ingress
  role (`gateway/systemd/nova-xray.service` is EXIT-shaped only), no
  ingress-specific provisioning/activation HTTP endpoint, no reload
  wiring. These are genuinely deployment/control-plane concerns that
  require an actual ingress host to design against meaningfully - adding
  them now, untested against a real host, would risk exactly the kind of
  premature/undemonstrated infrastructure this task explicitly warns
  against.

**Ingress role**: `IngressKind.DIRECT_IP` has the real runtime path above
(a plain host:port the client dials directly). `IngressKind.CDN_FRONTED`
remains typed-but-FOUNDATION - no legitimate operator-controlled CDN was
available to validate against this slice, and this codebase's own
principle 3 forbids ever impersonating a named third-party service to fake
one.
