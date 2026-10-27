# B-WL1/B-WL5 behavior-evidence pipeline (2026-09-27, IMPLEMENTED)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Real code, not a proposal - implements the pipeline this file's Reachability/
Smart Connect section already names as fixed and unmodified by this addition:
`NetworkProfiler -> RestrictionClassifier -> ReachabilityEngine ->
PathCandidateBuilder/PathScorer -> SmartConnectDecisionEngine/
AutoGatewaySelector -> TransportOrchestrator`. This slice's new code enters
at exactly two points in that fixed order - `RestrictionClassifier` (already
the sole classification authority) and `PathScorer` (already the sole
scoring authority) - and nowhere else; `ReachabilityEngine`,
`SmartConnectDecisionEngine`, `AutoGatewaySelector`, `TransportOrchestrator`,
and `RoutingDecisionEngine` are byte-for-byte unmodified.

- **`smartconnect/TransportBehaviorEvidence.kt`** - `TransportAttemptObservation`
  (closed, non-secret: transport protocol, connect/handshake stage outcomes,
  byte counts, `TrafficProgressOutcome`, `AttemptTermination`, an opaque
  `destinationKey` - never a host/IP/UUID/key) and `TransportBehaviorAnalyzer`
  (pure, deterministic: turns a list of these into ONE `TransportBehaviorPattern`
  plus a reused `RestrictionEvidenceQuality`). No byte-count threshold exists
  anywhere in this object - "early drop" requires connect+handshake+payload
  progression followed by a stall with no reset, never a raw byte count; a
  stall reset by the peer (RST) is never treated as early-drop evidence; a
  stall on one destination while another sustains progress is reported as
  `INSUFFICIENT`, never generalized to a network-wide claim.
- **`smartconnect/TransportObservationStore.kt`** - process-local, in-memory
  only (deliberately never persisted - this evidence is already bounded by
  `RestrictionClassifier`'s own staleness window), keyed by the SAME opaque
  network-fingerprint string `PathHistoryStore` already uses (never a second
  network-identity system), bounded in total capacity across every network
  combined (oldest evicted first). Reading one network's key never returns
  another network's observations.
- **`RestrictionClassifier` extension** - `RestrictionEvidence.transportObservations`
  (new, empty-by-default field) feeds `TransportBehaviorAnalyzer.assess()`
  through the SAME `nowEpochMillis`/`staleAfterMillis` staleness window every
  other signal already uses. The priority chain (`decide()`, replacing the
  old `classify()` body without changing its public signature) slots
  behavior-derived branches in at points strictly more specific than the
  existing probe-derived rules, and NEVER weakens the existing
  `POSSIBLE_HARD_WHITELIST` rule - that rule's original route (gateway
  unreachable via both protocols AND a diverse-majority failure) is
  untouched; a NEW additional route to the SAME class exists
  (`ALL_CONNECT_FAILED` behavior pattern plus the SAME diverse-reachability-
  failure evidence), never a shortcut from behavior evidence alone.
- **`PathScorer` extension** - `restrictionPreference()` (replacing the old
  `restrictionRank()`, same call site) now also reads the candidate's real
  `TransportCapabilities` for `POSSIBLE_UDP_FILTERING` (penalize
  UDP-only, favor a TCP transport declared `suitableForRestrictiveNetworks`)
  and `POSSIBLE_EARLY_DROP` (favor relay, penalize a plain direct TCP
  transport) - the returned rank stays strictly in `[-1, 1]` for every
  branch, so `RESTRICTION_TIER`'s existing tier-algebra proof is unaffected.
  `POSSIBLE_HARD_WHITELIST`'s existing relay/direct preference, and the
  existing zero-preference for `POSSIBLE_UDP_OR_AWG_FILTERING`/
  `POSSIBLE_FULL_SHUTDOWN`, are unchanged.
- **`VpnController` production wiring, precisely bounded** - a new optional
  `transportObservationStore` collaborator (additive, defaults to `null`,
  same seam as `pathHistoryStore`/`connectionOutcomeStore`) is written from
  the SAME authoritative connect-outcome call sites `recordPathHistory`
  already uses - never an independently-timed writer. A FAILED attempt
  (`recordTransportBehaviorObservation`) can only honestly confirm/deny a
  FRESH HANDSHAKE, so `connect`/`handshake` stage outcomes are recorded as
  `NOT_OBSERVED`/`FAILED` (never `connect=FAILED` - this app cannot separate
  the socket-connect step from the handshake step); `TransportBehaviorAnalyzer
  .failedBeforePayload()`'s TCP predicate accepts either shape as "failed
  before payload," so this genuine evidence still reaches `ALL_CONNECT_FAILED`.
  A SUCCESSFUL AmneziaWG attempt instead goes to `launchLiveProgressObservation`
  (below), which can actually sample real progress before its own, richer
  write. Protocol (`TransportAttemptProtocol.TCP`/`UDP`) is decided from the
  active transport's real `TransportCapabilities.usesUdp`, never a hardcoded
  `TransportKind` branch. `MainViewModel.restrictionClass()` reads this SAME
  store, scoped by the SAME network fingerprint `recordPathHistory` computes,
  and passes it into `RestrictionEvidence.transportObservations`.
- **`smartconnect/TrafficProgressMonitor.kt`** - a pure `evaluate()` judging
  `VERIFIED`/`STALLED_AFTER_INITIAL_PAYLOAD`/`NO_PAYLOAD`/`IDLE`/
  `UNAVAILABLE`/`VERIFYING` from bounded time windows over the EXISTING
  `TransportStats.Counters` type (no new stats type). **Wired into
  `VpnController`'s live session lifecycle via `launchLiveProgressObservation`**:
  called once, right after a real fresh AmneziaWG handshake, it samples
  `activeTransport.stats()` at the SAME poll cadence `awaitFreshHandshake`
  already uses (no second polling cadence, no new coroutine framework),
  feeding each sample to `evaluate()` and stopping the instant a decisive
  verdict is reached or the bounded `verificationWindowMillis +
  stallWindowMillis` window elapses - always terminates, never loops
  indefinitely. It writes exactly ONE `TransportAttemptObservation` per
  attempt (tracked in `progressObservationJob`, cancelled under the SAME
  `reconnectOwnershipLock`/generation discipline `reconnectJob` already uses,
  so a superseded attempt can never record stale evidence). A
  transport whose `dataPlaneCounters()` reports no real counters is
  recorded `NOT_OBSERVED` on the very first poll (AWG caller) or not at all
  (state-driven caller, see below), never a fabricated claim.
- **AWG dead-data-plane gate (2026-10-09, RU field test `CONNECTED_NO_DATA`)**:
  the one exception to "observation only". After recording, a decisive
  `NO_PAYLOAD` or `STALLED_AFTER_INITIAL_PAYLOAD` verdict makes
  `VpnController.failDeadDataPlane` end THAT session (only if it is still
  Connected on the same transport; the job detaches from
  `progressObservationJob` first so its own teardown cannot cancel it) via
  the same teardown as `abandonAttemptWithTerminalError`, recording
  `VpnError.DataPlaneNoTraffic` and `TransportState.Error(failureKind =
  REMOTE_UNCONFIRMED)`. It acts at most once, within the first ~30 s after
  the handshake; it never reconnects and never re-checks later. The
  existing failover watches do the rest: `AutoGatewayFailoverPolicy` advances
  Auto to the next candidate and `AwgXrayFailoverPolicy` falls back
  AWG->Xray (Manual gateway, Auto transport). VERIFIED/IDLE/UNAVAILABLE/
  still-VERIFYING leave the session alone; a healthy AWG session was held 45 s
  on the OPPO without teardown. B33's Xray confirmation and relay watchdog
  are unchanged.
- **Direct Xray uses the same gate (2026-10-09)**: the sampler reads
  `VpnTransport.dataPlaneCounters()`, never `stats()` - `stats()` Counters
  also drive `awaitFreshHandshake` (connect and reconnect), and Xray has
  byte counts but no handshake timestamp, so it must stay `Unsupported`
  there. AWG's `dataPlaneCounters()` is its `stats()`; REALITY/TLS/XHTTP
  return the `:xray` core's VLESS-outbound uplink (sent) / downlink
  (received) totals: the renderer enables `stats` + `policy.system.
  statsOutbound{Uplink,Downlink}`, xray-core counts AFTER TLS/REALITY/XHTTP
  security (no handshake or ACK bytes), and `NovaXrayVpnService` sums the
  resetting `queryAllOutboundTrafficStats()` readings per Started session
  (`XrayTrafficCounters`). Started from `recordStateDrivenOutcome` on a
  Direct non-AWG attempt's first Connected (after B33), so relayed attempts
  keep only the relay watchdog. No answer / another session / no Started
  mirror = `Unavailable` (no sample); a transport without counts
  (`Unsupported`) breaks at once and, for this caller, records no observation.
  Manual pinned Xray ends in Error with no substitute; Auto advances.
  Device (OPPO, 2026-10-09): healthy REALITY (11 runs) and TLS (1 run)
  sessions reached `VERIFIED` with rx/tx growing both ways and were never
  torn down; the teardown path is unit-tested only. Known limitation M1:
  the counters cannot tell an upload awaiting a delayed reply from a dead
  exit, so such a healthy Direct Xray session can be ended with
  `DataPlaneNoTraffic` (decision-logic behavior; frequency unknown; not
  reproduced on a device; see ROADMAP). P2 mitigation: the policy is chosen
  by the sampled transport's kind (`TrafficProgressPolicy.forTransport`) -
  Xray family stall window 65 s, AWG/others 20 s, verification 10 s for
  all; this only narrows M1, it does not resolve it. F1: before acting on
  NO_PAYLOAD/STALLED the gate asks `VpnTransport.probeIndependentEgress()`
  once (10 s caller bound) for the other catalog gateway's
  `/v1/tunnel-probe` through this session's core; REACHED (probe endpoint
  only, not general connectivity) restarts from a post-probe sample and
  extends the window once by one stall window, so a later stall still ends
  the session and a later IDLE keeps it; the gate stays one-shot. Separate: before the
  death-time Failed above, an unexpected `:xray` death was reported only
  after `DEATH_GRACE_MS` (~2.3 s measured) with the UI still Protected
  while the VPN network was gone. Packets leaving the device in that window
  were NOT measured; without Always-on + lockdown Android does not block
  them, and no app change can.
- **What this means for real production evidence, stated precisely**:
  `POSSIBLE_FULL_SHUTDOWN` (all-transports-connect-failed) and a
  connect-level `POSSIBLE_UDP_FILTERING` (AWG handshake fails while another
  transport's handshake succeeds) ARE reachable from real production
  evidence for every transport kind. `POSSIBLE_EARLY_DROP` and a
  payload-aware `POSSIBLE_UDP_FILTERING` ARE now reachable from real
  AmneziaWG production evidence (the live `TrafficProgressMonitor` wiring
  above); every other transport kind's evidence stays connect/handshake-level
  only until it exposes real `TransportStats.Counters`. No physical
  restricted-network/Russia validation of any of this exists yet.
- **Tests**: `TransportBehaviorAnalyzerTest`, `TransportObservationStoreTest`,
  `TrafficProgressMonitorTest`, plus `RestrictionClassifierTest` (new
  classes, corroboration, staleness, contradiction, the closed-field-set
  proof updated for the new field), `PathScorerTest` (capability-based
  preference, no-preference cases for unchanged classes),
  `VpnControllerTransportObservationTest` (records exactly one observation
  per authoritative outcome, network-scoped, no-op when unwired), and the
  new `VpnControllerLiveProgressObservationTest` (real-counter sampling ->
  `SUSTAINED`/`STALLED_AFTER_INITIAL_PAYLOAD`/`NOT_OBSERVED` verdicts,
  no-counter transports short-circuit to `NOT_OBSERVED` without waiting out
  the bounded window, capability-driven protocol mapping, and a superseded
  attempt's sampler never records stale/duplicate evidence). No Android
  Gradle/JVM test run was performed in this pass - see `docs/ROADMAP.md`'s
  B-WL row for why (pre-existing environment limitation, reproduces
  identically on unmodified `main`).
