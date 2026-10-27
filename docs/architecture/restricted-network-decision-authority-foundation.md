# Restricted-Network Decision Authority (B28) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Architecture principle: `RestrictionClass` (B18/B23) becomes decision-driving
for the first time - real restriction evidence now influences automatic
DIRECT vs RELAY path ranking, without a second decision authority, without
country/provider hardcoding, and without physically validating a real
restrictive network. No deployment, no device dependency. **Russia
hard-whitelist bypass remains UNVERIFIED** - nothing in this slice proves a
real fixed-allowlist network actually gets bypassed; it proves the scoring
fabric would PREFER a reachable relay over a direct path once such evidence
exists.

- **Where the decision is made (single authority, requirement 7)**:
  `PathScorer.score` (`reachability/PathScorer.kt`) gains ONE new tier,
  `RESTRICTION_TIER = 700`, sandwiched strictly between `HISTORY_TIER=1000`
  and `MATURITY_TIER=200` (tier-algebra re-verified in the class doc comment
  for all five tiers). `AutoGatewaySelector` and `MainViewModel` are
  UNCHANGED - the restriction value is read directly off data ALREADY
  present on `candidate.hops[0].reachability.evidence.restrictionClass`
  (every hop of one candidate carries the SAME class, since
  `MainViewModel.restrictionClass()` computes it once per read and threads
  it into every `ReachabilityEngine.assess` call for that read). No second
  selector, no new parameter threading through `AutoGatewaySelector`.
- **The exact rule (requirements 1-3)**: `restrictionRank(candidate,
  restrictionClass)` is nonzero ONLY for `RestrictionClass
  .POSSIBLE_HARD_WHITELIST` - every other class (`UNKNOWN`,
  `NO_RESTRICTION_OBSERVED`, `POSSIBLE_UDP_OR_AWG_FILTERING`, etc.)
  contributes exactly 0, so ordinary healthy-direct behavior under
  NORMAL/UNKNOWN evidence is byte-for-byte unaffected (requirement 1).
  Under `POSSIBLE_HARD_WHITELIST`: `+1` (bonus) for `PathCandidate.Relayed`,
  `-1` (penalty) for `PathCandidate.Direct` - symmetric, so the same
  tier-width proof covers both directions. The bonus depends only on
  candidate TYPE, never on `IngressKind` - `DIRECT_IP` and `CDN_FRONTED`
  relayed candidates get the IDENTICAL +1, so neither ingress kind is ever
  globally preferred; their relative order among themselves is still
  decided entirely by the higher `REACHABILITY_TIER`/`HEALTH_TIER`/
  `HISTORY_TIER` (requirement 3). `POSSIBLE_UDP_OR_AWG_FILTERING` gets NO
  dedicated branch (requirement 2) - it is itself derived from a real
  `awgHandshakeFresh == false` `ConnectionOutcome`, which already penalizes
  `AMNEZIA_WG` via the pre-existing `HEALTH_TIER`
  (`TransportHealthCalculator`); a second protocol-specific branch here
  would be exactly the redundant nested if/else the task asked not to add.
- **Eligibility is untouched (requirement 4)**: `PathScorer.isEligible`/
  `ineligibilityReason` gained ZERO new logic. Restriction only affects
  SCORE among already-eligible candidates - a relay candidate that is
  ineligible (fresh `ReachabilityState.UNREACHABLE`, no valid
  `IngressClientProfile`, transport not implemented) can never be promoted
  by the restriction bonus, structurally, not by a runtime check.
- **Evidence stays distinct (requirement 5)**: endpoint reachability
  (`ReachabilityEngine`/`ReachabilityState`), transport handshake/health
  (`TransportHealth`/`TransportHealthCalculator`), real end-to-end proof
  (B25/B26's `RelayReadinessStage`/`END_TO_END_DATA_PLANE_OK`), and
  restriction classification (`RestrictionClass`) remain four SEPARATE
  fields feeding four SEPARATE `PathScorer` tiers - never collapsed into one
  boolean. `RestrictionClassifier.classify` itself is unchanged in its own
  evidence-only discipline (still conservative, still never infers a
  country/operator claim - see the enum's own doc comment, unchanged since
  B18).
- **Hysteresis/TTL (requirement 8)**: `RestrictionMonitor` now stamps
  `lastProbeEpochMillis`/`lastDiverseReachabilityEpochMillis` (real wall
  clock via an injectable `nowProvider`, defaulting to
  `System::currentTimeMillis`) alongside its existing
  `lastProbeResult`/`lastDiverseReachabilityResult` StateFlows - still
  triggered ONLY by a real transport-state/network-type transition, never a
  timer (unchanged B8J discipline). `RestrictionEvidence` gained two
  matching optional fields, `gatewayProbeEpochMillis`/
  `diverseProbeEpochMillis` (both default `null`). `RestrictionClassifier
  .classify` gained `nowEpochMillis`/`staleAfterMillis` parameters (default
  `Long.MAX_VALUE`/`DEFAULT_STALE_AFTER_MILLIS = 30 * 60 * 1000L`, the SAME
  window `ReachabilityEngine` already uses) and a private `freshOrTrusted`
  helper: once a probe's own timestamp is older than `staleAfterMillis` (or
  future-dated - the same clock-skew guard `ReachabilityEngine.assess`
  already applies), that probe's value is treated as unknown (null) rather
  than trusted indefinitely, decaying `POSSIBLE_HARD_WHITELIST`/
  `POSSIBLE_UDP_OR_AWG_FILTERING` back toward `UNKNOWN`/
  `GATEWAY_HTTPS_UNREACHABLE` once its own evidence has expired. Backward
  compatible by design: an UNDATED value (no timestamp supplied - every
  pre-B28 caller) is legacy-trusted as-is, never treated as immediately
  stale, so no existing call site's classification changed.
  `MainViewModel.restrictionClass()` now passes the real `now` and both
  probe timestamps into `classify()` in production.
- **B26/B27 guarantees preserved (requirement 9)**: `AutoGatewaySelector`,
  `PathCandidate`, `RelayIngressResolverImpl`, `IngressProfileProvisioner`,
  and every activation/pause/resume/atomic-claim mechanism in
  `MainViewModel` are UNTOUCHED by this slice - restriction scoring is
  orthogonal to (runs strictly before) candidate ranking and pinning; once a
  candidate is selected and activated, restriction evidence has no further
  effect on it. Full `testDebugUnitTest`/`assembleDebug` re-run confirms no
  regression.
- **Diagnostics (requirement 10)**: `MainViewModel.combinedAutoRankingDiagnostics()`
  (new, `CombinedAutoRankingDiagnostics{restrictionClass, ranked:
  List<CombinedAttemptDiagnostic{kind, score, reasons}>}`) maps the
  ALREADY-public, already-ranked `combinedAutoAttempts()` output - never a
  second ranking pass. `kind` is one of `"DIRECT"`/`"CHAIN_DIRECT"`/
  `"CHAIN_CDN"` (derived from `RelayedAttempt.candidate.ingressKind`).
  `reasons` is filtered to the stable `PathScorer.Reason` token vocabulary
  only (`RESTRICTION_FAVORS_RELAY`/`RESTRICTION_PENALIZES_DIRECT` are the
  two new tokens) - no endpoint host/IP, UUID, activation credential, probe
  token, or key ever appears (closed field set, proven by
  `MainViewModelAutoGatewayTest`'s dedicated no-leak test). Deliberately a
  NEW surface, not a change to the existing Direct-only
  `AutoGatewayDiagnostics` (B16), which stays untouched.
- **Not done this slice**: no physical validation on any real restrictive
  network (this remains FOUNDATION-only, exactly like B23/B24/B25's own
  caveats); `RestrictionClass` is still never inferred from country/ASN/
  provider identity anywhere in this codebase; no new UI surface renders
  `combinedAutoRankingDiagnostics()` (diagnostics-only, same boundary as
  every prior diagnostics addition); the gateway/Python control plane is
  completely untouched (this slice is Android/Kotlin reachability-decision
  logic only).

### B28 review fix (PR #42) - correct no-viable-relay semantics + real hysteresis

Two blockers found on first review, both fixed within the SAME single
decision authority (no redesign):

- **Blocker 1 - endpoint reachability must never silently override
  restriction classification.** The original slice let `buildCombinedAttempts`
  offer a Direct attempt whenever ITS OWN endpoint happened to be reachable,
  even while `POSSIBLE_HARD_WHITELIST` was suspected and no eligible relay
  existed - collapsing two distinct evidence layers (requirement 5) back
  into one. Fixed: `AutoGatewaySelector.buildCombinedAttempts` gained a
  `restrictionClass` parameter (threaded from `MainViewModel`'s already-
  computed value, no new evidence source) and ONE inline gate, applied right
  where Direct and Relayed are already merged (still the one existing
  authority, never a second selector): `directAllowed = restrictionClass !=
  POSSIBLE_HARD_WHITELIST || relayed.isNotEmpty()`. When no eligible relay
  exists under `POSSIBLE_HARD_WHITELIST`, EVERY Direct candidate is excluded
  - the combined list becomes empty regardless of how reachable any single
  Direct endpoint's own probe says it is - producing genuine, truthful
  exhaustion rather than a silent fallback. When an eligible relay DOES
  exist, Direct is NOT excluded; it re-enters the same ranked list, where
  `RESTRICTION_TIER` already biases the ranking toward relay (requirement 3's
  "rank normally with relay preference"). A companion pure function,
  `AutoGatewaySelector.isRestrictedNetworkExhaustion(attempts,
  restrictionClass)`, is `true` exactly when this specific gate produced the
  empty result - used ONLY for truthful error labeling, never for
  ranking/eligibility. `MainViewModel.connectAuto()` uses it to report the
  new `VpnError.RestrictedNetworkNoViableRelay` (distinct from the generic
  `NoCandidateAvailable`) and sets `AutoGatewayDiagnostics.lastFailureReason
  = "RestrictedNetworkNoViableRelay"` - both purely presentational, no
  decision logic lives outside `buildCombinedAttempts` itself. Proven by
  `AutoGatewaySelectorTest`'s four new required cases (zero-eligible-relay
  exhaustion excludes Direct entirely; one-eligible-relay lets it execute
  and Direct still participates ranked; UNKNOWN-evidence-zero-relay stays
  ordinary Direct; a reachable Direct across MULTIPLE healthy gateways still
  cannot override the decision with zero relay candidates in the manifest at
  all) and one real end-to-end `MainViewModelAutoGatewayTest` case (a real
  manual handshake failure produces real `POSSIBLE_HARD_WHITELIST` evidence;
  switching to Auto afterward never dials a second candidate and reports
  `RestrictedNetworkNoViableRelay`).
- **Blocker 2 - TTL alone is not hysteresis.** `RestrictionClassifier`'s
  30-minute staleness window (requirement 8's first half) only EXPIRES old
  evidence - it does nothing to stop two back-to-back FRESH, genuinely
  differing probe results from flipping the DIRECT/RELAY ranking on every
  single read (e.g. `HARD_WHITELIST -> UNKNOWN -> HARD_WHITELIST` inside a
  few seconds). Fixed with a new, small, pure, O(1)-state object,
  `smartconnect/RestrictionStabilizer.kt` (option (b) from the task's own
  two choices - a minimum-RESIDENCE hold window, not "N consistent
  observations": a hold window needs only the single most-recent pending
  observation and its own timestamp, never an unbounded observation
  history). `State{establishedClass, establishedAtEpochMillis, pendingClass?,
  pendingSinceEpochMillis?}`; `advance(state, rawClass, now,
  minResidenceMillis = DEFAULT_MIN_RESIDENCE_MILLIS = 90_000L)` is the one
  pure transition function: a raw class differing from `establishedClass`
  only gets PROMOTED once it has been observed continuously (never reverting
  back to `establishedClass` or switching to a THIRD differing class in
  between - either resets its own residency timer) for at least
  `minResidenceMillis`; `RestrictionClass.NO_NETWORK`/`CAPTIVE_PORTAL` are
  exempt entirely (requirement's own "should not be hidden behind long
  hysteresis") and take effect immediately in both directions, entering AND
  leaving. The very FIRST observation any session ever makes is trusted
  immediately too (`initial()`) - hysteresis only guards CHANGES away from an
  already-established value, never an artificial startup delay.
  `MainViewModel` holds the one piece of state this needs
  (`restrictionStabilizerState: RestrictionStabilizer.State?`, its own
  session-scoped var) behind a NEW function, `stabilizedRestrictionClass()`
  - deliberately SEPARATE from the existing `restrictionClass()`, which
  stays the raw, immediate value every pre-B28 consumer (routing's
  `NO_NETWORK` check, `reachabilityDiagnostics()`'s own "OBSERVATIONAL ONLY"
  contract, and existing tests asserting a probe result is reflected right
  after it completes) keeps reading unchanged. ONLY
  `buildCombinedAutoAttempts()` - the one function that actually merges and
  ranks Direct against Relayed, feeding `connectAuto()`'s real execution -
  reads the stabilized value; `buildAutoGatewayCandidates()` (Direct-only,
  no relay comparison ever happens there) keeps reading the raw value.
  Proven by `RestrictionStabilizerTest` (single transient flip absorbed;
  sustained change eventually establishes in both directions - entering AND
  recovering out of `POSSIBLE_HARD_WHITELIST` are bounded by the identical
  window, never permanent; `NO_NETWORK`/`CAPTIVE_PORTAL` stay immediate;
  alternating short-lived evidence never accumulates enough continuous
  residency to oscillate the established value; a custom
  `minResidenceMillis` is honored).
- **Full re-run**: `compileDebugKotlin`/`testDebugUnitTest`/`assembleDebug`
  all green after both fixes, zero regressions across the existing suite.

### B28 review fix #2 (PR #42) - one consistent ranking/diagnostics snapshot

Third and final blocker: `combinedAutoRankingDiagnostics()` could report a
DIFFERENT `RestrictionClass` than the one that actually drove the ranking it
described - it called `combinedAutoAttempts()` (which internally reads
`stabilizedRestrictionClass()`) and then SEPARATELY called the raw
`restrictionClass()` for its own `restrictionClass` field. During
`RestrictionStabilizer`'s ~90s hold window these two reads could genuinely
disagree (e.g. raw already flipped to a new class while the established,
decision-driving class was still pending), producing diagnostics that lied
about why Auto made the decision it made.

Fixed with ONE shared internal snapshot, never a second/independent
recomputation: `buildCombinedAutoAttempts()` (private) is renamed
`buildCombinedAutoRankingSnapshot()` and now returns a private
`CombinedAutoRankingSnapshot{restrictionClass, attempts}` - `stabilizedRestrictionClass()`
is called EXACTLY ONCE inside it, and that SAME value both drives every
hop's `ReachabilityEngine.assess` call feeding `PathScorer`'s ranking AND is
returned alongside the ranked `attempts`. Every consumer of one combined
ranking now projects from this ONE call: `connectAuto()` (execution),
`combinedAutoAttempts()` (public attempt list, `= buildCombinedAutoRankingSnapshot().attempts`),
and `combinedAutoRankingDiagnostics()` (`= buildCombinedAutoRankingSnapshot()`'s
two fields directly). The raw, immediate `restrictionClass()` function
itself is unchanged and stays available separately for routing/observational
use (requirement 3 of the review) - only the COMBINED-RANKING surfaces were
ever at risk of disagreeing, and now cannot.

To make this deterministically testable without a real 90-second sleep, a
narrow test seam was added: `MainViewModel`'s new `nowProvider: () -> Long`
constructor parameter (defaults to `System::currentTimeMillis`, so every
production/existing call site is byte-for-byte unaffected - the exact same
additive-seam pattern `RestrictionMonitor`'s own `nowProvider` already
established in this codebase), used by both `restrictionClass()` and
`stabilizedRestrictionClass()`. Proven by three new
`MainViewModelAutoGatewayTest` cases, exercised through the REAL evidence
pipeline (a real handshake failure produces real `POSSIBLE_HARD_WHITELIST`
evidence; a second real probe round with diverse-reachability now true
produces a genuinely differing `GATEWAY_HTTPS_UNREACHABLE` classification -
substituting for a literal `...->UNKNOWN->...` sequence, which is
structurally unreachable once a real probe has run since
`RestrictionMonitor`'s probe StateFlows never revert to null; that exact
literal sequence is already proven in isolation by `RestrictionStabilizerTest`):
diagnostics reports the ESTABLISHED class (not the transient raw one) while
pending; once sustained past the hold window, diagnostics reports the
promoted class and the `RestrictedNetworkNoViableRelay` failure mode no
longer applies; two immediate back-to-back reads of
`combinedAutoAttempts()`/`combinedAutoRankingDiagnostics()` agree
byte-for-byte.

Full `compileDebugKotlin`/`testDebugUnitTest`/`assembleDebug` re-run green.
