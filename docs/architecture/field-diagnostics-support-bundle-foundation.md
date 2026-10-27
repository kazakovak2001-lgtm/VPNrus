# Field Diagnostics / Support Bundle (B29) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Architecture goal: a connection/support incident produces ONE bounded,
sanitized, structured diagnostic bundle a non-technical tester can export/
share with one tap - captured AUTOMATICALLY during the real connect flow,
never requiring developer mode/ADB/logcat. No deployment, no physical
device required to build/test this slice. **FOUNDATION only** - this has
not been field-tested with a real user/support workflow; it does NOT prove
Russia whitelist bypass, which remains UNVERIFIED.

- **Model (task A/B/C, `diagnostics/support/DiagnosticTypes.kt`)**:
  `DiagnosticSession` (sessionId - a locally-generated opaque UUID grouping
  id, never a device/tunnel identity; started/ended timestamps; app version;
  coarse network facts; `rawRestrictionClass`/`stabilizedRestrictionClass`;
  `routingMode`/`gatewaySelectionMode`; `selectedPathKind`
  (`DIRECT`/`CHAIN_DIRECT`/`CHAIN_CDN`/`PRIVATE`/`NONE` - the SAME three
  relay labels `combinedAutoRankingDiagnostics()` already uses, from B28);
  `selectedTransportKind`; a bounded `events: List<DiagnosticEvent>`
  (`MAX_EVENTS_PER_SESSION = 200`, enforced by the type's own `init{}`);
  `outcome`/`failureReason`) - deliberately carries NO endpoint host/IP,
  only stable enum labels and
  `net.pocvpn.client.reachability.NetworkFingerprinter`'s existing coarse,
  per-install, non-exportable fingerprint id. `DiagnosticEventType` (task
  B's 19 categories, verbatim) is a LABELING vocabulary over this
  codebase's own already-real state (`RestrictionClassifier`/
  `RestrictionStabilizer`, `AutoGatewaySelector`, `VpnSessionHealth`,
  `RelayReadinessStage`, `IngressActivationOutcome`) - never a second,
  independently-driven connection state machine. `DiagnosticFailureReason`
  (task C's 17 categories) is populated by pure mapping functions
  (`diagnostics/support/DiagnosticFailureMapping.kt`:
  `mapVpnErrorToFailureReason`/`mapRelayFailureCategoryToFailureReason`/
  `mapIngressActivationOutcomeToFailureReason`/
  `mapRestrictionClassToFailureReason`) from the EXISTING `VpnError`/
  `RelayFailureCategory`/`IngressActivationOutcome`/`RestrictionClass`
  types - those types are never replaced, only re-labeled for this one
  consumer.
- **Automatic capture (task D, `SupportDiagnosticsRecorder.kt`)**: the ONE
  place a session is assembled. Every `record*`/`finish*` function is
  narrow and typed - EVERY `record*` function has zero raw `String`
  parameters, with no exception (`DiagnosticTypesTest`'s reflection check
  enforces this structurally, not by convention) - so nothing secret-shaped
  can enter `DiagnosticEvent.tags` through this API at all.
  `recordManifestSourceSelected` takes the closed `ManifestSourceKind`
  enum (`LAST_KNOWN_GOOD`/`EMBEDDED_BOOTSTRAP`/`NONE`, mirroring
  `reachability.ManifestSource`'s own two real values plus "no trusted
  manifest") - never a free-text source label (PR #43 review fix; the
  earlier revision passed a raw `String` here and the structural test
  carried a one-method exception for it). Two-tier event
  model: NON-TERMINAL `record*` functions (`recordCandidateAttemptStarted`,
  `recordPathFailed`, `recordControlPlaneFailure`, etc.) append to the
  still-open session - a multi-candidate Auto failover sequence is ONE
  session, ONE timeline, not one session per candidate; TERMINAL
  `finish*` functions (`finishProtected`/`finishFailed`/
  `finishRestrictedNetworkExhaustion`/`finishDisconnected`) close it and
  hand it to the store - idempotent (a second `finish*` call once already
  closed is a safe no-op), so a generic backstop and a precise typed call
  can never double-record or corrupt one session. Wired into
  `MainViewModel` as an additive, nullable constructor param (every
  pre-B29 caller/test unaffected): `connectAuto`/`connectManual`/
  `connectPrivate` each `startSession(...)`; `attemptCombined`'s dispatch
  records `CANDIDATE_ATTEMPT_STARTED` with the real winning attempt's own
  path/transport kind; `attemptRelayedAttempt`/`armFailoverWatch` record
  the real `RELAY_ACTIVATION_REQUIRED`/`RELAY_ACTIVATION_RESULT`/
  `DATA_PLANE_READINESS_RESULT`/`RELAY_END_TO_END_PROOF_RESULT` events at
  their own real call sites (never fabricated); a `sessionHealth`
  collector (the SAME `StateFlow` the UI already reads) is a generic,
  idempotent BACKSTOP that finishes any session a more specific typed call
  did not already finish - guaranteeing no session is ever left open
  forever, without needing every single failure branch in this large
  class individually instrumented. `InMemoryDiagnosticSessionStore`
  (`DiagnosticSessionStore.MAX_RETAINED_SESSIONS = 8`, oldest-first
  eviction) is the bounded ring buffer - no unlimited logging.
- **Decision-snapshot consistency (task G)**: `connectAuto`'s
  `StartContext` is built from the SAME `CombinedAutoRankingSnapshot`
  (B28's own single-read discipline) that decided the ranked attempts -
  `rawRestrictionClass = restrictionClass()`,
  `stabilizedRestrictionClass = snapshot.restrictionClass`, both read
  once, never independently recomputed after the fact.
  `connectManual`/`connectPrivate` report the SAME raw value for both
  fields, honestly - restriction evidence has no decision-driving effect
  on either path (no relay comparison ever happens there), so there is
  only one real decision to report.
- **Sanitization boundary (task E, `DiagnosticSanitizer.kt`)**: TWO
  independent layers. Structural (primary): the recorder's typed API
  cannot accept a raw string in the first place. Pattern-based (defense in
  depth, applied a SECOND time by `buildSupportBundle` over every event
  tag value before serialization): `DiagnosticSanitizer.isSafeValue`
  rejects UUID-shaped strings, long mixed-case Base64 blobs (AWG/Xray/
  REALITY key shape), `Bearer ...` auth headers, PEM blocks,
  `token=`/`secret=`/`credential=`-shaped key-value pairs, URLs with query
  data, and IPv4/IPv6 addresses - `sanitize()` replaces a rejected value
  with a fixed `"[redacted]"` marker (never a partial/truncated echo,
  which could itself leak a prefix). `sessionId` itself is the one
  deliberate exception (task A's own "opaque diagnostic id", meant to be
  visible/copyable, never a secret). Proven by
  `DiagnosticSanitizerTest`/`SupportBundleTest`'s own required security
  test: sentinel secret strings (a UUID credential, a real-shaped AWG key,
  a bearer token, a PEM block, a URL with a secret query param, an
  endpoint IP) constructed deliberately and proven absent from the
  exported JSON.
- **Bundle/export (task H/I/J, `SupportBundle.kt`)**: `buildSupportBundle`
  is the ONE sanitizer/export boundary function; `SupportBundle.toJson()`
  serializes deterministically (every object's keys in a FIXED explicit
  order, tag maps sorted by key - never relying on `org.json.JSONObject`'s
  own iteration order). `MainViewModel.exportSupportBundleJson()`/
  `recentDiagnosticSessions()`/`clearDiagnosticSessions()`/
  `lastConnectionResultSummary()` are the four new accessors. UI:
  `SettingsScreen`'s new "Diagnostics" section shows only a simple,
  human-readable last-result sentence on the normal screen (task I -
  "the tester must not need technical knowledge") with "Export
  diagnostics"/"Clear diagnostics" one tap away; `AppRoot.kt` wires export
  to a real Android `ACTION_SEND` share-sheet intent carrying the
  sanitized JSON - task J's own "explicit user action... do not silently
  transmit diagnostics to a server" - nothing here is uploaded
  automatically or to any backend; the user's own share-sheet choice
  decides where it goes, exactly like the runbook's own manual-only design
  point.
- **Testability seam**: `MainViewModel`'s existing `nowProvider` (B28) is
  reused for `SupportDiagnosticsRecorder`'s own timestamps where
  applicable - no new wall-clock seam was needed beyond what B28 already
  added.
- **Tests**: `DiagnosticSanitizerTest`, `DiagnosticSessionStoreTest`
  (bounded retention/eviction), `SupportDiagnosticsRecorderTest` (DIRECT/
  CHAIN_DIRECT/CHAIN_CDN success bundles, `RestrictedNetworkNoViableRelay`,
  transport handshake failure, data-plane readiness failure, relay E2E
  proof failure, activation/control-plane failure representation, raw-vs-
  stabilized consistency, last-attempt-wins path/transport recording,
  per-session event bound, abandon-on-supersede, disconnect-before-start
  no-op), `SupportBundleTest` (deterministic serialization, the required
  security test, bounded size), `DiagnosticTypesTest` (closed field-set
  proofs, reflection-checked no-raw-string API surface), and
  `MainViewModelSupportDiagnosticsTest` (a REAL successful manual connect
  produces a real `PROTECTED`/`DIRECT` session end to end; the exported
  bundle never leaks a real gateway config's own host/public
  key/tunnel IP; clear + rebuild-over-empty-store). All new + full
  existing suite green (1148 total tests);
  `compileDebugKotlin`/`assembleDebug` green.
- **Not done this slice**: no field-testing with a real user/support
  workflow (this stays FOUNDATION-only until that happens); no backend
  telemetry/upload endpoint (task's own explicit exclusion - export is
  local share-sheet only); not every single MainViewModel failure branch
  is individually instrumented with a precise typed reason (the generic
  `sessionHealth`-driven backstop covers the remainder, mapped only as far
  as the existing `VpnError` on `DiagnosticsStore` allows); no persistent
  (disk-backed) session store yet - `InMemoryDiagnosticSessionStore` does
  not survive app process death, only app-instance lifetime; this does NOT
  prove Russia hard-whitelist bypass, which remains UNVERIFIED.
