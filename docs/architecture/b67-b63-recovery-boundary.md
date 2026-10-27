# B67/B63 recovery boundary (2026-09-26, ROADMAP-only re-scoping, no code change)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

- **B67 (Resilient Activation & Enrollment) is a recovery/re-scoping label, not
  a new architecture.** It groups the ALREADY-DOCUMENTED B56 ActivationEnvelope
  work (see "Resilient Activation & Control-Plane Access" and B56 sections
  above - schema/verifier/issuer-tooling/production-key ceremony, AND, as of
  B56-5, the runtime composition into `MainViewModel`/`ActivationScreen`/
  bootstrap networking, are all real and present at HEAD - see the "Last
  updated" note just above this section) together with PR #58's still-unmerged
  zero-touch field-enrollment service (`gateway/api/field_enrollment.py`,
  `gateway/tools/field_enrollment_admin.py`, Android `FieldCredentialStore.kt`)
  under one ROADMAP number, so neither loses tracking. See `docs/ROADMAP.md`'s
  B67 rows for the DONE/PARTIAL/PLANNED breakdown per sub-slice.
- **B67.3 (2026-09-26 audit) determined the `ActivationEnvelope` <-> legacy
  credential CONTRACT from the actual code, not by architectural preference:
  `ActivationEnvelope.credential` (`activation/ActivationEnvelope.kt`) IS an
  `ActivationCredential` - the SAME bearer token
  `gateway/tools/activation_tokens.py` always issued. `ActivationPackageRedeemer`
  extracts it and calls the SAME `MainViewModel.activateDevice()` a typed
  credential uses - no second activation/provisioning system, confirmed.
  `gateway/api/activations.py` has ZERO awareness of `ActivationEnvelope` or
  issuer keys - it authorizes purely via that legacy credential's own store
  record (`max_devices`/`expires_at`/`status`/`decide_and_bind`), unchanged.
  **The legacy credential is therefore the ONE live, unconditional,
  never-deprecated server-side authorization artifact; `ActivationEnvelope` is
  a CLIENT-SIDE-ONLY signed integrity/entitlement wrapper around distributing
  that SAME credential offline - never a second authorization mechanism, and
  never itself checked server-side.** Whether/when the legacy raw-credential
  manual-entry UI path is ever deprecated, and whether a future server-side
  envelope-verification path is ever built, are genuine, UNDECIDED product
  questions - not implemented, not assumed, not blocking this contract
  statement. Server-side rejection of the credential (revoked/expired/
  device-limit) is authoritative over a locally-valid envelope and was
  already provably terminal via B30's existing `AUTHORIZATION_REJECTED`
  taxonomy; B67.3 added the one test that had been missing - proving this
  through the REAL `MainViewModel.activateDevice()` mapping for the package
  flow specifically, not a stand-in (`MainViewModelActivationPackageAuthorityTest`).
  `bootstrapEndpointHints` remains a signed schema field with ZERO runtime
  consumer anywhere in the codebase (confirmed by search) - inert today, not
  an oversight to silently assume is wired.
- **Multi-path CONTROL-PLANE/activation discovery across DIRECT/CHAIN_DIRECT/
  CHAIN_CDN does not exist.** The existing `PathScorer`/`AutoGatewaySelector`
  multi-path ranking is a DATA-PLANE (VPN transport/gateway) authority only
  (see the Reachability/Smart Connect pipeline section at the top of this
  file). `ControlPlaneOriginSetBuilder`/`TrustedOriginRequestExecutor` (B30)
  only iterate origins WITHIN one already-known gateway's catalog entry - they
  do not select among DIRECT/relay/CDN paths for reaching the control plane
  itself. B67.2 is genuinely unimplemented, not a rename of existing code.
- **B63 (In-App Support & Diagnostics) reuses the existing B29 diagnostics
  stack** (`SupportDiagnosticsRecorder`/`DiagnosticSession`/`SupportBundle`/
  `DiagnosticSanitizer`/`DiagnosticsDialog`, all present at HEAD) - no support
  chat, ticket history, or support backend of any kind exists yet. B63 extends
  this existing plumbing; it does not introduce a second, parallel report/
  diagnostics system.
- **Milestone-number correction (2026-09-26, same pass)**: this section
  originally labeled the activation/enrollment recovery milestone "B62" -
  this collided with a REAL, already-merged slice on this branch's own commit
  history (`625d50a "B62: surface direct EXIT XHTTP in transport registry"`,
  part of the B59-B66.18 Direct-EXIT-XHTTP work). Renamed to **B67**
  throughout this file and `docs/ROADMAP.md` before any commit - `B62` was
  never free. The highest `B<n>` used anywhere in this repository's commit
  history at the time of this correction was `B66` (`B66.18`); `B67` is the
  next unused number in that sequence (`B63`, used for the separate In-App
  Support milestone, was independently confirmed free).
