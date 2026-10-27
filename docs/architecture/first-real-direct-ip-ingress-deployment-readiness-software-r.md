# First Real DIRECT_IP Ingress Deployment Readiness (B26) - software/repo side only

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Closes B25's remaining named client/server prerequisites for a real
DIRECT_IP ingress deployment. **Still no real ingress is deployed - Russia
hard-whitelist bypass remains UNVERIFIED.** See `docs/ROADMAP.md`'s B26 row
for the full evidence trail and `docs/B26_FIRST_INGRESS_RUNBOOK.md` for the
exact remaining physical-deployment sequence (human-approval-gated).

- **Composition root wired for real**: `MainViewModel.Factory` now
  constructs `FileIngressProfileStore` -> `RelayIngressResolverImpl` ->
  `HttpRelayEndToEndProbe`, plus per-endpoint `XrayProfileRepositoryResolver`/
  `XrayTlsProfileRepositoryResolver` lambdas (the same `{ id -> Factory.create(context, id, ...) }`
  shape the pre-existing Stockholm wiring already used), and passes all of
  it into `MainViewModel`'s constructor. `NotProvisionedRelayIngressResolver`/
  `NotConfiguredRelayEndToEndProbe` remain only as class-level defaults for
  tests/unwired callers - production no longer uses them. No Robolectric/
  instrumentation test proves this wiring mechanically (this repo's Kotlin
  suite has no such dependency) - reviewed by hand instead; a real gap, not
  claimed otherwise. `./gradlew compileDebugKotlin`, the full
  `testDebugUnitTest` suite (all pre-existing tests plus this slice's own),
  and `assembleDebug` all pass with this wiring in place (verified this
  slice against JDK 21/Gradle 8.10).
- **Real EXIT-side end-to-end health endpoint**: `GET /v1/relay-health`
  (`gateway/api/handler.py`), authenticated by a short-lived, self-verifying
  HMAC token (`gateway/api/relay_probe_token.py`) - minted by the INGRESS at
  `/v1/ingress-profile` time, verified by the EXIT using only a shared
  secret file (`POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE`/
  `NOVA_INGRESS_PROBE_HMAC_SECRET_FILE`, provisioned together by
  `gateway/tools/provision_relay_upstream_identity.py`). No shared live
  store between ingress and exit at verification time - the response is
  bound to the token's own signed `historyPathId` claim, computed
  server-side with the SAME `"ingressId:transport->exitId:transport"`
  format `PathCandidate.Relayed.historyPathId` already uses, so
  `HttpRelayEndToEndProbe.probe`'s existing `body.contains(plan.historyPathId)`
  check needed no change. A stolen probe token authenticates ONLY this one
  bound health GET, never VPN traffic (task C's own scoping requirement).
- **Android ingress activation client**: `ProvisioningClient.fetchIngressProfile`
  + `net.pocvpn.client.relay.IngressProfileProvisioner` -
  `MainViewModel.activateIngress(...)` is the real, production-wired
  control-plane path: POST `/v1/ingress-profile` -> cross-check the
  response's own `ingress_endpoint_id`/`server_address`/`server_port`
  against the CALLER's already-pinned facts (never re-derived from the
  response) -> `IngressClientProfile` -> `FileIngressProfileStore`
  (endpoint-scoped, so this can never overwrite a different ingress
  endpoint's profile). `ensureFreshProfile` is the bounded refresh policy:
  reuse a still-valid stored profile as-is, re-activate (at most one
  attempt) only when nothing usable is stored - no retry loop. No product
  UI screen invokes this yet (`ingressActivationState` is exposed but
  unwired to any Composable) - a real, named remaining gap.
- **EXIT relay identity apply/revoke**: `gateway/api/relay_identity_store.py` -
  an operator-maintained, atomically-written JSON file
  (`POCVPN_API_STATIC_RELAY_CLIENTS_FILE`) feeding `xray_config_renderer
  .render_server_config`'s pre-existing `static_clients` parameter (B25),
  applied/revoked via `gateway/tools/apply_relay_upstream_identity.py`.
  Proven by direct unit test to be idempotent and to never touch/be touched
  by ordinary per-user `activations_data` - a genuinely separate trust
  domain, not merely documented as one.
- **Ingress deploy tooling**: `gateway/scripts/install-ingress-role.sh`
  (idempotent bootstrap: users/dirs/perms/wrapper/sudoers/systemd units,
  installs no secret), `gateway/systemd/pocvpn-api-ingress.service`,
  `gateway/privileged/nova-xray-ingress-reload` +
  `gateway/config/xray-ingress.env`. These reuse the EXISTING
  `gateway/scripts/xray-activate.sh` validate/`xray run -test`/stage/atomic-
  replace/reload/rollback pipeline verbatim via one new, additive seam
  (`XRAY_ACTIVATE_ENV_FILE`, defaulting to the pre-B26 fixed path so every
  existing gateway deployment is byte-for-byte unaffected) - never a
  duplicated implementation.
- **Preflight/doctor**: `gateway/tools/ingress_preflight.py` - read-only,
  PASS/FAIL, no secret output.
- **Deployment descriptor**: `docs/ingress_deployment_descriptor.example.json`
  - secret-free, explicitly NOT folded into the signed production manifest
  by this slice (see `docs/B26_INGRESS_DEPLOYMENT_DESCRIPTOR.md`).
- **Review fix (PR #40, round 1) - real product activation entry point**:
  an earlier version of this slice wired `activateIngress` as a callable
  function with no product UI ever invoking it - fixed before merge.
  `AppRoot` reuses the EXISTING `ActivationScreen` composable verbatim
  (the same single "activation credential" text field every other
  endpoint's activation already uses - never a UUID/REALITY-key/probe-
  token paste field; `IngressClientProfile`'s fields are never exposed to
  any UI layer).
- **Review fix (PR #40, round 2) - pause/resume, not "call connect()
  again"**: round 1's own "on success, call `connect()` again" retry design
  was itself a blocker - a fresh `connect()` rebuilds/re-ranks a brand new
  combined candidate list, so the post-activation retry could silently
  resolve to a DIFFERENT ingress/exit/transport/historyPathId than the one
  that actually failed, violating the B23/B24/B25 attempt-pinning
  invariant. Replaced with a real PAUSE/RESUME design:
  `attemptRelayedAttempt`'s `NotProvisioned` branch, on its candidate's
  FIRST encounter with an activation-fixable `RelayFailureCategory`
  (`PROFILE_NOT_PROVISIONED`/`PROFILE_EXPIRED`/`PROFILE_MISMATCH` - see
  `RelayActivationRequest.ACTIVATION_FIXABLE_CATEGORIES`), PAUSES the
  combined Auto sequence entirely - it stores the FULL resume context
  (`MainViewModel.PendingRelayActivation`: the exact already-ranked
  `RelayAttemptCandidate` plus the `attempts`/`attemptedKeys` `attemptCombined`
  was mid-sequence with) and does NOT call `attemptCombined` - so nothing
  else (Direct or Relayed) starts while a human decision is pending. A
  bounded, UI-observable `MainViewModel.relayActivationNeeded` (a display-
  only projection) surfaces the prompt. On a successful
  `activateIngress()`, the BYTE-FOR-BYTE IDENTICAL paused candidate is
  retried via the SAME `attemptRelayedAttempt` function
  (`isActivationRetry = true`) - never a fresh ranking - which is what
  guarantees the retry's plan/binding/transport/historyPathId are
  unchanged; `isActivationRetry = true` also means this retry can never
  pause a second time (bounded to exactly one retry per activation), so
  its own failure just resumes `attemptCombined` with the ORIGINAL
  `attempts`/`attemptedKeys`. Any non-Saved activation outcome
  (unauthorized/revoked/mismatched/unavailable/unsupported-transport) and
  an explicit `dismissRelayActivationPrompt()` both take the SAME resume
  path - the paused candidate is NEVER retried without a real profile, and
  the original combined list/budget resumes exactly once, never re-ranked.
- **Review fix (PR #40, round 3) - atomic single-owner claim**: round 2's
  `activateIngress`/`dismissRelayActivationPrompt` each read
  `pendingRelayActivation` and only cleared it AFTER a suspending call
  (network I/O, or nothing at all for dismiss) - a second `activateIngress`
  call, or a `dismissRelayActivationPrompt` racing an in-flight activation,
  could observe the SAME non-null pending context and independently
  resume/retry it, causing duplicate/concurrent Auto progression. Fixed
  with one atomic claim: `MainViewModel.claimPendingRelayActivation()`
  reads `pendingRelayActivation` and nulls it out (together with its
  display projection, `relayActivationNeeded`) in one synchronous,
  non-suspending call. `activateIngress`/`dismissRelayActivationPrompt`
  both call it SYNCHRONOUSLY, at the very top, strictly before either does
  anything suspending - so two calls arriving back to back are processed
  in order on the same thread (the same single-dispatcher/`Dispatchers
  .Main.immediate` confinement `pendingFailoverAttempt`/`xrayAvailableEndpoints`
  already rely on without an explicit lock elsewhere in this class), and
  whichever call claims a non-null value is the ONLY one that may ever
  resume/retry it - every other caller gets `null` and does nothing
  further (never provisions, never resumes, never retries).
- **Review fix (PR #40) - real composition-root test**: an earlier version
  built the relay/ingress dependency graph inline inside
  `MainViewModel.Factory.create`, which ALSO eagerly constructs unrelated
  `AndroidKeyStore`-backed repositories at construction time - incompatible
  with this project's Robolectric version (a real, pre-existing
  incompatibility, confirmed by testing it directly: `KeyStoreException`/
  `NoSuchAlgorithmException`). Fixed by extracting
  `net.pocvpn.client.relay.RelayCompositionFactory.build(context,
  ingressProfileStore)` - the ONE function `Factory.create` now delegates
  relay composition to, which never touches `AndroidKeyStore`/crypto at
  all (every object it builds either takes an already-constructed store as
  input or defers Keystore-backed work into a lambda that only runs
  later, inside a real `resolve()`/`provision()` call).
  `RelayCompositionFactoryTest` (Robolectric, a real `Context`) proves this
  function selects `RelayIngressResolverImpl`/`HttpRelayEndToEndProbe`/a
  real `IngressProfileProvisioner`, never the `NotProvisionedRelayIngressResolver`/
  `NotConfiguredRelayEndToEndProbe` stand-ins.
- **Not done this slice**: the Frankfurt/Stockholm read-only SSH
  suitability audit could not be completed (no working credential
  available in this session for either host - see this PR's own report,
  no SAFE/NOT_SAFE verdict asserted).
