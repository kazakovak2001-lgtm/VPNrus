# B52 — Offline / Outage Mode Research

Status: `RESEARCH COMPLETE / OFFLINE-OUTAGE STATE MODEL SELECTED / IMPLEMENTATION PENDING`

## 1. Executive summary

Nova can degrade safely during an outage without weakening manifest trust, but “offline” must not be a single Boolean or a new source of authority. The selected design is a deterministic assessment over five independent dimensions: network availability, trusted-topology source, control-plane reachability, local provisioning usability, and actual data-plane health. Presentation and diagnostics are projections of that assessment; neither can authorize a connection.

An already-provisioned device may attempt or maintain a connection from local state only when a currently verified manifest describes the path and every required device credential/configuration is present, structurally valid, decryptable, endpoint-bound where applicable, and not known locally to be expired. A valid Last Known Good (LKG) manifest is preferred. A valid embedded bootstrap may be used when LKG is absent or invalid. If neither verifies, `TrustedManifestState.NoneTrusted` makes topology unavailable and connection/reconnection fails closed.

This is an architecture decision, not an Offline Mode implementation. Existing stores do not provide a single authoritative offline entitlement record, and most direct transport profiles have no explicit expiry. Consequently B52 does not invent a grace period or equate “revocation could not be checked” with “valid forever.” Follow-up implementation must reuse only validity that current artifacts can actually prove.

## 2. Scope

This research defines:

- current persisted and transient outage-related behavior;
- safe reuse rules for trusted topology, identities, credentials, profiles, history, and sessions;
- explicit unavailable/degraded states and user copy;
- recovery triggers and retry bounds;
- security, privacy, and lifecycle requirements;
- staged implementation and deterministic test work.

It covers fresh installs, provisioned devices, live sessions, reconnect, process death, and reboot across independent network, control-plane, manifest-origin, activation, profile-service, and data-plane failures.

## 3. Non-goals

B52 does not implement runtime behavior, extend validity, add endpoints, change Smart Connect scoring, deploy B51 infrastructure, add B50 survivability as authority, or build B56 QR/file/package activation. It does not change `PathScorer`, `AutoGatewaySelector`, `SmartConnectDecisionEngine`, `ManifestVerifier`, `ManifestRollbackGuard`, activation semantics, or production composition. It does not promise connectivity on every network.

## 4. Current architecture inventory

| Area | Current mechanism | Outage significance |
| --- | --- | --- |
| Topology authority | `EndpointManifestRepository`, `TrustedManifestState`, `ManifestSource` | One fail-closed trust boundary and explicit `NoneTrusted` |
| Durable topology | `FileLastKnownGoodManifestStore` | Versioned signed manifest survives process/reboot; malformed data is absent |
| Verification | `Ed25519ManifestVerifier` | Key, clock skew, expiry, signature checked at use |
| Rollback | `ManifestRollbackGuard` | Candidate version must be strictly newer |
| Live delivery | `RemoteManifestFetcher`, `ManifestDistributionClient`, multi-origin client | Bounded HTTPS fetch; transport is not trust; fetch failure does not alter LKG |
| Recovery delivery | `EmbeddedBootstrapManifest`, `SignedBootstrapBundleImporter` | Bootstrap verifies normally; imported candidate goes through `offer()` |
| Activation | `ActivationResilienceCoordinator`, `TrustedOriginRequestExecutor` | Typed bounded origin attempts; optional local reuse seam; terminal authorization failures stop |
| Device/profile state | identity, provisioned-profile, client-tunnel, Xray, TLS, Shadowsocks, ingress stores | Durable artifacts with different integrity and freshness properties |
| Selection memory | selected gateway and path-history stores | Durable preference/evidence; never topology or credential authority |
| Runtime | `MainViewModel`, `VpnController`, `VpnSessionHealth` | Refresh and connection state are currently separate; protection derives from data-plane proof |
| UI | `ProvisioningUiState`, `ActivationScreen`, product presentation | Activation outcomes exist, but no complete multidimensional outage projection exists |
| Diagnostics | reachability diagnostics and `SupportDiagnosticsRecorder` | Manifest source and typed control failures exist; full outage assessment is not yet recorded |

Startup constructs file-backed stores, reads persisted configuration, resolves trusted manifest state, and performs manifest refresh on lifecycle/network triggers. Runtime transport state, current attempt/session health, in-flight probes, and most current reachability observations are memory state and are not authority after process death.

## 5. Existing trust precedence

`EndpointManifestRepository.trustedState()` is the only session trust selection boundary:

1. Read LKG and verify it now. If valid, return `Trusted(..., LAST_KNOWN_GOOD)`.
2. Otherwise verify the embedded bootstrap with the same verifier and anchors. If valid, return `Trusted(..., EMBEDDED_BOOTSTRAP)`.
3. Otherwise return `NoneTrusted` with the bootstrap rejection reason.

Every offered candidate is re-verified and must be strictly newer than the currently trusted/stored version. A download, HTTPS success, APK embedding, or import channel does not confer trust. `IMPORTED_SIGNED_BOOTSTRAP` is one-time delivery provenance only; after adoption the artifact is ordinary LKG. No production catalog, raw host, path history, or cached address participates in this precedence.

## 6. Existing activation resilience

`ActivationResilienceCoordinator` first evaluates the caller-supplied `hasValidLocalActivation`. True returns `AlreadyValidLocally` without a network request and records reuse; false makes bounded calls through trusted control origins. Authorization rejection is terminal, while origin availability failures may exhaust the trusted origin set. The coordinator does not create identity or persist partial results.

This seam is appropriate only for automatic/background flows whose caller can prove local validity. `MainViewModel.activateDevice()` deliberately supplies `hasValidLocalActivation = { false }`: an explicit activation action must contact authority. B52 preserves that behavior. A server error is distinct from `Unauthorized`, `Revoked`, or `Expired`, and absence of a response must never be converted into success.

## 7. Outage dimensions

The assessment must represent these independently:

| Dimension | Examples | Why independent |
| --- | --- | --- |
| Device network | absent, present, indeterminate | No Internet differs from Nova-only failure |
| Control plane | reachable, unavailable, not attempted | Activation/profile/manifest services may fail while Internet works |
| Manifest origins | reachable, exhausted, not attempted | Valid local topology can outlive an origin outage only until real expiry |
| Trusted topology | LKG, embedded, none | A cryptographic fact, not a connectivity fact |
| Gateway/path | some eligible, one failed, all failed | One path failure need not be global failure |
| DNS/CDN | unavailable or usable | Trusted raw-IP/direct alternatives may differ from hostname/CDN paths |
| Provisioning | locally usable, activation required, refresh required, invalid | Fresh install differs from provisioned device |
| Data plane | protected, connecting/reconnecting, idle, failed | Control outage neither proves nor disproves protection |

Trusted-manifest exhaustion is a terminal trust state for topology even if the general Internet and control plane appear reachable.

## 8. Device lifecycle cases

1. **Fresh install, never activated:** may verify topology and retry discovery, but cannot fabricate activation or claim protection. Show activation-unavailable when authority cannot be reached.
2. **Activated device with local credentials:** may use a trusted manifest and complete local credential set under the rules in section 9. Server unavailability alone is not credential invalidity.
3. **Valid LKG, origins unavailable:** retain and use verified LKG; record refresh failure without a catastrophic primary error if a usable path remains.
4. **Corrupt LKG, valid embedded:** treat LKG as absent, independently verify embedded, then use it.
5. **Expired LKG, valid embedded:** reject LKG and use independently valid embedded.
6. **Both invalid/expired:** expose `NoneTrusted`; never guess endpoints.
7. **Healthy tunnel, control plane disappears:** keep it while its actual data-plane health remains good; a refresh failure is not a disconnect command.
8. **Tunnel fails during outage:** run normal reconnect/failover only over currently trusted, eligible, locally provisioned candidates. Otherwise fail closed.
9. **App restart during outage:** reconstruct authority from durable artifacts and verify again; do not restore an in-memory “success” flag as truth.
10. **Reboot during outage:** same as restart, plus OS VPN/TUN/process state is gone and must be re-established from valid durable inputs.

## 9. Local artifact reuse matrix

| Artifact | Persisted? | Trust/validity check | Safe to reuse offline? | Expiry behavior |
| --- | --- | --- | --- | --- |
| LKG signed manifest | Yes, atomic file | Decode plus current key/clock/expiry/signature verification | Yes, only while verification succeeds | Explicit manifest expiry; never extended |
| Embedded bootstrap | APK constant | Same verifier and anchors | Yes, only as repository fallback | Explicit manifest expiry; never extended |
| Imported signed bootstrap after adoption | Yes, as LKG | Same `offer()`, rollback, then normal LKG verification | Same as LKG; import provenance grants nothing | Same manifest expiry |
| AWG private/public device identity | Yes, device-local identity store | Complete parse/key consistency and keystore/storage access | Yes as identity input, never alone | No entitlement expiry; missing/corrupt fails closed |
| AWG gateway/provisioned config | Yes | Full structural validation and match to trusted endpoint/config | Conditionally | No authoritative expiry in `PersistedProfile`; gap |
| Per-gateway client tunnel identity | Yes | Valid IPv4 and matching gateway entry | Conditionally with complete config | No expiry; identity assignment is not entitlement proof |
| Xray REALITY profile | Yes, encrypted | Decrypt, full JSON decode, mapper/config checks, match trusted path | Conditionally | No explicit issued/expiry fields; revocation is online-only gap |
| TLS/TCP profile | Yes, encrypted | Same as Xray TLS repository and trusted path match | Conditionally | No explicit expiry; revocation gap |
| Shadowsocks credential | Yes, encrypted and endpoint-bound | Decrypt, method allowlist, Base64 and exact key length, endpoint match | Conditionally | No explicit expiry; revocation gap |
| Activation state/credential input | Result state is not a standalone entitlement record; input is not retained as authority | Existing concrete profile/identity evidence only | Never synthesize or replay UI success; reuse concrete valid artifacts only | No unified signed entitlement expiry exists |
| Selected gateway | Yes | Enum/format decode only; candidate must still be trusted/eligible | Preference only | No expiry; never authority |
| Path history | Yes | Versioned structural decode; keyed by fingerprint/path/transport | Scoring evidence only | Historical outcomes age by scorer semantics, never authorize topology |
| Network fingerprint/history | Fingerprint-derived history persists | Non-secret derived key and history validation | Context/scoring only | Never proof of current reachability or trust |
| Ingress client profile | Yes, encrypted and endpoint-bound | Decrypt, structural transport/binding/kind match, `isExpired(now)` | Yes when complete and not expired | Optional explicit expiry; null expiry leaves revocation/freshness gap |
| Relay plan/config | Plan is runtime-derived; ingress profile persists | Rebuild from trusted manifest and matching ingress credential | Do not reuse an old runtime plan directly | Re-evaluate manifest and ingress expiry |
| CDN/XHTTP session state | Runtime session is transient; TLS profile may persist | Recreate from trusted binding/profile; normal TLS and runtime proof | Persisted profile conditionally; session itself no | Profile lacks explicit expiry; session never survives restart |

“Conditionally” always means all dependencies exist and the ordinary transport resolver would accept them. Store presence alone is insufficient.

## 10. Manifest/LKG behavior

Live refresh is an optimization and update path, not a prerequisite for every connection. `ManifestDistributionClient` offers only successfully decoded fetches; any network, TLS, HTTP, or malformed response failure leaves repository state untouched. Multi-origin exhaustion has the same authority outcome. The repository then continues to expose a verified LKG if one remains valid.

LKG is evaluated against current device time on each `trustedState()` call. Corrupt bytes decode as absent. Invalid signature, unknown key, unacceptable clock, or expiry rejects the whole artifact. No partial endpoint extraction is allowed. New online state may replace it only through normal verification and strict version monotonicity.

## 11. Embedded-bootstrap behavior

The embedded bootstrap is a signed recovery candidate, not an implicit root of truth. It is consulted only after no valid LKG exists and passes the same key, time, expiry, and signature verification. UI may say “Using built-in verified recovery configuration”; diagnostics should expose `EMBEDDED_BOOTSTRAP`. If it is invalid or expired, the result is `NoneTrusted`, not a raw catalog fallback.

## 12. Profile freshness

| Profile | Local integrity/shape | Explicit expiry | Offline revocation knowledge |
| --- | --- | --- | --- |
| AWG persisted profile/client tunnel identity | Yes | No | None |
| Xray REALITY | Encrypted, decoded, mapped | No | None |
| Xray TLS/TCP/XHTTP | Encrypted, decoded, mapped | No | None |
| Shadowsocks 2022 | Encrypted, endpoint/method/key validated | No | None |
| Ingress client profile | Encrypted, binding/type validated | Optional `expiresAtEpochMillis` | Only local expiry; server revocation otherwise unknown |

“Server unavailable” must map to availability uncertainty, not profile invalidity. Conversely, successful decryption is not proof of current entitlement. Offline implementation can reuse these profiles only under an explicitly chosen product/security policy; it cannot claim that the existing artifacts cryptographically prove continuing authorization. An expired ingress profile is unusable even offline. A profile whose matching identity or trusted endpoint is missing is unusable.

## 13. Activation/entitlement behavior

New activation, profile issuance, device-limit decisions, and authoritative revoked/expired responses require live control-plane access. Existing device identity and profiles can avoid unnecessary background reactivation only when the calling flow has a concrete local-validity predicate. Explicit user activation continues to call the server.

There is currently no single signed offline entitlement artifact containing subject/device binding, scope, issued time, expiry, and revocation epoch. Therefore B52 cannot define “authorized until date X” uniformly. `ProvisioningUiState.Success` is UI/runtime outcome, not durable authority, and must not be persisted or resurrected as such.

## 14. Revocation-vs-offline trade-off

An unreachable server prevents immediate observation of server-side revocation. The client cannot guarantee both indefinite offline availability and immediate revocation enforcement. Defensible future policies include:

- signed, device-bound entitlement expiry and reuse only until that expiry;
- profile-specific signed expiry;
- a cryptographically authorized grace window encoded by the issuer;
- fail closed whenever live validation is required.

A locally invented “N days since last success” grace period is not authoritative and is not selected. Current profiles lack enough signed freshness semantics for a uniform bounded policy. Implementation must either preserve the existing risk deliberately and label it, or first introduce an authoritative expiring artifact in a separate reviewed slice.

## 15. Data-plane behavior

Protection is derived only from real `VpnSessionHealth`: direct protection requires confirmed transport connection; relay protection additionally requires end-to-end relay proof. A valid manifest merely supplies trusted topology.

A healthy established tunnel should remain active when only refresh/control-plane calls fail. The refresh path must not stop the tunnel. If the tunnel reports failure, normal reconnect/failover may run using a fresh assessment and ordinary eligibility. No expired topology/profile may be used to create a new session. Whether an already-established session must be torn down exactly when a manifest/profile expires is not currently encoded as a continuous runtime policy and requires an explicit implementation decision; B52 does not silently choose indefinite continuation.

## 16. Control-plane behavior

Control-plane unavailability is a typed failure of a requested operation, not global VPN state. Manifest refresh, activation, and profile provisioning should report distinct service/capability failures. Existing local state stays untouched on transport failure. A terminal signed/HTTP authorization response such as revoked or expired must not be reclassified as an outage or retried across origins as though it were transient.

## 17. Smart Connect interaction

Smart Connect may receive only candidates derived from the current trusted manifest and backed by required local credentials/configuration. It continues to apply existing reachability, eligibility, scoring, and decision logic. Outage assessment may explain why the candidate set is reduced or empty, but it may not create a candidate, resurrect an ineligible path, or change scorer/selector authority. Selected gateway and path history remain hints/evidence, not endpoint sources.

## 18. App restart behavior

After process death Nova may reload LKG, device identity, provisioned gateway data, per-gateway tunnel identity, Xray/TLS/Shadowsocks credentials, ingress profiles, selected gateway, and path history from their stores. Each store must complete its normal decode/decrypt/validation; the manifest must verify at the new time. Current transport/session health, active TUN/processes, in-flight operations, reachability snapshot, and ephemeral success state are reconstructed or absent—not trusted from persistence.

Startup should assess first, then make bounded refresh/probe attempts. A refresh failure must not erase usable LKG. An old “connected” presentation must never survive without current VPN runtime proof.

## 19. Device reboot behavior

Reboot has the same authority reconstruction rules as app restart and guarantees that process/TUN/runtime session state is gone. Automatic reconnection may be attempted only after OS VPN permission/always-on rules and the complete local artifact set are validated. Keystore-unavailable credentials are unavailable, not plaintext-recoverable. A reboot with uncertain time may cause legitimate artifacts to fail time checks; that is safer than weakening the verifier.

## 20. Clock/expiry risks

`ManifestVerifier` uses device wall time, rejects a manifest issued too far in the future (existing maximum future skew), and rejects `now >= expiresAt`. A forward clock jump can prematurely expire manifests; a backward jump can trigger future-issued/clock-skew rejection, but trustworthy elapsed offline time across reinstall/restore is not provided. Reboot before network time synchronization and stale RTC can therefore yield `NoneTrusted` even for otherwise legitimate data.

Manual time changes must not relax verification. B52 does not add a cached “last trusted time” as authority, because app-data rollback/restore could roll it back too. A future secure-time design would need rollback-resistant hardware/OS evidence and explicit threat analysis.

## 21. Corruption/recovery behavior

Recovery is whole-artifact and fail-closed:

- corrupt LKG → treat absent → independently verify embedded;
- corrupt embedded/verification failure → `NoneTrusted`;
- corrupt encrypted profile or failed decrypt → profile unavailable;
- partial/failed write → retain prior atomic file where the store provides that guarantee, otherwise reject unreadable data;
- profile without identity, identity without profile, or credential without matching trusted endpoint → no candidate;
- never parse and reuse the “good fields” of a corrupt artifact.

Recovery actions may clear/replace bad local data only through existing authorized provisioning or verified update paths.

## 22. Proposed typed outage-state model

Select a pure `OutageAssessment` product type, not a giant enum:

```kotlin
data class OutageAssessment(
    val network: NetworkAvailability,
    val topology: TopologyAvailability,
    val controlPlane: ControlPlaneAvailability,
    val provisioning: LocalProvisioningAvailability,
    val dataPlane: DataPlaneAvailability,
    val reasons: Set<OutageReason>,
)
```

Recommended closed dimensions:

- `NetworkAvailability`: `AVAILABLE`, `UNAVAILABLE`, `UNKNOWN`.
- `TopologyAvailability`: `TRUSTED_LKG(version, expiresAt)`, `TRUSTED_EMBEDDED(version, expiresAt)`, `NONE_TRUSTED(reason)`.
- `ControlPlaneAvailability`: `AVAILABLE`, `UNAVAILABLE(typedReason)`, `NOT_ATTEMPTED`.
- `LocalProvisioningAvailability`: `USABLE(candidateCount)`, `ACTIVATION_REQUIRED`, `PROFILE_REQUIRED`, `INVALID(typedReason)`, `UNKNOWN`.
- `DataPlaneAvailability`: `PROTECTED`, `CONNECTING`, `RECONNECTING`, `IDLE`, `UNAVAILABLE(typedReason)`.

`OutageReason` should reuse current closed vocabularies and add only facts the assessor observes: `NO_NETWORK`, `MANIFEST_ORIGINS_UNREACHABLE`, `USING_LAST_KNOWN_GOOD`, `USING_EMBEDDED_BOOTSTRAP`, `NO_TRUSTED_MANIFEST`, `ACTIVATION_SERVICE_UNAVAILABLE`, `PROFILE_SERVICE_UNAVAILABLE`, `NO_USABLE_LOCAL_PROFILE`, and `ALL_TRUSTED_PATHS_UNAVAILABLE`. The model is descriptive; connection authority remains in repositories/resolvers/controllers.

## 23. UX state model

Presentation uses priority plus coexistence, not one replacement banner:

| Condition | Primary copy | Action |
| --- | --- | --- |
| Network unavailable | “Internet connection unavailable.” | Retry when network changes; optional manual retry |
| Nova service unavailable, local path usable | “Nova servers are temporarily unavailable. Using verified saved configuration.” | Continue/connect if ordinarily eligible |
| Refresh failed, verified LKG | “Using verified saved network configuration.” | Non-blocking status; diagnostics available |
| Verified embedded selected | “Using built-in verified recovery configuration.” | Non-blocking degraded status |
| Activation required, service unavailable | “Activation requires a connection to Nova servers.” | Retry; no bypass |
| Profile required, service unavailable | “A secure connection profile could not be refreshed.” | Retry; do not claim protection |
| No trusted topology | “Secure network configuration is unavailable.” | Retry/import only in future B56; no “Connect anyway” |
| All eligible paths failed | “Secure connection paths are currently unavailable.” | Normal bounded retry |

The protection badge remains exclusively a projection of `VpnSessionHealth`. A degraded control-plane banner may coexist with “Protected”; valid LKG alone may not produce “Protected.” Technical sources and reasons belong in diagnostics.

## 24. Diagnostics model

Record stable typed events/snapshot fields:

- network availability at assessment time;
- trusted manifest source, version, expiry, and verification rejection category (no raw manifest);
- refresh attempted/succeeded/exhausted and typed fetch/origin reason;
- local activation reuse yes/no (reuse event already exists);
- profile reused/required/corrupt/expired, by non-secret transport kind;
- eligible/available path counts and non-secret endpoint IDs where already safe;
- session health and final typed failure reason;
- transition cause: startup, foreground, network change, manual retry, reconnect.

Reuse `ManifestSource`, manifest verification/fetch rejection kinds, control-plane failure reasons, reachability diagnostics, and `OFFLINE_STATE_REUSED`. Do not parse exception strings into policy. Avoid raw hostnames unless existing support policy explicitly permits them; never record credentials, UUIDs, private keys, Shadowsocks keys, bearer tokens, imported bytes, or free-form server responses.

## 25. Retry/recovery policy

- **Manual:** one explicit refresh/reassessment; disable duplicate concurrent action.
- **Startup:** one bounded assessment and refresh; local trusted state remains usable during failure.
- **Network change:** debounce, then reassess; refresh manifests and reachability when connectivity materially changes. Do not activate automatically.
- **Foreground:** refresh only when last attempt/state is stale under a future defined interval; coalesce with startup/network work.
- **Backoff:** bounded exponential delay with jitter per capability/origin, reset after success or meaningful network change; persist no “success authority.”
- **Reconnect:** controller’s normal bounded reconnect/failover over eligible local candidates; no tight polling.

Recovery order is: observe network → recompute trusted topology/current local provisioning → attempt bounded online refresh if appropriate → accept updates only through verification/rollback → recompute candidates → reconnect only if requested/policy-authorized. A malicious/old response after restoration is rejected normally.

## 26. B49 test matrix

| ID | Deterministic setup | Expected invariant |
| --- | --- | --- |
| O1 | Live manifest unavailable; valid LKG | LKG remains selected; refresh failure diagnostic |
| O2 | Live unavailable; corrupt LKG; valid embedded | Embedded selected after independent verification |
| O3 | Live unavailable; expired LKG; invalid/expired embedded | `NoneTrusted`; no candidates |
| O4 | Control unavailable; complete local profiles; trusted topology | Locally authorized eligible path remains attemptable |
| O5 | Control unavailable; fresh install | Activation explicitly blocked; no fabricated profile |
| O6 | Healthy tunnel; control failure | Session remains protected while real health stays good |
| O7 | Tunnel fails; valid local candidate | Normal bounded reconnect/failover runs |
| O8 | Tunnel fails; no trusted/provisioned candidate | Fail closed with typed reason |
| O9 | Network returns; newer valid manifest | Adopt only through verifier and rollback guard |
| O10 | Old/malicious candidate after outage | Reject; prior trusted state unchanged |

Add clock jumps, corrupt stores, keystore failure, process restart, reboot, coalesced triggers, no retry storm, and no secret diagnostic leakage as variants. These are later implementation tests, not claims that B52 research executes them.

## 27. B50 relationship

B50 survivability scoring may later explain concentration or remaining failure domains. It must not decide manifest trust, profile validity, entitlement, or candidate eligibility. B52 consumes at most a diagnostic result after normal authority decisions.

## 28. B51 relationship

An authorized non-datacenter endpoint may improve availability in some provider outages, but B52 must behave correctly with current topology and does not wait for or deploy B51. Any future B51 endpoint must arrive through the signed manifest and ordinary credential/provisioning mechanisms.

## 29. B56 relationship

B52 answers what an existing installation can safely reuse. B56 answers how signed activation/bootstrap material may arrive out of band. The integration boundary is `SignedBootstrapBundleImporter`/`EndpointManifestRepository.offer()` for topology and a future separately specified activation envelope for entitlement. B52 adds no QR UI, package parser, Level-2 bootstrap, import authority, or B56 runtime composition.

## 30. Security analysis

| Failure | Required outcome |
| --- | --- |
| Incorrect/manual device time | Existing clock/expiry verifier decides; no override |
| Corrupt manifest | Whole artifact rejected; embedded tried normally |
| Corrupt profile/credential | Reject profile; never partial reuse |
| Keystore unavailable | Encrypted credentials unavailable; no plaintext fallback |
| Partial disk write | Atomic prior value where supported; unreadable artifact rejected |
| Old backup/app-data rollback | Re-verify manifest and structural data; rollback-resistant profile/entitlement freshness remains a gap |
| Device clone/restore | `noBackupFilesDir`/keystore binding should prevent portable authority; any usable clone is a security defect |
| Profile exists, identity missing | Candidate unavailable |
| Trusted endpoint, credential absent | Candidate unavailable; no generated/default secret |
| DNS/CDN failure | Use only other ordinarily eligible signed paths; never substitute host/address |
| Revocation learned before outage | Honor it; outage cannot revive the artifact |

App-data rollback is particularly important: manifest rollback protection compares stored/current versions but cannot detect rollback of the entire local store to a self-consistent older snapshot unless another monotonic anchor exists. Current expiry limits exposure but does not eliminate it.

## 31. Privacy analysis

Outage telemetry/support export should use closed reason codes, counts, transport kinds, manifest version/source/expiry, and already-approved non-secret endpoint IDs. Redaction must cover activation codes, enrollment material, AWG private keys, Xray UUIDs and REALITY material, Shadowsocks secrets, probe/bearer tokens, tunnel identity details where identifying, full network fingerprints, raw imported packages, and arbitrary exception/server text. Do not increase logging merely because retry volume increases.

## 32. Known gaps

1. No unified signed, device-bound offline entitlement with authoritative expiry.
2. AWG, Xray, TLS, and Shadowsocks direct profiles lack explicit expiry fields.
3. Server-side revocation cannot be observed offline.
4. Continuous policy for an established tunnel crossing manifest/profile expiry is unspecified.
5. Full typed outage assessment and UX projection do not yet exist.
6. Refresh/provisioning retry orchestration is distributed and needs coalescing/backoff review.
7. Restriction/reachability evidence is partly transient and must not be mistaken for post-restart authority.
8. Whole-app-data rollback detection lacks a hardware/OS monotonic anchor.
9. Offline trustworthy time is not guaranteed.
10. Store atomicity/error surfaces are not perfectly uniform; all loaders must converge on typed unavailable/corrupt outcomes.

## 33. Proposed implementation slices

### B52-1 — Pure typed outage assessment

Introduce the dimension types and deterministic assessor over existing facts. No networking, persistence, or authority changes.

### B52-2 — Diagnostics integration

Map existing typed manifest/control/reachability outcomes into sanitized events and snapshot fields; add privacy regression tests.

### B52-3 — Proven local-state reuse

Inventory each transport resolver and wire reuse only where all existing validity predicates are demonstrable. Resolve direct-profile expiry/entitlement policy before enabling any new reuse path.

### B52-4 — Degraded and unavailable UX

Project assessment into banners/actions while leaving `Protected` exclusively controlled by session health. Add activation/profile-specific unavailable states and accessibility tests.

### B52-5 — Recovery lifecycle

Coalesce startup, foreground, network-change, and manual triggers; add bounded jittered backoff and ensure refresh failure never tears down a healthy session.

### B52-6 — Chaos and regression matrix

Implement O1–O10 plus clock, corruption, keystore, restart, reboot, rollback, storm, and privacy scenarios using B49-style deterministic injection.

A separate prerequisite slice may be required for signed expiring offline entitlement/profile metadata. It must not be smuggled into B52-3 as a locally invented grace period.

## 34. Decision gate

Decision: `RESEARCH COMPLETE / OFFLINE-OUTAGE STATE MODEL SELECTED / IMPLEMENTATION PENDING`.

The architecture is ready for staged implementation of assessment, diagnostics, truthful UX, and recovery because these need no trust bypass. Reuse expansion is conditionally ready only where current artifacts already prove all required facts. Direct-profile/entitlement freshness is a recorded security-policy gap and may require an authoritative signed-expiry prerequisite.

The gate explicitly preserves:

- real manifest/profile expiry;
- no unsigned or hardcoded topology fallback;
- strict rollback protection;
- separation of activation authority from local identity;
- real server contact for explicit activation;
- protection truth derived from the actual data plane;
- fail-closed behavior for ambiguous, corrupt, incomplete, or `NoneTrusted` state.
