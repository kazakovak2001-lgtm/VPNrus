# Config resolution atomicity

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

`SelectedProductionGatewaySource.snapshot()` resolves the selected gateway id exactly
once per `GatewayConfigurationRepository.get()` call - a concurrent selection change
mid-resolution can never combine one gateway's host with a different gateway's key/
identity/profile. `GatewayConfigSource.snapshot()` is the one method
`DefaultGatewayConfigurationRepository` actually calls; the six individual getters
exist for direct testability but must not be relied on for atomicity by new callers.

---
Last updated: 2026-09-01 (B19 - added the "Health-aware Auto ranking" section
above: fixed the disabled provider/ASN diversity bonus and added a bounded,
time-decaying failure cooldown to PathScorer, both consumed only by
AutoGatewaySelector - the single, unchanged Auto decision authority. Physically
validated end to end on a real device this pass (baseline, controlled
dynamic reordering via debug-injected real evidence, restore) - see this
section's own closing paragraph. Existing suite (878 tests) unaffected.)

Last updated: 2026-09-01 (B18/B18-2 - added the "Routing decision vs transport/
gateway selection" section above: RoutingMode/RoutingDecisionEngine
.decideAdaptiveRoute is the real, live DIRECT-vs-VPN authority, route-prefix-
level only, with RestrictionClassifier wired in conservatively. B18-2 extended
live enforcement from AmneziaWG-only to ALL currently-live transports
(AMNEZIA_WG/XRAY_REALITY/TLS_TCP) through one shared resolver
(RoutingDecisionEngine.resolveIpv4Routes) - no second routing engine, no
duplicated CIDR math. Physical validation completed 2026-09-01 after fixing
an unrelated stale-client-identity issue on the test device (see this
section's own closing paragraph) - Adaptive Direct Routing is now
IMPLEMENTED. Everything below this line predates B18 and is unaffected by it.)

Last updated: 2026-09-01 (B17 - Auto gateway/path DISCOVERY runtime authority
moved from `ProductionGatewayCatalog` to the verified `TrustedManifestState`;
the production Ed25519 key ceremony was performed (real keypair, private key
never printed/committed, stored offline outside the repo) and the embedded
bootstrap now names both real gateways under that same production key. Live
`/v1/manifest` serves a real, strictly-newer version 2 (same key, no
rotation) on both production VPSes, `BuildConfig.MANIFEST_URL` wires the
real fetch in both build types, `AutoGatewaySelector`'s pinned
`GatewayConfigSnapshot` now sources its AWG `endpointHost`/`endpointPort`
from the manifest's own transport binding (never the catalog) - and a real
device fetch->accept->LKG->restart->fetch-failure->LKG-survives->reconnect
cycle was physically proven end to end. Signed Offline Bootstrap is now
IMPLEMENTED with no remaining LKG-path caveat (see ROADMAP's own row).
Builds on B16's
consolidated review fix - the pinned `GatewayAttemptCandidate.configSnapshot`
is threaded verbatim through `TransportOrchestrator`/`VpnController.connect()`
and actually EXECUTED for the whole attempt, never reconstructed from
`SelectedGatewayStore`/`ClientTunnelIdentityStore`/`ProductionGatewayCatalog`;
the Auto-vs-`AwgXrayFailoverPolicy` relationship is documented accurately; and
same-day B16 physical validation - real Auto failover from Germany to
Stockholm, real data-plane confirmation, restore, normal reconnect confirmed.
If this file's "Current gateway state" table conflicts with `docs/ROADMAP.md`,
ROADMAP wins - update this file to match rather than trusting the stale copy.

---
Last updated: 2026-09-02 (B25 - added the "Relay Readiness / Protected Gating
+ Ingress Provisioning Control Plane" section above: real typed session
identity/Protected gating/end-to-end proof contract on the client, the
path-history ownership fix, a real persisted ingress profile model +
resolver, and a real role-aware `/v1/ingress-profile` control-plane
endpoint + ingress->exit relay identity contract + deployment tooling on
the server. Still FOUNDATION - no real ingress deployed, Russia
hard-whitelist bypass remains UNVERIFIED. See ROADMAP's own B25 row for
the full evidence trail and the exact remaining physical-deployment steps.)

---
Last updated: 2026-09-02 (B26 - added the "First Real DIRECT_IP Ingress
Deployment Readiness" section above: real production composition wiring,
a real EXIT-side end-to-end health endpoint + probe token lifecycle, a
real Android ingress activation client, EXIT relay identity apply/revoke
tooling, ingress deploy/preflight tooling, and a deployment descriptor.
Repository/software side is DEPLOYMENT READY per ROADMAP's own B26 row;
still no real ingress deployed, Russia hard-whitelist bypass remains
UNVERIFIED. PR #40 review fix (same day): closed the two blockers this
section originally left open - activateIngress is now reached through a
real, bounded, product-visible activation prompt (never a UI-less
function or a manual UUID/key paste), and the relay/ingress composition
graph was extracted into RelayCompositionFactory with a real,
Robolectric-backed composition-root test proving production selects the
real implementations. Remaining gap: Frankfurt/Stockholm SSH audit
incomplete (no working credential this session).)

---
Last updated: 2026-09-02 (B27 - added the "CDN_FRONTED Ingress Support"
section above: threaded B23's typed IngressKind through real candidate
construction (AutoGatewaySelector.RelayAttemptCandidate), execution
(RelayedExecutionPlan/RelayActivationRequest), and provisioning
(IngressClientProfile/IngressProfileProvisioner/the /v1/ingress-profile
wire contract) - DIRECT_IP and CDN_FRONTED ingress candidates now coexist
in one ranked relay fabric, and a provisioning response whose ingress_kind
disagrees with the pinned candidate fails closed. No kind-specific
execution/health branch was added anywhere - a CDN-fronted session reaches
RelayProtected through the exact same evidence-driven, end-to-end-proof-
gated path a DIRECT_IP one does. PR #41 review fix (same day): history
IS kind-scoped after all - PathCandidate.Relayed.historyPathId now encodes
ingressKind explicitly (format: ingressId:ingressKind:transport->exitId:
exitTransport), so the same endpoint+transport reclassified between
DIRECT_IP and CDN_FRONTED can never silently reuse the other kind's
success/failure/cooldown evidence - see this file's own "Reachability/
history" bullet above for the exact format and why no migration code was
needed (no pre-B27 relay history exists on any real device). Still
FOUNDATION - no real ingress of either kind is deployed, Russia
hard-whitelist bypass remains UNVERIFIED, and this slice does not claim
CDN whitelist bypass works.)

---
Last updated: 2026-09-19 (B56-1 - added the activation authority as a new,
independent boundary alongside the existing manifest/network authority: a
new `net.pocvpn.client.activation` package holds `ActivationEnvelope`/
`SignedActivationEnvelope` (activation entitlement metadata, signed by a
future delegated activation-issuer key - never a host/IP/port/SNI/gateway/
transport fact), `ActivationEnvelopeCanonicalizer` (deterministic canonical
encoding, mirroring `ManifestCanonicalizer`'s discipline, prefixed with a
fixed domain-separation tag `NOVA_ACTIVATION_ENVELOPE_V1` so its canonical
bytes can never be confused with `EndpointManifest`'s), `ActivationEnvelopeCodec`/
`ActivationEnvelopeTextCodec` (wire/text container, mirroring
`SignedManifestCodec`), `ActivationIssuerTrustAnchors`/
`FixedActivationIssuerTrustAnchors` (a trust-anchor type deliberately
DISJOINT from `ManifestTrustAnchors`/`FixedManifestTrustAnchors` - activation-
issuer keys and manifest signing keys are separate sets by construction, not
convention), and `Ed25519ActivationEnvelopeVerifier` (same BouncyCastle
Ed25519 primitives as `Ed25519ManifestVerifier`, own typed
`ActivationEnvelopeFailureKind` set). Pure Kotlin/JVM, no Android framework
dependency, no network/UI code added. This slice does NOT implement
`SignedBootstrapBundle` or the `NovaActivationPackage` container (schemaVersion
stays a container-level concern for a later slice) - see ROADMAP's B56 row
and `RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md` for the full design and
remaining slice breakdown.)

---
Last updated: 2026-09-19 (B56-1 correction, PR #92 review - the activation
authority described above was corrected on three points without changing
the boundary itself: (1) every ByteArray/list-bearing field on
`ActivationEnvelope`/`ActivationBundleRef`/`SignedActivationEnvelope`/
`FixedActivationIssuerTrustAnchors` is now defensively copied on the way in
and exposed only through a copying accessor on the way out, since a Kotlin
`val ByteArray` only fixes the reference, not the bytes - this closed a
hole where mutating a caller's own source array/list, or an array obtained
from an accessor, after construction/verification could change an
already-built or already-verified object's effective signed data; (2) the
Ed25519 verifier's clock policy was simplified to reuse
`Ed25519ManifestVerifier.DEFAULT_CLOCK_SKEW_TOLERANCE_MS` as its single
tolerance for both the `issuedAt`-implausibly-future check
(`CLOCK_UNCERTAIN`) and the `notBefore` lower bound, with `expiresAt`
checked as `now >= expiresAt` (boundary-exclusive, no tolerance) to match
`Ed25519ManifestVerifier`'s own expiry convention exactly - the previous
arbitrary ~10-year "absurd clock" heuristic was removed as a second,
undocumented clock-trust model; (3) `ActivationEnvelopeCanonicalizer`'s
string decoding is now strict UTF-8 (REPORT, not REPLACE, on malformed
input), and `issuerKeyId`/`bootstrapEndpointHints` now validate UTF-8 BYTE
length (not Kotlin character count) so every constructible
`ActivationEnvelope` is guaranteed to round-trip through encode/decode -
`ActivationEnvelopeTextCodec` also gained a pre-Base64-decode text-length
bound derived from `ActivationEnvelopeCodec.MAX_ENCODED_BYTES` and strict
canonical-alphabet checking. No architectural boundary moved; see
ROADMAP's B56 row for the corrected implementation status. Gradle
integration (`./gradlew :app:compileDebugKotlin` / `:app:testDebugUnitTest`)
was subsequently verified for real outside the review sandbox - 111/111
relevant tests pass; see that row for detail.)

---
Last updated: 2026-09-19 (B56-2 - added exactly one new client-side import
boundary, `net.pocvpn.client.reachability.SignedBootstrapBundleImporter`;
NO new trust boundary. A `SignedBootstrapBundle` is not a distinct
cryptographic artifact - for this slice it IS `SignedManifest`, decoded with
the existing unmodified `SignedManifestCodec` and adopted through the
existing unmodified `EndpointManifestRepository.offer()` - the ONE function
that can ever cause a new endpoint fact to become trusted. This importer
owns only delivery-provenance classification (the new
`ManifestSource.IMPORTED_SIGNED_BOOTSTRAP` diagnostic value - never a
`trustedState()` outcome, never a durable trust tier) and relabels
`offer()`'s existing typed rejection kinds into this slice's own
`BootstrapBundleImportRejectionKind` vocabulary. No second Ed25519 verifier,
no second `ManifestTrustAnchors` set, no second LKG store, and no
import-specific rollback rule were added; `offer()`'s body is byte-for-byte
unchanged. The activation authority (`net.pocvpn.client.activation`,
B56-1) remains fully disjoint - an activation-issuer key can never authorize
a bootstrap manifest through this path (see
`SignedBootstrapBundleImporterTest`'s explicit cross-trust regression). No
networking, no UI, no server/gateway changes. See ROADMAP's B56 row and
`RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md` section 16 for the full
design.)

---
Last updated: 2026-09-19 (B56-3 - new stable edge invariant: both
production control-plane vhost config files (`gateway/edge/nginx-pocvpn.conf` -
Germany, `gateway/edge/nginx-pocvpn-stockholm.conf` - Stockholm) carry
native nginx `limit_req`/`limit_conn` Level 1 abuse damping on
`/v1/activate` (30r/m, burst=20) and `/v1/manifest` (120r/m, burst=60 -
REQUEST-RATE burst tolerance only, not a concurrency allowance), sharing
one 20-connection-per-IP concurrency zone - the actual concurrent-
processing ceiling per source IP for both routes combined, independent of
either `burst` value - keyed on `$binary_remote_addr` only, rejecting with
an explicit `429`. Once deployed, this is the one and only rate-limiting boundary for
these two routes - no application-level duplicate limiter exists or
should be added. Values are initial conservative defaults, not
empirically tuned: the request-rate burst allowances absorb short
legitimate shared-CGNAT bursts, while the separate concurrency ceiling
bounds concurrent processing - an explicit abuse-damping trade-off, not a
guarantee (a legitimate client can still receive `429` once these bounds
are exceeded). This is abuse damping only, never DDoS protection or a
censorship/whitelist
mechanism (see ROADMAP's B56 row and
`RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md` section 22). Every other
route, the ACME bootstrap vhost, and the CDN/XHTTP origin config are
unaffected. No application code changed. **Repo config only, not deployed:**
Stockholm runtime verified without these limits (2026-10-02); Frankfurt
runtime not verified.)

---
Last updated: 2026-09-19 (B56-4A - new stable operator-tooling boundary:
`gateway/tools/activation_envelope_issuer.py` is a SEPARATE signing
authority/CLI from `gateway/tools/manifest_signing.py`, never sharing key
material, never crossing into `ManifestTrustAnchors`. It calls the
EXISTING `gateway.api.activations.issue_activation()`/`revoke_activation()`
directly - it is not a second activation-issuance authority, only a signed-
envelope wrapper around that existing store. Its private-key input is
file-based only (`--private-key-file`, exactly 32 raw bytes) - the repo's
FIRST activation/manifest-signing tool to avoid the older
`--private-key-b64`/stdout-JSON pattern `manifest_signing.py` still uses;
future signing-key tooling in this repo should follow this file's pattern,
not that older one. `docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md` is the
durable ceremony/rotation/revocation runbook for this authority, mirroring
`B12_MANIFEST_KEY_CEREMONY.md`'s role for the manifest key. No networking,
no UI, no server/gateway changes.)

---
Last updated: 2026-09-20 (B56-4B1 - production activation-issuer key
ceremony completed. A first candidate keypair
(`prod-activation-issuer-2026-09-20`) was generated via
`activation_envelope_issuer.py generate-key` on an operator-controlled
WSL/Linux machine but WITHOUT positive evidence of network isolation for
the generation process itself (ordinary networking, no namespace/interface
isolation used) - it was abandoned before merge (never trusted, never used
to issue anything; not a compromise claim). A second, FINAL keypair
(`issuerKeyId=prod-activation-issuer-2026-09-20-r2`) was then generated
inside an explicitly network-isolated Linux network namespace
(`unshare --net`, verified loopback-only/no-route immediately before
generation, in the same namespace/process); the private key exists only
outside this repository in both cases. The FINAL production PUBLIC key is
committed via `net.pocvpn.client.activation.ProductionActivationIssuerTrustAnchors`,
which populates the EXISTING `FixedActivationIssuerTrustAnchors` - no
second trust-anchor type or verifier was added, and the abandoned
candidate's key id is absent from the committed map. Real production-key
cross-verification (against the final key) passed against the EXISTING
`ActivationEnvelopeCodec`/`Ed25519ActivationEnvelopeVerifier`
(`ProductionActivationIssuerTrustAnchorsTest`). This object is a trust-root
SOURCE only - nothing in this slice references it from bootstrap
networking, UI, `MainViewModel`, `ActivationScreen`, or reachability code;
that runtime composition is B56-5's responsibility. No redeemable
production `ActivationEnvelope` has been issued and the production
activation store was never touched - see
`docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md` for the full ceremony record
(including the abandoned candidate), offline-backup status, and rotation
policy.)

---
Last updated: 2026-09-26 (B56-5 - Android runtime wired the B56-1..4B1
pieces together, adding no new trust root. `NovaActivationPackage`
(`nova-activation:1:` / `NOVA_ACTIVATION_PACKAGE_V1`) is a TRANSPORT
container only: the existing `SignedActivationEnvelope` bytes plus an
OPTIONAL exact-byte `SignedBootstrapBundle` (= `SignedManifest`) plus a
reserved, must-be-empty V1 Level-2 section (non-empty is rejected, never
silently ignored - the B56-6 extension point). `ActivationPackageImporter`
verifies the envelope via the EXISTING `Ed25519ActivationEnvelopeVerifier`/
`ProductionActivationIssuerTrustAnchors`, checks a local
`ActivationReplayGuard` (file-backed hash of issuerKeyId+activationId+nonce,
survives restart, never the credential/nonce/envelope itself - server-side
`max_devices`/binding/expiry/revocation remain the real replay bound), and
stages any bundle through the EXISTING `SignedBootstrapBundleImporter` ->
`EndpointManifestRepository.offer()` - no second manifest verifier or
repository. `ActivationPackageRedeemer` then calls the SAME
`MainViewModel.activateDevice()` a typed credential uses (a new optional
`onFinished` callback, every pre-B56-5 call site unaffected) - there is no
second activation/provisioning system. Offline is truthful: a locally
verified package with no network reachable reports `NetworkRequired`
(STAGED if its bundle was adopted, else NOT_INCLUDED) and is held
IN-MEMORY ONLY for retry; an app restart requires re-import, and a pending
package that expires while waiting is rejected on retry, never activated.
`bootstrapEndpointHints`/`bootstrapCapabilityHint` remain non-authoritative
hints, never a network-configuration authority. UI: `ActivationScreen` is
unchanged; `AppRoot` routes text starting with `nova-activation:1:` to
`importActivationPackage`, everything else to the existing raw-credential
`activateDevice` - one screen, one entry point, fixed non-secret copy per
rejection category. See `docs/B56_5_ANDROID_ACTIVATION_PACKAGE_RUNTIME.md`
and ROADMAP's B56 row. Next slice: B67.2 multi-path activation discovery -
not implemented here.)
