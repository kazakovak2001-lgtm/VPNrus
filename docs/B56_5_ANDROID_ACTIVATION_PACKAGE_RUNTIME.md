# B56-5: Android runtime integration for ActivationEnvelope / NovaActivationPackage

## Status

**B56-5 IMPLEMENTED (repo-side, test keys only) / GRADLE `:app` RUN AND PHYSICAL ACTIVATION NOT YET VERIFIED**

| Item | State |
|---|---|
| B56-4B2 offline issuer backup | **BLOCKED ON OPERATOR** (unchanged) |
| Production redeemable envelope | **NOT YET ISSUED** |
| B56-5 Android package runtime | Implemented in code, unit-tested with test keys |
| Physical activation on a device | **NOT YET VERIFIED** |

Nothing in this slice needs, reads or contains the production issuer private key.

## Scope note (naming)

`RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md` section 32 originally labelled
"B56-5" as the Level-1 `BootstrapCandidateRepository`/`BootstrapReachabilityResolver`.
This slice implements the owner-defined B56-5 instead: Android consumption of an
Activation Package, i.e. that doc's section 5/7 container and section 19's
`ActivationPackageParser`, wired into the existing activation flow. The
manifest-driven activation-origin resolver is **not** implemented (see
"Not implemented").

## Flow

```
text (QR / deep link / clipboard / manual entry)  or  bytes (file)
        │  ActivationPackageInput - source confers NO trust
        ▼
ActivationPackageParser            structural only: domain tag, schema v1,
        │                          envelope via existing ActivationEnvelopeCodec,
        │                          optional bundle bytes, reserved Level-2 section
        ▼
Ed25519ActivationEnvelopeVerifier  EXISTING; ProductionActivationIssuerTrustAnchors
        │                          (prod-activation-issuer-2026-09-20-r2, public key only)
        ▼
ActivationReplayGuard              local "already redeemed on this device"
        ▼
bundle ↔ bootstrapBundleRef        exact-byte SHA-256 + manifest version
        ▼
SignedBootstrapBundleImporter      EXISTING → EndpointManifestRepository.offer()
        │                          (manifest key, expiry, rollback guard, LKG)
        ▼
ActivationPackageRedeemer ──► MainViewModel.activateDevice(credential, gateway)
                                   EXISTING /v1/activate → device binding →
                                   AWG / Xray / TLS / Shadowsocks / Hysteria2 provisioning
```

The credential is read only after step 2 succeeds. A rejected package never
reaches `activateDevice()`.

## Package format (`NOVA_ACTIVATION_PACKAGE_V1`)

```
int domainTagLength, "NOVA_ACTIVATION_PACKAGE_V1"
int schemaVersion = 1
int envelopeLength, ActivationEnvelopeCodec bytes        (1..32768)
int bundleLength (0 = none), SignedManifestCodec bytes    (0..262144)
int level2SectionLength = 0                               (reserved for B56-6)
no trailing bytes
```

The text form is `nova-activation:1:` followed by unpadded canonical Base64URL.
The prefix is only a format marker. It tells a package apart from a raw
credential, whose alphabet is also URL-safe Base64.

Operators produce it with `gateway/tools/activation_envelope_issuer.py package
--envelope <issue --out artifact> [--bootstrap-bundle <signed manifest>] --out <file>`.
The output is secret: it is written 0600, refuses to overwrite, refuses to
write inside a git tree, and its content is never printed. Byte compatibility
is pinned by `ActivationEnvelopePythonCompatibilityTest` (a Python-produced
package parses, verifies and re-encodes byte-identically in Kotlin).

## Decisions

- **Bundle policy.**
  - A bundle the repository rejects as not newer is benign
    (`ALREADY_CURRENT_OR_NEWER`, and the newer LKG is kept).
  - Any other bundle rejection (bad or foreign signature, expired, malformed,
    signed by the activation-issuer key) rejects the whole package.
  - If `bootstrapBundleRef` is present, the carried bundle must match it
    exactly (`BOOTSTRAP_BUNDLE_MISMATCH`).
  - A bundle with no ref is still staged. It is authenticated independently
    by the manifest key.
- **Offline.**
  - Parsing, verification and bundle staging are all local.
  - If `/v1/activate` is unreachable, the state is `NetworkRequired(bootstrap)`.
    It says explicitly whether the package's network facts were `STAGED` or
    `NOT_INCLUDED`. The verified envelope stays pending in memory only.
    `retryPendingActivationPackage()` (or pressing Activate again) finishes it.
    After an app restart the package must be re-imported. The credential is
    never persisted anywhere new.
  - A pending envelope that expires is rejected on retry without activating.
- **Replay.** The server stays authoritative and unchanged: `max_devices`,
  race-free `decide_and_bind`, expiry and revocation. On top of that,
  `FileActivationReplayGuard` (`noBackupFilesDir`) records
  SHA-256(issuerKeyId, activationId, nonce) plus the expiry after a
  **successful** activation, and refuses that envelope afterwards
  (`ALREADY_REDEEMED`). A failed or network-failed attempt is not recorded.
  The guard file holds no credential, nonce or activationId, and entries are
  pruned after the envelope expires. Consequence: one package activates one
  gateway on this device. Activating an additional gateway keeps using the
  existing raw-credential path (B15).
- **Level 2 (extension point only).** The V1 layout has a reserved
  length-prefixed section. A non-empty section is rejected with
  `LEVEL2_NOT_SUPPORTED` and is never ignored, so a recovery package is never
  mistaken for a standard one. The envelope's `bootstrapCapabilityHint` is
  not acted on. B56-6 defines both, and no live capability issuance exists.
- **UI.** No redesign. On the existing `ActivationScreen`, text starting with
  `nova-activation:1:` goes to `importActivationPackage`, and anything else
  goes to the unchanged `activateDevice`. `ActivationPackageUiState` covers
  Idle, Verifying, Activating, Succeeded, Rejected(kind), NetworkRequired,
  ActivationFailed and Unavailable. User copy is fixed per category
  (`ui/ActivationPackagePresentation.kt`), for example "Activation package is
  invalid / has expired / is not trusted / was already used", and never
  includes package content, key ids or the credential. Server-side refusals
  (revoked, expired, device limit) keep showing the existing
  `ProvisioningUiState` copy.

## Tests

Tests were run with a standalone Kotlin 1.9.24 compiler + JUnit on the
pure-JVM activation/reachability sources, because this environment has no
Android SDK and no locally built AWG/Xray AARs:

- `ActivationPackageImporterTest` (32) covers:
  - valid package, round trip, file vs text input;
  - wrong-key signature, unknown issuer, production anchors rejecting a test
    key, expired, not-yet-valid, clock-uncertain, tampered credential,
    every single-byte flip;
  - malformed input and raw-credential-is-not-a-package, non-canonical Base64,
    wrong domain tag, unsupported schema, missing envelope, trailing bytes,
    Level-2 section, wrong envelope canonical encoding;
  - bundle staged/LKG, unreferenced bundle, hash and version mismatch,
    untrusted-key bundle, activation-issuer-key bundle rejected (trust
    separation), garbage bundle, older bundle keeping the newer LKG (rollback),
    referenced-but-missing bundle, invalid envelope never staging its bundle;
  - replay, and no credential in any string.
- `ActivationPackageRedeemerTest` (9) covers:
  - valid package reaches activation with exactly the envelope credential;
  - invalid, expired, unknown-issuer and malformed packages never reach it;
  - replay rejected across restarts;
  - failed and network-failed attempts not marked redeemed;
  - network-down with a staged bundle, then retry success;
  - network-down without a bundle reports `NOT_INCLUDED`;
  - a pending package that expires is not activated;
  - no-op retry; offline verification.
- `ActivationReplayGuardTest` (4), `ActivationRuntimeSecurityTest` (3: no
  private key or signing mode in main sources, production anchor shape,
  importer anchor type disjoint from manifest anchors), and
  `ActivationPackagePresentationTest` (5).
- Pre-existing activation tests (103) plus the new Python-compat package
  test all pass. The pre-existing manifest/bootstrap tests (72:
  `SignedBootstrapBundleImporterTest`, `EndpointManifestRepositoryTest`,
  `ManifestVerifierTest`, `ManifestCanonicalizerTest`, `SignedManifestCodecTest`,
  `EmbeddedBootstrapManifestTest`) are unchanged and pass.
- Python `gateway/tools`: `test_activation_envelope_issuer.py` 129/129
  (6 new `PackageTests`).

**Not run here:** `./gradlew :app:compileDebugKotlin :app:testDebugUnitTest`.
The `MainViewModel` wiring (constructor param, `activateDevice(onFinished)`,
`importActivationPackage`/`retryPendingActivationPackage`, Factory) and the
`AppRoot` routing were not compiled in this environment. They must be
compiled and run on the operator machine (JDK 21 + Android SDK + local AARs,
as in B46-4A) before merge.

## Not implemented (explicitly)

- Production redeemable envelope and physical device activation (blocked on
  B56-4B2).
- Real QR scanner, deep-link intent filter, and file picker. Only the import
  boundary (`ActivationPackageInput.Text/Bytes`) exists, and text pasted
  into the activation field works today.
- Manifest-driven activation-origin resolution (architecture doc's
  `BootstrapCandidateRepository`/`BootstrapReachabilityResolver`).
  Activation still dials `ProductionGatewayCatalog`'s compiled control-plane
  origins, and a staged bundle refreshes the trusted manifest/LKG used by
  connect-time selection.
- Using `bootstrapEndpointHints`. They are non-authoritative and ignored.
- Level 2 recovery (B56-6).
