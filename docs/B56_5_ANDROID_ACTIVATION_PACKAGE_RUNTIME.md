# B56-5 - Android Activation Package Runtime

Status: DONE (this slice only - see "Not in this slice" below).

## What this is

`NovaActivationPackage` (`android/.../activation/NovaActivationPackage.kt`)
is a TRANSPORT container, never a new trust root: it carries the existing
B56-1 `SignedActivationEnvelope` bytes plus an OPTIONAL exact-byte
`SignedBootstrapBundle` (= `SignedManifest`, the existing manifest
authority) plus a reserved, must-be-empty V1 "Level-2" section (the B56-6
extension point - a non-empty section is rejected, never silently
ignored).

Text form: `nova-activation:1:` + unpadded canonical Base64URL of the
binary container (`NOVA_ACTIVATION_PACKAGE_V1`). The prefix is a format
marker only, never a trust signal - `ActivationPackageParser.looksLikePackageText`
is the ONLY thing that routes input to this flow; everything else keeps
going through the unchanged raw-credential path.

## Pipeline (`ActivationPackageImporter`, fails closed at every step)

```
parse (NovaActivationPackage)
  -> decode envelope (existing ActivationEnvelopeCodec)
  -> verify signature/issuer/validity (existing Ed25519ActivationEnvelopeVerifier
     + ProductionActivationIssuerTrustAnchors)
  -> local replay guard (ActivationReplayGuard)
  -> optional bootstrap bundle: exact-byte SHA-256 + manifest-version match
     against bootstrapBundleRef, then the EXISTING SignedBootstrapBundleImporter
     -> EndpointManifestRepository.offer()
  -> ActivationPackageImportResult.Verified(envelope, bootstrapStatus, ...)
```

The credential is read from the envelope only after step 2 succeeds. A
rejected package never reaches redemption.

## Trust-domain separation

The activation issuer (`ActivationIssuerTrustAnchors`) and the manifest
signing authority (`ManifestTrustAnchors`) are disjoint types - a bundle
signed by the activation-issuer key is rejected as `BOOTSTRAP_BUNDLE_INVALID`
(see `ActivationPackageImporterTest` / `ActivationRuntimeSecurityTest`).
This layer never invents a second manifest verifier, a second bootstrap
repository, or a network-configuration authority: `bootstrapEndpointHints`/
`bootstrapCapabilityHint` on the envelope remain non-authoritative hints
only, as they were in B56-1.

## Replay protection (`ActivationReplayGuard`)

Local-only, file-backed (`FileActivationReplayGuard`), keyed by a SHA-256
of `(issuerKeyId, activationId, nonce)` - never the credential, private
key, raw envelope, or nonce itself. Entries are pruned once the envelope's
own expiry has passed. This is an additional CLIENT-SIDE convenience
refusal, not the real replay bound: server-side `max_devices`/device
binding/expiry/revocation remain fully authoritative and unaffected.

## Redemption (`ActivationPackageRedeemer` + `MainViewModel`)

`ActivationPackageRedeemer.redeem`/`retry` call the SAME
`MainViewModel.activateDevice()` a typed credential uses, via a new
optional `onFinished` callback parameter - every pre-existing call site is
byte-for-byte unaffected. There is no second activation or provisioning
system.

Offline/network-required semantics are truthful: a locally verified
package that cannot reach `/v1/activate` reports
`ActivationPackageUiState.NetworkRequired(bootstrap)` (bootstrap says
whether the package's own bundle was staged) and is held **in memory
only** so `MainViewModel.retryPendingActivationPackage()` can finish once
connectivity returns. Nothing new is persisted for this - an app restart
requires re-importing the package. A pending package whose envelope has
expired while waiting is rejected on retry, never activated.

## UI (`AppRoot` + `ActivationScreen`, unchanged screen)

`AppRoot` inspects the credential field: text starting with
`nova-activation:1:` routes to `MainViewModel.importActivationPackage`,
everything else keeps using `MainViewModel.activateDevice` exactly as
before. No second onboarding screen, no second entry point.
`ActivationPackagePresentation.kt` provides fixed, category-based, non-secret
copy for every rejection kind - never the credential, nonce, UUID, envelope
contents, private key, or a raw exception/HTTP message.

## Not in this slice

- No new activation path (DIRECT/CHAIN_DIRECT/CHAIN_CDN) - B67.2.
- No Hysteria2/B46-4P material.
- No new whitelist detection/scoring (B-WL) or support backend (B63).
- No new redeemable production `ActivationEnvelope` was issued and no
  production private issuer key exists in this repository.
