# Activation Import Layer & One-Time Handoff Contract

Status: **File import and App Link plumbing are implemented and tested.
The one-time activation handoff backend endpoint below is a DESIGN
ARTIFACT ONLY - not implemented, not deployed.** QR *payload parsing* is
implemented and tested; QR *camera scanning* is not wired to any UI (see
"What is NOT implemented" below).

## Why this exists

Manual copy/paste of a `nova-activation:1:...` package into the activation
screen's text field is fragile: a keyboard/editor that "helpfully" rewrites
`-`/`_` characters, or an incomplete copy from a wrapped line, silently
corrupts the Base64URL payload and produces a structurally-valid-looking but
undecodable string - which the existing pipeline correctly rejects as
`PACKAGE_MALFORMED`, but with no way for an ordinary user to tell what went
wrong. This layer adds three additional ways to get the SAME package text
into the SAME existing pipeline, without ever touching that pipeline's own
trust decisions.

## Architecture

```
Source adapter                    Normalization (pure JVM, zero crypto)         Existing pipeline (UNCHANGED)
───────────────                   ─────────────────────────────────────         ─────────────────────────────
Paste (existing)  ─┐
File (SAF)         ├─► ActivationInput ──► ActivationInputResolver ──► ActivationInputResolution
QR payload         │                         .resolve()                    │
App Link Intent   ─┘                                                       ├─ Ready(ActivationPackageInput.Text)
                                                                             │     └─► MainViewModel.importActivationPackage()
                                                                             │            └─► ActivationPackageRedeemer.redeem()
                                                                             │                   └─► ActivationPackageImporter.import()
                                                                             │                         (signature / issuer trust / expiry /
                                                                             │                          replay / gateway eligibility - ALL unchanged)
                                                                             │                              └─► existing /v1/activate flow
                                                                             │
                                                                             ├─ NeedsHandoff(token)  ──► surfaced as "not yet supported" (see below)
                                                                             └─ Rejected(reason)     ──► surfaced as an adapter-level message
```

- `ActivationInput` / `ActivationInputResolution` / `ActivationInputResolver` -
  `android/app/src/main/java/net/pocvpn/client/activation/ActivationInput.kt`.
  Pure JVM (no `android.net.Uri`, no I/O), unit-tested without
  Robolectric/instrumentation.
- `MainViewModel.submitActivationInput(resolution, targetGatewayId)` is the
  ONE entry point every non-paste adapter calls. For `Ready`, it calls the
  EXISTING `importActivationPackage(text, targetGatewayId)` - byte-for-byte
  the same call the paste path already makes.
- `MainActivity` owns the two Android-framework touchpoints: the SAF
  `ActivityResultContracts.OpenDocument()` launcher, and
  `onNewIntent`/`onCreate`'s handling of an incoming `ACTION_VIEW` Intent.
  Neither performs any validation - both just build an `ActivationInput` and
  hand it to the resolver.
- `ActivationScreen` gained two optional buttons (`onChooseFileClick`,
  `onScanQrClick`), both null by default so every pre-existing call site
  (in particular the relayed-ingress `ActivationScreen` reuse, which
  activates a *different* bearer credential and never touches
  `NovaActivationPackage` at all) is unaffected.

## What is implemented

1. **File import** - `ACTION_OPEN_DOCUMENT` via
   `ActivityResultContracts.OpenDocument()`. Preferred MIME type
   `application/vnd.nova.activation-package` with `text/plain` fallback
   (matches the current `.txt` package convention). Reads the file's exact
   UTF-8 text via `ContentResolver` + `InputStreamReader`; the only
   normalization applied anywhere is the SAME outer-whitespace `.trim()`
   `ActivationPackageParser.parse()` already applies to a pasted string -
   never a Base64URL re-encoding, never a character substitution. No
   persistable URI permission is requested (the file is read exactly once,
   synchronously, at pick time), so there is nothing to explicitly release
   afterward.
2. **QR payload parsing** - `ActivationInputResolver.resolveQr(payload)`
   recognizes exactly two shapes: an `https://` App Link URL (delegates to
   the SAME `resolveAppLinkUrl` validation as path 3 below - never a second,
   independently-implemented URL check), or an offline package payload
   recognized by the EXISTING `ActivationPackageParser.looksLikePackageText`
   prefix check. **The actual camera capture UI is NOT implemented** - see
   "What is NOT implemented" below.
3. **HTTPS Android App Link** - `AndroidManifest.xml`'s `MainActivity`
   intent-filter: `ACTION_VIEW` + `CATEGORY_DEFAULT` + `CATEGORY_BROWSABLE`,
   `android:autoVerify="true"`, exact `scheme="https"`,
   `host="activate.aknova.pp.ua"` (TODO below), `pathPrefix="/a/"` - never a
   wildcard host or scheme. `ActivationInputResolver.resolveAppLinkUrl`
   independently re-validates the SAME host/path/token shape at runtime, so
   a manifest/resolver drift can never silently widen what is accepted.
   A well-formed link produces `NeedsHandoff(token)` - it is NEVER treated
   as a ready package (see the security-invariant test:
   `a NeedsHandoff token is never itself treated as a Ready package`).

## What is NOT implemented (by design, not oversight)

- **The one-time activation handoff backend endpoint** (turning a
  `NeedsHandoff(token)` into an actual package) - see the contract below.
  No fake/guessed endpoint was wired to avoid inventing a server behavior
  that does not exist. Today, resolving an App Link or a QR-encoded
  activation URL surfaces "This activation link requires a feature that
  isn't available yet" and stops there - it never attempts a network call.
- **QR camera capture UI.** This repo has no QR/camera dependency today
  (checked `android/app/build.gradle.kts` - no ZXing/ML Kit/CameraX). Adding
  one means a new third-party dependency AND a new `CAMERA` runtime
  permission in a VPN security app - a decision worth its own explicit
  sign-off rather than folding it silently into this change. The "Scan QR
  code" button exists in the UI and is wired to `ActivationInputResolver`,
  but currently shows "QR scanning is not available in this build yet."
  instead of opening a camera. Swapping in a real scanner later only means
  producing a decoded string and calling
  `viewModel.submitActivationInput(ActivationInputResolver.resolveQr(decoded))`
  - no other code in this layer changes.
- **`assetlinks.json` publication.** The exact JSON this App Link needs is
  below, but it must be served from `https://activate.aknova.pp.ua/.well-known/assetlinks.json`
  - infrastructure this repo's checkout cannot deploy to. Until it is
  published, Android does not auto-verify the App Link; a tapped link falls
  back to a disambiguation chooser (a safe, non-broken degraded state -
  never a security issue, never a silent failure).
- **Confirming `activate.aknova.pp.ua` is the real, assigned production
  activation host.** This repo has no prior reference to an "activation"
  subdomain anywhere - the value chosen here reuses the existing
  `aknova.pp.ua` family (`edge-sthlm.aknova.pp.ua` is the Stockholm
  CDN-fronted ingress - see `ProductionGatewayCatalog.STOCKHOLM`) rather
  than inventing an unrelated domain, but it is a placeholder, not a
  confirmed assignment. `ActivationInputResolver.PRODUCTION_ACTIVATION_HOST`
  is the ONE place to change this once the real host is assigned - the
  manifest's `android:host` literal must be updated to match in the same
  change.

## The one-time activation handoff backend contract (DESIGN ONLY)

This is what `activate.aknova.pp.ua/a/<token>` would need to resolve against
if/when this ships. **None of this is implemented in `gateway/api/` today.**

```
GET /v1/activation-handoff/<token>
```

- `<token>`: the SAME opaque, URL-safe string carried in the App Link path
  (`ActivationInputResolver.resolveAppLinkUrl`'s `TOKEN_FORMAT`,
  16-256 chars, `[A-Za-z0-9_-]+`) - never the activation credential itself,
  never derived from it in a reversible way.
- **Short-lived**: a fixed, short TTL (minutes, not hours) from issuance -
  mirrors this codebase's own `--envelope-valid-for-hours` discipline of an
  explicit, bounded, operator-chosen lifetime, just much shorter, since a
  handoff token's only job is to survive "scan/tap -> app opens -> one HTTP
  round trip", not "carry an entitlement for days".
- **Single-use**: the store must atomically mark a token consumed on its
  first successful resolution (same race-free discipline
  `gateway.api.activations.decide_and_bind` already uses for device
  binding) - a second resolution attempt for the same token fails closed,
  never re-serves the same package.
- **Revocable**: an operator-facing `revoke <token>` action (mirroring
  `activation_tokens.py revoke <activation_id>`'s existing shape) that makes
  an unconsumed token permanently unresolvable.
- **Replay-safe**: resolving a token never itself creates or mutates an
  activation record - it can only ever return an envelope for an activation
  that a human operator already created via the EXISTING, unmodified
  `activation_tokens.py issue` + `activation_envelope_issuer.py
  sign-existing` two-step ceremony. The handoff endpoint's own store is
  disjoint from `activations.json` - it holds ONLY `{token -> package
  bytes, expires_at, consumed}`, never a second copy of activation-lifecycle
  state.
- **Response body**: the EXACT existing `NovaActivationPackage` wire bytes
  (or its `nova-activation:1:...` text form) - never a new wire format. A
  successful response is `200` with that body; an expired/consumed/unknown
  token is a generic `404` (never distinguishing "expired" from "consumed"
  from "never existed" in the response - that distinction is not needed by
  a legitimate caller and would only help an attacker enumerate token
  states).
- **No issuer private key material, ever, anywhere near this endpoint.**
  This endpoint only serves bytes an offline `sign-existing` ceremony
  already produced and an operator already uploaded to this store by some
  separate, out-of-band channel (not specified here - e.g. the SAME
  operator terminal session that ran `sign-existing`, uploading its `--out`
  file). It never calls `activation_envelope_issuer.py` itself, never reads
  a private key file, never signs anything.
- **Auditable without logging the credential**: every resolution attempt
  (success or failure) should be logged with ONLY the token's own
  non-secret identifier (e.g. a hash of the token, or a separate
  operator-assigned label - never the token itself, since the token is a
  bearer reference until consumed) and a timestamp - mirroring
  `activation_envelope_issuer.py`'s own "never print/log the credential,
  only bounded non-secret fields" discipline throughout this codebase.
- **The client MUST still verify the returned `ActivationEnvelope` locally**
  exactly as it already does for a pasted/file/QR-offline package - a `200`
  response is never itself treated as proof of trust. This is already
  guaranteed structurally: whatever bytes this endpoint returns still have
  to go through `ActivationPackageInput.Text`/`Bytes` →
  `ActivationPackageImporter.import()` → the EXISTING signature/issuer/
  expiry/replay/eligibility pipeline, unchanged. Implementing this endpoint
  requires zero changes to that pipeline - only a new call site (inside
  `MainViewModel.submitActivationInput`'s `NeedsHandoff` branch) that fetches
  bytes and hands them to the SAME `ActivationPackageInput.Text`/`Bytes`
  entry point `importActivationPackage` already uses.

## `assetlinks.json` (template - not deployed by this change)

Must be served, byte-for-byte, from
`https://activate.aknova.pp.ua/.well-known/assetlinks.json` (a plain HTTPS
GET, no auth) before `android:autoVerify="true"` will actually auto-verify
this app for that host:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "net.pocvpn.client",
      "sha256_cert_fingerprints": [
        "REPLACE_WITH_REAL_SHA256_CERT_FINGERPRINT"
      ]
    }
  }
]
```

Get the real fingerprint from the ACTUAL signing key that will sign the
shipped APK (never a guessed/placeholder value):

```
keytool -list -v -keystore <release-keystore-path> -alias <alias> | grep "SHA256:"
```

For a debug-signed build during testing, the same command against
`~/.android/debug.keystore` (alias `androiddebugkey`) gives the debug
fingerprint - useful for local App Link testing, never for the production
`assetlinks.json`.

## Security invariants preserved (unchanged code paths)

- Signature verification (`Ed25519ActivationEnvelopeVerifier`) - unchanged,
  untouched.
- Issuer trust anchors (`ProductionActivationIssuerTrustAnchors`) - unchanged.
- Expiry/not-yet-valid/clock-uncertain checks - unchanged.
- Replay guard (`FileActivationReplayGuard`) - unchanged.
- Gateway eligibility (`EntitlementGatewayEligibility`) - unchanged.
- `/v1/activate` call path (`ActivationResilienceCoordinator` →
  `ProvisioningClient`) - unchanged.
- No credential, envelope, package text, or App Link token is logged
  anywhere in the new code (`ActivationInput`'s variants all override
  `toString()` to redact; `MainActivity`'s file-read/App-Link handling never
  logs the Uri's resolved content or the extracted token).
- No new persistence of credential material - `submitActivationInput`
  never writes to `SharedPreferences` or any store; the only persistence
  touched is the EXISTING `FileActivationReplayGuard` file, unchanged.

## Known limits

- QR scanning has no camera UI yet (see above) - a follow-up decision, not
  a silent gap.
- The production activation host is a placeholder pending confirmation.
- The one-time handoff endpoint does not exist; `NeedsHandoff` always
  surfaces as "not yet supported" today.
- `assetlinks.json` is not published anywhere; App Links degrade to a
  disambiguation chooser until it is.
