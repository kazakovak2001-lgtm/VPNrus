# Resilient Bootstrap + Self-Service Activation Architecture

**Status: ARCHITECTURE / RESEARCH.** Nothing in this document is implemented.
It is a design proposal, produced against the real repository state as of
`origin/main` at the SHA recorded in this branch's final report. See the
Decision Gate and Recommended Implementation Slices sections for what would
actually need to be built, and in what order, if this proposal is approved.

This document was produced applying the `vpn-architecture` review discipline
in-session (per `CLAUDE.md` rule 7 - no `Agent`/`Task` subagent dispatch is
available in this session's tool surface for that persona), by reading
`PROJECT_ARCHITECTURE.md`, the relevant `docs/ROADMAP.md` rows (B42-B44,
B51-B55), and the actual activation/manifest source files cited throughout,
rather than re-deriving architecture from scratch or attempting to invoke a
subagent that cannot be dispatched here. Stated once, per that rule, not
repeated per section.

---

## 1. Current-state audit

Verified directly against the repository (file paths and behavior described
below were read, not assumed):

**Activation (B8C1/B8C1A/B8C1B/B8C1C, `gateway/api/activations.py` +
`gateway/tools/activation_tokens.py`):**
- A durable JSON store keyed by `SHA-256(credential)` - the plaintext
  credential is never persisted, only its digest (`credential_digest`).
- `issue_activation()` (operator CLI only) generates a random
  `secrets.token_urlsafe(32)` credential and a random 32-hex `activation_id`,
  with `max_devices` and optional `expires_at`. The plaintext credential is
  printed to stdout **exactly once**, at issue time - this file's own
  docstring makes that discipline explicit.
- `decide_and_bind()` is the one function `POST /v1/activate` calls. It runs
  under a single `flock(LOCK_EX)` spanning read -> decide -> write, so two
  concurrent first-use requests for different public keys against the same
  `max_devices` activation cannot both win (pending entries count toward the
  limit the instant they exist). `provision_with_activation()` additionally
  wraps decide/provision/finalize-or-rollback in a **per-activation** lock
  (keyed by credential digest) so the AWG provisioning side effect itself is
  serialized per activation, not just the bookkeeping. This is already a
  correct, race-free, atomic redemption transaction - see the "Redemption
  transaction" section below for why this slice reuses it unchanged.
- Device identity for binding is the device's own AmneziaWG public key
  (`ClientKeyRepository`/`AwgClientKeyRepository`,
  `android/app/src/main/java/net/pocvpn/client/identity/ClientKeyRepository.kt`):
  a real Ed25519X25519 keypair generated once, private key AES-GCM-encrypted
  at rest, public key handed to `/v1/activate`. This is already the
  "device generates keypair -> activation includes public key -> server
  atomically binds" model the task asks about - it exists today, it is not a
  gap.
- `ActivationResilienceCoordinator` (B30,
  `android/.../controlplane/ActivationResilienceCoordinator.kt`) wraps the
  client's own `/v1/activate` call with short-circuit local-freshness reuse
  and retries across `ControlPlaneOrigin` candidates from
  `ControlPlaneOriginSetBuilder.forGateway()` - which **only ever returns
  `ProductionGatewayCatalog`-compiled hosts, never an arbitrary caller-
  supplied URL** (its own docs state this is a structural, not conventional,
  guarantee for exactly the reason this design must respect: "never accept
  arbitrary user-supplied activation URLs in Auto mode"). This is the
  existing control-plane multi-origin pattern - separate from, and today
  narrower than, the manifest's multi-origin pattern (see below).
- Nginx already exposes `/v1/activate` (`POST`) and `/v1/manifest` (`GET`)
  as the only two routes reachable **without** an existing device-specific
  authenticated session - `gateway/edge/nginx-pocvpn.conf` and
  `nginx-pocvpn-stockholm.conf` both show this. **No `limit_req`/`limit_conn`
  directive exists anywhere in `gateway/edge/*.conf` today** - there is
  currently no rate limiting on `/v1/activate` or `/v1/manifest` at the edge.
  This is a real, pre-existing gap this design must not paper over (see
  "Abuse/rate limiting" and "Owner decisions required").

**Enrollment tokens (older, distinct mechanism -
`gateway/tools/enrollment_tokens.py` + `gateway/api/tokens.py`):**
- A token is bound to a specific public key **at issuance time** by the
  operator CLI; the HTTP API is read-only over that store by construction
  (no write-capable code path exists under `gateway/api/` for it at all).
  This is fundamentally different from activation credentials, which bind to
  *whichever* device first presents them, up to `max_devices`. This document
  never conflates the two, per the task's explicit instruction, and does not
  touch `enrollment_tokens.py`/`tokens.py`.

**Manifest / bootstrap trust (B11/B12/B17/B20/B42-B44,
`android/.../reachability/*.kt`):**
- `EndpointManifest` (`EndpointManifest.kt`) is a signed, versioned, typed
  set of `EndpointDescriptor`s, each carrying id/roles/region/provider/ASN
  and a list of `EndpointTransportBinding` (kind/host/port/free-form string
  metadata). `ManifestCanonicalizer` is a deterministic, dependency-free,
  fixed-field-order binary encoding - the exact bytes an offline tool
  (`gateway/tools/manifest_signing.py`) signs and `Ed25519ManifestVerifier`
  verifies. No credential-bearing material is ever in this structure.
- `Ed25519ManifestVerifier` checks: unknown signing key -> reject, clock
  skew (issuedAt implausibly in the future, 5-minute tolerance) -> reject,
  expired -> reject, bad signature -> reject. Every rejection is a distinct
  typed `ManifestVerificationFailureKind`.
- `EndpointManifestRepository.trustedState()` is **the one place** a
  manifest becomes trusted for a session, with fixed precedence: (1) LKG if
  it verifies, else (2) the embedded bootstrap if it *also* verifies against
  the same trust anchors, else (3) `NoneTrusted` - an explicit fail-closed
  state, never a silent "use whatever shipped in the APK anyway."
  `EmbeddedBootstrapManifest` is a real, offline-signed manifest naming both
  real production gateways with only public routing facts. `ManifestRollbackGuard`
  (consumed by `offer()`) prevents an older-or-equal-version candidate from
  ever replacing what is currently trusted.
- **Key rotation precedent already exists**: `EmbeddedBootstrapManifest`
  embeds *two* simultaneously-trusted key IDs
  (`prod-manifest-key-2026-09-01` and `prod-manifest-key-2026-09-14`) via
  `FixedManifestTrustAnchors`. This is the exact mechanism this design reuses
  for activation-issuer key rotation - no new rotation mechanism is needed.
- **Multi-origin delivery already exists for the manifest** (B20):
  `MultiOriginManifestDistributionClient` fetches from every configured
  `BuildConfig.MANIFEST_URLS` origin (both real production gateways today,
  Frankfurt and Stockholm) on every refresh, feeds each origin's bytes
  through the *same* `EndpointManifestRepository.offer()` trust boundary,
  and an origin is explicitly "transport availability only, never a trust
  authority" (verbatim invariant from `PROJECT_ARCHITECTURE.md`). This is
  already exactly Pattern C from the task's research context - it does not
  need to be invented for manifests, only reused for the activation package.
- B44 (`docs/ROADMAP.md`) added signed endpoint operational state
  (`ACTIVE`/`DISABLED`/`RETIRED`) for emergency rotation using existing
  manifest metadata - status **PARTIAL**, route-level disable and production
  control-plane emission remain out of scope there.
- B43 "Bootstrap Resilience" (**PARTIAL**) and B52 "Offline / Outage Mode
  research" (**RESEARCH**, not started) are the two existing roadmap rows
  closest to this document's subject; neither is an activation-package or
  self-service-issuance design. B51 (non-datacenter endpoint research) and
  B54 (restricted-network field validation) are adjacent but distinct.

**What does not exist today** (confirmed by search, not assumed absent):
no activation-package/voucher format, no QR/deep-link import path, no
self-service (non-operator) issuance channel, no dedicated "bootstrap edge"
service or nginx location distinct from the existing `/v1/activate`/
`/v1/manifest` routes, no rate limiting at the edge for either route, no
delegated activation-issuer key distinct from the manifest signing key, no
peer-pairing/relay code.

---

## 2. Problem statement

A new Nova install has no per-device credential and no trusted live manifest
beyond the embedded bootstrap. If the reachable network already blocks the
real Nova API host(s) before the device has ever successfully talked to
them, the device has no way to obtain a working activation credential or a
fresher manifest than what shipped in the APK - a circular dependency
between "needs the API to activate" and "needs to already be activated (or
otherwise routed) to reach the API." The goal is to give the client enough
*locally verifiable, portable* information ahead of time that the very
first live connection attempt is not the device's *only* chance to guess at
where the Nova control plane lives, without turning that portable
information into a universal secret or an unrestricted VPN.

## 3. Constraints

- Reuse the existing Ed25519/manifest trust primitives; no new cryptography.
- Never conflate activation credentials with enrollment tokens.
- Never replace `decide_and_bind`/`provision_with_activation`'s already
  race-free redemption transaction.
- Never let a package supply an arbitrary host/URL that bypasses
  `ControlPlaneOriginSetBuilder`'s "no caller-supplied origin" invariant.
- No infrastructure stood up, no production nginx/gateway changes, no
  billing, no peer relay, in this slice.
- No claim of guaranteed whitelist bypass, Russia connectivity, or
  untraceability anywhere in the resulting design or its UX copy.

## 4. External design patterns reviewed

Summarized only as architectural reference; Nova implements its own
mechanism (see Constraints):

- **Proton-style alternative routing** -> informs `BootstrapReachabilityResolver`
  (section 11): a small resolver layer that tries alternate *paths*, never a
  general traffic proxy.
- **Psiphon-style embedded bootstrap knowledge** -> already implemented for
  the manifest (`EmbeddedBootstrapManifest`); this design extends the same
  idea to the activation package rather than re-inventing it.
- **Lantern-style multi-origin configuration, trust-by-signature** ->
  already implemented for the manifest (`MultiOriginManifestDistributionClient`);
  reused verbatim for package *delivery* (section 10).
- **Outline/Amnezia-style self-contained access package** -> the activation
  package itself (section 7): QR/deep-link/file/clipboard, verifiable before
  any network access.

## 5. Target architecture

```
Activation Package (signed, portable)
        |
ActivationPackageVerifier      (new, offline, mirrors Ed25519ManifestVerifier)
        |
BootstrapCandidateRepository   (new, thin - reads EndpointManifestRepository)
        |
EndpointManifestRepository     (existing, UNCHANGED trust precedence)
        |
BootstrapReachabilityResolver  (new, thin orchestration only)
        |
ReachabilityEngine / NetworkProfiler / RestrictionClassifier   (existing, reused as-is)
        |
BootstrapLaneClient            (new - talks to the SAME /v1/activate, /v1/manifest routes)
        |
provision_with_activation()    (existing, gateway/api/activations.py, UNCHANGED)
        |
existing profile repositories (AWG/Xray/etc, UNCHANGED)
```

The activation package is deliberately **not** a second trust root. It is a
signed pointer/envelope: it carries (a) a reference to an activation
credential already issued through the existing `activation_tokens.py issue`
path, and (b) optional, non-authoritative hints about which manifest-known
endpoints to try first. It never carries new host/IP facts that aren't
already inside a manifest the client can independently verify, and it never
grants entitlement by itself - see section 6 and section 15 (Revocation).

## 6. Trust model

One hierarchy, two purposes, already partially precedented by the manifest's
own two-simultaneously-trusted-keys design:

```
Offline root ceremony (docs/B12_MANIFEST_KEY_CEREMONY.md process, reused)
        |
        +-- manifest signing key(s)        (existing: prod-manifest-key-*)
        |
        +-- activation-issuer key(s)       (NEW, delegated, distinct from manifest keys)
```

- The activation-issuer key is a **separate** key from the manifest signing
  key, generated the same offline way, embedded the same way
  (`FixedManifestTrustAnchors`-shaped keyset, but its own set - never merged
  with the manifest trust anchors) so a compromise of one key's *usage
  surface* does not automatically compromise the other's.
- The manifest root/signing key stays reserved for infrequent, high-value,
  operator-only manifest signing (as today). The activation-issuer key is
  the one used for higher-volume, eventually self-service package issuance -
  this is precisely "do not use the root/high-value manifest key for
  high-volume online voucher issuance," satisfied by delegation, not by
  inventing a second independent PKI.
- **Trust comes from the Ed25519 signature over canonical bytes, exactly as
  today.** A compromised delivery origin (dashboard, mirror, email) can
  serve anything it wants; the client rejects anything that doesn't verify.
- A valid package signature proves the package was genuinely issued by
  Nova's activation-issuer key. It does **not** prove current entitlement -
  the activation store (`gateway/api/activations.py`) remains the sole,
  final, online authority for revoked/consumed/device-count/expiry (see
  section 15).

## 7. Activation package format

Minimum fields, derived from the audit above - deliberately **not** the
example schema in the task prompt, because several of its fields either
already exist server-side (device counting, expiry) or would create a
second, competing source of truth if duplicated client-side:

```
NovaBootstrapPackage {
    schemaVersion        : int            // format version, independent of manifestVersion
    activationId         : 32 lowercase hex   // same non-secret id activations.py already prints via status/list
    credential           : string         // the SAME plaintext bearer credential issue_activation() already produces once
    issuedAt             : epoch millis
    notBefore            : epoch millis   // package-envelope validity window; independent of the activation's own server-side expires_at
    expiresAt            : epoch millis   // package-envelope validity window; SHORTER than or equal to the activation's own expires_at is the operational default, not a hard schema rule
    bootstrapManifestVersion : int        // informational only - "the manifest version this package's issuer expected the client to already trust or fetch"
    bootstrapEndpointHints   : list of EndpointId strings (0..N) // NON-authoritative ranking hint, see section 9
    nonce                 : 16 random bytes  // LOCAL replay/import dedupe only, not a security boundary (see section 14)
    issuerKeyId            : string
    signature              : Ed25519, 64 bytes, over the canonical encoding of every field above
}
```

Explicit answers to the task's checklist:

- **Must be inside**: `activationId`, `credential`, the envelope's own
  `notBefore`/`expiresAt`, `issuerKeyId`, `signature`. Without the plaintext
  credential the package cannot bootstrap anything - see "Model" discussion
  in section 16 for why this is not a new secret category.
- **Must NOT be inside**: `max_devices`, a redemption counter, per-device
  keys, AWG/Xray/REALITY credentials, raw host/IP/port facts not already in
  a verifiable manifest, any PII.
- **Public**: `activationId`, `issuerKeyId`, `schemaVersion`,
  `bootstrapManifestVersion`, `bootstrapEndpointHints`, timestamps,
  `signature` itself.
- **Secret** (bearer, not encrypted - see below): `credential`.
- **Signed**: every field, over the same fixed-order canonical-bytes
  convention `ManifestCanonicalizer` already uses (reused, not reinvented).
- **Encrypted**: no. Rationale: the client has no pre-shared key or
  passphrase to decrypt with that wouldn't itself need the same secure
  channel the package already travels over; encrypting the credential a
  second time adds UX friction (a passphrase) without shrinking the actual
  exposure window, which is already bounded by the envelope's own
  `notBefore`/`expiresAt` and the activation's server-side `max_devices`/
  `expires_at`/revocation. This mirrors why the existing plaintext
  credential itself is not encrypted at rest in the operator's terminal
  output today - the *scope* of the secret is deliberately bounded through
  server-side mechanisms, not through cryptographic wrapping of the bearer
  value.
- **Stable identifier**: `activationId`.
- **One-time value**: the `credential`, made one-time *in effect* by
  `decide_and_bind()`'s existing per-key-then-max_devices binding (already
  race-free, see section 1) - for the common `max_devices=1` case this is
  genuinely single-use; for `max_devices>1` it is a shared secret with an
  already-enforced cap, exactly as today, unchanged by this design.
- **Replay prevention**: two independent layers, never confused with each
  other - (a) server-side: unchanged, already race-free
  `decide_and_bind`/`per_activation_lock`. (b) client-side: the `nonce` is
  used only for **local** "have I already successfully imported this exact
  package on this device" bookkeeping (a UX/idempotency convenience, e.g. to
  avoid re-showing "Checking activation package" for a package already
  consumed on this device) - it is explicitly **not** a security control and
  must never be relied on to prevent a *different* device from redeeming a
  copied package; that property is, and remains, the server's job.
- **Package theft**: identical blast radius to today's credential theft -
  bounded by the activation's own `max_devices`/`expires_at`/revocation.
  The package's own shorter envelope `expiresAt` reduces the *exposure
  window* (a screenshot/forward found weeks later is simply rejected
  locally as `PACKAGE_EXPIRED` before ever reaching the network) but does
  not change the underlying entitlement model.
- **Simultaneous redemption from two devices**: unchanged from today -
  `decide_and_bind`'s existing flock-guarded pending-count-toward-max_devices
  check already makes this race-free (see section 1's citation); the
  package format adds nothing here and removes nothing.
- **max_devices interaction**: none beyond what already exists - the
  package is a delivery wrapper around one `activationId`; every device
  that imports a copy of the same package presents the same underlying
  credential to the same, unchanged, server-side entitlement check.
- **After expiry**: two independent, non-conflatable outcomes - a
  *package-envelope*-expired package is rejected locally
  (`PACKAGE_EXPIRED`) without any network call; a package that still
  verifies locally but whose underlying activation has separately expired
  server-side still reaches `decide_and_bind`'s own `EXPIRED` outcome,
  surfaced as `ACTIVATION_EXPIRED` (not `PACKAGE_EXPIRED` - these must
  render as distinct UX states, see section 20).
- **Issuer-key rotation**: identical mechanism to the manifest's already-
  proven two-key `FixedManifestTrustAnchors` pattern - embed the current and
  the immediately-previous activation-issuer key simultaneously; a package
  signed by either verifies. A signed keyset-update object (the task's own
  "signed keyset updates" idea) is explicitly deferred to future work
  (section 30) rather than built now - out of scope per the "no new
  production control-plane surface this slice" instruction.
- **Device clock wrong**: reuse `Ed25519ManifestVerifier`'s existing
  clock-skew-tolerance constant and reasoning verbatim (a small forward
  tolerance, no backward tolerance) for `notBefore`/`expiresAt`; distinguish
  a package that is `EXPIRED` under a plausible clock from one that is only
  rejected because the *device* clock is implausible, and surface the latter
  as the distinct `CLOCK_UNCERTAIN` failure (section 20) rather than
  silently loosening the check.

## 8. Key hierarchy

Covered in section 6. Concretely: one offline ceremony process (the
existing `docs/B12_MANIFEST_KEY_CEREMONY.md` procedure, reused, not
reinvented) produces both the manifest signing key and a **new**,
independently rotatable activation-issuer key. Embedded public-key sets for
each purpose are separate `FixedManifestTrustAnchors`-shaped objects, never
merged. Compromise of the activation-issuer key's signing capability lets an
attacker mint *packages* that verify - but per section 6/15, a verifying
package alone confers no entitlement; the server-side activation store is
still the final gate. This bounds blast radius of an issuer-key compromise
to "can produce spam/decoy packages," not "can provision arbitrary devices."

## 9. Bootstrap candidate model

No new candidate type. `bootstrapEndpointHints` in the package is a list of
`EndpointId` values that **must already appear** in whatever manifest the
client currently trusts (via `EndpointManifestRepository.trustedState()`,
unchanged). The `BootstrapCandidateRepository` (new, thin) does exactly one
thing: given the currently-trusted manifest and an optional hint list,
produce an ordered subset of that manifest's own `EndpointDescriptor`s/
`EndpointTransportBinding`s - hints reorder, they never introduce. This is
what makes "never accept arbitrary user-supplied activation URLs" hold
structurally for bootstrap too, not just for the existing `ActivationResilienceCoordinator`
path: a hint that names an `EndpointId` absent from the trusted manifest is
silently ignored (never an error, never a fallback host).

A future slice (see section 32) may add a narrow capability flag to
`EndpointTransportBinding.metadata` (already a free-form string map, so this
needs no wire-format change) marking which bindings a *bootstrap* client
(no device profile yet) is allowed to dial - server-enforced (section 11),
not merely a client-side hint.

## 10. Multi-origin retrieval design

For the **package itself**: reuse Pattern C exactly as already proven for
manifests. The package's integrity is its signature; therefore *any* of
dashboard, email, QR, downloadable file, or a static mirror is pure
delivery, never a trust authority. No new mechanism is needed here - the
manifest's own `MultiOriginManifestDistributionClient` already demonstrates
the pattern this design would apply to package distribution, and the
principle transfers without new code (there is nothing to "fetch" over
multiple origins for a package the user already imported by QR/file/paste -
multi-origin *retrieval* in the package case reduces to "multi-channel
*distribution*", handled in section 27, not a network resolver).

For the **manifest** consulted during bootstrap: unchanged - the existing
`EndpointManifestRepository`/`MultiOriginManifestDistributionClient`
precedence (LIVE via configured origins -> LKG -> EMBEDDED) is reused
as-is; a bootstrapping device with no profile yet can still refresh/consult
the manifest through this exact existing path, since manifest fetch has
never depended on per-device provisioning.

## 11. Restricted bootstrap lane

**Finding, not proposal**: the production control plane already is a
narrowly-scoped, unauthenticated-reachable surface for exactly two routes -
`POST /v1/activate` and `GET /v1/manifest` (confirmed in both
`nginx-pocvpn.conf` and `nginx-pocvpn-stockholm.conf`). There is no VPN data
plane reachable before activation succeeds; "restricted bootstrap lane" is
therefore mostly **already true by construction** for the control-plane
half of the problem - a bootstrapping device was never going to get
"arbitrary Internet access" through these two HTTP routes regardless of this
design.

What is genuinely missing (confirmed absent, not assumed): **rate limiting**.
No `limit_req`/`limit_conn` exists anywhere in `gateway/edge/*.conf` today,
for any route, including `/v1/activate`. Publishing this design (and
especially self-service issuance, section 25) increases the incentive to
abuse `/v1/activate`, so closing this gap is a genuine prerequisite - see
section 22 and "Owner decisions required."

Enforcement must be server-side (nginx `limit_req_zone`/`limit_req` keyed by
client IP for `/v1/activate` and `/v1/manifest`, plus the existing
per-activation flock already bounding concurrent redemption attempts for one
`activationId`) - never client-side-only. A dedicated "Bootstrap Edge"
service/segment is **not** proposed for v1: the two existing routes are
already narrow enough that standing up a separate nginx listener or network
segment would add operational surface without closing a real gap that rate
limiting doesn't already close more cheaply. Revisit this decision if a
production incident shows the two-route scope is not narrow enough in
practice.

## 12. Redemption transaction

Unchanged. `provision_with_activation()` (section 1) already provides:
atomic per-activation serialization across the whole
decide/provision/finalize-or-rollback sequence, race-free device-limit
enforcement under concurrent same/different-key requests, and monotonic,
ownership-checked rollback on a failed provisioning attempt. This design
adds nothing to `/v1/activate`'s semantics - a package-derived redemption
request is byte-for-byte the same `(public_key, activation_credential)` pair
the existing endpoint already accepts. **No change to `/v1/activate` is
required by this slice.**

## 13. Device binding

Unchanged (section 1): the device's own AWG keypair
(`ClientKeyRepository`) is the binding identity, exactly as today. A
reinstall/lost-app-data/new-device scenario is already the existing
`BOUND_EXISTING` vs `DEVICE_LIMIT` outcome space in `activations.py` -
nothing new to design here.

## 14. Replay prevention

See section 7's answer in full. Server-side: unchanged, already correct.
Client-side `nonce`: explicitly non-security, local dedupe only - stated
here again because it is the single easiest place for a future implementer
to over-claim a security property this field does not have.

## 15. Revocation

Local package verification proves *provenance* (issued by Nova's
activation-issuer key), never *current entitlement*. A device that only
ever gets as far as offline package verification, and never reaches a live
`/v1/activate` call, must never be shown "activated" - the client's own
package-import success state must be phrased as "package verified, ready to
attempt activation," not "activated" (see section 20/24). Revocation remains
exactly what it already is: `revoke_activation()` flips the activation's
server-side `status` to `REVOKED`, observed by any subsequent
`decide_and_bind`/`finalize_reservation` call under the same lock discipline
already analyzed for the B8C1A/B8C1B races. A package cannot un-revoke
itself by being re-imported.

## 16. Manifest/LKG/embedded integration

Deliberately unchanged (section 1/9/10): `EndpointManifestRepository`'s
existing LIVE->LKG->EMBEDDED precedence and rollback guard are reused
verbatim. The package never carries manifest bytes and never asserts a
manifest version *takes precedence over* what the device already trusts -
`bootstrapManifestVersion` is informational (lets the client's diagnostics
report "issuer expected version N, device currently trusts version M"),
never an input to `ManifestRollbackGuard`. This satisfies the task's
explicit warning against letting an older package roll back an
already-trusted newer manifest, structurally: the field is never consulted
by the rollback guard at all.

## 17. Transport selection integration

Not touched. Once `provision_with_activation()` succeeds, normal profile
provisioning (AWG/Xray/REALITY/TLS-TCP/etc, as already gated by
`TransportRegistry`/`AutoGatewaySelector`/Smart Connect) takes over
unchanged. The bootstrap package's authority ends the moment a device
profile exists - see section 24.

## 18. Server architecture

No new service for v1 (section 11). Concretely, this slice's *eventual*
server-side implementation work (not built now) is:
1. `limit_req_zone`/`limit_req` for `/v1/activate` and `/v1/manifest` in
   both existing nginx configs (closes the confirmed gap in section 1/11).
2. A new, separate CLI (mirroring `activation_tokens.py`'s own structure,
   never modifying it) for the future self-service issuer to mint activation
   credentials via the *existing* `issue_activation()` function, then wrap
   the result into a signed `NovaBootstrapPackage` using the new,
   independently-rotatable activation-issuer key. This CLI is an *issuance*
   tool only - it never touches `/v1/activate`'s runtime path.

## 19. Client architecture

New components, all thin, all reusing existing authorities:
- `ActivationPackageParser` - decode/schema-validate only, no crypto.
- `ActivationPackageVerifier` - mirrors `Ed25519ManifestVerifier`'s shape
  (own trust-anchor set, own typed failure enum) almost exactly; genuinely
  new code, but not a new *pattern*.
- `BootstrapCandidateRepository` - thin read-through over
  `EndpointManifestRepository.trusted()` plus hint reordering (section 9).
- `BootstrapReachabilityResolver` - thin orchestration calling the existing
  `ReachabilityEngine`/`NetworkProfiler`/`RestrictionClassifier` over the
  candidates above; produces an ordered attempt list, never a new scorer.
- `BootstrapLaneClient` - calls the same `/v1/activate` HTTP shape the
  existing `ProvisioningClient`/`ActivationResilienceCoordinator` already
  use, parameterized by the package's credential instead of an
  operator-typed one; **not** a new HTTP client stack.

**Explicitly not duplicated**: `ReachabilityEngine`, `PathScorer`,
`PathCandidateBuilder`, `AutoGatewaySelector`, `SmartConnectDecisionEngine`,
`EndpointManifestRepository`, `Ed25519ManifestVerifier`'s crypto primitive,
`ManifestCanonicalizer`'s encoding convention, `ClientKeyRepository`,
`provision_with_activation()`.

## 20. Failure model

Typed, per the task's own list, mapped to this design's actual checks (no
invented category beyond what a component above actually produces):
`PACKAGE_MALFORMED`, `PACKAGE_SIGNATURE_INVALID`, `PACKAGE_EXPIRED`,
`PACKAGE_NOT_YET_VALID`, `PACKAGE_VERSION_UNSUPPORTED`,
`ISSUER_KEY_UNKNOWN`, `CLOCK_UNCERTAIN` (section 7),
`BOOTSTRAP_MANIFEST_UNAVAILABLE` (delegates to
`TrustedManifestState.NoneTrusted`, unchanged), `NO_TRUSTED_BOOTSTRAP_CANDIDATE`,
`ALL_BOOTSTRAP_PATHS_UNREACHABLE`, `BOOTSTRAP_AUTH_REJECTED` (maps to
`decide_and_bind`'s existing `INVALID`), `ACTIVATION_REVOKED` (existing
`REVOKED_OUTCOME`), `ACTIVATION_EXPIRED` (existing `EXPIRED` - kept
textually distinct from `PACKAGE_EXPIRED`, section 7), `DEVICE_LIMIT_REACHED`
(existing `DEVICE_LIMIT`), `PROFILE_PROVISIONING_FAILED` (existing
provisioning-error path), `BOOTSTRAP_RATE_LIMITED` (new, once section 11's
rate limiting exists).

## 21. Threat model

- **Network adversary**: unchanged from the existing manifest/activation
  threat surface - DNS/IP/DPI blocking of one origin is mitigated by the
  already-proven multi-origin manifest fetch and, for the package, by
  channel-independent delivery (section 27); this design cannot create
  connectivity where a hard whitelist admits none (section 27's own
  limitation section restates this explicitly).
- **Package thief**: bounded exactly as an activation-credential thief is
  bounded today (section 7) - no worse.
- **Reverse engineer**: assume APK-embedded activation-issuer public keys,
  manifest public keys, and embedded bootstrap manifest are all recoverable
  - none of them are secrets; only the per-package `credential` is, and it
  is never embedded in the APK.
- **Malicious mirror**: cannot forge a package or manifest (signature), and
  cannot roll back a newer trusted manifest (`ManifestRollbackGuard`,
  unchanged) or a newer-issued package (package `notBefore`/`expiresAt` are
  envelope facts checked against device clock, not against "newest seen" -
  a malicious mirror serving an old-but-still-validly-signed package can at
  worst hand out a package whose underlying `activationId` may already be
  consumed/revoked, which `decide_and_bind` already rejects).
- **Compromised bootstrap endpoint** (i.e. a compromised production
  gateway's control-plane process): blast radius is exactly what compromise
  of `pocvpn-api` already means today - it is not raised or lowered by this
  design, because no new server-side trust authority is introduced. It
  cannot mint arbitrary permanent device profiles beyond what a compromised
  `pocvpn-api` could already do to `activations.py`'s own store.
- **Compromised activation voucher/credential**: bounded by
  `max_devices`/`expires_at`/revocation, unchanged.
- **Clock manipulation**: section 7's `CLOCK_UNCERTAIN` handling.
- **Replay**: section 14.
- **Denial of service**: section 11/22.

## 22. Abuse/rate limiting

The one concrete, currently-missing control this design surfaces (section
11): per-IP `limit_req` on `/v1/activate` and `/v1/manifest`. Additional
layers worth designing *before* self-service issuance ships (section 25),
not before this architecture slice: per-`activation_id` attempt caps (cheap
to add - `decide_and_bind` already reads/writes under a per-activation lock,
a natural place to also track a bounded recent-attempt counter without
introducing a second store) and avoiding simplistic IP-only lockouts for
shared/NAT'd carrier IPs, per the task's own caution.

## 23. Privacy

Bootstrap-time server visibility, enumerated exhaustively for this design:
source IP (already true for any HTTP request), `activation_id`/credential
digest (already logged server-side today, unchanged), the device's AWG
public key (already sent to `/v1/activate` today), app version (if already
sent - unchanged), the manifest version currently trusted, and which
transport binding was attempted. Nothing new: no device serial, IMEI,
advertising ID, phone number, contacts, or new fingerprinting is introduced
by this design.

## 24. Observability

New, safe event names for the new client components only (server-side
event naming is unchanged, existing): `BOOTSTRAP_PACKAGE_IMPORTED`,
`BOOTSTRAP_PACKAGE_VERIFIED`, `BOOTSTRAP_PACKAGE_REJECTED` (with the typed
kind from section 20, never a raw string), `BOOTSTRAP_MANIFEST_SOURCE_SELECTED`,
`BOOTSTRAP_PATH_ATTEMPT`, `BOOTSTRAP_PATH_REACHABLE`,
`BOOTSTRAP_LANE_ESTABLISHED`, `ACTIVATION_REDEMPTION_STARTED`,
`ACTIVATION_REDEMPTION_ACCEPTED`, `ACTIVATION_REDEMPTION_REJECTED`,
`DEVICE_BOUND`, `NORMAL_PROFILE_PROVISIONED`, `BOOTSTRAP_CONSUMED`. None of
these ever carry the plaintext credential, a private key, raw package
bytes, or a bearer token - matching the existing `SupportDiagnosticsRecorder`
discipline of tagging events with closed enums/indices, never raw secrets
or hostnames.

## 25. UX

```
Install Nova -> Open app -> Scan QR / paste activation package
  -> "Checking activation package"      (local verification, section 7/20)
  -> "Finding a connection route"       (BootstrapReachabilityResolver, section 19)
  -> "Activating this device"           (BootstrapLaneClient -> /v1/activate, unchanged endpoint)
  -> "VPN is ready"
```

No manifest/transport/gateway/signing-key language surfaces in this flow.

## 26. Migration/backward compatibility

Phase 1 (this design, if implemented): operator-issued raw activation
credentials (today's flow) keep working completely unchanged - the package
format is an additional, optional, *wrapper* around the exact same
`issue_activation()`-produced credential, not a replacement transport for
it. Phase 2: self-service issuance (section 25 interface only, not billing)
becomes the default distribution path for new customers. Phase 3: raw
credential distribution (copy/paste a bare token) is deprecated for new
issuance but never removed from what `/v1/activate` accepts, so already-
issued/undelivered credentials keep working. No existing user or activation
record is broken at any phase - `activations.py`'s schema is untouched.

## 27. Hard-whitelist limitations

Stated plainly, matching the task's explicit prohibition on overclaiming:
if a network permits only a fixed external destination whitelist and *none*
of Nova's manifest-known endpoints, package-delivery channels, or issuer
domains are on that whitelist, this architecture cannot create
connectivity that does not exist. Multi-origin delivery and embedded
bootstrap knowledge reduce dependence on any *one* reachable path; they
cannot manufacture a path where the network genuinely permits none. This
document makes no guaranteed-whitelist-bypass, guaranteed-Russia-connectivity,
untraceability, or universal-censorship-bypass claim, anywhere. Future,
separately-researched mechanisms for the genuinely-hard-whitelist case
(pre-provisioned working endpoint, trusted personal relay/pairing, offline
transfer of a currently-reachable gateway's data) are named in the task
prompt and are explicitly out of scope for this slice (see peer pairing,
section 29, and B51).

## 28. Test plan

Unit: package parsing (well-formed/malformed), signature verification
(valid/unknown-key/tampered), expiry/not-before (including clock-skew
tolerance boundary), hint-list filtering against a manifest that does/does
not contain the hinted `EndpointId`s, and - reusing existing test fixtures
where possible - the already-proven `decide_and_bind`/`finalize_reservation`/
`unbind_reservation` race tests remain the authority for redemption
correctness; this design adds no new redemption test surface because it
adds no new redemption code path.

Integration: primary manifest origin reachable/blocked (reuses existing
`MultiOriginManifestDistributionClientTest` fixtures), LKG-only, embedded-
only, all manifest origins blocked, a `BootstrapLaneClient` request against
a revoked/consumed/expired activation (reuses existing `activations.py`
fixtures, no new server-side test surface needed), simultaneous redemption
(already covered by existing B8C1A/B8C1C tests, re-verified not re-invented).

Chaos: DNS failure/timeout/TLS failure/reset during bootstrap lane
resolution (reuses existing `ReachabilityEngine`/`RestrictionClassifier`
chaos-test patterns, not a new harness), corrupt persisted LKG (existing
`EndpointManifestRepositoryTest` coverage, reused).

Security: replay of a captured package against a second device (must be
rejected at the server, proving client-side `nonce` really is non-load-
bearing - see section 14), signature substitution/downgrade (must be
rejected by `ActivationPackageVerifier`), attempted unlimited bootstrap
egress (must be structurally impossible today per section 11's finding -
test asserts no data-plane route exists pre-activation), device-count race
under concurrent redemption from two copies of the same package (reduces to
the already-proven `decide_and_bind` race test, re-run, not reinvented).

No test in this plan produces or implies a real Russia/hard-whitelist claim.

## 29. Rollout plan

See section 26 (phased backward compatibility) and section 32 (slices). No
rollout of production infrastructure occurs in this document.

## 30. Open questions

- Should the activation-issuer key rotation eventually be delivered as its
  own small signed keyset-update object (mirroring a future manifest
  keyset-update mechanism), or is APK-release-only rotation acceptable
  indefinitely? Deferred - not blocking Slice 1/2.
- Should `bootstrapEndpointHints` be present at all in v1, given
  `EndpointManifestRepository`'s existing precedence already produces a
  reasonable default ordering? It is optional and non-authoritative, so it
  can ship empty in v1 without any behavior change, and be populated later
  once real operational data justifies it.
- Peer pairing (section 29 of the task prompt / section 31 below) remains
  future research only; no architectural commitment is made here beyond
  "the design above does not preclude it" (a peer-transferred package is
  just another delivery channel, per section 10's principle).

## 31. Explicitly rejected alternatives

- **A separate, independent trust root for activation packages** - rejected;
  violates the task's own "one root architecture, multiple delivery paths"
  principle and the repository's own precedent (one ceremony, delegated
  keys).
- **A brand-new "bootstrap edge" service/network segment for v1** -
  rejected for now (section 11); the existing two-route surface is already
  narrow, and the real gap is rate limiting, not topology.
- **Encrypting the package's credential field** - rejected (section 7); adds
  UX friction without shrinking the actual exposure window, which is already
  bounded by envelope expiry and server-side entitlement controls.
- **A package-level redemption/device counter duplicating `max_devices`** -
  rejected; would create a second, unsynchronized source of truth racing
  against the server's own already-correct counter.
- **Model 3 (unauthenticated public bootstrap tunnel with broad restricted
  egress)** - rejected; the existing two narrow HTTP routes already satisfy
  "restricted bootstrap lane" without introducing a new tunnel/egress
  surface to defend at all.
- **Reusing enrollment tokens as the bootstrap credential** - rejected per
  the task's explicit instruction not to conflate the two mechanisms; they
  have different binding semantics (pre-bound-to-a-key vs. first-use-binds).

## 32. Recommended implementation slices

Numbered as a **new** roadmap item - B42-B55 are all already-assigned,
unrelated or adjacent work (section 1); this proposal is provisionally
**B56 - Self-Contained Bootstrap Activation Packages**, to be confirmed by
the repository owner before `docs/ROADMAP.md` is updated with anything
beyond the "ARCHITECTURE / RESEARCH" placeholder row this branch adds.

1. **B56-1** - `ActivationPackageParser`/`ActivationPackageVerifier` +
   canonical encoding + typed failure enum + unit tests. No network code, no
   server changes. Independently reviewable and fail-closed on its own.
2. **B56-2** - Delegated activation-issuer key ceremony (reusing the
   existing B12 ceremony process) + a new operator-only issuance CLI that
   calls the *existing* `issue_activation()` and wraps its result into a
   signed package. No `/v1/activate` changes.
3. **B56-3** - `limit_req`/`limit_conn` for `/v1/activate` and
   `/v1/manifest` in both existing nginx configs - closes the confirmed gap
   in section 1/11, independently useful even if the rest of this proposal
   is never built.
4. **B56-4** - `BootstrapCandidateRepository`/`BootstrapReachabilityResolver`/
   `BootstrapLaneClient` client components, wired to the existing
   `ReachabilityEngine`/`EndpointManifestRepository`, behind a debug-only
   entry point first (mirroring how `XrayDiagnosticsActivity` stays
   debug-only) before any release-facing QR/deep-link UI.
5. **B56-5** - QR/deep-link import UI + recovery UX (section 25/20), release-
   facing only after B56-1 through B56-4 are merged and reviewed.
6. **B56-6** - Self-service issuance interface definition (entitlement
   system -> issuer -> user), explicitly without billing/ecommerce, per the
   task's own scope limit.
7. **B56-7** - Chaos/security validation pass (section 28) against a real
   staging activation store, before any production rollout decision.

Each slice fails closed on its own and does not require the next slice to
exist to be safe to merge.

---

## Decision Gate

**Verdict: B - ARCHITECTURE READY WITH EXPLICIT OWNER DECISIONS.**

The trust model is coherent (one delegated hierarchy, section 6), the
package format is defined (section 7), replay/device-binding design is
defined by reusing already-correct existing mechanisms (sections 12-14),
multi-origin retrieval is defined by reusing the already-proven manifest
pattern (section 10), and the existing signed manifest/LKG architecture is
reused cleanly with no changes required to it. No unresolved cryptographic
or trust-model blocker was found. The following are genuine **owner
decisions**, not open technical unknowns, and are why this is B rather than A:

1. **Rate limiting is a real, currently-missing production gap** (section
   1/11/22) that this proposal's B56-3 would close. Should B56-3 be
   prioritized and shipped independently of the rest of this proposal,
   given it improves the *existing* `/v1/activate`/`/v1/manifest` surface
   regardless of whether packages ever ship?
2. **Package envelope default `expiresAt` window** (section 7) - this
   document recommends "short, e.g. 24-72h" as an operational default, not
   a schema requirement. The owner should set the actual product-facing
   default.
3. **Whether self-service issuance (B56-6) is wanted at all before a
   billing/entitlement system exists**, or whether packages should remain
   operator-issued-only (via the new CLI, B56-2) indefinitely, with
   self-service deferred until commerce infrastructure exists.
4. **Whether `bootstrapEndpointHints` ships empty in v1** (section 30) or is
   populated from day one - purely a scope choice, not a security one.
5. **B56's assigned milestone number** - this document proposes B56;
   `docs/ROADMAP.md` is only updated in this branch with a minimal
   placeholder row (status `ARCHITECTURE / RESEARCH`) rather than a fully
   fleshed-out row, pending the owner's confirmation of the number/scope.

## Final report

See the branch's final message to the user for the full 40-point report
(starting SHA, files changed, confirmations that B46-2P/B37/PR #35/PR #86/
B45B-5/production infrastructure/production transport selection were all
untouched, and that no universal long-lived bootstrap secret or whitelist-
bypass claim was introduced).
