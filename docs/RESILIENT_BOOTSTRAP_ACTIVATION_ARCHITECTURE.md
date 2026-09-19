# Resilient Bootstrap + Self-Service Activation Architecture

**Status: ARCHITECTURE / RESEARCH.** Nothing in this document is implemented.
It is a design proposal, produced against the real repository state as of
`origin/main` at the SHA recorded in this branch's final report. See the
Decision Gate and Recommended Implementation Slices sections for what would
actually need to be built, and in what order, if this proposal is approved.

**Revision note (correction pass):** the first version of this document
(reviewed on PR #91) left one load-bearing gap: it defined credential
delivery and offline verification, but never actually gave a bootstrapping
device a way to reach `/v1/activate` if every endpoint the app already knew
about was blocked - the imported package could only reorder already-known,
already-trusted candidates, never add a genuinely new reachable one, and no
restricted-transport fallback existed for the case where none of them work.
That left the original "needs the API to activate, needs to be routed to
reach the API" cycle partially intact. This revision closes that gap by
splitting the single package into two independently authenticated objects
(section 5-7) and by adding a two-level bootstrap reachability model
(section 11). Every section below reflects the corrected design; nothing
from the first version survives silently unreviewed - where a prior
decision was reused, it is re-justified here, not just repeated.

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

Unchanged from the first version (re-verified, not re-derived, for this
correction pass):

**Activation (B8C1/B8C1A/B8C1B/B8C1C, `gateway/api/activations.py` +
`gateway/tools/activation_tokens.py`):**
- A durable JSON store keyed by `SHA-256(credential)` - the plaintext
  credential is never persisted, only its digest (`credential_digest`).
- `issue_activation()` (operator CLI only) generates a random
  `secrets.token_urlsafe(32)` credential and a random 32-hex `activation_id`,
  with `max_devices` and optional `expires_at`. The plaintext credential is
  printed to stdout **exactly once**, at issue time.
- `decide_and_bind()` is the one function `POST /v1/activate` calls, under a
  single `flock(LOCK_EX)` spanning read -> decide -> write - already
  race-free for concurrent first-use requests. `provision_with_activation()`
  additionally wraps decide/provision/finalize-or-rollback in a
  **per-activation** lock so the AWG provisioning side effect itself is
  serialized per activation. This is already a correct, race-free, atomic
  redemption transaction - reused unchanged (section 12).
- Device identity for binding is the device's own AmneziaWG public key
  (`ClientKeyRepository`/`AwgClientKeyRepository`) - a real keypair generated
  once, private key AES-GCM-encrypted at rest, public key handed to
  `/v1/activate`. Already the "device generates keypair -> activation
  includes public key -> server atomically binds" model; not a gap.
- `ActivationResilienceCoordinator` (B30) wraps `/v1/activate` with
  short-circuit local-freshness reuse and retries across `ControlPlaneOrigin`
  candidates from `ControlPlaneOriginSetBuilder.forGateway()` - which
  **only ever returns `ProductionGatewayCatalog`-compiled hosts, never an
  arbitrary caller-supplied URL** (a structural, not conventional,
  guarantee). This is the existing control-plane multi-origin pattern,
  narrower today than the manifest's own.
- Nginx already exposes `/v1/activate` (`POST`) and `/v1/manifest` (`GET`)
  as the only two routes reachable without an existing device-specific
  session (`nginx-pocvpn.conf`, `nginx-pocvpn-stockholm.conf`). **No
  `limit_req`/`limit_conn` directive exists anywhere in `gateway/edge/*.conf`
  today** for either route - confirmed absent, not assumed. See section 11
  for why this is a real but *separate* gap from the reachability gap this
  revision fixes.

**Enrollment tokens (older, distinct mechanism -
`gateway/tools/enrollment_tokens.py` + `gateway/api/tokens.py`):** bound to a
specific public key at issuance time, read-only HTTP API. Fundamentally
different from activation credentials (first-use binds, up to
`max_devices`). Never conflated with activation credentials or with the new
objects introduced below; not touched.

**Manifest / bootstrap trust (B11/B12/B17/B20/B42-B44,
`android/.../reachability/*.kt`):**
- `EndpointManifest`/`ManifestCanonicalizer`/`Ed25519ManifestVerifier` - a
  signed, versioned, typed endpoint set, deterministic canonical encoding,
  four typed rejection categories (unknown key, clock skew, expired, bad
  signature). No credential-bearing material ever enters this structure.
- `EndpointManifestRepository.trustedState()` is **the one place** a
  manifest becomes trusted for a session: (1) LKG if it verifies, else (2)
  the embedded bootstrap if it *also* verifies, else (3) `NoneTrusted` -
  explicit fail-closed. `offer()` is the **one place** a new candidate can
  ever be adopted into LKG - it re-verifies from scratch and enforces
  `ManifestRollbackGuard` against whatever is *currently trusted*,
  regardless of the candidate's origin. **This is the exact function this
  revision's imported-manifest path (section 10/16) reuses without
  modification** - `offer()` was already origin-agnostic by construction,
  it just has never been called with a candidate that arrived via anything
  other than an HTTPS fetch.
- **Key rotation precedent already exists**: `EmbeddedBootstrapManifest`
  embeds *two* simultaneously-trusted key IDs via `FixedManifestTrustAnchors`
  - reused for activation-issuer key rotation, no new mechanism needed.
- **Multi-origin delivery already exists for the manifest** (B20):
  `MultiOriginManifestDistributionClient` fetches every configured HTTPS
  origin on every refresh, feeds each through the *same* `offer()` boundary;
  an origin is "transport availability only, never a trust authority."
- B44 added signed endpoint operational state (`ACTIVE`/`DISABLED`/
  `RETIRED`) - **PARTIAL**. B43 "Bootstrap Resilience" - **PARTIAL**. B52
  "Offline / Outage Mode research" - **RESEARCH**, not started.

**What does not exist today** (unchanged): no activation-package/voucher
format, no QR/deep-link import path, no self-service issuance channel, no
dedicated bootstrap-transport listener, no rate limiting at the edge, no
delegated activation-issuer key, no peer-pairing/relay code, and -
confirmed newly in this pass - **no code path anywhere calls
`EndpointManifestRepository.offer()` with a candidate that did not arrive
over the existing HTTPS `MultiOriginManifestDistributionClient`**. That last
fact is exactly the gap this revision's imported-manifest design closes
(section 10/16), and it closes cleanly because `offer()`'s own contract
never assumed HTTPS as the only legitimate way a candidate could arrive.

---

## 2. Problem statement

Unchanged, restated precisely because the correction below exists to
actually solve it, not merely to describe it: a new Nova install has no
per-device credential and no trusted live manifest beyond the embedded
bootstrap. If the reachable network already blocks every endpoint the
device currently knows about - both the embedded bootstrap's endpoints and
anything a package could merely *point at* among them - no signed pointer
alone helps, because pointing at an already-blocked candidate changes
nothing. **The root architectural gap this revision fixes**: the first
version of this design could deliver a credential and could re-rank already-
known endpoints, but could not deliver *new, verifiably-authentic* endpoint
facts, and had no fallback transport level for when direct HTTPS to every
known control-plane origin fails outright. Both are fixed below.

## 3. Constraints

Unchanged, plus one addition:

- Reuse the existing Ed25519/manifest trust primitives; no new cryptography.
- Never conflate activation credentials with enrollment tokens.
- Never replace `decide_and_bind`/`provision_with_activation`'s already
  race-free redemption transaction.
- Never let a package supply an arbitrary host/URL that bypasses
  `ControlPlaneOriginSetBuilder`'s "no caller-supplied origin" invariant, and
  never let it supply a network fact that bypasses `EndpointManifestRepository`'s
  signature/rollback boundary either (new, section 6/16 - this is the
  correction's central invariant).
- No infrastructure stood up, no production nginx/gateway changes, no
  billing, no peer relay, in this slice - a restricted pre-activation
  transport (section 11, Level 2) is designed here, never built.
- No claim of guaranteed whitelist bypass, Russia connectivity, or
  untraceability anywhere in the resulting design or its UX copy.

## 4. External design patterns reviewed

Unchanged from the first version, with Proton-style alternative routing now
actually implemented at the architecture level (section 11, Level 2) rather
than only named:

- **Proton-style alternative routing** -> Level 2 restricted bootstrap
  transport (section 11): a small resolver layer that tries alternate
  *paths* to the control plane, never a general traffic proxy.
- **Psiphon-style embedded bootstrap knowledge** -> already implemented for
  the manifest; this design's imported-manifest path (section 10) extends
  the same idea with a genuinely new *delivery* channel, not a new trust
  mechanism.
- **Lantern-style multi-origin configuration, trust-by-signature** ->
  already implemented for the manifest; reused for both package and
  imported-manifest delivery (section 10).
- **Outline/Amnezia-style self-contained access package** -> the
  `NovaActivationPackage` container (section 5/7): QR/deep-link/file/
  clipboard, verifiable before any network access.

## 5. Target architecture

**Correction 1 applied.** The package is no longer one signed object. It is
a container carrying **two independently authenticated logical objects**,
each verified by its own key and its own existing code path - never merged
into one signature, so a compromise of one never lets an attacker forge the
other:

```
NovaActivationPackage (container - QR / deep link / file / clipboard)
        |
        +---------------------------+---------------------------+
        |                                                       |
ActivationEnvelope                                    SignedBootstrapBundle
(signed by the activation-issuer key,                 (signed by the EXISTING
 a NEW delegated key - section 6/8)                    manifest signing key -
        |                                               NO new key)
        v                                                       v
ActivationPackageVerifier                             EndpointManifestRepository.offer()
(new, offline, mirrors                                (EXISTING, unmodified - section 16)
 Ed25519ManifestVerifier)                                       |
        |                                              new ManifestSource.IMPORTED_SIGNED_BOOTSTRAP
        |                                              on acceptance; same LKG store either way
        |                                                       |
        +---------------------------+---------------------------+
                                     |
                        BootstrapCandidateRepository
                        (new, thin - reads whatever
                         EndpointManifestRepository now trusts,
                         AFTER the bundle above was offered)
                                     |
                        BootstrapReachabilityResolver
                        (new, thin orchestration only)
                          /                        \
           LEVEL 1: direct control-plane      LEVEL 2: restricted
           reuses ReachabilityEngine/          bootstrap transport
           NetworkProfiler/                    (architecture-level only,
           RestrictionClassifier                NOT built this slice -
                          \                        section 11)
                           \                      /
                        BootstrapLaneClient
                        (talks to the SAME /v1/activate,
                         /v1/manifest routes either way)
                                     |
                        provision_with_activation()
                        (EXISTING, gateway/api/activations.py, UNCHANGED)
                                     |
                        existing profile repositories (AWG/Xray/etc, UNCHANGED)
```

Neither signed object is a second trust *root*. The `ActivationEnvelope`
grants no authority over network facts - it cannot invent, alter, or imply
a host/port/endpoint (Correction 1's core rule). The `SignedBootstrapBundle`
grants no activation entitlement - it is exactly a manifest candidate,
subject to exactly the same rules any other manifest candidate already is.
Only their *combination*, arriving through `provision_with_activation()`
and `EndpointManifestRepository` respectively, produces a working device.

## 6. Trust model

**Correction 1 applied precisely**: two purposes, two keys, one ceremony
process, and - critically - the second "new" key claimed in the first
version of this document is now **not actually new for network facts**.
Network-fact authority stays with the manifest signing key that already
exists; only activation-entitlement-envelope authority gets a new delegated
key.

```
Offline root ceremony (docs/B12_MANIFEST_KEY_CEREMONY.md process, reused)
        |
        +-- manifest signing key(s)        (EXISTING: prod-manifest-key-* -
        |                                    SignedBootstrapBundle uses THIS,
        |                                    not a new key)
        |
        +-- activation-issuer key(s)       (NEW, delegated, distinct from
                                             manifest keys - ActivationEnvelope
                                             uses THIS, and ONLY this)
```

- **`ActivationEnvelope`** is signed by the activation-issuer key. It may
  contain `activationId`, the existing plaintext activation credential,
  envelope validity window, package metadata, and a reference (version and/or
  content hash) to the accompanying `SignedBootstrapBundle` - never a host,
  IP, port, SNI, or any other network fact. This is enforced structurally in
  the schema (section 7), not by convention: the envelope's canonical
  encoding has no field capable of carrying one.
- **`SignedBootstrapBundle`** is signed by the *existing* manifest key(s) -
  the same `FixedManifestTrustAnchors`/`Ed25519ManifestVerifier` machinery
  already in production, unmodified. It is not a new artifact type at the
  cryptography layer - it is an ordinary `SignedManifest` (or a subset-shaped
  manifest, see section 9), verified and adopted the exact same way any
  manifest candidate already is. This is what makes network-endpoint
  authority stay unique (Correction 3's requirement): there is exactly one
  key family that can ever make a client trust a new host, and it was never
  touched by this design.
- The activation-issuer key is used for envelope issuance only - never for
  signing anything that reaches `EndpointManifestRepository`. Compromise of
  this key cannot mint network facts (see the corrected threat model,
  section 21, for the precise blast radius, distinguished per Correction 10
  from compromise of the *issuance service* that holds it).
- Trust for both objects still ultimately comes from an Ed25519 signature
  over canonical bytes - no new cryptography, exactly as before. A
  compromised delivery channel (dashboard, mirror, email, QR host) can serve
  anything; the client rejects whatever doesn't verify, for each object
  independently.
- A valid `ActivationEnvelope` proves provenance, never current entitlement
  - unchanged, section 15. A valid `SignedBootstrapBundle` proves the
  endpoints inside it are genuinely Nova-issued, never that they are
  *newer or more trustworthy* than what the device already has -
  `ManifestRollbackGuard` decides that, unchanged (section 16).

## 7. Activation package format

**Correction 1 applied**: the container now holds two objects. Neither
duplicates a schema-level field that already exists server-side or in the
manifest.

```
NovaActivationPackage {
    schemaVersion         : int
    envelope               : ActivationEnvelope        // section 6, signed by activation-issuer key
    bootstrapBundle         : SignedBootstrapBundle | null   // section 9, signed by the EXISTING manifest key; MAY be omitted (see below)
}

ActivationEnvelope {
    activationId          : 32 lowercase hex   // same non-secret id activations.py already prints via status/list
    credential             : string             // the SAME plaintext bearer credential issue_activation() already produces once
    issuedAt               : epoch millis
    notBefore              : epoch millis       // envelope validity window; independent of the activation's own server-side expires_at
    expiresAt              : epoch millis       // envelope validity window; SHORTER than or equal to the activation's own expires_at is the operational default, not a hard schema rule
    bootstrapBundleRef      : { manifestVersion: int, contentHash: bytes } | null   // informational cross-reference to `bootstrapBundle` above, NEVER a host/port fact
    bootstrapEndpointHints  : list of EndpointId strings (0..N)   // NON-authoritative ranking hint over whatever manifest is ALREADY trusted, see section 9
    bootstrapCapabilityHint : opaque bytes | null   // OPTIONAL - see section 11's chosen bootstrap-auth model; carries no network fact either
    nonce                   : 16 random bytes   // LOCAL replay/import dedupe only, not a security boundary (see section 14)
    issuerKeyId              : string
    signature                : Ed25519, 64 bytes, over the canonical encoding of every ActivationEnvelope field above
}

SignedBootstrapBundle {
    // Exactly a SignedManifest (EndpointManifest + Ed25519 signature) as it
    // already exists today, OR a size-bounded subset of one (a small,
    // still-independently-verifiable manifest naming only bootstrap-capable
    // endpoints) - see section 9 for which shape is recommended and why.
    // Signed by an EXISTING manifest signing key. Adds NOTHING to
    // EndpointManifest's own schema.
}
```

`bootstrapBundle` is nullable because it solves a *specific* failure mode
(every endpoint the device already knows is blocked) - a package issued for
a device that will almost certainly still reach a known origin does not need
one, and omitting it keeps the QR/package small (Correction 9 - this is an
out-of-band *recovery* mechanism, not a mandatory part of every activation).

Explicit answers to the task's checklist, corrected where Correction 1
changes them:

- **Must be inside**: (envelope) `activationId`, `credential`, `notBefore`/
  `expiresAt`, `issuerKeyId`, `signature`; (bundle, when present) exactly
  what `EndpointManifest` already requires - nothing more.
- **Must NOT be inside**: (envelope) any host/IP/port/SNI/transport fact,
  `max_devices`, a redemption counter, per-device keys, AWG/Xray/REALITY
  credentials, PII. (bundle) anything `EndpointManifest` already forbids
  today (credential-bearing material) - unchanged.
- **Public**: `activationId`, `issuerKeyId`, `schemaVersion`,
  `bootstrapBundleRef`, `bootstrapEndpointHints`, timestamps, both
  signatures, and everything already public inside a `SignedManifest`.
- **Secret** (bearer, not encrypted - see below): `credential`.
  `bootstrapCapabilityHint`, if present, is short-lived and narrowly scoped
  (section 11) - not a long-lived secret, and its absence never blocks
  Level 1 bootstrap.
- **Signed**: every `ActivationEnvelope` field under the activation-issuer
  key; every `EndpointManifest` field under the manifest key - two
  independent signatures, reusing the same canonical-bytes convention
  (`ManifestCanonicalizer`) for both, never merged into one signature over
  the concatenation of both (which would recreate a single trust root by
  accident).
- **Encrypted**: no, for the same reasoning as the first version (adds UX
  friction without shrinking the actual exposure window, which is bounded by
  envelope expiry and server-side entitlement controls) - unchanged by this
  correction, since it was never about network-fact authority.
- **Stable identifier**: `activationId`.
- **One-time value**: the `credential`, made one-time *in effect* by
  `decide_and_bind()`'s existing binding - unchanged.
- **Replay prevention**: unchanged (section 14) for the envelope/credential.
  For the bundle: `EndpointManifestRepository.offer()`'s existing rollback
  guard is itself the replay defense for network facts - a captured old
  bundle is simply not-newer and rejected, exactly like a captured old
  HTTPS-fetched manifest would be.
- **Package theft**: unchanged for the envelope/credential (bounded by
  `max_devices`/`expires_at`/revocation). A stolen bundle grants nothing new
  - it can, at most, tell a thief's device about endpoints that were already
  going to be signed and public regardless of who imports them.
- **Two devices redeeming simultaneously**: unchanged (section 12) -
  `decide_and_bind`'s race-free binding is untouched by adding a bundle.
- **max_devices interaction**: unchanged - the bundle carries no entitlement.
- **After expiry**: unchanged three-way distinction (envelope-expired vs.
  activation-expired), plus a **new**, independent fourth case: a bundle
  whose *own* manifest `expiresAtEpochMillis` has passed is rejected by the
  *existing* `Ed25519ManifestVerifier` the same way any expired manifest is
  - surfaced as `BOOTSTRAP_BUNDLE_EXPIRED` (section 20), never conflated with
  `PACKAGE_EXPIRED` (envelope) or `ACTIVATION_EXPIRED` (server-side).
- **Issuer-key rotation**: unchanged for the activation-issuer key (two-key
  `FixedManifestTrustAnchors` pattern). The bundle needs no separate rotation
  story at all - it rotates exactly when the manifest signing key already
  does, because it *is* signed by that key.
- **Device clock wrong**: unchanged (`CLOCK_UNCERTAIN`, section 7 original /
  20) for both objects independently - the bundle already gets this for free
  from `Ed25519ManifestVerifier`'s existing clock-skew handling.

## 8. Key hierarchy

Corrected per Correction 1/6: one offline ceremony produces the manifest
signing key (unchanged, reused for `SignedBootstrapBundle`) and a **new**
activation-issuer key (used only for `ActivationEnvelope`). These are never
merged, never cross-trusted (an envelope signed by the manifest key, or a
bundle signed by the activation-issuer key, must both be rejected as
`UNKNOWN_SIGNING_KEY` by their respective verifiers - each verifier's trust-
anchor set only ever contains keys for its own purpose). Blast radius of
each key's compromise is analyzed precisely in the corrected threat model
(section 21), not summarized here as it was in the first version.

## 9. Bootstrap candidate model

`bootstrapEndpointHints` (unsigned, inside the envelope) is unchanged from
the first version and its rule is unchanged (Correction 8, made explicit):
**hints may only reorder candidates already present in whatever manifest is
currently trusted** - they can never introduce a new one. This remains true
even after this correction, and is now stated precisely alongside the
mechanism that *can* introduce new candidates:

**New candidate facts can enter only through a validly-signed
`SignedBootstrapBundle`, consumed by `EndpointManifestRepository.offer()`
(section 16) - never through any unsigned field.** This is Correction 8's
distinction made structural: an attacker who can inject or modify an
unsigned hint list gains nothing (it only reorders what a signature already
vouches for); an attacker who wants to add a new endpoint must forge a
manifest-key signature, which this design never weakens.

`SignedBootstrapBundle`'s recommended shape: reuse `EndpointManifest`
byte-for-byte (Correction 1's "choose the cleanest format after inspecting
existing manifest types" - a full, ordinary `SignedManifest` already
satisfies every requirement here with zero new wire format). A future slice
may additionally define a narrower, size-bounded bundle shape (a manifest
naming only the endpoints/bindings an operator wants to hand out via
out-of-band recovery packages) if QR payload size becomes a real constraint
- but this is an operational packaging choice, not a new trust type, since
it would still be exactly an `EndpointManifest` under exactly the same
signature.

A future slice may add a narrow capability flag to
`EndpointTransportBinding.metadata` (already a free-form string map, no wire
change needed) marking which bindings a bootstrapping client (no device
profile yet) may dial under Level 2 (section 11) - server-enforced, never
merely a client-side hint, unchanged from the first version's proposal.

## 10. Multi-origin retrieval design

Corrected per Correction 9: this section now names three *distinct*
mechanisms explicitly, rather than treating package delivery as if it were
equivalent to live multi-origin manifest retrieval.

1. **Live multi-origin manifest retrieval** (unchanged, existing,
   `MultiOriginManifestDistributionClient`): network-time redundancy across
   already-configured HTTPS origins. Solves "one origin is down/blocked,
   others aren't." Does not help if *every* configured origin is blocked.
2. **Out-of-band imported signed manifest** (new, this revision,
   `SignedBootstrapBundle`): solves a *different* failure - the device's
   entire currently-trusted candidate set (LIVE origins that are all
   blocked, LKG, and embedded bootstrap) is stale or fully blocked, and an
   operator hands the user a *signed* replacement/addition out-of-band (QR,
   file, support channel). This is delivery-channel diversity for the
   *manifest itself*, not network-path diversity for reaching one - it
   recovers a device that has no working network path to any manifest
   origin at all, by letting a human carry the signed bytes around that
   barrier instead. It reuses `offer()`'s trust boundary; it does not
   replace live retrieval, and it does not run periodically - it is
   consumed once, at import.
3. **Package delivery** (envelope + bundle container, unchanged
   reasoning from the first version): QR/email/file/dashboard/messenger are
   all pure delivery for the *container*; integrity comes from the two
   signatures inside it, never from which channel carried it.

## 11. Restricted bootstrap lane

**Correction 4/5/6 applied - this section now defines two genuinely distinct
levels, not one.**

### Level 1 - direct control-plane bootstrap (preferred, cheapest)

`BootstrapCandidateRepository` builds an ordered candidate list from
whatever `EndpointManifestRepository` now trusts - which, after this
revision, may include endpoints that only became trusted because a
`SignedBootstrapBundle` was just offered and accepted (section 10.2). Every
candidate is dialed as an ordinary HTTPS request to `/v1/activate` or
`/v1/manifest`, using the *existing* `ReachabilityEngine`/`NetworkProfiler`/
`RestrictionClassifier` (never a parallel scorer, per the task's own
constraint). If any candidate succeeds, bootstrap is done at Level 1 - no
new transport, no new authentication, nothing beyond what
`ActivationResilienceCoordinator`'s pattern already demonstrates, just
widened to whatever the manifest (possibly just-freshened by an imported
bundle) now names.

**Finding, reused from the first version**: `/v1/activate` and
`/v1/manifest` are already the only two unauthenticated-reachable routes,
and there is already no VPN data plane reachable pre-activation - Level 1
was never at risk of becoming "arbitrary Internet access." What Level 1
alone cannot do is help a device on a network that blocks literally every
manifest-known origin/IP by destination, regardless of protocol - that is
Level 2's job.

### Level 2 - restricted pre-activation bootstrap transport (fallback,
architecture defined here, NOT built this slice)

**Correction 5 - bootstrap auth model selected: Hybrid (Model D), with the
two authorities kept deliberately separate:**

- The **transport-access question** ("may this client use the narrow
  Level 2 lane at all, and how much of it") is answered by a short-lived,
  narrow-scope **bootstrap capability** - conceptually a small, server-
  minted, time-boxed token (reusing existing HMAC/Ed25519 primitives, no new
  cryptography) that a Level-2 listener can check locally without touching
  the activation store. It is bound to the `ActivationEnvelope`'s signature/
  `activationId` (so a capability cannot be requested without presenting a
  validly-signed envelope first) but is **not** the activation credential
  itself and **grants no entitlement** - it only opens a narrow pipe.
  `bootstrapCapabilityHint` (section 7) is where a *pre-issued* capability,
  if the issuer chose to hand one out at package-creation time, would travel
  - optional, because a capability can equally be requested live (envelope
  presented to a narrow, rate-limited capability-issuance endpoint) at
  bootstrap time instead of being pre-baked into the package.
- The **entitlement question** ("does this device actually get provisioned")
  stays exactly what it already is - `/v1/activate`'s existing
  `decide_and_bind`/`provision_with_activation`, reached *through* the
  Level-2 lane once it's open, unchanged (section 12).
- This separation is the point of Correction 5: a stolen capability alone
  (short TTL, narrow scope, no entitlement) cannot provision a device
  without also having the real credential; a stolen credential alone
  (today's existing risk, unchanged) cannot open the Level-2 lane without
  also presenting a validly-signed envelope. Two independent, narrower
  blast radii instead of one wider one.

**Correction 6 - server-side enforcement boundary, defined but not built:**

Level 2 requires a real network listener distinct from "an HTTP route
behind the normal control-plane" - a capability alone is meaningless without
something that checks it before permitting *any* bytes through. Conceptually:
a narrow, dedicated listener (a separate bind/socket, not merely another
nginx `location` on the existing control-plane vhost) that:
- accepts a connection, checks the bootstrap capability before relaying
  anything,
- allowlists destinations to exactly `/v1/activate` and `/v1/manifest` on
  the same gateway (never a general egress path, never another gateway's
  data plane),
- enforces its own short TTL, per-capability bandwidth/request caps, and
  connection caps, independent of and in addition to whatever rate limiting
  Level 1's existing routes eventually get (section 22),
- runs as its own least-privilege service/account so a bug in it cannot
  reach `activations.py`'s store directly - only through the same
  `/v1/activate` HTTP call Level 1 already makes.

This is an architecture-level specification, not a build: no listener, no
nginx change, no capability-issuance endpoint is created by this PR. It
exists so that if Level 1 is approved and later found insufficient in the
field (B54), Level 2 has a concrete, already-reviewed target to build
against instead of an open question.

## 12. Redemption transaction

Unchanged. `provision_with_activation()` already provides atomic
per-activation serialization, race-free device-limit enforcement, and
monotonic ownership-checked rollback. Neither the envelope/bundle split nor
the two-level bootstrap model changes `/v1/activate`'s semantics at all - a
redemption request reaching it, whether via Level 1 or Level 2, is
byte-for-byte the same `(public_key, activation_credential)` pair the
existing endpoint already accepts. **No change to `/v1/activate` is
required by this slice.**

## 13. Device binding

Unchanged (section 1): the device's own AWG keypair remains the binding
identity. Nothing about the envelope/bundle split changes this.

## 14. Replay prevention

Unchanged for the envelope/credential (section 7's answer). For the bundle:
see section 7's new bullet - `ManifestRollbackGuard` is the replay defense
for network facts, already existing, reused without modification. For a
Level 2 bootstrap capability (section 11): bounded by its own short TTL and
narrow scope - a replayed capability is only ever useful for the narrow
window and narrow destinations it was already scoped to, never a standing
credential.

## 15. Revocation

Unchanged (section 1 original): local verification of either signed object
proves provenance, never current entitlement. `revoke_activation()` remains
the sole, final, online authority for the underlying activation. A
Level 2 bootstrap capability's own short TTL is its own de facto revocation
mechanism (it simply stops working); no separate capability-revocation list
is proposed for v1 given the short TTL already bounds exposure.

## 16. Manifest/LKG/embedded integration

**Correction 2/3 applied - this is the section that most changed.**

`EndpointManifestRepository`'s existing precedence and rollback guard are
reused **unmodified**, with one new, additive fact source layered in at
exactly the point the existing design already generalizes to:

```
Precedence, corrected:
  1. LIVE  - via MultiOriginManifestDistributionClient, EXISTING, unchanged
  2. LKG   - EXISTING, unchanged
  3. EMBEDDED_BOOTSTRAP - EXISTING, unchanged
  4. IMPORTED_SIGNED_BOOTSTRAP - NEW delivery-only source: a SignedBootstrapBundle
     the user imported out-of-band, offered to the SAME EndpointManifestRepository.offer()
     every other candidate already goes through.
```

Concretely, `IMPORTED_SIGNED_BOOTSTRAP` is not a new precedence *tier* with
special privilege - it is simply calling the existing `offer(candidate)`
with a candidate whose bytes arrived via QR/file instead of HTTPS. `offer()`
already re-verifies signature/expiry/clock-skew from scratch and already
rejects anything not strictly newer than what is currently trusted
(`ManifestRollbackGuard`), regardless of who calls it or how the bytes
arrived - this is precisely why no change to that function is required.
The only new code is the call site (a client-side "import bundle" action)
and a new `ManifestSource.IMPORTED_SIGNED_BOOTSTRAP` value purely for
diagnostics (so a support engineer can see *why* a candidate got adopted),
never a new acceptance rule.

Explicit resolution of every case Correction 3 asked for:

- **Imported version newer than embedded** -> accepted by the existing
  rollback guard exactly like a newer HTTPS-fetched manifest would be;
  becomes the new LKG.
- **Imported version older than LKG** -> rejected by the existing rollback
  guard (`ROLLBACK_OR_NOT_NEWER`), exactly like a stale HTTPS fetch; LKG
  untouched. An imported bundle can **never** roll back an already-trusted
  newer manifest - this was already structurally true of `offer()` before
  this revision existed, and remains true now.
- **Imported manifest expired** -> rejected by `Ed25519ManifestVerifier`
  (`EXPIRED`), exactly like an expired HTTPS fetch.
- **Imported manifest signed by a previous-but-still-trusted key** ->
  accepted, exactly like the manifest's existing two-key rotation window
  already handles for HTTPS fetches (`prod-manifest-key-2026-09-01` and
  `-09-14` both currently verify).
- **Imported manifest signed by an unknown key** -> rejected
  (`UNKNOWN_SIGNING_KEY`), exactly like an HTTPS fetch signed by a key the
  device has never embedded.
- **Device offline for months** -> unchanged existing behavior: LKG (if
  still unexpired) or embedded bootstrap remains the fallback exactly as
  today; an imported bundle, if the user has one, is simply one more
  candidate offered through the same boundary - it does not need to be
  "newer than everything" to be useful, only newer than whatever the device
  currently trusts, which may itself be very stale after months offline.
- **Emergency rollback policy** -> unchanged: none exists today beyond
  "a strictly newer valid manifest wins," and this revision does not add
  one. An operator recovering a fleet of devices stuck behind a block would
  issue a new, strictly-newer, validly-signed bundle - never a mechanism to
  force-accept an older one.

This satisfies Correction 2's explicit requirement ("must not bypass
`EndpointManifestRepository`... must NOT create a second trust path... the
source is only a delivery mechanism") by construction: there is exactly one
function, `offer()`, that can ever cause a new endpoint fact to become
trusted, and this revision adds no second one.

## 17. Transport selection integration

Unchanged. Once `provision_with_activation()` succeeds, normal profile
provisioning takes over unchanged. Neither Level 1/Level 2 bootstrap nor the
imported-bundle path is consulted again once a device profile exists.

## 18. Server architecture

Corrected to reflect the two-level model (section 11), still nothing built
this slice:
1. `limit_req_zone`/`limit_req` for `/v1/activate` and `/v1/manifest` in
   both existing nginx configs (Level 1 hardening - section 11/22, unchanged
   from the first version, still a real and separate gap).
2. A new, separate CLI (mirroring `activation_tokens.py`'s structure, never
   modifying it) that calls the *existing* `issue_activation()` and wraps
   the result into a signed `ActivationEnvelope` using the new activation-
   issuer key - and, separately, a way for an operator to attach an existing,
   already-signed `EndpointManifest` (produced by the *existing*
   `manifest_signing.py`, unmodified) as the package's `SignedBootstrapBundle`
   when out-of-band manifest recovery is the goal.
3. (Level 2 only, deferred - section 11) a narrow, dedicated
   listener/service issuing and checking bootstrap capabilities, allowlisted
   to `/v1/activate`/`/v1/manifest` on its own gateway, least-privilege,
   rate/bandwidth/TTL-bounded. Specified, not built.

## 19. Client architecture

Corrected component list - `ActivationPackageVerifier` is now two verifiers
behind one container parser, and a new resolver step chooses between Level 1
and Level 2:

- `ActivationPackageParser` - decodes the container into its two logical
  objects; no crypto.
- `ActivationEnvelopeVerifier` - mirrors `Ed25519ManifestVerifier`'s shape,
  own trust-anchor set (activation-issuer keys only), own typed failures.
- **`SignedBootstrapBundle` verification performs NO new verification code**
  - it is handed to the *existing* `EndpointManifestRepository.offer()`
  unmodified (section 16); there is deliberately no
  `BootstrapBundleVerifier` type, because inventing one would be exactly the
  second trust path Correction 2 forbids.
- `BootstrapCandidateRepository` - thin read-through over
  `EndpointManifestRepository.trusted()` (called *after* any bundle offer)
  plus hint reordering (section 9) - unchanged in shape from the first
  version, now simply reading a possibly-just-refreshed trust state.
- `BootstrapReachabilityResolver` - thin orchestration; tries Level 1 first
  (existing `ReachabilityEngine`/`NetworkProfiler`/`RestrictionClassifier`
  over the candidates above), falls back to Level 2 only if every Level 1
  candidate is exhausted and a Level 2 lane is actually configured/available
  (it may not be, in v1 - see section 32's slice ordering).
- `BootstrapLaneClient` - calls the same `/v1/activate` HTTP shape either
  way; parameterized by which lane (Level 1 direct, or Level 2 through the
  capability-gated listener) it is currently using, never a new HTTP client
  stack.

**Explicitly not duplicated** (unchanged list, still holds): `ReachabilityEngine`,
`PathScorer`, `PathCandidateBuilder`, `AutoGatewaySelector`,
`SmartConnectDecisionEngine`, `EndpointManifestRepository`,
`Ed25519ManifestVerifier`'s crypto primitive, `ManifestCanonicalizer`'s
encoding convention, `ClientKeyRepository`, `provision_with_activation()`.

## 20. Failure model

Corrected/extended failure set - every addition maps to a check a component
above actually performs, none invented beyond that:

`PACKAGE_MALFORMED`, `ENVELOPE_SIGNATURE_INVALID`, `PACKAGE_EXPIRED`
(envelope), `PACKAGE_NOT_YET_VALID`, `PACKAGE_VERSION_UNSUPPORTED`,
`ISSUER_KEY_UNKNOWN` (envelope), `BOOTSTRAP_BUNDLE_SIGNATURE_INVALID`,
`BOOTSTRAP_BUNDLE_EXPIRED`, `BOOTSTRAP_BUNDLE_UNKNOWN_KEY`,
`BOOTSTRAP_BUNDLE_ROLLBACK_REJECTED` (all four map 1:1 to the *existing*
`ManifestVerificationFailureKind`/`ManifestUpdateRejectionKind` enums via
`offer()` - no new verification logic, just a client-facing label for an
existing rejection reached from a new call site), `CLOCK_UNCERTAIN`,
`BOOTSTRAP_MANIFEST_UNAVAILABLE` (`TrustedManifestState.NoneTrusted`,
unchanged), `NO_TRUSTED_BOOTSTRAP_CANDIDATE`,
`ALL_LEVEL1_PATHS_UNREACHABLE` (renamed from `ALL_BOOTSTRAP_PATHS_UNREACHABLE`
to be precise about which level exhausted), `LEVEL2_UNAVAILABLE` (new - no
capability, or no configured Level 2 lane, or the lane itself rejected the
capability), `BOOTSTRAP_AUTH_REJECTED` (`decide_and_bind`'s `INVALID`),
`ACTIVATION_REVOKED`, `ACTIVATION_EXPIRED`, `DEVICE_LIMIT_REACHED`,
`PROFILE_PROVISIONING_FAILED`, `BOOTSTRAP_RATE_LIMITED` (Level 1, once
section 22 ships).

## 21. Threat model

**Correction 10 applied - blast radii now distinguished by exactly which
authority is compromised, not collapsed into "activation-issuer key
compromise" as a single category:**

- **Signing-key-only compromise (activation-issuer key)**: an attacker who
  extracts only the private key can forge `ActivationEnvelope`s that verify
  locally, but every one of them still terminates at `decide_and_bind`,
  which only ever binds/provisions for an `activationId` that genuinely
  exists, is `ACTIVE`, unexpired, and under its device cap in the *real*
  server-side store. Blast radius: can produce plausible-looking but
  non-functional decoy/spam packages; **cannot** provision any real device,
  because forging a signature does not create a matching store entry.
- **Signing-key-only compromise (manifest key)**: unchanged from today
  (pre-existing risk, not introduced by this design) - can forge a
  `SignedBootstrapBundle` (or any manifest) that verifies, but
  `ManifestRollbackGuard` still bounds it to "can supply endpoints, cannot
  roll back a newer trusted manifest." This is the highest-value key in the
  whole system precisely because it is the *only* one with network-fact
  authority - which is exactly why this design deliberately never gives the
  activation-issuer key that power (section 6).
- **Package-delivery compromise** (a mirror, dashboard, or QR-hosting
  service is compromised): can serve a stale-but-still-validly-signed
  object, or refuse to serve anything, or serve garbage - cannot forge
  either signature, cannot roll back a newer manifest, cannot grant
  entitlement. Unchanged from the first version's "malicious mirror"
  analysis, now stated for both objects, not just the package.
- **Issuer-*service* compromise** (the running process/host that holds the
  activation-issuer private key AND is authorized to call the existing
  `issue_activation()` on the live store): **materially worse than
  signing-key-only compromise**, and understated as "spam/decoy" in the
  first version of this document - corrected here. Such a compromise can
  mint **real**, server-valid activations (via the legitimate
  `issue_activation()` call, which the service is *supposed* to be able to
  make) and wrap them in validly-signed envelopes - i.e. it can provision
  real devices, up to whatever `max_devices`/rate limits are in force. This
  is why the future self-service issuance service (section 32, B56-8) needs
  its own hardening review before it goes live, separate from and *in
  addition to* this architecture document - the issuer-service's ability to
  call `issue_activation()` is the actual high-value target, not the
  signing key alone.
- **Activation-store/API compromise** (`pocvpn-api` itself, or its
  `activations.py` store, compromised): unchanged from today - this
  design introduces no new authority here; blast radius is exactly what
  compromise of `pocvpn-api` already means, whether or not packages exist.
- **Compromised bootstrap capability** (Level 2 only, section 11): bounded
  by its own short TTL, narrow destination allowlist, and the fact that it
  grants transport, not entitlement - a stolen capability alone cannot
  provision a device without also having the real credential.
- **Reverse engineer**: assume APK-embedded activation-issuer public keys,
  manifest public keys, and embedded bootstrap manifest are all recoverable
  - none are secrets. Only the per-envelope `credential` is secret, and it
  is never embedded in the APK.
- **Clock manipulation / Replay / Denial of service**: sections 7/14/22,
  unchanged in substance, now covering both objects and both bootstrap
  levels explicitly.

## 22. Abuse/rate limiting

**Correction 11 applied**: rate limiting is reframed as one of four
*independent* layers this architecture identifies, not treated as if it
were the primary fix for the reachability gap (it never was):

1. **Level 1 edge rate limiting** (`limit_req` on `/v1/activate`/
   `/v1/manifest`) - protects the *existing* activation surface from abuse,
   independent of whether packages ever ship. Confirmed still missing
   (section 1).
2. **Package/envelope signing** - solves credential *delivery* integrity,
   not abuse capacity.
3. **Imported signed manifest** (section 10/16) - solves stale/blocked
   endpoint *knowledge*, not abuse capacity.
4. **Level 2's own capability TTL/scope/bandwidth/request caps** (section
   11) - solves restricted-transport abuse specifically, independent of
   Level 1's edge limiting, because Level 2 is a different listener with a
   different abuse surface (connection/bandwidth exhaustion, not just
   request-rate abuse).

None of these four substitute for another; all four are genuinely
independent hardening layers, and shipping any subset without the others
leaves exactly the gap that subset doesn't cover - stated explicitly so a
future implementer doesn't treat "we added rate limiting" as if it also
means "Level 2 abuse is handled."

## 23. Privacy

Unchanged from the first version, extended only by the fact that a Level 2
lane (if built) would also see: which capability was presented and which
narrow destination was requested - nothing beyond what Level 1 already sees
today (source IP, activation_id/credential digest, device public key, app
version, manifest version, transport binding attempted). No device serial,
IMEI, advertising ID, phone number, contacts, or new fingerprinting.

## 24. Observability

Corrected event list - splits the original `BOOTSTRAP_PACKAGE_*` events by
which object they describe, and adds Level 1/Level 2/bundle-specific events:
`ENVELOPE_IMPORTED`, `ENVELOPE_VERIFIED`, `ENVELOPE_REJECTED` (typed kind),
`BOOTSTRAP_BUNDLE_IMPORTED`, `BOOTSTRAP_BUNDLE_OFFERED`,
`BOOTSTRAP_BUNDLE_ACCEPTED`, `BOOTSTRAP_BUNDLE_REJECTED` (typed kind, one of
the four `offer()`-derived reasons), `BOOTSTRAP_MANIFEST_SOURCE_SELECTED`
(now including `IMPORTED_SIGNED_BOOTSTRAP` as a possible value),
`BOOTSTRAP_LEVEL1_PATH_ATTEMPT`, `BOOTSTRAP_LEVEL1_PATH_REACHABLE`,
`BOOTSTRAP_LEVEL2_REQUESTED`, `BOOTSTRAP_LEVEL2_ESTABLISHED`,
`BOOTSTRAP_LANE_ESTABLISHED`, `ACTIVATION_REDEMPTION_STARTED`,
`ACTIVATION_REDEMPTION_ACCEPTED`, `ACTIVATION_REDEMPTION_REJECTED`,
`DEVICE_BOUND`, `NORMAL_PROFILE_PROVISIONED`, `BOOTSTRAP_CONSUMED`. None of
these ever carry the plaintext credential, a private key, raw package
bytes, a bootstrap capability's raw bytes, or a bearer token.

## 25. UX

Unchanged in shape from the first version - the corrected architecture is
invisible to the user by design:

```
Install Nova -> Open app -> Scan QR / paste activation package
  -> "Checking activation package"      (envelope + bundle local verification, section 7/20)
  -> "Finding a connection route"       (BootstrapReachabilityResolver - Level 1, then Level 2 if configured, section 19)
  -> "Activating this device"           (BootstrapLaneClient -> /v1/activate, unchanged endpoint)
  -> "VPN is ready"
```

No manifest/transport/gateway/signing-key/"Level 1 vs Level 2" language
surfaces in this flow.

## 26. Migration/backward compatibility

Unchanged in substance from the first version. Phase 1: operator-issued raw
credentials keep working unchanged; the envelope is an additive wrapper, the
bundle is an additive, optional recovery object - neither replaces anything.
Phase 2: self-service issuance (section 32, B56-8) becomes the default
distribution path. Phase 3: raw credential distribution is deprecated for
new issuance but never removed from what `/v1/activate` accepts. No existing
user or activation record is broken at any phase; `activations.py`'s and
`EndpointManifest`'s schemas are both untouched by this design.

## 27. Hard-whitelist limitations

Restated, now honestly accounting for what Level 2 does and does not change:
if a network permits only a fixed external destination whitelist and *none*
of Nova's manifest-known endpoints, a Level 2 lane's own destination (were
one ever deployed), package-delivery channels, or issuer domains are on that
whitelist, this architecture still cannot create connectivity that does not
exist. Level 2 widens *which* destinations might work (a small, dedicated,
differently-hosted listener is one more thing that could be on, or added to,
a whitelist by the network operator - it is not a technique for getting onto
a whitelist the operator did not choose to include it on) - it does not
change the fundamental limitation. This document makes no guaranteed-
whitelist-bypass, guaranteed-Russia-connectivity, untraceability, or
universal-censorship-bypass claim, anywhere, including about Level 2.
Future, separately-researched mechanisms for the genuinely-hard-whitelist
case (pre-provisioned working endpoint, trusted personal relay/pairing,
offline transfer of a currently-reachable gateway's data) remain named but
out of scope (peer pairing, B51, B54).

## 28. Test plan

Extended from the first version with bundle/Level-2-specific cases, nothing
removed:

Unit: envelope parsing/signature/expiry (unchanged from the first version's
package tests, now scoped to `ActivationEnvelope` only), hint-list filtering
(unchanged), and - new - `SignedBootstrapBundle` offering through `offer()`
reusing the *existing* `EndpointManifestRepositoryTest` fixtures directly
(newer-than-embedded accepted, older-than-LKG rejected, expired rejected,
unknown-key rejected, previous-but-still-trusted-key accepted) - proving
this design adds no new acceptance logic to verify, only a new call site.

Integration: Level 1 exhausted -> falls back to attempting bundle import (if
the user has one) -> re-resolves candidates -> succeeds; all manifest
origins AND all embedded/LKG candidates blocked with no bundle available ->
correctly reports `NO_TRUSTED_BOOTSTRAP_CANDIDATE`/`ALL_LEVEL1_PATHS_UNREACHABLE`
rather than silently hanging; simultaneous redemption (unchanged, reuses
existing B8C1A/B8C1C tests).

Chaos: unchanged from the first version, extended to include a bundle
import racing a concurrent LIVE manifest refresh (both should converge on
the same "highest valid version wins" outcome via the existing rollback
guard - no new race to prove, since both paths call the same `offer()`
under whatever concurrency control it already has).

Security: replay/theft (unchanged), bundle substitution/downgrade (must be
rejected by the *existing* rollback guard, not a new one - test asserts no
new code path exists to bypass it), attempted unlimited Level 2 egress (must
be rejected by the architecture-level destination allowlist - deferred to
whenever Level 2 is actually built, section 32), device-count race
(unchanged, reduces to existing `decide_and_bind` tests).

No test in this plan produces or implies a real Russia/hard-whitelist claim.

## 29. Rollout plan

See section 26 (phased backward compatibility) and section 32 (slices). No
rollout of production infrastructure occurs in this document.

## 30. Open questions

- Should `SignedBootstrapBundle` ship as a full `EndpointManifest` or a
  narrower, size-bounded subset shape in v1? (section 9) - a packaging
  choice, not a trust-model choice; either is verified identically.
- Should Level 2 ship in the same initial rollout as Level 1, or only after
  field evidence (B54) shows Level 1 alone is insufficient? (Now an explicit
  owner decision, section "Owner decisions required" below - this was
  previously the undecided architectural gap; it is now a genuine, resolved-
  at-the-architecture-level, deferred-at-the-build-level choice.)
- Should a Level 2 bootstrap capability ever be issuable *without* an
  already-presented envelope (e.g. a fully anonymous, extremely narrow
  "probe" capability just to check reachability)? Not proposed here -
  default is capability issuance always requires a validly-signed envelope
  first.
- Peer pairing remains future research only; unchanged from the first
  version.

## 31. Explicitly rejected alternatives

Unchanged list from the first version, plus two new rejections from this
correction pass:

- **A separate, independent trust root for activation packages** - rejected;
  violates "one root architecture, multiple delivery paths."
- **A brand-new "bootstrap edge" service/network segment for Level 1** -
  still rejected; Level 1's existing two-route surface is already narrow.
- **Encrypting the envelope's credential field** - rejected; adds friction
  without shrinking the actual exposure window.
- **A package-level redemption/device counter duplicating `max_devices`** -
  rejected; second unsynchronized source of truth.
- **Model 3 (unauthenticated public bootstrap tunnel with broad restricted
  egress)** - rejected for Level 1; Level 2 (Model D hybrid) is deliberately
  narrower than this.
- **Reusing enrollment tokens as the bootstrap credential** - rejected.
- **New: signing the envelope and the bundle together as one object under
  one signature** - rejected; this is exactly the "one physical encoding"
  the correction explicitly warned against - it would silently recreate a
  single trust root, defeating the entire point of separating activation
  entitlement authority from network-fact authority (section 6).
- **New: letting the activation-issuer key sign network endpoint facts
  directly, to avoid having two signature types in one package** - rejected;
  this is precisely Correction 1's forbidden shortcut. Implementation
  convenience is not a reason to let a high-volume, eventually self-service
  key acquire network-fact authority.

## 32. Recommended implementation slices

Corrected per Correction 13 - reordered so the load-bearing reachability
work (envelope/bundle split, imported-manifest path) lands before anything
that only reorders already-trusted candidates, and Level 2 is explicitly
its own, later, separately-gated slice:

1. **B56-1** - `ActivationEnvelope` parser/verifier + canonical encoding +
   typed failure enum + unit tests. No network code, no server changes, no
   bundle handling yet.
2. **B56-2** - Client-side "import a `SignedBootstrapBundle`" action that
   calls the *existing* `EndpointManifestRepository.offer()` unmodified,
   plus the new `ManifestSource.IMPORTED_SIGNED_BOOTSTRAP` diagnostic value
   and its unit tests (reusing existing `EndpointManifestRepositoryTest`
   fixtures per section 28). This is the slice that actually closes the
   circular-dependency gap and is deliberately sequenced before rate
   limiting or issuance tooling, since it is the load-bearing fix.
3. **B56-3** - `limit_req`/`limit_conn` for `/v1/activate` and
   `/v1/manifest` in both existing nginx configs - closes the confirmed,
   independent gap (section 1/11/22), does not depend on B56-1/2.
4. **B56-4** - Delegated activation-issuer key ceremony + operator-only
   issuance CLI producing `ActivationEnvelope`s via the *existing*
   `issue_activation()`, plus an operator workflow for attaching an
   existing signed `EndpointManifest` as a package's optional bundle.
5. **B56-5** - `BootstrapCandidateRepository`/`BootstrapReachabilityResolver`
   (Level 1 only)/`BootstrapLaneClient`, wired to the existing
   `ReachabilityEngine`/`EndpointManifestRepository`, behind a debug-only
   entry point first.
6. **B56-6** - Level 2 restricted bootstrap transport: capability
   issuance/validation, the dedicated listener, its destination allowlist
   and abuse limits (section 11) - explicitly gated on an owner decision
   (below) about whether it ships in the same rollout as Level 1 or only
   after field evidence justifies it. Independently reviewable and
   independently deferrable without blocking B56-1 through B56-5.
7. **B56-7** - QR/deep-link/import UX + recovery UX (section 25/20),
   release-facing only after B56-1/2/5 are merged and reviewed (B56-6 not
   required for a release if Level 2 is deferred).
8. **B56-8** - Self-service issuance interface definition, explicitly
   without billing/ecommerce, **with its own security review of the
   issuer-service compromise scenario** (section 21's corrected finding -
   this is now an explicit prerequisite of this slice, not an afterthought).
9. **B56-9** - Chaos/security/replay/outage validation pass (section 28)
   against a real staging activation store, before any production rollout
   decision.

Each slice fails closed on its own and does not require a later slice to
exist to be safe to merge. B56-6 (Level 2) is the one slice this correction
pass explicitly allows to be deferred independently of the rest - Level 1
(B56-1/2/3/4/5/7) is a complete, self-consistent bootstrap architecture on
its own; Level 2 is additive hardening for the harder reachability case.

---

## Decision Gate

**Verdict: B - ARCHITECTURE READY WITH EXPLICIT OWNER DECISIONS.**

Re-decided from scratch, not carried over from the first version. Every
load-bearing architectural question Correction 1-11 raised now has a
defined answer:

- Credential delivery: solved (`ActivationEnvelope`, section 6/7).
- Fresh endpoint recovery when known endpoints are blocked: solved
  (`SignedBootstrapBundle` through the existing, unmodified
  `EndpointManifestRepository.offer()`, section 10/16) - **this is the fix
  for the gap that made the first version insufficient.**
- Direct bootstrap reachability: defined (Level 1, section 11, reuses
  existing reachability infrastructure).
- Restricted fallback transport: defined at the architecture level (Level 2,
  section 11) with a selected auth model (Hybrid/Model D) and an explicit
  server-side enforcement boundary - not built, but no longer an open
  question either.
- Manifest authority uniqueness: preserved structurally (section 6/9) - the
  activation-issuer key can never sign a network fact; `offer()` remains the
  one and only acceptance point for endpoint facts, unmodified.
- Rollback/precedence behavior: fully specified for every case Correction 3
  asked about (section 16), all resolved by the existing rollback guard.
- Threat model: corrected with distinguished blast radii per authority
  (section 21), including the previously-understated issuer-service
  compromise case.

No unresolved cryptographic or trust-model blocker remains. This stays a
**B**, not an A, because the following are genuinely product/operational
choices, not technical unknowns - unchanged in kind from the first version,
with three new items reflecting Level 2's now-defined-but-not-built status:

1. **Rate limiting** (section 1/11/22) - still real and missing; B56-3 is
   independent of everything else and can ship regardless of the rest of
   this proposal's timeline.
2. **Envelope default `expiresAt` window** - "short, e.g. 24-72h"
   recommended, not mandated.
3. **Self-service issuance timing** (B56-8) - and now explicitly gated on
   its own issuer-service security review per the corrected threat model
   (section 21).
4. **Whether Level 2 (B56-6) ships in the same rollout as Level 1, or only
   after field evidence (B54) shows Level 1 is insufficient** - new, and
   deliberately classified here as a product/operational timing choice, not
   a load-bearing architecture gap, because Level 1 alone is already a
   complete, self-consistent bootstrap architecture (section 32).
5. **Bootstrap capability TTL and abuse limits** (Level 2, section 11/22) -
   concrete numeric defaults, not an open trust-model question.
6. **Imported-bundle maximum acceptable age / any additional recovery rules
   beyond what `ManifestRollbackGuard` already enforces** - new; this
   document's position is that no additional rule is needed (the existing
   guard already fully specifies acceptance), but the owner may want an
   operational policy on top (e.g. "don't hand out a bundle recovery package
   for a manifest generation older than N").
7. **B56's assigned milestone number** - reconfirmed still free on
   `origin/main` as of this correction pass; provisional.

## Final report

See the branch's final message to the user for the full point-by-point
report, including the corrected starting-baseline SHA (this branch's actual
parent commit, not the stale local ref the first version's report cited),
confirmations that B46-2P/B37/PR #35/PR #86/B45B-5/production infrastructure/
production transport selection were all untouched, and that no universal
long-lived bootstrap secret or whitelist-bypass claim was introduced.
