# B12 — Endpoint Manifest trust-key procedure

**Status (B17, 2026-09-01): the production key ceremony has been performed.**
The embedded trust key shipped in this app (`EmbeddedBootstrapManifest`) is
now a real production Ed25519 keypair, generated and used entirely inside one
local, offline script invocation — the private key bytes were never printed
to any terminal/tool output, never passed as a CLI argument, never
committed, and are stored only in an operator-local file outside this
repository. See "Production ceremony (B17, completed)" below for the exact
procedure and what remains an operator step (live deployment to both VPSes).

## Production ceremony (B17, completed)

- **Key id**: `prod-manifest-key-2026-09-01`
- **Public key (base64)**: `yvxGVezkV5tkkzcQVf975mSDY9xYh72eOLOMwSFy+aw=`
- **Public key SHA-256 fingerprint**:
  `2c39eddd256115600e3008495ee52b95865ab7a525f102f2fe45aad17b614aa1`
  — use this fingerprint to confirm the embedded key's identity out-of-band;
  never the private key itself.
- **Private key**: generated with `Ed25519PrivateKey.generate()` and used to
  sign the production manifest inside one local Python process (never
  `gateway/tools/manifest_signing.py generate-key`'s own CLI, which prints
  the private key to stdout — deliberately avoided here). The private key
  bytes were written directly to an operator-local file outside this
  repository (path recorded only in the operator's own local notes, not in
  this document or in git) and never appeared in any command's arguments or
  output. This document does not and must not record that path or the key
  itself.
- **Manifest signed**: `manifestVersion=1`, `signingKeyId=prod-manifest-key-2026-09-01`,
  issued 2026-09-01, expires 180 days later (2027-02-27) — see "Versioning
  and expiry policy" below for why 180 days.
- **Endpoints named**: `frankfurt` (Germany/Oracle Cloud, `152.70.43.1`) and
  `stockholm` (Sweden/AWS, `16.170.208.231`), each with AMNEZIA_WG (51820),
  XRAY_REALITY (2053), and TLS_TCP (2083) transport bindings — host/port
  only, no per-device secrets, no server public keys, no client tunnel IPs
  (see `EmbeddedBootstrapManifest`'s own docs for the full "what must never
  be embedded" list, unchanged from B11).
- **Source JSON**: `gateway/tools/production_manifest_2026-09-01.json`
  (public, safe to commit — no secret material).
- **Signed artifact**: `gateway/tools/endpoint-manifest-2026-09-01.bin` (the
  exact bytes to deploy at `POCVPN_API_MANIFEST_PATH` on BOTH gateways, and
  the same bytes packed into `EmbeddedBootstrapManifest`'s embedded
  constants).
- **Embedded in**: `EmbeddedBootstrapManifest.kt`
  (`BOOTSTRAP_PUBLIC_KEY_BASE64`/`CANONICAL_BYTES_BASE64`/`SIGNATURE_BASE64`).
- **NOT yet done as of this ceremony**: live deployment of
  `endpoint-manifest-2026-09-01.bin` to either gateway's
  `POCVPN_API_MANIFEST_PATH`, and fronting `GET /v1/manifest` at either
  nginx edge — both remain explicit operator deploy actions (see "What
  remains an explicit operator step" below), never performed automatically
  by this ceremony or by any code change in this PR.

## Versioning and expiry policy

- **Monotonic version**: `manifestVersion` starts at 1 for this production
  root and must strictly increase on every re-signed manifest —
  `ManifestRollbackGuard` already enforces this unconditionally.
- **Creating version N+1**: edit
  `gateway/tools/production_manifest_2026-09-01.json` (or a newly-dated
  copy) with the new `manifestVersion`/facts, then re-run the SAME offline,
  private-key-never-printed signing procedure this ceremony used (see
  `ceremony` step-by-step below), against the SAME production private key
  file. Never sign version N+1 with a different key unless this is
  deliberately a key rotation (see "Rotation" below, unchanged from B11).
- **Choosing expiry**: 180 days balances the manual re-signing ceremony's
  real operational cost (an offline, human-in-the-loop action - see
  "Procedure" below) against bounding how long a compromised-but-undetected
  signing key could keep signing valid-looking manifests. Shorter-lived
  production infrastructure facts (e.g. an emergency address rotation) do
  not need to wait for the full 180 days — see "Emergency endpoint changes"
  below.
- **Emergency endpoint changes** (e.g. Stockholm's non-durable IP finally
  rotates): sign a new manifest with a strictly higher `manifestVersion`,
  the SAME production key, and a fresh `issuedAt`/`expiresAt` window — same
  procedure as any other new version, just sooner than the normal 180-day
  cadence. Never edit `production_manifest_2026-09-01.json` in place and
  reuse its old signature — any change to the manifest content requires a
  fresh signature over the new canonical bytes.
- **Rollback rules**: unchanged from B11/B12 — `ManifestRollbackGuard`
  rejects any candidate whose `manifestVersion` is not strictly greater than
  whatever is currently trusted (LKG or bootstrap), and `offer()` never
  touches the stored LKG when it rejects a candidate. There is no separate
  "manual rollback" affordance — reverting to an older manifest's CONTENT
  requires re-signing that content under a NEW, higher version number.

## Why this is safe to defer

`EndpointManifestRepository`/`Ed25519ManifestVerifier`/`ManifestTrustAnchors`
were deliberately built so which key is trusted is a **data** question
(`ManifestTrustAnchors.publicKeyFor(TrustedKeyId)`), never a code question.
Rotating from the placeholder to a production key requires no change to any
verification logic — only:

1. generating the real key (below),
2. replacing `EmbeddedBootstrapManifest`'s embedded public key + a freshly
   signed bootstrap artifact, and
3. (once a distribution channel exists — see `docs/ROADMAP.md`'s Signed
   Offline Bootstrap row) publishing manifests signed by the new key via
   `GET /v1/manifest`.

## Root / signing separation

This slice keeps root and signing collapsed into one key (same discipline
B11 already documented). The interfaces below don't assume that forever:

- **Root key** (future): held completely offline, ideally on an air-gapped
  machine or hardware token. Its only job, if/when introduced, is to sign a
  short-lived statement authorizing a **signing key** — never to sign
  manifests directly. `ManifestTrustAnchors` already accepts an arbitrary
  `Map<TrustedKeyId, PublicKeyBytes>`, so a root→signing-key certificate
  chain can be added later as a *second* trust-anchor lookup layered in
  front of it, without touching `Ed25519ManifestVerifier`'s signature check
  itself.
- **Signing key** (what exists today): the key that actually signs each
  `EndpointManifest` via `gateway/tools/manifest_signing.py`. **Must never
  touch the production VPS** — see `gateway/api/handler.py`'s own docstring:
  `GET /v1/manifest` only ever reads and serves a file an operator placed on
  disk; the gateway process holds no private key material for this at all.

## Procedure for a real production signing key

Run entirely offline, on a machine that never has the resulting private key
transferred to the production VPS:

```bash
python3 gateway/tools/manifest_signing.py generate-key --key-id <descriptive-id>
```

This prints `{keyId, privateKeyBase64, publicKeyBase64}`.

1. **Store the private key offline.** Recommended: a password manager entry
   or an encrypted offline volume, never in this repository, never in an
   environment variable on any server, never in a CI secret store unless
   that CI is itself fully offline/air-gapped for this purpose.
2. **Embed the public key** in `EmbeddedBootstrapManifest.BOOTSTRAP_PUBLIC_KEY_BASE64`
   (and update `TRUSTED_KEY_ID` if the key id changes) — this constant is
   the only place the public key needs to change on the client.
3. **Sign a real production manifest:**
   ```bash
   python3 gateway/tools/manifest_signing.py sign-and-package \
     --manifest <production-manifest.json> \
     --private-key-b64 <the offline private key> \
     --out endpoint-manifest.bin
   ```
4. **Deploy the artifact** to the production VPS at the path configured as
   `POCVPN_API_MANIFEST_PATH` (see `gateway/api/config.py`) — a plain file
   copy, no server-side signing step, ever.
5. **Re-embed a matching bootstrap** in the app (steps 2–3 against the SAME
   manifest content) and cut a new app release, so the embedded emergency
   fallback and the live-served manifest are never signed by different,
   inconsistent trust roots.

## Rotation

To rotate the signing key (suspected compromise, scheduled rotation, or
introducing root/signing separation for real):

1. Generate a new keypair (step 1 above) with a **new** `--key-id` — never
   reuse a `TrustedKeyId`, so an old cached/pinned manifest can never be
   confused with a new key's manifest.
2. Publish a manifest **signed by the new key**, with a **higher
   `manifestVersion`** than anything currently live — `ManifestRollbackGuard`
   already refuses anything older, so this is the only requirement for a
   clean cutover.
3. Ship an app update whose `EmbeddedBootstrapManifest`/`ManifestTrustAnchors`
   trust the new key. For a transition window, `ManifestTrustAnchors` can
   hold **both** the old and new key simultaneously (it's a `Map`, not a
   single value) so already-installed old-app-version clients and
   already-downloaded old manifests keep verifying until they update.
4. Once confident no client still needs the old key, remove it from
   `ManifestTrustAnchors` in a later app release.

## Revocation

There is no separate "revoke a key" mechanism in this slice beyond
rotation — a compromised signing key is handled by rotating away from it
(above) and, if the compromise is severe enough that even old cached
manifests signed by it must stop being trusted, removing it from
`ManifestTrustAnchors` immediately (skipping the transition window) in an
emergency app update. A dedicated revocation list/mechanism is future work,
not built here — flagging it explicitly rather than pretending a stopgap is
the same thing.

## What remains an explicit operator step

- ~~Generating the real production keypair~~ — **done (B17, 2026-09-01)**,
  see "Production ceremony" above.
- Deploying `endpoint-manifest-2026-09-01.bin` to BOTH production VPSes
  (Frankfurt and Stockholm) and setting `POCVPN_API_MANIFEST_PATH` on each —
  an explicit operator deploy action, NOT performed by this PR's code
  changes and requiring the repository owner's approval before touching
  live infrastructure (see this repo's own merge/infra-safety rules).
- Fronting `GET /v1/manifest` at each gateway's public HTTPS edge (nginx,
  alongside the existing `/v1/activate`/`/v1/xray-profile` routes) — an
  operator deploy action.
- External verification after deployment: HTTPS success, exact byte
  identity against `endpoint-manifest-2026-09-01.bin`, valid signature,
  version/expiry, and that a tampered copy is rejected by the client.
