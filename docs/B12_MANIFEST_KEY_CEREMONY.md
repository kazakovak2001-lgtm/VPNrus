# B12 — Endpoint Manifest trust-key procedure

**Status: interfaces and tooling are real and ready; the production key
ceremony itself has NOT been executed.** The embedded trust key shipped in
this app (`EmbeddedBootstrapManifest`) remains the B11 placeholder — a real
Ed25519 keypair generated for that PR, documented as such in that file's own
docstring. Nothing in this document should be read as claiming a production
key ceremony is complete; it is not.

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

- Generating the real production keypair (step 1) — an intentional human
  action with real security consequences, never automated.
- Deploying `endpoint-manifest.bin` to the production VPS and setting
  `POCVPN_API_MANIFEST_PATH` — an operator deploy action.
- Fronting `GET /v1/manifest` at the public HTTPS edge (nginx, alongside the
  existing `/v1/activate`/`/v1/xray-profile` routes per
  `docs/B8K5A`-era deployment notes) — an operator deploy action, not
  something this PR's code changes perform.
