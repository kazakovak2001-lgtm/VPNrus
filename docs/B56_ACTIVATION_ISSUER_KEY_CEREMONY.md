# B56 Activation-Issuer Key Ceremony

Status as of this document: **B56-4A tooling implemented and cross-language
verified. NO production ceremony has been performed.** No production
activation-issuer private key exists, no production public key is embedded
in `net.pocvpn.client.activation.ActivationIssuerTrustAnchors`, and
`gateway/tools/activation_envelope_issuer.py` has never been run against a
real production activation store. See "What B56-4B still has to do" below
for the exact remaining steps.

## Purpose separation from the manifest signing key

This is a **second, independent** Ed25519 signing authority - never the
same key, never the same tool, never cross-verifiable:

| | Activation authority | Network (manifest) authority |
|---|---|---|
| Signs | `ActivationEnvelope` | `EndpointManifest` / `SignedBootstrapBundle` |
| Verified by | `Ed25519ActivationEnvelopeVerifier` + `ActivationIssuerTrustAnchors` | `Ed25519ManifestVerifier` + `ManifestTrustAnchors` |
| Operator tool | `gateway/tools/activation_envelope_issuer.py` (B56-4A, this doc) | `gateway/tools/manifest_signing.py` (B11/B12, unchanged - see `B12_MANIFEST_KEY_CEREMONY.md`) |
| Domain-separation tag | `NOVA_ACTIVATION_ENVELOPE_V1` | (implicit - separate canonical format/codec entirely) |
| Content | Activation entitlement metadata only - **never** a host/IP/port/SNI/transport fact | Endpoint routing facts |

The two key material files, the two trust-anchor types
(`ActivationIssuerTrustAnchors` vs. `ManifestTrustAnchors`), and the two
operator CLIs are **disjoint by construction** - `activation_envelope_issuer.py`
never imports or touches `manifest_signing.py`'s key material, never signs a
manifest, and never adds an activation key to `ManifestTrustAnchors`. See
`ActivationIssuerTrustAnchorsTest` and
`ActivationEnvelopePythonCompatibilityTest`'s explicit cross-trust
regression for the compile-time/runtime proof of this separation.

## The private key never enters the repo, the VPS, argv, or stdout

`activation_envelope_issuer.py` deliberately does **not** repeat
`manifest_signing.py`'s historical `--private-key-b64`/JSON-stdout
`generate-key` weakness (see that file's own `generate-key`/`sign` commands,
predating this ceremony's safer pattern). Instead:

- `generate-key --private-key-out PATH` writes the raw 32 private key bytes
  directly to a file - **never** printed, logged, or included in any
  exception message.
- `issue --private-key-file PATH` reads that same raw-32-byte file - the
  key is **never** passed as a CLI argument, **never** read from an
  environment variable, **never** accepted as Base64/JSON.
- Both commands refuse to write an output file that already exists, and
  refuse to write into any directory that is (or is inside) a git working
  tree - a real production private key file must live somewhere entirely
  outside this repository's checkout, on an operator-controlled offline
  machine.
- Public metadata (`issuerKeyId`, `publicKeyBase64`, a SHA-256
  fingerprint) is written to a **separate** file and contains no private
  material at all - see `test_activation_envelope_issuer.py`'s
  `GenerateKeyTests` for the automated proof.
- `issue` never accepts a raw exception message from anything that runs
  after the credential exists in memory (see "Post-issuance failures never
  leak diagnostic text" below) - only bounded, non-secret fields (a phase
  description, the failing exception's class name, and the activation ID)
  are ever printed on a failure path.

### Real atomic no-clobber file publication - and its precise durability model

Every sensitive output (the private key, the public metadata, and a signed
envelope artifact) is published through the SAME two functions
(`publish_secret_no_clobber`, then separately `confirm_post_publication`),
in two explicit phases with the ROLLBACK BOUNDARY drawn precisely at the
line between them (PR #95 review fix, round 3):

```text
The secret payload is fully written and fsynced before the atomic no-clobber
final-path publication. A successful final link is the logical transaction
commit point. Directory fsync is attempted to confirm crash durability;
failure of that post-publication durability confirmation is surfaced as an
operator warning and does not roll back an already-published activation/key.
```

Concretely: the payload is written to a sibling temp file and `fsync`ed
FIRST (this is PRE-publication - failures here may freely propagate,
nothing has been committed yet), then published to the final path using
`os.link` - which the operating system itself guarantees fails atomically
with `FileExistsError` if the final path already exists, closing a real
TOCTOU race an earlier `if os.path.exists(...): ... ; os.replace(...)`
pattern was vulnerable to (a concurrent writer creating the destination in
the gap between the check and the replace would have been silently
overwritten). If the underlying filesystem cannot provide this no-clobber
guarantee at all (`os.link` raises anything other than `FileExistsError`),
the tool fails closed with an error - it never falls back to an
overwrite-capable write. This `os.link` call succeeding is the ONE logical
commit point - the final path exists and is complete from that instant on.
`publish_secret_no_clobber` returns IMMEDIATELY once that link succeeds -
it performs no further fallible work of its own - which is what lets
`issue`'s and `generate-key`'s own rollback/revocation regions end right
there, with zero risk of a later, purely additional confirmation step
being mistaken for a publication failure.

This second, entirely separate function, `confirm_post_publication`, is
called AFTERWARD, OUTSIDE any rollback/revocation region, and does two
purely additional things - removing the now-redundant temp hardlink name,
and a `fsync` of the file's CONTAINING DIRECTORY, an additional, SEPARATE
confirmation that the new directory *entry* (not the file's own
already-fsynced contents) will survive a crash. Neither step is ever
called "confirmed" when it did not succeed, and this function itself
**never raises, under any circumstance** - including if the attempt to
print its own warning fails (a closed stderr, `BrokenPipeError`, or any
other exception from the output channel is itself swallowed). If either
step fails, the already-published file is NOT deleted, no already-created
activation is revoked because of it, and the tool prints a best-effort,
non-secret `WARNING - durability: ...` message when it can. For a real
production ceremony, such a warning should be treated as an operator
condition worth investigating (e.g. a degraded filesystem) BEFORE
distributing the resulting artifact - but it never makes the
already-published private key or envelope vanish logically, and it never
triggers a rollback.

### Private-key read-time hygiene

Before `issue` ever uses a private key file, it requires the file to be a
regular file and, on POSIX platforms, rejects a mode that is
group/other-readable, -writable, or -executable (the same "unsafe existing
mode" discipline `gateway/api/activations.py`'s own store already applies)
- `chmod 600` a real production key file before use.

### Platform limitation - be truthful about it

`generate-key`/`issue`'s output files are written with POSIX `0600`
permissions where the platform supports it (`os.chmod`), and the POSIX
mode check above only runs on POSIX. **On Windows, `os.chmod`'s single
owner-write bit is not an equivalent ACL guarantee** - it does not
restrict which other local accounts can read the file the way POSIX
group/other permission bits do, and no mode check is performed there at
all. The tool prints an explicit warning when run on Windows; an operator
generating a real production key on Windows must additionally apply a real
NTFS ACL (or, preferably, perform the ceremony on a Linux/WSL machine,
matching the existing B12 manifest key ceremony's own recommended
environment).

## Safe key-generation command shape

```text
python3 gateway/tools/activation_envelope_issuer.py generate-key \
  --key-id <issuer-key-id> \
  --private-key-out <path-OUTSIDE-this-repo>/activation-issuer-<key-id>.key \
  --public-metadata-out <path-OUTSIDE-this-repo>/activation-issuer-<key-id>.meta.json
```

This never prints the private key. It prints only: the key id, the public
key's SHA-256 fingerprint, and the two output paths.

`generate-key` publishes the PUBLIC metadata file first and the PRIVATE key
file second - the successful no-clobber final-path link of the PRIVATE
KEY is the sensitive commit point. If metadata publication fails, no
private key was ever written. If the private key's own publication then
fails BEFORE its final link succeeds, the command returns failure and the
already-published metadata is deliberately LEFT IN PLACE, never deleted:

```text
Metadata-only orphan after private-key pre-publication failure is harmless
public data and intentionally not deleted automatically, avoiding a cleanup
TOCTOU race.
```

An unconditional `os.remove()` of the metadata pathname would delete
WHATEVER currently occupies that path - which, in a genuine race, could be
a completely different file a concurrent actor placed there after this
command's own publish. The metadata is public data that cannot sign
anything by itself, and `issue` already requires its recorded public key
to match a private key's OWN derived public key - so an orphaned metadata
file with no matching private key is simply unusable, never a security
risk. Once the private key file's final link has succeeded, neither file
is ever deleted for any reason (including a later directory-fsync warning
or a cosmetic print failure).

## issue consumes the generated metadata file - the key id is never independently typed

`issue` does **not** accept a free-standing `--issuer-key-id`. It accepts
`--issuer-metadata-file`, the EXACT public-metadata JSON `generate-key`
produced alongside `--private-key-file`:

```text
python3 gateway/tools/activation_envelope_issuer.py issue \
  --store <activations.json> \
  --issuer-metadata-file <path>/activation-issuer-<key-id>.meta.json \
  --private-key-file <path-OUTSIDE-this-repo>/activation-issuer-<key-id>.key \
  --envelope-valid-for-hours <N> \
  --out <signed-envelope.bin>
```

Before anything else happens (before any activation is created), `issue`:

1. strictly parses the metadata file, requiring EXACTLY the three fields
   `issuerKeyId`/`publicKeyBase64`/`publicKeyFingerprintSha256Hex`, and
   verifies the fingerprint field actually matches SHA-256 of the metadata's
   own `publicKeyBase64` (a hand-edited/corrupted metadata file is rejected,
   not trusted);
2. derives the public key from `--private-key-file` and requires it to
   match the metadata's `publicKeyBase64` byte-for-byte.

Without this, an operator could accidentally sign with private key A while
labeling the resulting envelope `issuerKeyId=B` - a validly-signed envelope
that no Android trust-anchor population could ever verify, because Android
selects which public key to check against purely by `issuerKeyId`. Any
mismatch here exits non-zero **before `issue_activation()` is ever
called** - no activation is created, no envelope is written.

## The transaction commit point

The LOGICAL commit point is the successful no-clobber final-path
publication of the signed envelope artifact - precisely, the moment
`os.link(tmp, args.out)` succeeds inside `publish_secret_no_clobber(args.out, artifact)`.
Everything fallible - building the envelope, canonicalizing it, signing
it, encoding the outer container, computing its SHA-256, and the
pre-publication temp-file write/fsync - happens strictly BEFORE that
link, and `cmd_issue`'s activation-revocation `try` block ends
IMMEDIATELY after calling `publish_secret_no_clobber` (round 3 review
fix) - `confirm_post_publication`, the ONLY thing that runs afterward,
is called OUTSIDE that block and never raises. The rule this enforces:

- **Before** that link succeeds: any failure (including the newly-issued
  activation record failing to read back at all, which is itself treated
  as an invariant violation) revokes the activation that was just created
  via the existing `revoke_activation()`, and no envelope artifact exists.
- **After** that link succeeds: `revoke_activation()` is structurally
  unreachable from any code path - the activation stays `ACTIVE` and the
  artifact stays on disk, permanently. This includes a failure of the
  POST-publication directory-fsync durability confirmation or of the
  redundant-temp-file cleanup (both surfaced only as a best-effort,
  non-throwing warning, per the durability model above), and any later,
  purely cosmetic failure (e.g. an unrelated print statement) - none of
  these can ever cause a rollback of a transaction that has already
  logically committed.

## Post-issuance failures never leak diagnostic text

Once `issue_activation()` has produced the plaintext credential, no raw
exception message from anything that runs afterward (signing, encoding,
writing the artifact, or the revocation call itself) is ever printed - only
a fixed phase description, the failing exception's CLASS NAME, and the
(non-secret) `activation_id`. This is deliberately conservative: today's
exception messages in that code path are benign, but a future change to a
lower layer could raise an exception whose message happens to embed
sensitive input, and this rule means that would never reach stdout/stderr
regardless.

## Public fingerprint verification

Exactly like `B12_MANIFEST_KEY_CEREMONY.md`'s own convention: record the
printed SHA-256 fingerprint of the public key (hex) somewhere out-of-band
(this document, an operator runbook, a signed commit message) so anyone
verifying which physical key ceremony produced a given
`ActivationIssuerTrustAnchors` entry can confirm it independently of the
committed Kotlin source - **never** by comparing private key material.

## Rotation model

`ActivationIssuerTrustAnchors`/`FixedActivationIssuerTrustAnchors` is a
`Map<ActivationIssuerKeyId, ByteArray>` - it already supports more than one
simultaneously-trusted public key, exactly like
`EmbeddedBootstrapManifest.trustAnchors()` currently trusts two manifest
keys (`prod-manifest-key-2026-09-01` and `-09-14`) during its own rotation
window. The same pattern applies here:

1. Generate a new activation-issuer keypair (new `issuerKeyId`) with
   `generate-key`, offline, well before the old key's planned retirement.
2. Add the new key's public bytes to Android's
   `FixedActivationIssuerTrustAnchors` **alongside** the old one (both
   trusted simultaneously) - a client build with both keys present accepts
   an envelope signed by **either**.
3. Once every envelope that could still be presented (bounded by the
   longest `--envelope-valid-for-hours` ever issued under the old key) has
   expired, remove the old key's public bytes from a later Android build.

There is no "gap" where both an old and a new envelope are simultaneously
un-verifiable, and no envelope-specific rotation logic exists in
`SignedBootstrapBundleImporter`/the verifier itself - rotation is entirely
a trust-anchor-set change, exactly like the manifest key's own rotation.

## Revocation implications

Revoking an **activation** (`activation_tokens.py revoke <activation_id>`,
unchanged) makes the credential inside an already-issued
`ActivationEnvelope` useless the moment the server-side entitlement check
runs - but it does **not** retroactively invalidate the envelope's Ed25519
signature. A previously-issued, still-cryptographically-valid envelope for
a revoked activation will still decode and verify client-side; it simply
fails to redeem successfully against the (now-revoked) server entitlement.
This is the same shape as any bearer-credential system: signature validity
is a property of the envelope's own history, not of the credential's
current live status - there is no envelope revocation list in B56-4A or
B56-4B.

Revoking an **activation-issuer key itself** (suspected key compromise) is
the rotation procedure above run in reverse: remove the compromised key's
public bytes from a new Android build's `FixedActivationIssuerTrustAnchors`
as soon as possible. Any envelope that key ever signed - for a still-ACTIVE
activation or not - stops verifying entirely once that public key is no
longer trusted, since verification (not just redemption) fails closed on
an unknown `issuerKeyId`.

## Issuer-service compromise vs. key-only compromise

- **Key-only compromise** (the private key file leaks, but the operator's
  issuance workflow/store is untouched): an attacker can mint arbitrarily
  many envelopes for entitlements that do not exist server-side (since
  `issue_activation()` is what actually creates the redeemable credential -
  a leaked signing key alone lets an attacker sign a *plausible-looking*
  envelope, but it can only ever wrap a credential that
  `gateway.api.activations.issue_activation()` genuinely created and
  `decide_and_bind` will genuinely accept). The blast radius of a pure key
  leak is therefore bounded by the SAME device-binding/max_devices/expiry
  rules every other activation credential is already bound by - it is not
  a network-fact or reachability compromise (no host/IP/port/SNI can ever
  be signed into an envelope - see structural test coverage).
- **Issuer-service/store compromise** (an attacker who can run
  `activation_envelope_issuer.py issue` itself, or write directly to
  `activations.json`): strictly worse - this is equivalent to compromising
  `activation_tokens.py`'s own operator access today, since B56-4A adds no
  new privilege beyond calling the SAME `issue_activation()`. There is
  nothing B56-4A introduces that widens this existing operator-trust
  boundary; the mitigation is the same one that already applies to
  `activation_tokens.py`: protect operator/CLI access to the production
  store and its lock file, not anything specific to the envelope signing
  key.

Both scenarios are explicit, out-of-scope-for-automated-mitigation
operator-trust assumptions, same as the rest of this codebase's activation
tooling - B56-4A does not add self-service or remote issuance (see its own
module docstring: no daemon, no HTTP endpoint).

## The envelope is a bearer secret

A signed `ActivationEnvelope` contains the plaintext activation credential
(`ActivationEnvelope.credential`) - anyone who obtains a copy of the
envelope artifact can redeem it exactly as if they had the raw credential
string. It must be handled with the same care as the raw credential itself:
never committed, never logged, transmitted only over a channel the intended
recipient controls (B56-7's job, not this tool's). The issuer CLI enforces
this at the tooling boundary (atomic non-overwriting writes, restrictive
permissions where supported, never printed to stdout/stderr) but cannot
enforce anything about what happens to the file afterward - that remains an
operator/delivery-channel responsibility.

## B56-4A has NOT performed the production ceremony

Confirmed explicitly, to keep `ActivationIssuerTrustAnchors`'s own
"no production activation-issuer key is populated here or anywhere in this
slice" statement true after this document exists:

- No `generate-key` invocation against a real, retained private key file
  has been run as part of B56-4A.
- No production public key/fingerprint is recorded in this document or
  anywhere else in this repository.
- `FixedActivationIssuerTrustAnchors`'s only populated instances remain
  test-only (see `ActivationIssuerTrustAnchorsTest`,
  `ActivationEnvelopePythonCompatibilityTest` - both use a deterministic,
  clearly-labeled TEST-ONLY key, never committed as a retained secret since
  its "secrecy" is irrelevant - it exists purely to prove the encoding is
  byte-for-byte compatible).
- No Android production trust-anchor population change was made.

## What B56-4B still has to do

1. Run `generate-key` for real, on an operator-controlled offline machine
   (Linux/WSL recommended - see platform-limitation note above), with the
   private key file written OUTSIDE any git working tree and never
   transmitted electronically.
2. Record the printed public key fingerprint out-of-band (this document's
   "Production ceremony" section, once it exists, mirroring
   `B12_MANIFEST_KEY_CEREMONY.md`'s own).
3. Add the production public key bytes + `issuerKeyId` to Android's
   `FixedActivationIssuerTrustAnchors` population (currently test-only) and
   ship that in a client build.
4. Perform a REAL cross-verification against that production key (not the
   deterministic test key this PR's fixtures use) - sign a real test
   envelope offline, verify it decodes/verifies correctly against the
   shipped Android trust anchor, exactly mirroring this PR's
   `ActivationEnvelopePythonCompatibilityTest` methodology.
5. Decide and document the real operational rotation/retirement schedule
   (this document's "Rotation model" section is the mechanism; B56-4B picks
   actual dates/cadence).
6. Only after all of the above: `activation_envelope_issuer.py issue` may
   be run against a real production activation store to mint the first
   real, redeemable `ActivationEnvelope`.

None of this is performed by B56-4A. This tooling slice exists specifically
so all of the above can be reviewed and exercised against test-only key
material BEFORE any production secret is ever generated.
