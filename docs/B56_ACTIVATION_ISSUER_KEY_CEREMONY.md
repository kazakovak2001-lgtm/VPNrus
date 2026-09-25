# B56 Activation-Issuer Key Ceremony

Status as of this document: **B56-4A tooling implemented and cross-language
verified. B56-4B1 production key ceremony COMPLETED (final, network-isolated
key)** - see "Production ceremony - 2026-09-20 (final, network-isolated)"
below. The FINAL production activation-issuer keypair
(`prod-activation-issuer-2026-09-20-r2`) was generated exactly once, inside
an explicitly network-isolated Linux network namespace on an
operator-controlled WSL/Linux machine; the PRIVATE key was never displayed,
never committed, and remains outside this repository; the PUBLIC key is
committed through
`net.pocvpn.client.activation.ProductionActivationIssuerTrustAnchors` and
cross-verified against the real private key (see that section).

An earlier candidate keypair (`prod-activation-issuer-2026-09-20`, no `-r2`
suffix) was generated in a first ceremony pass that did NOT establish
positive, after-the-fact evidence that the key-generation process itself
was network-isolated - see "Abandoned candidate" below. It was **never
merged, never trusted by any client build, and never used to issue a
redeemable activation** - it is superseded in full by the final key below
and does not appear in `ProductionActivationIssuerTrustAnchors`.

**No redeemable production `ActivationEnvelope` has been issued** -
`gateway/tools/activation_envelope_issuer.py issue` has never been run
against a real production activation store, and the production store itself
was never touched by either ceremony pass. See "What B56-4B still has to
do" below for the remaining steps (B56-4B2 onward).

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

## B56-4A did NOT perform the production ceremony (historical, superseded by B56-4B1 below)

Confirmed explicitly at the time B56-4A merged, to keep
`ActivationIssuerTrustAnchors`'s then-current "no production
activation-issuer key is populated here or anywhere in this slice"
statement true:

- No `generate-key` invocation against a real, retained private key file
  had been run as part of B56-4A.
- No production public key/fingerprint was recorded in this document or
  anywhere else in this repository.
- `FixedActivationIssuerTrustAnchors`'s only populated instances were
  test-only (see `ActivationIssuerTrustAnchorsTest`,
  `ActivationEnvelopePythonCompatibilityTest` - both use a deterministic,
  clearly-labeled TEST-ONLY key, never committed as a retained secret since
  its "secrecy" is irrelevant - it exists purely to prove the encoding is
  byte-for-byte compatible).
- No Android production trust-anchor population change had been made.

**This is no longer the current state** - see "Production ceremony -
2026-09-20" below, where B56-4B1 performed the real ceremony and committed
`ProductionActivationIssuerTrustAnchors`. This section is kept as an
accurate historical record of B56-4A's own scope.

## Abandoned candidate — prod-activation-issuer-2026-09-20 (first pass)

A first ceremony pass ran the merged B56-4A `generate-key` command on an
operator-controlled WSL/Linux machine, with output written to a directory
outside any git working tree (`~/.nova-secrets/activation-issuer/`, mode
`700`; the private key file itself mode `600`). Its `issuerKeyId` was
`prod-activation-issuer-2026-09-20` (no `-r2` suffix), public key
`HZLHOiOrEXM3VXvpIudoBORhJBXUXh7lNcRry5Gcg1M=`, fingerprint
`b7ba79ed8284e1eade23f19f842f1dee1ca5d1b2c69ef367fc227afdf4d809c5`.

On review, no positive evidence could be established that the
key-generation *process itself* had no external network path at the instant
it ran - the machine was an ordinary WSL/Linux shell with normal networking
available, not an explicitly isolated namespace, and no isolation mechanism
(e.g. `unshare --net`, a disabled interface) was used during that pass.
Being inside WSL and writing outside Git are real, verified properties, but
they are **not** equivalent to a network-isolation guarantee for the
generation step - so this candidate's ABSENCE of network isolation is
treated as fact, not merely "unproven," and it is retired accordingly:

- **ABANDONED BEFORE MERGE — offline isolation provenance not proven.**
- It was never added to a merged `ProductionActivationIssuerTrustAnchors`,
  never trusted by any client build, and never used to sign or issue a
  redeemable activation.
- This is explicitly **not** a claim of key compromise or leak - the
  private key was never displayed, never left the operator-controlled
  machine, and the issue is provenance assurance only, not a known
  exposure.
- Its private key file (`prod-activation-issuer-2026-09-20.key`) and public
  metadata remain on the operator-controlled WSL machine, untouched
  (neither deleted nor overwritten) as an audit record of this pass; they
  were never committed and must never be added to
  `ProductionActivationIssuerTrustAnchors`.

## Production ceremony — 2026-09-20 (final, network-isolated)

Performed as B56-4B1, on the same operator-controlled WSL/Linux machine,
this time using the merged B56-4A `generate-key` command run **inside an
explicitly network-isolated Linux network namespace**
(`unshare --net --fork bash -c '...'`). Immediately before generation, the
namespace was verified via `ip -br addr` and `ip route`, both run inside
that same namespace/process invocation:

```text
$ ip -br addr
lo               DOWN
$ ip route
(no output - no routes)
```

Only a `DOWN` loopback interface and zero routes were present - no
externally routable interface and no default route of any kind. `generate-key`
was then run inside that same isolated namespace, so the key-generation
process itself had no possible external network path at the instant it ran.
Output was written to the same protected directory, outside any git working
tree (`~/.nova-secrets/activation-issuer/`, mode `700`; the private key file
itself mode `600`), under a distinct issuer key id for unambiguous audit
history.

- **issuerKeyId**: `prod-activation-issuer-2026-09-20-r2`
- **publicKeyBase64**: `zevmlNdAu9l7ofRx9MFvp1oK2dSMA0ckIgqVYvuLtNE=`
- **publicKeyFingerprintSha256Hex**:
  `88ccf8198af0d7775946253eb958f60f5174c652f6e28a4daecd857ab293e840`
- **Ceremony date**: 2026-09-20.
- **Network-isolation mechanism**: `unshare --net` Linux network namespace,
  verified loopback-only/no-route (see transcript above) in the same
  namespace/process that then ran `generate-key`.
- The PRIVATE key exists ONLY outside this repository, in the
  operator-controlled ceremony location described above. It was never
  printed, logged, displayed, hashed-and-reported, base64-encoded for
  display, copied into any Git checkout, or transmitted anywhere.
- **No redeemable production `ActivationEnvelope` was issued.** This
  ceremony ran ONLY `generate-key` - `issue` was never invoked, and
  `gateway.api.activations.issue_activation()` was never called.
- **The production activation store was not touched** - no
  `activations.json` was read, created, or modified as part of this
  ceremony.
- **Cross-verification result: PASSED.** A synthetic, clearly non-redeemable
  test envelope (`activationId=b564b100000000000000000000000002`,
  `credential=B56_4B1_R2_NON_REDEEMABLE_TEST_CREDENTIAL`, fixed test
  timestamps, no bootstrap bundle ref, no bootstrap capability hint) was
  signed OFFLINE with the real, final production private key using the
  already-reviewed `canonical_bytes`/`sign_envelope`/`pack_signed_envelope`
  primitives directly (never `issue`). The resulting artifact decodes
  through the existing `ActivationEnvelopeCodec` and verifies `Valid`
  through the existing `Ed25519ActivationEnvelopeVerifier` against
  `ProductionActivationIssuerTrustAnchors.trustAnchors()` (the real
  committed production public key) - see
  `ProductionActivationIssuerTrustAnchorsTest` (Kotlin), which also proves
  32-byte key length, the fingerprint match above, single-byte-tamper
  rejection, that the abandoned first-candidate key id is absent from the
  trust anchor map, and that manifest trust anchors are never involved.
  This fixture is explicitly labeled a
  `NON_REDEEMABLE PRODUCTION-KEY CROSS-VERIFICATION FIXTURE` in that test's
  own docs and was never inserted into any activation store.

### Offline backup status

```text
PRODUCTION_ISSUER_OFFLINE_BACKUP_PENDING
```

The final private key's only retained copy is the primary copy in the
operator-controlled WSL secret directory above. No removable/offline backup
has been created yet. **An operator-controlled offline backup MUST be
created before the first redeemable production `ActivationEnvelope` is ever
issued** (B56-4B2) - this ceremony does not invent or claim one. No air-gapped
hardware, HSM, or secure-erase of the abandoned candidate's key material has
occurred either - none of those are claimed here.

### B56-4B2 offline backup procedure (prepared; NOT yet performed)

Status: **BLOCKED ON OPERATOR** - the only copy of the key lives on the
operator's WSL machine; no automated/cloud session may hold, copy, or see
it. Nothing below has been executed. Record the outcome in this section
(date, media count, locations - never contents) when it is.

Custody rules: the private key never goes to a cloud drive, password-manager
sync, email, chat, CI, Git, the VPS, or the APK; it is never printed,
`cat`-ed, base64-displayed, or hashed-for-display (the fingerprint is of the
PUBLIC key only).

1. **Media**: two new USB drives (A, B) dedicated to this key, or one USB +
   one paper/QR-free-of-network alternative the operator already trusts.
   Two copies in two physically separate locations the operator controls.
2. **Encrypt at rest**: inside the same `unshare --net` network-isolated
   namespace used for generation (verify `ip -br addr` = `lo DOWN`, `ip
   route` empty), create an encrypted container on each medium (e.g. LUKS2
   `cryptsetup luksFormat`, or `age -p` / `gpg --symmetric --cipher-algo
   AES256` on the single 32-byte file) with a long passphrase. The
   passphrase is stored separately from the media (sealed paper), never
   beside it.
3. **Copy**: copy `~/.nova-secrets/activation-issuer/<r2 private key file>`
   and its public metadata JSON onto each encrypted medium; `chmod 600` the
   key copy.
4. **Verify each copy without revealing it** (decrypt/mount inside the
   isolated namespace, then):

   ```text
   python3 gateway/tools/activation_envelope_issuer.py verify-key \
     --private-key-file <mounted backup>/<key file> \
     --issuer-metadata-file <mounted backup>/<metadata json> \
     --expected-fingerprint 88ccf8198af0d7775946253eb958f60f5174c652f6e28a4daecd857ab293e840
   ```

   Required output (public data only):
   `OK issuerKeyId=prod-activation-issuer-2026-09-20-r2 publicKeyFingerprintSha256Hex=88ccf819...e840`.
   Any other output = that copy is not a valid backup; redo it.
5. **Restore drill**: on a clean isolated namespace, restore from backup B
   only, re-run step 4 against the restored file, then securely delete the
   restored drill copy (`shred -u`; SSD wear-levelling caveat noted, not
   claimed as secure erase).
6. **Record** in this document: date, "2 encrypted copies, 2 locations,
   verify-key OK on both, restore drill OK" - then flip
   `PRODUCTION_ISSUER_OFFLINE_BACKUP_PENDING` to `..._DONE`.
7. **Loss/compromise recovery**: primary lost + backup OK -> restore and
   continue (same key id). Backup or primary suspected compromised -> treat
   as key compromise: new ceremony (`-r3`), add the new public key to
   `ProductionActivationIssuerTrustAnchors` alongside `-r2`, ship, stop
   issuing under `-r2`, remove `-r2` once every `-r2` envelope has expired
   (see "Rotation model"); revoke any activations whose envelopes may have
   been forged via `revoke_activation()`.

Only after step 6: `issue` may mint the first redeemable production
envelope (see "What B56-4B2+ still has to do").

### Rotation / review policy

```text
key-id:            prod-activation-issuer-2026-09-20-r2
review:            2027-03-20
planned rotation no later than: 2027-09-20
immediate rotation: on suspected compromise
```

This is an operational policy (when to plan the next ceremony), not a
cryptographic expiry - envelope validity remains separately bounded by each
signed envelope's own `expiresAtEpochMillis`. The rotation MECHANISM is the
"Rotation model" section above: `FixedActivationIssuerTrustAnchors` already
supports trusting an old and a new key simultaneously during a rotation
window.

## What B56-4B2+ still has to do

B56-4B1 (this ceremony) completed steps 1-4 below for real. Remaining:

5. ~~Decide and document the real operational rotation/retirement
   schedule~~ - done above (review 2027-03-20, rotate no later than
   2027-09-20).
6. Create a real operator-controlled offline backup of the production
   private key (see "Offline backup status" above - currently
   `PRODUCTION_ISSUER_OFFLINE_BACKUP_PENDING`).
7. Only after step 6: `activation_envelope_issuer.py issue` may be run
   against a real production activation store to mint the first real,
   redeemable `ActivationEnvelope` (B56-4B2).
8. B56-5 owns wiring `ProductionActivationIssuerTrustAnchors` into real
   bootstrap/runtime composition - now implemented in code (see
   `B56_5_ANDROID_ACTIVATION_PACKAGE_RUNTIME.md`). After step 7, wrap the
   envelope for delivery with `activation_envelope_issuer.py package
   --envelope <artifact> [--bootstrap-bundle <signed manifest>] --out <file>`
   (secret output).

Historical record (completed by B56-4B1):

1. ~~Run `generate-key` for real, on an operator-controlled offline
   machine~~ - done, see "Production ceremony - 2026-09-20" above.
2. ~~Record the printed public key fingerprint out-of-band~~ - done, same
   section.
3. ~~Add the production public key bytes + `issuerKeyId` to Android's
   `FixedActivationIssuerTrustAnchors` population~~ - done via
   `ProductionActivationIssuerTrustAnchors` (not yet wired into any runtime
   composition - that remains B56-5).
4. ~~Perform a REAL cross-verification against that production key~~ -
   done, see "Production ceremony - 2026-09-20" above.
