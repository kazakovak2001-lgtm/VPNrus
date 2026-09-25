# B-WL-R6 - Adding a TransportKind to the signed manifest: compatibility analysis and rollout proposal

Status (2026-09-25):
- Step 1 (stable wire IDs) is IMPLEMENTED and tested (section 5).
- Step 2 (tolerant schema-2 decoder, client side) is IMPLEMENTED and tested,
  NOT DEPLOYED (section 6). No schema-2 manifest exists or is published.
- Steps 3-5 are NOT implemented.

`XRAY_REALITY_XHTTP` must not appear in any published manifest until the
proposal's gates are met.

## 1. How the codec worked before step 1 (verified in source at a2eb56f)

- Container: `SignedManifestCodec.decode` reads
  `[format=1][len][canonical bytes][len][signature]` and immediately calls
  `ManifestCanonicalizer.decode(canonicalBytes)`.
- Each transport binding is `writeInt(kind.ordinal)` + host + port + metadata
  (`EndpointManifest.kt` `writeBinding`/`readBinding`). The server-side signer
  writes the same integer (`gateway/tools/manifest_signing.py`, `kind_ordinal`,
  JSON field `kindOrdinal`).
- `readBinding` does `TransportKind.entries.getOrNull(ordinal) ?: throw
  IllegalArgumentException("unknown TransportKind ordinal ...")`.
- The signature is verified over a RE-ENCODING of the decoded manifest
  (`Ed25519ManifestVerifier.verify` -> `ManifestCanonicalizer.canonicalBytes(manifest)`),
  not over the received bytes.
- Canonical format version is a single constant (`FORMAT_VERSION = 1`); the
  decoder rejects any other value.

## 2. Answers

1. **How does an older client decode an unknown ordinal?** It does not.
   `readBinding` throws `IllegalArgumentException` on the first unknown ordinal.
2. **What happens with a manifest containing a new kind?** The exception
   propagates out of `SignedManifestCodec.decode`. `RemoteManifestFetcher`
   maps it to `ManifestFetchResult.Failed(MALFORMED)`. The same happens on
   every origin, because all origins serve the same file. The fetched
   candidate never reaches `EndpointManifestRepository.offer`.
3. **Whole manifest or just the binding?** The **whole manifest** is rejected.
   A partial decode that skips the binding would also fail verification,
   because the signature covers the full re-encoded manifest.
4. **Is the current manifest backward-compatible?** No. Adding any enum value
   and publishing a binding of it is a breaking change for every older client.
   **It has already happened twice:** production manifest v3 introduced
   ordinal 4 (`XRAY_XHTTP`), and production manifest v4 (deployed to both
   hosts, see `docs/B45B4P_SHADOWSOCKS_SELECTION_PHYSICAL_VALIDATION.md` section 9)
   contains ordinal 5 (`SHADOWSOCKS_2022`).
   - Every client built before commit `d3ce844` (B45B-1, the commit that added
     that enum value) now rejects every manifest fetch.
   - Those clients keep running on their last-known-good (LKG) manifest.
   - They receive no further updates: no rotation, no B44 `DISABLED`/`RETIRED`
     states, no new gateways.
   - When their LKG expires (180-day validity; v3 expires around 2027-03-13),
     they fall back to the embedded bootstrap, if that is still valid, or else
     fail closed.
   - Today these are development/test builds only, but the same mechanism would
     hit a released app.
5. **Safest rollout mechanism.** Never put a new kind into the manifest that
   existing clients fetch. Publish new kinds only in a separate, versioned
   manifest channel that only clients able to parse it will fetch (section 3).
6. **Stable wire IDs without breaking old manifests?** Yes. Give every
   `TransportKind` an explicit, frozen `wireId` equal to its current ordinal
   (AMNEZIA_WG=0 ... SHADOWSOCKS_2022=5, XRAY_REALITY_XHTTP=6), and
   encode/decode via that table instead of `ordinal`.
   - The bytes and signatures of every existing manifest stay identical.
   - Enum reordering can never silently change the wire format again.
   - This protects future changes only. It does not make old clients tolerant
     of new IDs.
7. **Versioned manifest / capability gating** (since section 6 alone cannot
   fix already-installed clients):
   - Clients that understand schema 2 fetch `/v1/manifest-v2` (new path, new
     canonical `FORMAT_VERSION = 2`). They fall back to `/v1/manifest` if it is
     unavailable.
   - Schema-2 decoding keeps unknown wire IDs as opaque, ignored bindings, and
     verifies the signature over the **received** canonical bytes.
   - Old clients only ever request `/v1/manifest`, which keeps using schema 1
     and existing kinds only.
8. **How to keep old clients from losing working endpoints.** Hold the
   schema-1 manifest to the kinds every supported client understands. Keep
   re-signing and publishing it for rotation, `DISABLED` states and expiry
   renewal until those clients are retired. New transports appear only in
   schema 2.

## 3. Proposal (ordered; each step independently shippable)

1. **Stable wire IDs (client).** DONE - see section 5. The Python signer
   already takes explicit integers (`kindOrdinal` in the source JSON), so it
   needed no change; those integers are the wire IDs in section 5.
2. **Tolerant schema-2 decoder (client).** DONE (client-side, test-only
   fixtures) - see section 6.
   - Parse `FORMAT_VERSION` 1 and 2.
   - For 2: an unknown wire ID becomes an ignored binding, and the signature is
     verified over the received canonical bytes.
   - Keep strict rejection of every other malformation.
3. **Decide what to do about v4 (owner decision, separate).**
   - Option A: accept that pre-`d3ce844` builds are stuck. They are development
     builds only.
   - Option B: publish a parallel schema-1 manifest without the
     `SHADOWSOCKS_2022` binding on the old path, and move `SHADOWSOCKS_2022` to
     schema 2.
4. **Schema-2 channel (server).**
   - Add a new signed artifact at a new path. It uses the same signing key
     unless the owner decides otherwise.
   - The manifest version is monotonic within each channel. The client must
     never compare versions across channels (`ManifestRollbackGuard` scope
     needs a design note).
5. **Only then add `XRAY_REALITY_XHTTP`**, in schema 2 only. Preconditions:
   - the server inbound is deployed;
   - the firewall/security group is opened with explicit owner approval;
   - the path/mode metadata is signed;
   - a physical test on an unrestricted network has passed first.

## 4. Current protection for XRAY_REALITY_XHTTP (verified)

- No published manifest contains wire ID 6.
- A binding is usable only if all of these hold:
  - the device holds a valid REALITY profile for the endpoint;
  - there is a trusted signed binding of exactly this kind;
  - its signed path/mode parse.
- Any failure makes the kind `NOT_IMPLEMENTED` in the registry, excludes it
  from `AutoGatewaySelector`, and makes `VpnController` throw before
  `connect()`.
- The kind is appended last in the enum, so every existing wire ID is unchanged.

## 5. Stable wire IDs (implemented, step 1)

**Why ordinal was not a stable protocol ID.** Kotlin's `ordinal` is the
declaration position. The codec wrote `kind.ordinal` and also sorted bindings
by it inside the signed canonical bytes. Two unrelated changes would therefore
silently change what is signed: inserting a constant anywhere but the end, or
reordering constants. Adding a constant at the end was also a breaking change
for older clients (section 2).

**Now.** `TransportKind(val wireId: Int)`.
- The ID is a mandatory constructor argument, so a kind without an explicit ID
  does not compile.
- `TransportKind.fromWireId(id)` returns null for an unknown ID.
- Every place a kind is signed or persisted uses the wire ID:
  - `ManifestCanonicalizer`: write, read, and binding sort order;
  - `PathHistoryStore`;
  - `ConnectionOutcomeStore`.
- `ordinal` remains only in in-memory candidate ordering in
  `AutoGatewaySelector`, which never leaves the process.

| TransportKind | Historical ordinal | Stable wire ID | Status |
|---|---|---|---|
| AMNEZIA_WG | 0 | 0 | in production manifests v1-v4 and bootstrap |
| XRAY_REALITY | 1 | 1 | in production manifests v1-v4 and bootstrap |
| QUIC | 2 | 2 | reserved; never published |
| TLS_TCP | 3 | 3 | in production manifests v1-v4 and bootstrap |
| XRAY_XHTTP | 4 | 4 | since manifest v3 (breaks clients older than B35) |
| SHADOWSOCKS_2022 | 5 | 5 | since manifest v4 (breaks clients older than `d3ce844`) |
| XRAY_REALITY_XHTTP | 6 (new) | 6 | **reserved; must never appear in a schema-1 manifest** |

IDs are frozen. Never change, remove or reuse one; a new kind takes the next
unused integer.

**Compatibility proof.** `ManifestWireCompatibilityTest` ran green BEFORE the
change and again AFTER it, against the real signed production files
`gateway/tools/endpoint-manifest-*.bin` v1-v4 (SHA-256 pinned in the test; the
v4 hash matches the deployed file) and the embedded bootstrap manifest. It
checks:
- decode followed by re-encode is byte-identical, for both the container and
  the canonical bytes;
- every Ed25519 signature still verifies against the embedded trust anchors;
- ID 6 encodes and decodes on this client;
- an unknown ID (7, 99, -1, `Int.MAX_VALUE`) still rejects the whole manifest.

**Regression guard.** `TransportKindWireIdTest`:
- pins the table above;
- requires IDs to be unique and non-negative;
- checks the `fromWireId` round-trip;
- scans the three codecs for any `kind.ordinal`, `transport.ordinal` or
  `TransportKind.entries`/`values()` indexing.

A mutation run (reintroducing `kind.ordinal` into the manifest writer) was
caught by this test.

**What this does NOT solve.** A stable ID protects future changes only. A
client that does not know an ID still rejects the whole manifest; that is
schema 2's job (section 6).

## 6. Schema 2 (implemented client-side, step 2; NOT deployed)

Code: `reachability/ManifestSchema2Codec.kt`; dispatch in
`SignedManifestCodec`; verification in `Ed25519ManifestVerifier`. Tests:
`ManifestSchema2DecoderTest`, with fixtures generated deterministically from a
fixed test key. No production manifest, bootstrap manifest, signer, server or
fetch path was changed.

### 6.1 Schema 1 vs schema 2

The container is the same for both:
`[container=1][len][canonical bytes][len][signature]`. The **schema marker** is
the first big-endian int of the canonical bytes, so the marker is itself
signed. `SignedManifestCodec` dispatches on it explicitly:
- 1 -> the schema-1 decoder;
- 2 -> the schema-2 decoder;
- any other value, or fewer than 4 canonical bytes -> rejected.

There is no "try schema 2 if schema 1 fails" path.

| | Schema 1 (unchanged) | Schema 2 |
|---|---|---|
| Marker | `1` | `2` |
| Header | version, issuedAt, expiresAt, signingKeyId | same |
| Roles | int = `EndpointRole.ordinal` (historical) | int from the explicit frozen table `ROLE_WIRE_IDS` (INGRESS 0, GATEWAY 1, EXIT 2 = historical values). An unknown role id is rejected. |
| Binding | wireId, host, port, metadata | same envelope for every kind, known or not. A new kind puts anything extra in signed metadata. |
| Unknown transport wire ID | whole manifest rejected | binding structurally validated, then ignored and counted |
| Canonical order on read | not checked (the signature over the re-encoding enforces it) | enforced, strictly ascending: endpoint ids and metadata keys by unsigned UTF-8 byte order (= Unicode code point order, not JVM UTF-16 `compareTo`); roles and transport wire IDs numerically. Duplicates are therefore rejected. |
| Endpoint operational state | merged over the bindings that declare it | must be uniform over ALL bindings (unknown included) and a supported value |
| Booleans | any non-zero byte reads as true | only `0`/`1` |
| Strings | UTF-8, lenient | UTF-8, malformed sequences rejected |
| Signature is verified over | the re-canonicalization (byte-identical to the received bytes, proven for v1-v4 + bootstrap) | the **exact received canonical bytes** (`SignedManifest.signedCanonicalBytes`) |
| LKG persists | the re-canonicalization | the received bytes, verbatim |

Schema-2 flow, in order:
1. **Structural parse** (`ManifestSchema2Codec.parse`): bounds, exact EOF,
   canonical order, duplicates, and envelope validity of every binding (known
   or unknown). The endpoint operational state (`endpointOperationalState`
   binding metadata) must be identical on every binding, known or unknown,
   and must be a supported value. Otherwise a DISABLED/RETIRED state, or a
   conflict, carried only by an ignored binding would silently turn into
   ACTIVE. Wire IDs are not resolved to `TransportKind` here. Anything
   wrong, including truncation, raises `IllegalArgumentException`.
2. **Candidate interpretation** (`interpret`):
   - drop bindings with unknown IDs;
   - drop endpoints left with no known binding, and, transitively, any
     endpoint whose `relayTo` target was dropped;
   - the counts go into `ManifestTolerance`.

   The result is an UNTRUSTED candidate; nothing reads it before step 3.
3. **Verification** (`Ed25519ManifestVerifier`): key lookup and time window
   from the header, then Ed25519 over the exact received bytes.
4. **Binding the interpretation to the bytes**: only after the signature
   verifies, the verifier re-derives the interpretation from those verified
   bytes. It accepts only if that equals the candidate manifest and
   tolerance. Otherwise the result is `INVALID_SIGNATURE`.

Failure mapping (no new fallback policy):
- Malformed input, an unsupported schema, duplicates or non-canonical order ->
  `IllegalArgumentException` -> the existing `MALFORMED` fetch result. The
  candidate never reaches `offer()`, and LKG/bootstrap stay trusted.
- An invalid signature, or modified payload, unknown binding or signature ->
  `offer()` rejects it with `INVALID_SIGNATURE`, and LKG is untouched.
- A valid schema-2 manifest with an unknown kind is `Accepted`, stored in LKG
  as the exact received container, and re-verified on every read.

Diagnostics: if the trusted manifest ignored anything, `connectAuto` records
`MANIFEST_UNKNOWN_TRANSPORT_IGNORED` with two tags, `count` (ignored bindings)
and `droppedEndpoints`. It records counts only: never wire IDs, hosts,
metadata, URLs or keys.

Still open (unchanged by step 2):
- the server-side schema-2 channel and path (step 4);
- the rule that the rollback guard must never compare versions across
  channels;
- the owner decision on v4 (step 3);
- rollout policy: a validly signed schema-2 manifest whose interpretation
  drops every usable endpoint is still Accepted and advances the version
  floor.

Because nothing publishes schema 2 today, the tolerant path is reachable
only by bytes that carry marker 2.

### 6.2 Why an unknown transport may be ignored but unknown bytes may not

These are two different kinds of ignorance, and they must not be confused.

**Semantic ignorance is safe.** The client does not know what transport kind 7
means, so it cannot use it. Ignoring a binding it cannot use removes only
options. The client never gains a path, a host or a trust decision it did not
already have. Every known binding, endpoint and header field is still exactly
what the signer signed.

**Cryptographic ignorance is not safe.** The signature covers bytes, not
meaning. If the client dropped the bytes it does not understand and then
checked the signature over a re-serialization of what is left, it would be
verifying a different message from the one that was signed. There are two
possible outcomes:
- It fails every time, so the tolerant decoder is useless.
- The signer is made to sign the filtered form. Then the unknown bytes are
  not covered by any signature, and anyone on the path can add, change or
  remove them undetected.

When that client, or a later client that does know kind 7, persists and later
interprets those bytes, they are attacker-controlled. That breaks the one
property the manifest exists to provide.

So schema 2 is tolerant only about meaning, never about integrity:
1. every byte, including every byte of every unknown binding, is covered by
   the signature and checked in its received form;
2. unknown bindings must still be structurally well-formed, so there is one
   unambiguous parse;
3. what is ignored is decided only after the signature over those bytes
   verified;
4. those same bytes, never a re-encoding, are what LKG keeps.

`ManifestSchema2DecoderTest` proves this:
- modifying an unknown binding's host, port, metadata or wire ID after
  signing is rejected;
- stripping the unknown binding, which yields the same interpreted manifest,
  is rejected;
- a mutation that verifies over the filtered re-serialization makes 8 tests
  fail.
