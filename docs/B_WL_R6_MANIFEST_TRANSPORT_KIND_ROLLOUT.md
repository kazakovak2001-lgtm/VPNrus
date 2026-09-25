# B-WL-R6 - Adding a TransportKind to the signed manifest: compatibility analysis and rollout proposal

Status (2026-09-25): proposal step 1 (stable wire IDs) is IMPLEMENTED and
tested (see section 5). Steps 2-5 are NOT implemented. `XRAY_REALITY_XHTTP`
must not appear in any published manifest until the proposal's gates are met.

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
2. **Tolerant schema-2 decoder (client).**
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

## 6. Schema 2 (design note, NOT implemented)

- It is a new canonical `FORMAT_VERSION = 2` served on a new path; schema 1
  and its path stay unchanged.
- Bindings are encoded by explicit wire ID (section 5).
- The tolerant decoder keeps a binding with an unknown wire ID as opaque and
  ignores it for selection. It keeps rejecting every other malformation.
- The signature is verified over the exact received canonical bytes, never a
  re-encoding, because a re-encoding cannot reproduce ignored bindings.
- Schema 1 must contain only kinds that every supported target client
  understands.
- The manifest version is monotonic within each channel. The rollback guard
  must never compare versions across channels.
- No production schema-2 manifest exists or is planned before the owner
  approves it.
