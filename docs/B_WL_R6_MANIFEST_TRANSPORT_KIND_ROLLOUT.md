# B-WL-R6 - Adding a TransportKind to the signed manifest: compatibility analysis and rollout proposal

Status: analysis + proposal only (2026-09-25). Nothing described in
"Proposal" is implemented. `XRAY_REALITY_XHTTP` must not appear in any
published manifest until the proposal's gates are met.

## 1. How the codec works today (verified in source)

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

1. **Stable wire IDs (client + signer).** Add an explicit wire-ID table and
   a test that pins every existing ID. No byte changes. Pure refactor.
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
