# CDN provider capability profile

`CdnProviderCapabilityProfile` describes an operator's declared CDN/XHTTP
constraints. It is paired with `CdnClientCapabilityPolicy`, which decides
whether this local client and pinned Xray core may even present the
`CDN_FRONTED` binding as a relayed candidate. This is still not a deployed
transport or evidence of reachability.

The profile is stored as version 2 JSON in the existing transport binding's
`cdnProviderProfile` metadata string. `withCdnProviderProfile` requires an
explicit `CDN_FRONTED` **XRAY_XHTTP** binding whose host matches the client-facing hostname.
It preserves unrelated metadata. Objects and sets are written in deterministic
order, within the existing 4096-byte metadata value and 64-entry limits.
The manifest binary format and existing signed bootstrap bytes do not change.
Publishing NEW profile content still requires a newly signed manifest through
the existing operator workflow; parsing metadata is not signature verification.

The model distinguishes:

- Provider identifier and a positive 32-bit ASN, with no built-in provider list.
- Client-facing hostname, CDN technical hostname, origin hostname, origin TLS
  server name, and a distinct signed control-plane hostname. TLS client SNI
  and the origin Host header are explicit too.
- XHTTP mode, path, uplink method, padding placement/range, non-secret query
  parameters, headers, and additional descriptive parameters.
- Minimum TLS version, ALPN requirements, and a declared client fingerprint.
- Cache policy, streaming support, maximum request body size, and request timeout.
- Supported exit identifiers, minimum client version code, minimum Xray core
  version, and explicit required client capability identifiers.

Hostnames accept ASCII DNS labels (IDNs as A-labels), not URLs, IP literals,
ports, or wildcards. The XHTTP path excludes query/fragment components;
query parameters have their own field. Parameters are bounded and reject
control characters; reserved credential, Host, and framing headers are rejected.
All metadata must remain non-secret: credentials belong in existing encrypted
profile stores, including when an operator chooses names for extra parameters.

`controlPlaneHostname` is a signed provisioning authority only. It must never
be inferred from the CDN edge or origin, and a control-plane response never
becomes authority for the data plane: Android must still cross-check the
returned edge host/port against the signed `EndpointTransportBinding`.

Profile v2 is valid only on `XRAY_XHTTP`. Copying the same metadata to
`TLS_TCP`, `XRAY_REALITY`, `QUIC`, or another transport is rejected fail-closed.

`cdnProviderProfile()` returns `Missing`, `Invalid`, `UnsupportedVersion`, or
`Parsed`. Missing metadata leaves legacy direct-IP bindings untouched. Required
fields, types, enum values, bounds, and host/kind binding are validated.
Unknown policy fields are rejected in this version rather than silently
ignored.

`cdnClientCompatibility()` checks the parsed profile against the local runtime:
supported exit id, minimum client version, minimum Xray-core version, required
client capability labels, XHTTP mode/method/padding support, TLS
version/fingerprint/ALPN support, streaming support, request body bound, and
request timeout bound. `AutoGatewaySelector.buildRelayedCandidates()` applies
this gate only for `IngressKind.CDN_FRONTED`; `DIRECT_IP` and legacy/null
ingress-kind bindings keep their existing behavior. A `CDN_FRONTED` binding
with missing, malformed, unsupported-version, or locally incompatible profile
is excluded before scoring, rather than silently downgraded.

The B35 foundation includes a resolver/renderer that can turn a compatible,
already-signed profile plus the persisted per-device UUID into a validated Xray
wire configuration. It is still not a live transport: `XRAY_XHTTP` remains
`NOT_IMPLEMENTED`, and no Smart Connect/runtime executor consumes that rendered
configuration. The selector gate remains a compatibility filter, not a scorer:
measured health must continue to come from existing reachability/history and
relay proof mechanisms, never a provider's declaration in signed metadata.

The first executable server slice is intentionally narrower than the general
metadata model: only `PACKET_UP` + `POST` with bounded H1/H2 connection setup is
accepted by the runtime resolver. H3 is rejected until its QUIC establishment
path has the same bounded-dial guarantee. Next steps are deployment-specific CDN
validation, wiring real runtime capability values, live executor integration,
and end-to-end relay proof validation. No Russia reachability claim follows from
this model, resolver, selector gate, or unit tests.
