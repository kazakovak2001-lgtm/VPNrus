# CDN provider capability profile

`CdnProviderCapabilityProfile` describes an operator's declared CDN/XHTTP
constraints. It is a foundation for future CDN activation and capability
gating, not a deployed transport or evidence of reachability.

The profile is stored as version 1 JSON in the existing transport binding's
`cdnProviderProfile` metadata string. `withCdnProviderProfile` requires an
explicit `CDN_FRONTED` binding whose host matches the client-facing hostname.
It preserves unrelated metadata. Objects and sets are written in deterministic
order, within the existing 4096-byte metadata value and 64-entry limits.
The manifest binary format and existing signed bootstrap bytes do not change.
Publishing NEW profile content still requires a newly signed manifest through
the existing operator workflow; parsing metadata is not signature verification.

The model distinguishes:

- Provider identifier and a positive 32-bit ASN, with no built-in provider list.
- Client-facing hostname, CDN technical hostname, origin hostname, and origin
  TLS server name. TLS client SNI and the origin Host header are explicit too.
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

`cdnProviderProfile()` returns `Missing`, `Invalid`, `UnsupportedVersion`, or
`Parsed`. Missing metadata leaves legacy bindings untouched. Required fields,
types, enum values, bounds, and host/kind binding are validated. Unknown policy
fields are rejected in this version rather than silently ignored. A parsed
profile has NOT passed a client capability check, exit topology validation,
provider compatibility test, or an end-to-end data-plane probe.

No consumer applies these fields to Xray, changes path ranking, provisions
CDN infrastructure, or promotes a candidate to Protected in this slice.
`UNSUPPORTED`/`UNKNOWN` cache policy and unmet requirements remain descriptive;
future execution must reject incompatible profiles explicitly. Measured health
must continue to come from existing reachability/history and relay proof
mechanisms, never a provider's declaration in signed metadata.

Next steps are to implement client/core capability gating, validate against a
pinned Xray version, and integrate the model with actual provider deployment
and the existing end-to-end relay proof. No Russia reachability claim follows
from this model or its unit tests.
