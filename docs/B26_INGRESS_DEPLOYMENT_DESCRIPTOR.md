# B26 (task H) - ingress deployment descriptor

A secret-free, typed, operator-readable description of ONE future/candidate
DIRECT_IP ingress deployment. Its purpose is purely for a human (or a
future automation step, not this slice) to review what an ingress host
claims to be, BEFORE it is ever added to the signed production manifest -
see PROJECT_ARCHITECTURE.md's B23 manifest-schema notes for why a real
endpoint only ever enters that manifest through the offline signing
ceremony (`gateway/tools/manifest_signing.py`), never this descriptor
directly.

**This file is descriptive, not authoritative.** It carries no signature
and grants no trust by itself - a client never reads it. It exists so an
operator has one place to record "what this candidate ingress host is"
before deciding whether to fold it into a real signed manifest entry.

## Schema (informal - see the example file for the concrete shape)

| Field | Type | Notes |
|---|---|---|
| `ingress_id` | string | Matches `NOVA_INGRESS_ENDPOINT_ID` / `ingress_endpoint_id` |
| `role` | string | Always `"INGRESS"` |
| `ingress_kind` | string | `"DIRECT_IP"` or `"CDN_FRONTED"` (both have a real software-side runtime path as of B27 - see PROJECT_ARCHITECTURE.md's B24/B27 sections; CDN_FRONTED is still FOUNDATION - no legitimate operator-controlled CDN has been validated against this slice) |
| `region` | string | Free-text, e.g. `"eu-central"` |
| `provider` | string | Free-text, e.g. `"Hetzner"` |
| `asn` | string | e.g. `"AS24940"` - diagnostics/operator use only |
| `public_host` | string | The host clients dial and `/v1/ingress-profile`'s `server_address` matches |
| `supported_client_transports` | array of string | Subset of `["XRAY_REALITY", "TLS_TCP"]` |
| `supported_exits` | array of string | Stable exit endpoint id(s) this ingress relays to (today: exactly one, `ingress_exit_endpoint_id`) |
| `ports` | object | `{"reality": <port>, "tls": <port or null>}` |
| `reality_connection_facts` | object | `{"server_name", "fingerprint", "reality_public_key", "short_id"}` - all client-safe, PUBLIC values (same ones `/v1/ingress-profile` returns) |
| `tls_connection_facts` | object or null | `{"server_name", "fingerprint"}` when TLS is enabled, else `null` |
| `health_path` | string | Always `"/v1/relay-health"` |
| `status_path` | string | Always `"/v1/ingress-profile"` (the activation endpoint, since there is no separate public status endpoint) |
| `deployment_status` | string | One of `"CANDIDATE"`, `"PREFLIGHT_PASSED"`, `"AWAITING_APPROVAL"`, `"MANIFEST_APPLIED"` - operator-updated, informational only |

## MUST NEVER contain

- any device UUID (a per-device activation is never known before a device
  activates - and even then, never belongs in a descriptor);
- the ingress->exit upstream relay UUID (`NOVA_INGRESS_UPSTREAM_UUID_FILE`'s
  contents);
- the ingress's own REALITY private key;
- the manifest signing private key (this repository's own hard invariant -
  see PROJECT_ARCHITECTURE.md's "no private signing key on the production
  VPS if avoidable");
- any probe bearer token or the probe HMAC secret.

## Relationship to the signed manifest

This descriptor is NOT placed into `gateway/tools/production_manifest_*.json`
or re-signed by this slice - see ROADMAP's B26 row: doing so before a real
host exists and has been validated would mean a client sees an ingress
candidate as a real, trusted endpoint before it is one. Once a real host
passes `gateway/tools/ingress_preflight.py` and has been physically
validated (see `docs/B26_FIRST_INGRESS_RUNBOOK.md`), an operator manually
authors the REAL `EndpointDescriptor`/`EndpointTransportBinding` entry
(reusing this descriptor's own facts) and runs the existing offline signing
ceremony - a deliberate, human-reviewed step, exactly like every other
production manifest update.
