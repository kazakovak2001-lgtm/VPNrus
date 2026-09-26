# B-WL - Adaptive network layer (whitelist / UDP filtering / early drop)

Status as of 2026-09-25. Authoritative per-item status lives in
`docs/ROADMAP.md` ("Adaptive Network Layer (B-WL)"). This file records the
audit, how the requested flow maps onto code that already existed, what this
slice added, and what is still missing.

## 1. Requested flow -> existing mechanism

| Requested stage | Where it already lives | This slice |
|---|---|---|
| Network observation | `RestrictionMonitor` (gateway + diverse HTTPS probes), `ConnectionOutcomeStore`, `NetworkProfiler` | + `TransportAttemptObservation` (per-attempt behavior); **not yet captured at runtime** |
| Network classification | `RestrictionClassifier` (single authority, B8J/B8M/B28/B40) | + `TransportBehaviorAnalyzer`, + `POSSIBLE_EARLY_DROP`, `POSSIBLE_FULL_SHUTDOWN` |
| Confidence | B40 `RestrictionAssessment.evidenceQuality` (qualitative, deliberately not a probability) | reused; behavior-driven classes carry the behavior's own quality |
| Candidate generation | `AutoGatewaySelector` + `PathCandidateBuilder` (B41 synthesizer), signed manifest `endpoints[]` | unchanged |
| Candidate ranking | `PathScorer` (single ranking authority, restriction tier B28) | restriction tier now reacts to UDP filtering and early drop |
| Preflight / connect / per-attempt transport / active transport ownership | `VpnController`, `AwgXrayFailoverPolicy`, `AutoGatewayFailoverPolicy`, B34 fairness | unchanged |
| Post-connect verification | B33 in-tunnel remote confirmation (Xray), AWG fresh-handshake gate, B33 relay watchdog | + `TrafficProgressMonitor` (pure); **not yet wired** |
| Failover | `AutoGatewayFailoverPolicy`, bounded `MAX_ATTEMPTS`, B34 | unchanged |
| Failure memory / cooldown | `PathHistoryStore` (B11/B39, network-fingerprint scoped) + `PathScorer` cooldown (B19) | reused; covered by new tests |
| Ingress vs exit | `EndpointRole` INGRESS/EXIT/GATEWAY, `relayTo`, `PathCandidate.Relayed`, `IngressKind` DIRECT_IP/CDN_FRONTED (B23-B27) | unchanged (already two-hop capable) |
| Multi-endpoint config/API | signed endpoint manifest (`endpoints[]`, per-endpoint `transports[]`, roles, `relayTo`) | unchanged |

No second resolver, classifier, failover system or endpoint model was created.

## 2. Classification (B-WL1)

Name mapping to the requested classes:

| Requested | `RestrictionClass` |
|---|---|
| NORMAL_NETWORK | `NO_RESTRICTION_OBSERVED` |
| POSSIBLE_UDP_FILTERING | `POSSIBLE_UDP_FILTERING` (new, behavior-only: UDP no-response while TCP works). The existing probe-derived `POSSIBLE_UDP_OR_AWG_FILTERING` is kept separate because its trigger is the last outcome of ANY transport |
| POSSIBLE_WHITELIST | `POSSIBLE_HARD_WHITELIST` (existing; now also from ALL_CONNECT_FAILED with validated internet and failing diverse probes) |
| POSSIBLE_EARLY_DROP | `POSSIBLE_EARLY_DROP` (new) |
| FULL_SHUTDOWN | `POSSIBLE_FULL_SHUTDOWN` (new; OS cannot validate internet AND every attempt across 2+ destinations failed before payload) |
| UNKNOWN | `UNKNOWN` |

Early drop = TCP connected + handshake completed + some payload received +
no progress for the stall window while we kept sending + no RST. There is no
byte threshold anywhere (tests pin identical results at 1 KB, 16 384 B and
1 MB). One occurrence gives LOW quality; a repeat (on one or several
destinations) gives HIGH `POSSIBLE_EARLY_DROP`. Early drop is never mapped to
`POSSIBLE_HARD_WHITELIST`: stalls on many foreign destinations look like
per-destination stream filtering, and without an allowed-reference contrast
they say nothing about an allowlist. An early drop on one path while another TCP path
progresses is contradictory and yields UNKNOWN.

With no observations the classifier is byte-for-byte its previous self.

## 3. Candidate ordering (B-WL5)

`PathScorer` restriction tier, rank kept in [-1, 1] (tier proof unchanged),
facts read only from the registry's real `TransportCapabilities`:

| Class | Effect |
|---|---|
| NORMAL / UNKNOWN / FULL_SHUTDOWN / probe-derived UDP_OR_AWG | none (existing order: AWG, QUIC, REALITY, XHTTP, TLS, SS2022) |
| `POSSIBLE_UDP_FILTERING` (behavior-only) | UDP-only -1; TCP + `suitableForRestrictiveNetworks` (XHTTP) +1 |
| Possible whitelist | relay +1, direct -1 (B28, unchanged) |
| Early drop | relay +1; direct TCP that is not restrictive-network-suitable -1; UDP 0 |

Both new branches react only to behavior-derived classes, which nothing
produces at runtime yet, so **live Auto ranking is unchanged** until B-WL1 is
wired. Resulting order with today's capability profiles (tested):
NORMAL `AWG, REALITY, relay XHTTP, TLS`; UDP filtering `relay XHTTP, REALITY,
TLS, AWG`; whitelist and early drop `relay XHTTP, AWG, REALITY, TLS`.
Repeated retries of a failed candidate are prevented by the existing
`PathHistoryStore` history/cooldown tiers, which outrank the restriction tier.

## 4. VLESS + REALITY + XHTTP (B-WL2)

Verified against the pinned xray-core v26.7.28 source (commit 5ca6f4b):
`transport_internet.go` accepts `security: "reality"` with network `xhttp`
(ProtocolName `splithttp`) - "REALITY only supports RAW, XHTTP and gRPC";
XHTTP settings are `xhttpSettings` (`SplitHTTPConfig`, `transport_method.go`)
with `mode` in auto/packet-up/stream-up/stream-one.

Added: `XrayVlessRealityXhttpConfig` + validator + renderer (client) and an
optional `RealityXhttpServerConfig` inbound (server, reuses the one REALITY
key set, own port). No Vision flow over XHTTP. Not registered, not
provisioned, not deployed. Registering it needs a `TransportKind` decision
(new kind vs. a security variant of `XRAY_XHTTP`), which touches Android code
that must be compiled and physically tested.

HTTPUpgrade does not exist in this project and was not added; if ever added it
ranks below XHTTP. ECH: FUTURE RESEARCH only.

## 5. Server side (audit)

- `nova-xray.service` config is rendered by `gateway/api/xray_config_renderer.py`
  from `_render_candidate` (REALITY RAW + optional TLS). REALITY+XHTTP is now
  renderable but `_render_candidate` does not pass it (no config key yet).
- CDN XHTTP (TLS) ingress already exists (`xray_ingress_config_renderer.py`, B35).
- `/v1/activate` / `/v1/xray-profile` return one per-device profile; the
  candidate list is the signed endpoint manifest, which already separates
  ingress from exit (`roles`, `relayTo`). A per-endpoint profile API is not
  needed for this slice.
- No server/production infrastructure change was made. Client code changed, but live Auto ranking is unchanged until behavior observations are wired (see section 3).

## 6. Still missing

- Runtime capture of `TransportAttemptObservation` (Xray has no per-flow
  counters today; only AWG implements `stats()` counters) and wiring
  `TrafficProgressMonitor` into `VpnController`'s session loop.
- `MainViewModel` passing observations into `RestrictionEvidence`.
- Registering REALITY+XHTTP as a selectable transport; server config key +
  deployment.
- A domestic reference probe (tells whitelist apart from full shutdown more
  reliably than OS validation).
- Physical measurements (B-WL6 lab, ROADMAP B54).

## 7. Risks

- Once wired, UDP-filtering ranking demotes AWG one restriction step before
  AWG's own health has degraded; history/health still outrank it.
- A future `RealityXhttpServerConfig` deployment opens a new port and needs a
  firewall/security-group change with explicit owner approval.
- `POSSIBLE_FULL_SHUTDOWN` leans on Android's validation, which itself may be
  blocked under a whitelist; the rule needs 2+ destinations to limit false
  positives.
- Stall detection relies on byte counters; transports without counters give
  VERIFYING/UNAVAILABLE, never a false UNHEALTHY.
