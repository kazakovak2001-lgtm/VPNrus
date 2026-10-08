# B50 — Provider / ASN Survivability Score

## 1. Executive summary

B50 implements a pure, deterministic, explainable survivability assessment without changing path ranking. It separates signed structural topology, freshness-decayed current reachability, network-scoped local history, N−1 concentration, confidence, and external ASN observations.

**Provider/ASN diversity is not proof of reachability or censorship resistance.**

**B50 does not introduce provider-name allowlists or automatic provider-based path selection.**

## 2. Scope

The model answers diagnostic questions about correlation, usable alternatives, evidence volume, and known unknowns. It is production-source pure Kotlin so future diagnostics can consume the same stable types, but it has no runtime caller in this slice.

## 3. Non-goals

B50 does not choose paths, alter Smart Connect, perform WHOIS/BGP lookups at runtime, infer provider quality, add UI, deploy infrastructure, or claim field survivability.

## 4. Existing diversity architecture

`PathCandidate` pins direct or ingress→exit hops. Bindings carry signed opaque `InfrastructureFailureDomains`. `PathDiversity` grants only a capped tie-break to fully-known unique domains. `PathScorer` remains the single ranking authority. `AutoGatewaySelector` builds and ranks executable candidates. `EndpointReachability` is freshness-decayed current evidence. `PathHistoryStore` is keyed by network fingerprint, path identity, and transport.

## 5. Trust model

Failure-domain labels and endpoint topology are structural facts only after the existing signed-manifest pipeline verifies them. External ASN observations below are not copied into manifest metadata and never become topology authority. An unavailable public routing service cannot affect VPN operation.

## 6. Data-source classification

| Category | Inputs |
|---|---|
| Trusted structural | verified endpoint roles/topology, relay relationship, signed opaque failure-domain IDs |
| Measured current | `EndpointReachability`, latency and recent endpoint/transport outcomes already incorporated there |
| Local historical | network-fingerprint-scoped `PathHistoryEntry` counts, last result and failure streak |
| External observational | origin ASN, announced prefix and registry organization at an observation time |
| Unknown | missing signed labels, absent reachability, absent local history or unobserved public endpoint |

## 7. Current endpoint inventory

The verified embedded bootstrap names two active gateway/exit endpoints. `frankfurt` uses public address `152.70.43.1` for AWG, REALITY and TLS/TCP; `stockholm` uses `16.170.208.231` for the same roles/transports. No active CDN-fronted ingress is present in that bootstrap. These are public routing facts, not credentials.

## 8. Current point-in-time ASN observations

Observed at `2026-09-21T12:41:45Z` using RIPEstat's `network-info` and `as-overview` APIs:

| Endpoint | Role | Public IP | Origin ASN | Announced prefix | Registry organization |
|---|---|---:|---:|---|---|
| frankfurt | GATEWAY, EXIT, control-plane host | 152.70.43.1 | AS31898 | 152.70.40.0/21 | ORACLE-BMC-31898 — Oracle Corporation |
| stockholm | GATEWAY, EXIT, control-plane host | 16.170.208.231 | AS16509 | 16.170.0.0/15 | AMAZON-02 — Amazon.com, Inc. |

Sources: RIPEstat [`network-info` for Frankfurt](https://stat.ripe.net/data/network-info/data.json?resource=152.70.43.1), [`network-info` for Stockholm](https://stat.ripe.net/data/network-info/data.json?resource=16.170.208.231), [`AS31898 overview`](https://stat.ripe.net/data/as-overview/data.json?resource=AS31898), and [`AS16509 overview`](https://stat.ripe.net/data/as-overview/data.json?resource=AS16509). Organization names are labels only, never policy inputs.

## 9. Signed failure-domain topology

The code supports signed operator/network/region/CDN/control-plane IDs, but the current embedded production bootstrap contains none. The roadmap likewise records that B38-signed production diversity metadata has not been deployed. Therefore B50 must classify current signed structural independence as **UNKNOWN**, even though external routing observation finds two ASNs.

## 10. Structural diversity model

`FailureDomainConcentration` counts known unique domains by dimension and paths with incomplete metadata. Two endpoint IDs alone never imply independence. Full known separation across operator, network, region and control plane is `STRONG`; some separation is `PARTIAL`; shared known domains are `LOW`; incomplete multi-path metadata is `UNKNOWN`.

## 11. Current reachability model

Each path is summarized from its worst hop's existing `ReachabilityState`. Reachable and degraded paths count as usable now; unreachable paths do not; unknown remains unknown. B50 adds no freshness rule and performs no probe.

## 12. Historical reliability model

The caller supplies only history already read under the current `NetworkFingerprint`. Counts are capped defensively, zero observations remain `UNKNOWN`, a recent failure streak is visible, and a stable classification requires at least 20 observations with at least 75% successes. B50 does not persist or merge history.

## 13. Confidence/sample-size handling

Confidence is a bounded enum, not a probability. Complete structure, known current reachability and evidence volume add independent points. One observation yields less confidence than a substantial history; no candidates are explicitly insufficient. No division, NaN, overflow-prone multiplication, or deceptive percentage is used.

## 14. Overall assessment model

`INSUFFICIENT_EVIDENCE`, `FRAGILE`, `LIMITED`, and `RESILIENT` are comparative engineering labels. Zero usable paths or an N−1 domain whose loss leaves zero usable alternatives is fragile. Resilient requires strong known structure, at least two usable paths, and no poor history. Reasons are stable typed enums sorted by declaration order.

## 15. N-1 failure-domain survivability

For operator, network, region, CDN and control plane separately, B50 removes each known domain in turn and reports the worst remaining currently usable path count. Unknown paths do not fabricate known diversity. No known domain produces a null result rather than a guessed capacity.

## 16. ASN concentration

External observation currently shows two origin ASNs across two gateway/exit/control-plane public addresses: one endpoint per ASN. This is evidence of network-origin diversity only. It does not prove independent routing, operations, control-plane availability, or restricted-network reachability.

## 17. Current Nova assessment

| Dimension | Assessment |
|---|---|
| Signed structural topology | Two endpoint IDs, but failure-domain labels absent: UNKNOWN independence |
| External ASN observation | Two distinct origin ASNs at the observation time |
| Current reachability | UNAVAILABLE on this host; no live probes were performed |
| Local historical reliability | UNAVAILABLE; no production-device `PathHistoryStore` was imported |
| Overall | INSUFFICIENT_EVIDENCE for a current survivability claim |

## 18. Deterministic scenario results

Sixteen tests cover S1–S12 plus unknown N−1 values, empty/single sets, stable output/reason ordering, and confidence bounds. They prove identical domains remain correlated, shared control plane limits otherwise-diverse paths, unreachable diversity remains structurally visible but unusable now, histories remain a separate dimension, and N−1 loss is explicit. The focused B50/ranking regression matrix passed 179/179. The broad JVM suite executed 1,751 tests with the sole failure being the known `EffectiveConfigDiffTest` line 177 `ClassCastException`; the identical failure was already reproduced against clean unchanged `origin/main` (`75cb4b2`) during B49, and B50 does not touch that test or its production path.

## 19. Relationship to PathDiversity

`PathDiversity` is unchanged. It remains the narrow signed-metadata tie-break used by ranking. B50 reads the same `failureDomains()` semantics to provide richer diagnostics around concentration and N−1 behavior; it does not alter the meaning or score contribution of diversity.

## 20. Relationship to PathScorer

`PathScorer` and its callers are unchanged. B50 has no import or call site from `PathScorer`, `AutoGatewaySelector`, `SmartConnectDecisionEngine`, or transport selection. Regression suites verify their existing output remains intact. ASN/provider names never enter scoring.

## 21. Relationship to B49

B50 has no compile dependency on draft PR #103. A later integrated test could use B49 to make a failure-domain unavailable and then pass resulting reachability into B50. That would remain simulation, not field proof.

## 22. Limitations

Declared domains can be incomplete or stale until a newly signed manifest is distributed. ASN origin can change and says nothing about upstream/transit correlation. Reachability is device/network/time-specific. Aggregate history is not causal evidence. Shared exits in relay chains remain dependencies even when ingress networks differ.

## 23. NOT MEASURED / UNKNOWN items

No live endpoint reachability, latency, device history, runtime DNS resolution, transit/provider upstream graph, CDN edge, relay ingress, operator organizational independence, or field-restriction behavior was measured. Current signed failure-domain IDs are absent. These remain unknown rather than assumed correlated or independent.

## 24. Recommended remediation/infrastructure diversification actions

Publish reviewed opaque failure-domain IDs in a newly signed manifest; independently verify that the labels match operational reality; add an independently operated network/control-plane/region where concentration remains; keep control and data-plane dependencies explicit; and validate any added diversity through B54 field measurements. Do not select infrastructure by provider reputation.

## 25. B51 dependencies

B51 should define ownership/authorization evidence, stable addressing, independent operator/network/control-plane/exit domains, and measurement procedures for any non-datacenter endpoint research. B50 can compare topology only after those facts are trusted and current reachability is measured.

## 26. Decision gate

Decision: **SURVIVABILITY ASSESSMENT IMPLEMENTED / CURRENT TOPOLOGY BASELINED WITH INSUFFICIENT SIGNED DOMAIN DATA**. The model is ready for diagnostics/research use but is deliberately not wired into selection. Field censorship survivability remains unverified.
