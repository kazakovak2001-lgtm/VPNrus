# B-WL (Whitelist / Restricted-Network Adaptation) recovery boundary (2026-09-26)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

- **B-WL is a distinct concern from B67, and both are distinct from B8/B8I
  and B54.** B67 governs bootstrap/activation/enrollment/entitlement -
  "is this device authorized and does it have a profile." B-WL governs
  network-restriction classification and DATA-PLANE candidate transport/
  front/ingress ranking - "given this network's observed behavior, which
  transport/path should be tried, in what order." Neither replaces B8/B8I's
  existing preflight/transport-resolution/per-attempt-ownership/failover
  pipeline (unchanged, only extended) or B54's restricted-network field
  validation matrix (B-WL6 IS that matrix, not a second one).
- **`RestrictionClassifier.RestrictionClass`** (`smartconnect/RestrictionClassifier.kt`)
  already carries `POSSIBLE_HARD_WHITELIST`/`POSSIBLE_UDP_OR_AWG_FILTERING`,
  named `POSSIBLE` by design (B8M/B18 discipline - never a confirmed claim),
  fed by a genuine multi-signal, nullable `RestrictionEvidence` model
  (`awgHandshakeFresh`/`gatewayHttpsReachable`/B8M's strict-majority
  `diverseInternetReachable`). **B-WL1 is now IMPLEMENTED** (2026-09-27): the
  SAME, ONE classifier now also derives `POSSIBLE_EARLY_DROP`/
  `POSSIBLE_UDP_FILTERING`/`POSSIBLE_FULL_SHUTDOWN` from a new
  `RestrictionEvidence.transportObservations` field (empty by default, so
  every pre-B-WL1 caller is byte-for-byte unaffected) - see the "B-WL1/B-WL5
  behavior-evidence pipeline" section below for the concrete mechanism. No
  second classifier or second `RestrictionClass`-like enum was introduced;
  existing naming/semantics are unchanged.
- **`TransportKind.XRAY_XHTTP`** (VLESS+REALITY+XHTTP/TCP-443) is a real,
  live, EXIT-role-capable transport (B35 CDN-relay origin work, plus this
  branch's own B59-B64 Direct-EXIT-XHTTP plumbing, confirmed wired into
  `MainViewModel.buildTransportRegistry`'s transport registry surfacing and
  client-side provisioning). **B66.18 (rebased onto main 2026-10-09, from
  `a2e4a77`)**: the AWG->Xray intra-gateway failover target is chosen by
  `AwgXrayFailoverPolicy.selectXrayFailoverTarget` - `XRAY_XHTTP` only when
  `MainViewModel.restrictionAssessment()` says `POSSIBLE_UDP_OR_AWG_FILTERING`
  with HIGH/MEDIUM evidence quality AND the endpoint's registry has a Direct
  EXIT XHTTP descriptor AVAILABLE; otherwise `XRAY_REALITY` as before. The
  target's binding is pinned from the signed manifest
  (`trustedTransportBindingFor(endpointId, targetKind)`). `RestrictionMonitor.probeNow()`
  refreshes evidence inline before that decision. Still one-shot: a failed
  XHTTP fallback ends in Error, never a second fallback to REALITY. Applies
  to Manual gateway + Auto transport only; Auto gateway mode advances
  candidates instead (B16/B34). B-WL2 does not build XHTTP; its
  ranking role is B-WL5's `PathScorer.restrictionPreference` (in source):
  under `POSSIBLE_UDP_FILTERING` the only profile declaring
  `suitableForRestrictiveNetworks` (`XRAY_XHTTP`) gets +1 and UDP-only -1,
  never a hardcoded "restricted implies XHTTP" branch, never XHTTP as the
  sole candidate, never above health/reachability/history - pinned by
  `XhttpRestrictedNetworkPreferenceTest`. `POSSIBLE_HARD_WHITELIST` stays
  relay-vs-direct only (B28). Field effect UNVERIFIED.
- **`CdnProviderCapabilityProfile`/`CdnProviderProfileMetadata`** (B35,
  `reachability/` package) already model a provider-agnostic front/CDN
  capability set (provider identity is a data field, never a hardcoded
  branch) - this is the `FrontProvider { A, B, C }` abstraction B-WL3 asks
  for; it already exists and is already separate from activation authority
  and VPN exit identity (`EndpointRole`/`EndpointDescriptor`/`EndpointManifest`,
  B11, see the per-device-identity invariant above). B-WL3 extends B27's
  typed `IngressKind` (`DIRECT_IP`/`CDN_FRONTED`) with whitelist/front
  semantics; it does not create a new ingress abstraction.
- **The CLIENT -> INGRESS -> EXIT relay architecture (B24-B34) already
  separates ingress availability, exit availability, routing, health, and
  failover** - see the B33/B34 sections above (`RelayIngressResolver`,
  `IngressProfileStore`, `PathScorer`'s relay-fairness logic,
  `HttpRelayEndToEndProbe`, the post-Connected relay-health watchdog). The
  physical Stockholm(ingress)->Frankfurt(exit) test cited there proves the
  two-hop DATA PLANE works end-to-end on an UNRESTRICTED network - it is
  **not** whitelist/restricted-network evidence, and B-WL may never cite it
  as such (this file's own B33 section already states this; B-WL4 exists
  only to make the distinction explicit at the roadmap level too).
- **The "successful handshake never proves a working tunnel" principle is
  already a hard invariant**, not a B-WL proposal - see this file's own
  "Xray/TLS Connected confirmation (hard invariant, B33)" section
  (`confirmRemoteConnectivity`, the relay-health watchdog). **B-WL5 is now
  IMPLEMENTED** (2026-09-27): `PathScorer.restrictionPreference` (the SAME,
  ONE scorer) now reads B-WL1's richer restriction classes and the
  candidate's own `TransportCapabilities` to prefer/penalize candidates
  under `POSSIBLE_UDP_FILTERING`/`POSSIBLE_EARLY_DROP` - never a
  per-classification hardcoded if/else chain (roadmap architecture
  principle 6), never a hardcoded `TransportKind` branch. **B-WL7 (traffic
  progress) is IMPLEMENTED as a pure decision function** (`TrafficProgressMonitor`)
  **and is now wired into `VpnController`'s live AmneziaWG session lifecycle**
  (bounded, observational-only real-counter sampling; every other transport
  kind stays connect/handshake-level only) - see the section below for the
  exact boundary.
