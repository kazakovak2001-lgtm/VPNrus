# B51 — Owned/authorized Non-Datacenter Endpoint Research

## 1. Executive summary

B51 finds one defensible first proof shape: an owner-controlled business premises, a business fixed circuit with static public addressing and written permission for the intended VPN/server role, and a dedicated appliance used initially as a bounded ingress/relay—not an unrestricted public exit. No reviewed public offer alone supplies enough authorization evidence, so no concrete provider is deployment-ready and no endpoint was deployed.

Architecture diversity is not field proof. Nothing in this report claims effectiveness in Russia, under a hard whitelist, or under any operator restriction.

## 2. Scope

This is a point-in-time architecture, authorization, market, security and operations study dated 2026-09-21. It evaluates legitimate endpoint classes in Czechia/nearby EU markets without purchasing, provisioning, probing or modifying production.

## 3. Authorization boundary

Eligibility requires owner authorization plus upstream/provider permission covering the exact role (public server/VPN ingress, relay, or exit). Product advertising, an open port, a static IP, or lack of an obvious prohibition is insufficient. Ambiguity is `AUTHORIZATION_UNCONFIRMED` and blocks deployment.

Authorization evidence should be a contract clause, applicable service/AUP text, or written provider confirmation naming server/VPN operation, expected traffic and resale/public-access boundaries.

## 4. Explicit exclusions

Rejected outright: residential proxy markets, compromised or hijacked systems/IP space, botnets, malware exits, third-party open proxies, credential sharing, carrier/ISP bypass, false subscriber identity, informal borrowed connections, consumer service contrary to its terms, and unrelated infrastructure used as a decoy. B51 does not research covert acquisition of residential IPs.

## 5. Current Nova infrastructure baseline

Nova currently documents Oracle/Frankfurt and AWS/Stockholm gateway/exit/control-plane hosts. B50 externally observed two origin ASNs but found no signed production failure-domain metadata. There is no active signed non-datacenter ingress and no basis for asserting trusted structural independence.

## 6. B50 dependency

A future B51 endpoint affects B50 only after verified topology is published with signed opaque domain IDs and current reachability/history exists. Provider names and public ASN observations remain separate evidence and never become selection preferences.

## 7. Candidate endpoint classes

Six classes were evaluated: business fixed broadband/static IP; DIA/leased line; business fixed-wireless/4G/5G; M2M/IoT APN; owner-operated small-office appliance; and contractually authorized partner operation. A connection product and an operating model are separate: the last two must use one of the first four connectivity classes.

## 8. Business fixed broadband

Potential strengths are availability, premises diversity and moderate cost. Required facts are public static dual stack, no CGNAT, customer-controlled inbound TCP/UDP, port policy, address persistence, upload capacity and explicit server/VPN permission. Retail-style business broadband remains best-effort, physically shared and vulnerable to asymmetric upload, provider CPE limits and address-policy changes.

Current examples: [O2 Fixed IP](https://www.o2.cz/podnikatele-a-firmy/internet/pevna-ip-adresa) advertises one public static IPv4 plus an IPv6 `/64`; [O2 remote-access support](https://www.o2.cz/podpora/internet/nefunkcni-vzdaleny-pristup) explains that fixed public IP and router NAT are needed for inbound access. [T-Mobile Business NET](https://www.t-mobile.cz/podnikatele-firmy/business-net) offers an optional public static IPv4. [Vodafone Business fixed terms](https://www.vodafone.cz/podminky/nabidky-a-akce/podminky-sluzby-vodafone-business-pevny-internet/) state that a paid public static IP is available on request. These establish addressing capability, not permission to run Nova.

Decision: **B — promising, provider confirmation required**.

## 9. DIA/leased-line options

DIA is stronger where it contractually supplies symmetric committed capacity, routed addresses, monitoring and SLA. [Quantcom Internet Profi](https://www.quantcom.cz/files/q_web_produktlist_A4_Internet_Profi_757df54aca.pdf) advertises guaranteed symmetric unaggregated capacity, IP assignment/routing, unlimited transfer, optional SLA and 24/7 monitoring; its [DIA page](https://www.quantcom.cz/operator/internet/direct-internet-access/) targets businesses/operators and includes firewall/anti-DDoS context. Dynamic routing/BGP, prefix portability, physical path and server/VPN authorization still require a specific quote/contract.

DIA may terminate at ordinary premises, but a carrier PoP/backhaul can remain datacenter-correlated. Cost, lead time and construction burden are high.

Decision: **A architecture / BLOCKED procurement**—suitable in principle for a controlled PoC after written authorization and technical survey; no purchase in B51.

## 10. Fixed-wireless options

Business FWA may add access-technology and last-mile diversity but can still share the same mobile operator/core. Static IP does not prove inbound TCP/UDP. Required confirmation covers public rather than private IP, CGNAT, APN, inbound initiation, UDP, reconnect persistence and traffic policy. Radio congestion, weather/site line-of-sight and CPE restrictions reduce reliability.

[Vodafone public fixed-IP support](https://www.vodafone.cz/pece/internet-data/internet-v-pocitaci/pevna-ip-adresa/) says mobile static IP is available to business customers through Telemetry, but does not authorize a public VPN server. Decision: **B — provider confirmation required**.

## 11. Mobile/M2M/APN options

Three roles must remain separate:

- Public static Internet endpoint: potentially client-facing only when inbound TCP/UDP and server/VPN use are confirmed. [Vodafone documents a business Telemetry static-IP option](https://www.vodafone.cz/pece/internet-data/internet-v-pocitaci/pevna-ip-adresa/); [O2's business price documentation](https://www.o2.cz/osobni/podpora/ceniky-a-dokumenty/cenik-zakladnich-sluzeb-pro-firemni-zakazniky/cenik-zakladnich-sluzeb-pro-firemni-zakazniky/Cenik_zakladnich_sluzeb_pro_firemni_zakazniky_10_03_2025.pdf) describes an APN with public static IP.
- Private APN endpoint: useful for managed backhaul/relay but not public ingress without an authorized gateway. [O2 IoT](https://www.o2.cz/podnikatele-a-firmy/firemni-reseni/iot/iot-konektivita) supports private, Internet and telemetry APNs.
- Outbound-only IoT: not client-facing ingress. [Vodafone IoT Easy Connect terms](https://www.vodafone.cz/podminky/nabidky-a-akce/podminky-sluzby-vodafone-business-iot-easy-connect/) assign private addresses and provide OpenVPN toward the customer's server. [1NCE's service description](https://1nce.com/wp-content/1NCE-global-service-description-EN.pdf) describes private APN/VPN connectivity; that is controlled IoT backhaul, not public inbound hosting.

LPWA speed/data limits can make a VPN endpoint inappropriate. Decision: public-static business APN **B/BLOCKED confirmation**; private/outbound APN **C for public ingress**, potentially useful for management/backhaul.

## 12. Owner-operated premises endpoint

An owner-controlled office/branch with a dedicated mini-PC, SBC or managed router is operationally plausible. Ownership solves physical permission, not upstream authorization. It needs separated LAN/VLAN, dedicated hardware, console recovery, watchdog, UPS, replaceable storage, documented inventory and a contractually suitable circuit. No hardware is purchased here.

Decision: **A operating model**, conditional on an authorized circuit.

## 13. Partner-operated model

An endpoint operated by a partner requires a written agreement identifying premises owner, subscriber, infrastructure operator, authorized roles/traffic, incident and abuse contacts, monitoring boundary, key custody, revocation, access termination, evidence retention, equipment return/destruction and upstream permission. A friend's connection or verbal consent is rejected.

Decision: **B — viable only after formal agreement and provider authorization**.

## 14. Addressing/NAT analysis

The acceptance checklist records IPv4/IPv6, public/private, prefix, static/dynamic, CGNAT, inbound TCP/UDP, provider and customer firewalls, reverse DNS, reconnect behavior and address-persistence SLA. DDNS can reduce name-update delay but cannot remove CGNAT, inbound filtering or stale-manifest risk; it is not a substitute for stable routed reachability.

Minimum first-PoC requirement: public static IPv4 or stable globally routed IPv6, inbound TCP and UDP confirmed by provider and measured later, customer-controlled firewall, no CGNAT, and written persistence terms.

## 15. Transport compatibility

| Transport | Technical prerequisite | Research classification |
|---|---|---|
| AWG | bidirectional UDP, stable address/port | possible on fixed/DIA; unknown on FWA/mobile until measured |
| REALITY | inbound TCP and compatible TLS routing | possible; permission and filtering unknown |
| TLS/TCP | inbound TCP, certificate/address lifecycle | possible; static addressing preferred |
| Shadowsocks | inbound TCP/UDP as configured | possible; authorization/abuse boundary required |
| XHTTP | legitimate owned origin/CDN architecture | possible only with separately authorized CDN/origin design |
| Hysteria2 | UDP plus future production integration | `PENDING B46-3A` |

No protocol is claimed working on any candidate.

## 16. Ingress-vs-relay-vs-exit analysis

- Ingress only: smallest abuse footprint; still depends on exit/control plane.
- Relay: useful diversity if ingress path is independent; bandwidth and chain health must be proven.
- Exit: greatest legal, abuse, copyright, reputation and subscriber-liability exposure; premises IP becomes public egress.
- Combined ingress+exit: simplest data plane but maximizes premises exposure and operational responsibility.

Recommendation: first PoC is bounded ingress/relay to a controlled exit, with strict test traffic—not an unrestricted public exit.

## 17. Control-plane dependency

Model 1 (premises ingress → existing exit/control plane) adds client-facing access diversity but loses service when the shared exit/control plane fails. Model 2 (premises ingress → independent exit → existing control plane) improves data-plane N−1 but retains provisioning/bootstrap concentration. Model 3 adds an independently reachable, trusted bootstrap/control-plane path and provides the strongest independence, at the highest security/operations burden. The first PoC should test Model 1 honestly, while documenting the retained dependency.

## 18. Failure-domain analysis

| Class | Operator/network | Region | CDN | Control plane | Premises/power/access |
|---|---|---|---|---|---|
| Business fixed | potentially distinct | premises-specific | none unless added | shared initially | new physical/power/last-mile domains |
| DIA | potentially strong, survey required | premises-specific | none | shared initially | new, usually SLA-backed |
| FWA/mobile | distinct only if different operator/core | radio/site-dependent | none | shared initially | new access tech, shared mobile core possible |
| Private APN | mobile-core/operator correlated | device location | none | APN/VPN gateway correlation | outbound/private role |
| Partner site | unknown until contract/topology proof | potentially distinct | none | shared initially | new owner creates governance dependency |

Marketing names do not prove independence. Physical premises, power and access technology stay research metadata unless a future signed schema adopts them.

## 19. Security model

Minimum: dedicated/strongly isolated host; minimal OS; defined unattended security updates; default-deny inbound firewall; SSH keys only; password SSH disabled; non-root operator; narrow sudo; unique endpoint credentials; no gateway-secret reuse; encrypted secret storage; revocation; remote health monitoring; integrity-controlled configuration; secret-free audit logs; automatic restart; staged OS upgrades; rate limits; and documented backup/restore. Secure boot and full-disk encryption are preferred when remote unattended recovery remains possible.

## 20. Physical-security model

Threats include theft, unauthorized console/reset access, removable-storage extraction, router/LAN compromise, tampering and power loss. Use locked placement, tamper evidence, disabled external boot, protected firmware settings, encrypted storage, isolated network and UPS. Loss response: mark endpoint disabled in the next signed manifest, revoke every endpoint credential, rotate affected relationship keys, investigate logs, replace/reprovision from clean media, then require canary validation.

## 21. Operational lifecycle

Research workflow: `PROPOSED → AUTHORIZED → PROVISIONED → CANARY → ACTIVE → DEGRADED → DISABLED → RETIRED`. Production `EndpointOperationalState` already represents `ACTIVE`, `DISABLED`, and `RETIRED`; do not add a second production state machine. Earlier states belong in operator change records. `DEGRADED` is measured health, not necessarily signed lifecycle state.

## 22. Signed-topology publication model

After authorization and B54 evidence, publish the endpoint/relationship through the existing signed manifest. Bindings should carry reviewed opaque `failureDomain.operator`, `.network`, `.region`, optional `.cdn`, and `.controlPlane` IDs. Use stable IDs such as `fd-op-03`, never provider praise or reachability claims. Do not publish private addresses, subscriber data, contracts, keys or credentials. B51 makes no manifest change.

## 23. Failure-domain registry proposal

Maintain a private operator registry containing opaque ID, internal meaning, evidence reference, owner, lifecycle, reviewer and change history. Keep a secret-free schema/template in-repo if useful, but authorization contracts and personally identifying premises details belong in access-controlled operator documentation. Only opaque IDs and deployment-necessary public facts enter signed topology.

## 24. Current provider/product examples

All entries are **examples of product classes, not approved Nova candidates**:

- O2 Fixed IP: static public IPv4 plus IPv6 `/64`; server/VPN permission not found.
- T-Mobile Business NET: optional static public IPv4; business service; server/VPN permission not found.
- Vodafone Business fixed: paid static public IP by request; permission not found.
- Quantcom Internet Profi/DIA: symmetric dedicated capacity, routed IP, SLA/monitoring; exact server/VPN and public-relay terms require contract confirmation.
- Vodafone Telemetry/mobile static IP: public static addressing advertised; inbound UDP and VPN/server permission require confirmation.
- O2 Machine/APNs: Internet/private/telemetry APNs; public inbound role depends on contracted APN.
- Vodafone IoT Easy Connect and 1NCE: private APN/VPN backhaul; not public ingress by default.

## 25. ToS/AUP authorization findings

| Example | Public evidence | Finding |
|---|---|---|
| O2 Fixed IP | static dual stack; inbound NAT guidance | `AMBIGUOUS` for Nova server/VPN/relay/exit |
| T-Mobile Business NET | business access + static IPv4 | `AMBIGUOUS` |
| Vodafone Business fixed | static public IP available | `AMBIGUOUS` |
| Quantcom Internet Profi/DIA | routed IP, business/ISP positioning, SLA | `AMBIGUOUS`; strongest route to written bespoke authorization |
| Vodafone Telemetry | mobile static public IP advertised | `AMBIGUOUS`; intended product scope must be confirmed |
| O2 IoT/APN | private/Internet/telemetry APNs | `AMBIGUOUS` for public endpoint role |
| Vodafone IoT Easy Connect | private IP + OpenVPN | `EXPLICITLY NOT PUBLIC INGRESS BY DEFAULT`; server role still unconfirmed |
| 1NCE private APN/VPN | private IoT addressing/backhaul | `EXPLICITLY NOT PUBLIC INGRESS BY DEFAULT` |

No reviewed concrete offer is `EXPLICITLY_ALLOWED` for Nova's intended public service. Absence of prohibition was not treated as permission.

## 26. Evaluation matrix

| Class | Auth | Static/public | Inbound TCP/UDP | Independence | SLA | Burden | Ingress | Relay | Exit | Gate |
|---|---|---|---|---|---|---|---|---|---|---|
| Business fixed | unconfirmed | commonly available | verify | potentially partial/strong | low/optional | medium | good | good | high abuse risk | B |
| DIA/leased line | contractable | routed | expected, verify | potentially strongest | strong | high | excellent | excellent | possible but risky | A/BLOCKED purchase |
| Business FWA | unconfirmed | product-specific | unknown | access-tech diversity | variable | medium | possible | possible | weak | B |
| Public-static M2M | unconfirmed | product-specific | unknown | mobile-core diversity | variable | medium | possible | limited | inappropriate initially | B |
| Private/outbound APN | scoped IoT use | private | no public inbound | mobile/backhaul only | variable | medium | no | management/backhaul | no | C |
| Owner premises | depends on circuit | depends | depends | adds premises/power | depends | medium/high | preferred | preferred | defer | A model |
| Partner premises | written agreement required | depends | depends | potentially distinct | depends | high governance | possible | possible | defer | B |

## 27. B49 simulation implications

Future isolated scenarios: datacenter network lost while premises ingress remains reachable; premises ISP lost; premises power loss; shared control plane lost; independent ingress with shared exit lost; recovery after appliance restart; stale signed endpoint disabled. Simulation must retain the field-proof disclaimer.

## 28. B50 survivability impact

Synthetic example only: adding a verified premises ingress with distinct signed operator/network/region IDs would increase known structural domains. If it still shares the existing control-plane and exit IDs, B50 should show stronger ingress/network diversity but control-plane/exit N−1 weakness. Current topology remains `UNKNOWN` until signed metadata exists; B51 does not change B50 code or ranking.

## 29. B54 validation requirements

For every candidate record authorization reference, physical/operator network, timestamp, device, endpoint ID, ISP/access technology, address/NAT/firewall facts, transport, client result, server-side handshake/traffic confirmation, real exit result, DNS result, IPv4/IPv6 behavior, failure injection, cleanup and recovery. Repeat across reconnect/reboot and relevant network conditions. A ping, open port or control-plane response alone is insufficient.

## 30. Risks

Lower uptime, power loss, asymmetric bandwidth, CGNAT/filtering, dynamic addressing, weak CPE, theft, local compromise, no DDoS protection, limited remote recovery, ISP maintenance, complaints/suspension, IP reputation damage and operator dependence. Exit operation materially increases subscriber, copyright, unlawful-traffic, logging/retention and abuse-response exposure; legal/provider review is mandatory.

## 31. Unknowns

Exact premises availability, quotes/cost, contractual permission, inbound UDP, blocked ports, CGNAT, routed IPv6, prefix/reconnect persistence, SLA, actual path/ASN/upstreams, DDoS handling, resale/public-user restrictions, local legal/retention duties, and whether the owner has a suitable controlled site.

## 32. Rejected approaches

All strict exclusions in Section 4; consumer residential service without explicit permission; DDNS behind CGNAT; static-IP advertising treated as authorization; private APN described as public ingress; a high-volume premises exit as the first PoC; and provider/ASN identity used as a ranking heuristic.

## 33. Candidate decision gates

- Business fixed + owner premises: **B**, becomes **A** after written authorization and technical survey.
- DIA + owner premises: **A architecture / BLOCKED** on quote, authorization and procurement.
- FWA/public-static mobile: **B**, requires inbound/UDP/APN and authorization confirmation.
- Private/outbound IoT APN: **C** for client-facing ingress; useful only for management/backhaul research.
- Formal partner site: **B**, requires agreement and upstream proof.
- Informal/unauthorized/residential proxy classes: **D — reject**.

## 34. Recommended B51-1P controlled PoC

Prepare—not purchase or deploy—a canary plan for one owner-controlled business premises using either an authorized business fixed-static circuit or DIA. Obtain written permission first. Use dedicated hardened hardware as ingress/relay, permit only named test clients, retain the existing controlled exit/control plane initially, define automatic disable/revocation, publish only after a signed canary topology review, and execute the full B54 contract. This is preferred over an initial premises exit because it limits abuse and legal exposure while testing the new access failure domain.

## 35. Final decision gate

**RESEARCH COMPLETE / CONTROLLED POC ARCHITECTURE SELECTED / PROVIDER AUTHORIZATION BLOCKING DEPLOYMENT.** No provider or endpoint is approved, purchased, provisioned, deployed or field-validated. Next work is B51-1P authorization and PoC planning, not infrastructure activation.
