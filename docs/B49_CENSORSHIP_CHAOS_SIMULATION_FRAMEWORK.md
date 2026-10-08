# B49 — Censorship / Chaos Simulation Framework

## 1. Executive summary

B49 adds a deterministic JVM-test fault-injection harness under `android/app/src/test`. It supplies ordered typed outcomes at existing dependency boundaries; production classifiers, failover policies, repositories, controllers, and lifecycle code remain authoritative. No production source or infrastructure changed.

**Simulation is not restricted-network field evidence.** Passing B49 is not proof that Nova works in Russia, under a hard whitelist, or under any specific operator restriction.

## 2. Scope and non-goals

The scope is bounded application behavior: classification, next-action eligibility, ordered evidence, recovery, and fail-closed behavior. It is not a packet/network emulator, public fault service, censorship detector, transport fingerprint change, Hysteria2 integration, or replacement for physical/field validation.

## 3. Existing architecture/seam inventory

| Boundary | Existing seam / authority | Current result shape | Time / cleanup |
|---|---|---|---|
| Android network facts | `NetworkProfiler`, `NetworkProfile` | typed facts | observer lifecycle |
| restriction | `GatewayReachabilityProbe`, `RestrictionMonitor`, `RestrictionClassifier`, `RestrictionStabilizer` | booleans plus typed assessment | timestamps injectable into classifier; probe timeout bounded |
| transport selection | `SmartConnectDecisionEngine`, `AwgXrayFailoverPolicy`, `TransportOrchestrator` | typed decision/state/error | controller owns transport cleanup |
| gateway selection | `AutoGatewaySelector`, `AutoGatewayFailoverPolicy` | pinned candidate and typed eligibility | max four attempts |
| reachability/history | `ReachabilityEngine`, `PathScorer`, `PathHistoryStore`, `EndpointOutcomeMatcher` | typed reachability/history | `nowEpochMillis` seams |
| manifest | `RemoteManifestFetcher`, `ManifestDistributionClient`, `EndpointManifestRepository` | typed fetch/rejection/trust state | injected repository clock |
| control plane | `TrustedOriginRequestExecutor`, `ActivationResilienceCoordinator` | typed failure/exhaustion | bounded origin list |
| relay | `RelayIngressResolver`, `RelayEndToEndProbe`, relay readiness states | typed resolution/probe failures | caller/controller teardown |
| Xray/Shadowsocks | runtime/controller interfaces and test fakes | typed lifecycle states | coroutine test scheduler and explicit stop |
| VPN ownership | `VpnTransport`, `VpnController`, reconnect manager | `TransportState`, `VpnError` | disconnect, observer/job cancellation |
| diagnostics | support recorder/bundle/sanitizer | closed events and redaction | session-owned |

Generic exceptions/booleans remain at some low-level boundaries (notably the reachability probe boolean and some transport start exceptions); production code already maps the consequential cases to typed policy inputs. B49 does not widen production APIs merely for tests.

## 4. Failure taxonomy

`ChaosFailure` is closed and test-only. It covers DNS (NXDOMAIN, SERVFAIL, timeout, empty/malformed answer, resolver unavailable); TCP (connect timeout/refused/reset, immediate/delayed close, no application response); UDP (silent drop, local/network failure, one-way, delayed/no response); TLS (timeout, alert, certificate/hostname failure, peer close, TCP-up/TLS-down); meaningful HTTP statuses and malformed/truncated bodies; manifest availability/trust failures; named transport signatures; and gateway/control-plane/ingress/relay/exit failures. Arbitrary failure strings are not accepted.

## 5. Scenario model

A `ChaosStep` names a component plus optional non-secret gateway/transport IDs, one typed outcome, logical delay, bounded repetition (1–100), and an expected transition. This is intentionally a small model, not a general DSL.

## 6. Framework architecture

`ScriptedChaosEngine` expands bounded repetitions, strictly matches each requested operation against the next step, advances logical time without sleeping, and records immutable `ChaosEvidence`. It never calls Smart Connect or chooses a fallback. Adapters expose the script through `GatewayReachabilityProbe` and `RemoteManifestFetcher`; product policy consumes their results normally.

## 7. B48 signature-to-simulation mapping

The named fixtures are `AWG_SILENT_DROP`, `REALITY_TLS_ALERT_OR_CLOSE`, `TLS_TCP_CONNECT_THEN_CLOSE`, `SHADOWSOCKS_RESET`, `XHTTP_EXPECTED_PATH_HTTP_ERROR`, `INGRESS_CONNECTION_REFUSED`, and `CONTROL_PLANE_UNAVAILABLE`. Stockholm `:2093` refusal has a separate typed infrastructure case. These are reproductions of bounded observations, not universal censorship signatures.

## 8. DNS simulations

All requested DNS outcomes are representable. Current production boundaries often collapse them to network/unreachable categories, so tests may retain the finer chaos evidence while asserting the coarser production result truthfully.

## 9. TCP/UDP simulations

TCP close/reset/refusal/timeout and UDP silence/failure/one-way/no-response are representable. AWG silence is explicit and advances a virtual timeout instantly.

## 10. TLS simulations

Handshake timeout, alert, certificate validation failure, hostname mismatch, peer close, and TCP-success/TLS-failure are explicit. No trust-all manager or certificate bypass was added.

## 11. HTTP/control-plane simulations

The taxonomy covers connection failure, timeout, 400/401/403/404/429/500/502/503, malformed and truncated responses. The manifest adapter maps these into existing `ManifestFetchFailureKind`; activation/profile resilience remains tested through the existing coordinator suites. No activation bypass exists.

## 12. Manifest/trust simulations

Existing repository tests remain the authority for LIVE failure → verified LKG, invalid LKG → verified embedded bootstrap, invalid signature/expiry/rollback rejection, and `NoneTrusted`. The chaos fetch adapter cannot mark bytes trusted: only `EndpointManifestRepository.offer` and `trustedState` can do so.

## 13. Transport failover simulations

The baseline script records AWG silent timeout followed by REALITY. `AwgXrayFailoverPolicy`—not the simulator—authorizes the transition. Manual preference still blocks fallback. Current policy does not provide an automatic REALITY → TLS/TCP chain, so B49 records REALITY failure as fail-closed rather than changing product policy.

## 14. Gateway failover simulations

A two-gateway script preserves ordered gateway IDs and delegates next-candidate eligibility to `AutoGatewayFailoverPolicy`. Existing auto-gateway/controller suites cover pinned endpoint/config identity and history isolation. All-gateway exhaustion is terminal and retains both attempts.

## 15. Relay/ingress simulations

Ingress refusal/timeout, relay unavailable/health timeout/start-then-die, and exit-health failure are typed, including the observed Stockholm `:2093` refusal case. Existing relay/controller tests provide the executable ownership and teardown assertions; B49 adds reusable inputs without claiming a deployed relay.

## 16. XHTTP simulations

DNS failure, TLS-up/HTTP-path failure, 400/403, CDN unavailable, and origin unavailable can be composed from the DNS/TLS/HTTP/transport types. B49 does not change XHTTP path, padding, headers, or fingerprint.

## 17. Recovery simulations

A failure followed by a fresh success consumes two distinct ordered outcomes; the latter is `RECOVERED`, proving the script does not poison subsequent attempts. Existing path-history tests remain responsible for intentional memory aging/scoring behavior.

## 18. Resource-cleanup evidence

Cleanup is not simulated as process-table inspection. Existing controller, terminal teardown, relay teardown, Xray lifecycle/watchdog, Shadowsocks lifecycle, and reconnect tests assert no stale owner/runtime/pending endpoint/observer/watchdog. The B49 evidence sequence makes each failed attempt auditable and its terminal transition explicit; it does not replace those ownership tests.

## 19. Diagnostic evidence

Each evidence record contains only sequence, logical time, component, non-secret gateway/transport identifiers, typed outcome, and expected action. `safeCode()` is derived solely from closed enum names. It cannot include passwords, UUIDs, keys, bearer tokens, endpoints, URLs, or exception text. Existing sanitizer suites remain in the test matrix.

## 20. Test matrix

| Group | B49 coverage | Existing authority reused |
|---|---|---|
| A classification | no network, UDP/AWG-only suspicion, broad loss, unknown | `RestrictionClassifier` |
| B AWG→REALITY | silence/timeout, auto eligible, manual blocked | `AwgXrayFailoverPolicy` |
| C multi-transport | AWG then REALITY; terminal after REALITY | current policy boundary |
| D/E gateways | ordered IDs, next-candidate eligibility, fail closed | `AutoGatewayFailoverPolicy` |
| F/G manifest/control | typed HTTP failure adapter; trust suites | repository/coordinator |
| H relay/ingress | named typed fixtures plus lifecycle suites | relay/controller seams |
| I XHTTP | named path error and composable layers | XHTTP/lifecycle suites |
| J recovery | failure then success with logical time | scripted source/history suites |

Execution on 2026-09-21 (Android Studio JBR and local Android SDK, no device or Internet): the dedicated B49 class passed 9/9; the focused relevant package matrix passed 1,000/1,000; the broad JVM suite ran 1,744 tests with 1 failure. The sole failure, `EffectiveConfigDiffTest` at line 177 (`ClassCastException`), was reproduced independently by running that exact test against a clean detached `origin/main` (`75cb4b2`), 1/1 failed identically, and is therefore pre-existing rather than introduced by B49.

## 21. Unsupported/not-yet-simulatable cases

Production does not expose every low-level DNS/TCP/TLS distinction after mapping; one-way UDP is representable but not directly observable through a dedicated production result; REALITY→TLS/TCP automatic fallback is unsupported; Hysteria2 is `PENDING B46-3A`; real TUN/process/kernel behavior, public CDN behavior, and operator filtering require integration/field evidence. The relay health endpoint is documented as out-of-band control-plane evidence, not authoritative in-tunnel proof.

## 22. Relationship to B47/B48

B47/B47-1P remain separate fingerprint/capture work. B48 supplied observed signature-shaped fixtures; B49 only makes those deterministic test inputs. It neither changes nor completes either audit and does not modify PRs #99–#102.

## 23. Relationship to future B50/B54

B50 may consume deterministic histories when validating provider/ASN survivability scoring, without provider-name allowlists. B54 can reuse the harness for future resilience gates. Neither milestone may reinterpret simulated success as real restricted-network evidence.

## 24. Limitations

This is application-boundary simulation. It cannot validate packets, timing fingerprints, Android kernel/TUN behavior, radio transitions, real certificate chains, CDN behavior, geographic reachability, or censorship systems. Logical delay verifies ordering, not real latency. Fine-grained chaos types may intentionally map to coarser current production categories.

## 25. Decision gate

Decision: **FRAMEWORK IMPLEMENTED / BASELINE SCENARIOS PASSING**, subject to the recorded JVM test results. B49 is sufficient to proceed to B50 as a reusable deterministic baseline; additional B49 slices should deepen controller-level scripted transport adapters and manifest signed-fixture composition rather than change production policy. Real-world censorship resistance remains unproven.
