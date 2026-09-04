package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.ReachabilityEvidenceSummary
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.reachability.withIngressKind
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B34 - physically reproduced as a real bug (PR #53's own CHAIN_DIRECT
 * physical validation, 2026-09-04): with B33 correctly making every failed
 * Direct Xray attempt take its full bounded confirmation window rather than
 * falsely succeeding instantly, 4 ranked Direct candidates alone consumed
 * the ENTIRE shared `MAX_ATTEMPTS` budget before a real, eligible Relayed
 * (`stockholm-ingress-1` -> Germany) candidate ranked 5th was ever tried -
 * Auto reported "Automatic gateway candidates exhausted" despite a
 * genuinely viable path existing. [AutoGatewaySelector.applyRelayFairness]
 * fixes this by reordering (never re-scoring - see its own docs) the
 * already-ranked combined list so the single highest-ranked Relayed
 * candidate is guaranteed a slot within the budget whenever it would
 * otherwise fall outside it.
 *
 * Uses synthetic [AutoGatewaySelector.AutoConnectAttempt] values directly
 * (never the full eligibility/reachability pipeline - already proven
 * correct by [AutoGatewaySelectorTest]/[ProductionIngressEndpointsTest])
 * so this file is a pure, fast, focused test of the fairness/reordering
 * policy itself.
 */
class AutoGatewaySelectorFairnessTest {

    private val exitBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 2053)

    private fun directAttempt(name: String, score: Long, gatewayId: ProductionGatewayId = ProductionGatewayId.STOCKHOLM, transport: TransportKind = TransportKind.XRAY_REALITY) =
        AutoGatewaySelector.AutoConnectAttempt.DirectAttempt(
            GatewayAttemptCandidate(
                gatewayId = gatewayId,
                endpointId = EndpointId(name),
                transport = transport,
                region = "test",
                configSnapshot = GatewayConfigSnapshot(
                    endpointHost = "203.0.113.10", endpointPort = "51820", serverPublicKey = "key",
                    clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1", allowedIps = "0.0.0.0/0",
                    profile = AwgProfile.none(),
                ),
                score = score,
                reasons = listOf("test"),
            ),
        )

    private fun relayedAttempt(name: String, score: Long) =
        AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt(
            AutoGatewaySelector.RelayAttemptCandidate(
                ingressEndpointId = EndpointId(name),
                exitEndpointId = EndpointId("frankfurt"),
                ingressTransport = TransportKind.XRAY_REALITY,
                exitTransport = TransportKind.XRAY_REALITY,
                ingressBinding = exitBinding,
                exitBinding = exitBinding,
                ingressKind = IngressKind.DIRECT_IP,
                ingressRegion = "test", exitRegion = "test",
                score = score,
                reasons = listOf("test"),
                historyPathId = "$name:DIRECT_IP:XRAY_REALITY->frankfurt:XRAY_REALITY",
            ),
        )

    // --- 1: only Direct candidates - unchanged ---

    @Test
    fun `only Direct candidates - order and count unchanged`() {
        val sorted = listOf(directAttempt("a", 400), directAttempt("b", 300), directAttempt("c", 200))

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 4)

        assertEquals(sorted, result)
    }

    // --- 2: a Relayed candidate already within the window is left alone ---

    @Test
    fun `a Relayed candidate already ranked within the window is not moved`() {
        val relay = relayedAttempt("stockholm-ingress-1", 250)
        val sorted = listOf(directAttempt("a", 400), relay, directAttempt("b", 100))

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 4)

        assertEquals(sorted, result)
    }

    // --- 3: the exact physically-reproduced scenario - 4 Direct + 1 Relayed, MAX_ATTEMPTS=4 ---

    @Test
    fun `four Direct plus one Relayed with MAX_ATTEMPTS=4 - Relayed receives the reserved last slot`() {
        val d1 = directAttempt("stockholm", 400, gatewayId = ProductionGatewayId.STOCKHOLM, transport = TransportKind.XRAY_REALITY)
        val d2 = directAttempt("stockholm", 390, gatewayId = ProductionGatewayId.STOCKHOLM, transport = TransportKind.TLS_TCP)
        val d3 = directAttempt("frankfurt", 380, gatewayId = ProductionGatewayId.GERMANY, transport = TransportKind.XRAY_REALITY)
        val d4 = directAttempt("frankfurt", 370, gatewayId = ProductionGatewayId.GERMANY, transport = TransportKind.TLS_TCP)
        val relay = relayedAttempt("stockholm-ingress-1", 100)
        val sorted = listOf(d1, d2, d3, d4, relay)

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 4)

        // The 3 highest-ranked Direct candidates keep their earlier turns...
        assertEquals(listOf(d1, d2, d3, relay, d4), result)
        // ...and within the first 4 (the real budget), the relay now appears.
        assertTrue(result.take(4).any { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt })
        // The lowest-ranked Direct candidate (d4) is the one displaced past the budget - never d1-d3.
        assertEquals(d4, result[4])
    }

    // --- 4: no re-scoring - the candidate objects/scores themselves are untouched ---

    @Test
    fun `reordering never mutates any candidate's own score`() {
        val d1 = directAttempt("stockholm", 400)
        val d2 = directAttempt("frankfurt", 390)
        val relay = relayedAttempt("stockholm-ingress-1", 50)
        val sorted = listOf(d1, d2, relay)

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 2)

        assertEquals(400L, (result.first { it === d1 }).score)
        assertEquals(50L, (result.first { it === relay }).score)
    }

    // --- 5: multiple Relayed candidates - only the highest-ranked one is guaranteed a slot ---

    @Test
    fun `multiple Relayed candidates - only the highest-ranked one is reserved a slot, bounded count unchanged`() {
        val d1 = directAttempt("stockholm", 400)
        val d2 = directAttempt("frankfurt", 390)
        val d3 = directAttempt("stockholm", 380, transport = TransportKind.TLS_TCP)
        val bestRelay = relayedAttempt("stockholm-ingress-1", 100)
        val worseRelay = relayedAttempt("other-ingress", 50)
        val sorted = listOf(d1, d2, d3, bestRelay, worseRelay)

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 3)

        assertEquals(5, result.size) // total pool size never changes, only order
        assertEquals(listOf(d1, d2, bestRelay, d3, worseRelay), result)
        assertTrue(result.take(3).any { it === bestRelay })
        assertTrue("only the best relay needed reordering", result.indexOf(worseRelay) >= 3)
    }

    // --- 6: no Relayed candidate at all - no-op ---

    @Test
    fun `no Relayed candidate - list unchanged`() {
        val sorted = listOf(directAttempt("a", 400), directAttempt("b", 300))

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 1)

        assertEquals(sorted, result)
    }

    // --- 7: no Direct candidate at all - no-op (nothing to be fair between) ---

    @Test
    fun `only a Relayed candidate - list unchanged`() {
        val relay = relayedAttempt("stockholm-ingress-1", 100)
        val sorted = listOf(relay)

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 4)

        assertEquals(sorted, result)
    }

    // --- 8: never grows the total attempt bound ---

    @Test
    fun `reordering never changes the total number of attempts in the list`() {
        val sorted = listOf(
            directAttempt("a", 400), directAttempt("b", 390), directAttempt("c", 380), directAttempt("d", 370),
            relayedAttempt("stockholm-ingress-1", 100),
        )

        val result = AutoGatewaySelector.applyRelayFairness(sorted, maxAttempts = 4)

        assertEquals(sorted.size, result.size)
        assertEquals(sorted.toSet(), result.toSet())
    }

    // --- 9: end-to-end through nextCombinedAttempt - the real walking logic is untouched and stays bounded ---

    @Test
    fun `nextCombinedAttempt walks the fairness-reordered list and still never exceeds MAX_ATTEMPTS`() {
        val d1 = directAttempt("stockholm", 400, gatewayId = ProductionGatewayId.STOCKHOLM, transport = TransportKind.XRAY_REALITY)
        val d2 = directAttempt("stockholm", 390, gatewayId = ProductionGatewayId.STOCKHOLM, transport = TransportKind.TLS_TCP)
        val d3 = directAttempt("frankfurt", 380, gatewayId = ProductionGatewayId.GERMANY, transport = TransportKind.XRAY_REALITY)
        val d4 = directAttempt("frankfurt", 370, gatewayId = ProductionGatewayId.GERMANY, transport = TransportKind.TLS_TCP)
        val relay = relayedAttempt("stockholm-ingress-1", 100)
        val fair = AutoGatewaySelector.applyRelayFairness(listOf(d1, d2, d3, d4, relay), maxAttempts = 4)

        var attemptedKeys = emptySet<String>()
        val order = mutableListOf<AutoGatewaySelector.AutoConnectAttempt>()
        while (true) {
            val next = AutoGatewaySelector.nextCombinedAttempt(fair, attemptedKeys) ?: break
            order += next
            attemptedKeys = attemptedKeys + next.attemptKey
        }

        assertEquals(4, order.size) // bounded - d4 never attempted, budget exhausted first
        assertTrue("the relayed candidate must be among the real attempts made", order.any { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt })
        assertEquals(listOf(d1, d2, d3, relay), order)
    }

    // --- 10: production-shaped integration test - the REAL buildCombinedAttempts/PathScorer pipeline, the exact requested shape ---

    private val germany = ProductionGatewayCatalog.GERMANY
    private val stockholm = ProductionGatewayCatalog.STOCKHOLM
    private val catalogById = ProductionGatewayCatalog.all.associateBy { it.endpointId }
    private val ingressId = EndpointId("stockholm-ingress-1")

    private fun reachable(endpointId: EndpointId, kind: TransportKind) = EndpointReachability(
        endpointId = endpointId,
        transportKind = kind,
        state = ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(
            transportHealthState = TransportHealthState.HEALTHY,
            transportHealthAgeMillis = 0,
            endpointSpecificReachable = true,
            networkUsable = true,
            restrictionClass = RestrictionClass.UNKNOWN,
        ),
    )

    private fun healthyProdRegistry() = TransportRegistry.build(
        listOf(TransportKind.XRAY_REALITY, TransportKind.TLS_TCP).map { kind ->
            TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.xrayRealityAdapterShell(), factory = { throw UnsupportedOperationException() })
        },
    )

    /** Real Germany/Stockholm manifest endpoints, each declaring BOTH XRAY_REALITY and TLS_TCP - "Direct A REALITY, Direct A TLS, Direct B REALITY, Direct B TLS". */
    private fun twoTransportManifestEndpoint(gateway: net.pocvpn.client.vpn.config.ProductionGatewayDescriptor) = EndpointDescriptor(
        id = gateway.endpointId,
        roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
        region = "${gateway.displayCountry} / ${gateway.displayCity}",
        provider = gateway.provider,
        transports = listOf(
            EndpointTransportBinding(TransportKind.XRAY_REALITY, gateway.awg.endpointHost, 2053),
            EndpointTransportBinding(TransportKind.TLS_TCP, gateway.awg.endpointHost, 2083),
        ),
    )

    private val productionIngress = EndpointDescriptor(
        id = ingressId,
        roles = setOf(EndpointRole.INGRESS),
        region = "Sweden / Stockholm",
        provider = "AWS",
        transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, stockholm.awg.endpointHost, 2093).withIngressKind(IngressKind.DIRECT_IP)),
        relayTo = germany.endpointId,
    )

    @Test
    fun `production-shaped - Direct A REALITY, Direct A TLS, Direct B REALITY, Direct B TLS, plus Relayed - Relayed is attempted within the real MAX_ATTEMPTS budget`() {
        val manifestEndpoints = listOf(
            twoTransportManifestEndpoint(germany),
            twoTransportManifestEndpoint(stockholm),
            productionIngress,
        )
        val attempts = AutoGatewaySelector.buildCombinedAttempts(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyProdRegistry() },
            xrayAvailableFor = { true },
            xrayTlsAvailableFor = { true },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { TransportHealth(state = TransportHealthState.HEALTHY, consecutiveFailures = 0, latencyMillis = null, lastProbeEpochMillis = null) },
            historyFor = { _, _ -> null },
        )

        // Real discovery genuinely produced exactly 4 Direct candidates (2
        // gateways x 2 transports). Relayed count is 2, not 1 - real,
        // documented buildRelayedCandidates behavior: it scores every
        // (ingress transport, exit transport) PAIR the exit endpoint
        // declares independently (never assumes one shared transport per
        // hop - see that function's own docs), and Germany's manifest entry
        // here declares both XRAY_REALITY and TLS_TCP as its own exit
        // transports (the SAME entry also used for Germany's OWN Direct
        // candidates above) - so the single ingress transport pairs with
        // BOTH, correctly, never a bug to "fix" here.
        val directCount = attempts.count { it is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt }
        val relayedCount = attempts.count { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt }
        assertEquals(4, directCount)
        assertEquals(2, relayedCount)

        // Simulate every Direct attempt failing truthfully (walking the REAL
        // returned - already fairness-reordered inside buildCombinedAttempts
        // - list via the REAL, unchanged nextCombinedAttempt) and require
        // the Relayed candidate to be reached within the real production
        // MAX_ATTEMPTS bound.
        var attemptedKeys = emptySet<String>()
        val order = mutableListOf<AutoGatewaySelector.AutoConnectAttempt>()
        while (true) {
            val next = AutoGatewaySelector.nextCombinedAttempt(attempts, attemptedKeys) ?: break
            order += next
            attemptedKeys = attemptedKeys + next.attemptKey
        }

        assertTrue("total attempts must never exceed MAX_ATTEMPTS", order.size <= AutoGatewaySelector.MAX_ATTEMPTS)
        assertTrue(
            "the Relayed CHAIN_DIRECT candidate must be reached within the real bounded sequence - this is the exact PR #53 physical bug",
            order.any { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt },
        )
    }

    @Test
    fun `production-shaped - if Relayed then also fails, the sequence still genuinely exhausts at MAX_ATTEMPTS, never beyond`() {
        val manifestEndpoints = listOf(
            twoTransportManifestEndpoint(germany),
            twoTransportManifestEndpoint(stockholm),
            productionIngress,
        )
        val attempts = AutoGatewaySelector.buildCombinedAttempts(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyProdRegistry() },
            xrayAvailableFor = { true },
            xrayTlsAvailableFor = { true },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { TransportHealth(state = TransportHealthState.HEALTHY, consecutiveFailures = 0, latencyMillis = null, lastProbeEpochMillis = null) },
            historyFor = { _, _ -> null },
        )

        var attemptedKeys = emptySet<String>()
        var attemptCount = 0
        while (true) {
            val next = AutoGatewaySelector.nextCombinedAttempt(attempts, attemptedKeys) ?: break
            attemptCount++
            attemptedKeys = attemptedKeys + next.attemptKey
        }

        // Every candidate (all 4 Direct + the 1 Relayed) fails - the bounded
        // walk stops at exactly MAX_ATTEMPTS, never fewer (the pool has
        // enough candidates) and never more (the hard bound).
        assertEquals(AutoGatewaySelector.MAX_ATTEMPTS, attemptCount)
    }
}
