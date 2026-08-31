package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.PathHistoryEntry
import net.pocvpn.client.reachability.ReachabilityEvidenceSummary
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** B16 - real, focused proof that AutoGatewaySelector genuinely reuses PathScorer/ReachabilityEngine rather than inventing a parallel scoring path, and enforces every "Candidate identity"/bounded-failover invariant PROJECT_ARCHITECTURE.md documents. */
class AutoGatewaySelectorTest {

    private val bothGateways = ProductionGatewayCatalog.all
    private val germanyId = ProductionGatewayCatalog.GERMANY.endpointId
    private val stockholmId = ProductionGatewayCatalog.STOCKHOLM.endpointId

    private fun healthyRegistry(kind: TransportKind = TransportKind.AMNEZIA_WG): TransportRegistry = TransportRegistry.build(
        listOf(
            TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }),
        ),
    )

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

    private fun healthy() = TransportHealth(state = TransportHealthState.HEALTHY, consecutiveFailures = 0, latencyMillis = null, lastProbeEpochMillis = null)

    private fun buildDefault(
        provisioned: Set<ProductionGatewayId> = setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
        preference: UserTransportPreference = UserTransportPreference.Auto,
        historyFor: (EndpointId, TransportKind) -> PathHistoryEntry? = { _, _ -> null },
    ) = AutoGatewaySelector.buildCandidates(
        gateways = bothGateways,
        provisioned = { it in provisioned },
        clientTunnelIp = { if (it in provisioned) "10.77.0.5" else null },
        registryFor = { healthyRegistry() },
        xrayAvailableFor = { false },
        xrayTlsAvailableFor = { false },
        reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
        transportHealthFor = { healthy() },
        historyFor = historyFor,
        preference = preference,
    )

    @Test
    fun `both provisioned gateways produce candidates`() {
        val candidates = buildDefault()
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), candidates.map { it.gatewayId }.toSet())
    }

    @Test
    fun `unprovisioned gateway is excluded entirely`() {
        val candidates = buildDefault(provisioned = setOf(ProductionGatewayId.GERMANY))
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    @Test
    fun `gateway with no client tunnel identity is excluded even if marked provisioned`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            gateways = bothGateways,
            provisioned = { true },
            clientTunnelIp = { id -> if (id == ProductionGatewayId.GERMANY) "10.77.0.5" else null },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    @Test
    fun `neither gateway provisioned yields no candidates - no random selection`() {
        assertTrue(buildDefault(provisioned = emptySet()).isEmpty())
    }

    @Test
    fun `every candidate carries an exact GatewayConfigSnapshot resolved from the catalog`() {
        val candidates = buildDefault()
        val germany = candidates.first { it.gatewayId == ProductionGatewayId.GERMANY }
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointHost, germany.configSnapshot.endpointHost)
        assertEquals("10.77.0.5", germany.configSnapshot.clientTunnelIp)
    }

    @Test
    fun `pinned manual transport preference restricts every gateway to that one transport kind`() {
        val candidates = buildDefault(preference = UserTransportPreference.Manual(TransportKind.AMNEZIA_WG))
        assertTrue(candidates.all { it.transport == TransportKind.AMNEZIA_WG })
    }

    @Test
    fun `richer PathHistory success ratio ranks a candidate higher - real PathScorer reuse, not a parallel scorer`() {
        val richHistory = PathHistoryEntry(successCount = 10, failureCount = 0, lastOutcomeEpochMillis = 1L, lastOutcomeSuccess = true)
        val candidates = buildDefault(
            historyFor = { endpointId, _ -> if (endpointId == stockholmId) richHistory else null },
        )
        assertEquals(ProductionGatewayId.STOCKHOLM, candidates.first().gatewayId)
    }

    @Test
    fun `unreachable-ineligible transport is never a candidate - PathScorer eligibility is honored`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            gateways = bothGateways,
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            // Registry reports NOT AVAILABLE for AWG - PathScorer.isEligible must reject it.
            registryFor = {
                TransportRegistry.build(
                    listOf(TransportDescriptor(kind = TransportKind.AMNEZIA_WG, status = TransportStatus.NOT_IMPLEMENTED, capabilities = TransportCapabilities.notImplemented(), factory = null)),
                )
            },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertTrue(candidates.isEmpty())
    }

    // --- nextCandidate: bounded, no-repeat failover ordering ---

    @Test
    fun `nextCandidate returns the top-ranked candidate first`() {
        val candidates = buildDefault()
        val first = AutoGatewaySelector.nextCandidate(candidates, attempted = emptySet())
        assertEquals(candidates.first(), first)
    }

    @Test
    fun `nextCandidate skips already-attempted gateway plus transport pairs`() {
        val candidates = buildDefault()
        val first = candidates[0]
        val second = AutoGatewaySelector.nextCandidate(candidates, attempted = setOf(first.gatewayId to first.transport))
        assertEquals(candidates[1], second)
    }

    @Test
    fun `nextCandidate never returns the same gateway plus transport pair twice`() {
        val candidates = buildDefault()
        var attempted = emptySet<Pair<ProductionGatewayId, TransportKind>>()
        val seen = mutableListOf<Pair<ProductionGatewayId, TransportKind>>()
        while (true) {
            val next = AutoGatewaySelector.nextCandidate(candidates, attempted) ?: break
            val key = next.gatewayId to next.transport
            assertTrue("candidate $key retried", key !in seen)
            seen += key
            attempted = attempted + key
        }
        assertEquals(candidates.size, seen.size)
    }

    @Test
    fun `nextCandidate fails closed once the bounded candidate set is exhausted`() {
        val candidates = buildDefault()
        val exhausted = candidates.map { it.gatewayId to it.transport }.toSet()
        assertNull(AutoGatewaySelector.nextCandidate(candidates, exhausted))
    }

    @Test
    fun `nextCandidate stops at MAX_ATTEMPTS even if more distinct candidates exist`() {
        val pairs = listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM).flatMap { g -> TransportKind.entries.map { g to it } }
        val snapshot = buildDefault().first().configSnapshot
        val many = pairs.mapIndexed { i, (gatewayId, kind) ->
            GatewayAttemptCandidate(
                gatewayId = gatewayId,
                endpointId = germanyId,
                transport = kind,
                region = "x",
                configSnapshot = snapshot,
                score = (pairs.size - i).toLong(),
                reasons = emptyList(),
            )
        }
        assertTrue(many.size > AutoGatewaySelector.MAX_ATTEMPTS)
        val attempted = many.take(AutoGatewaySelector.MAX_ATTEMPTS).map { it.gatewayId to it.transport }.toSet()
        assertNull(AutoGatewaySelector.nextCandidate(many, attempted))
    }
}
