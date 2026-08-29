package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8I1 - RECONCILED narrow tests: SmartConnectCandidateSelector is now THE
 * ONE Smart Connect decision authority, and it REUSES
 * SmartConnectDecisionEngine for the transport sub-decision rather than
 * re-deciding independently (see ConnectionCandidate.kt's own docs). Covers
 * this feature's own required cases 2, 3 (via never disagreeing with the
 * reused engine), 4, 5.
 */
class SmartConnectCandidateSelectorTest {

    private fun configuredGateway() = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10",
        endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2",
        gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0", "::/0"),
        profile = AwgProfile.none(),
    )

    private fun usableProfile(type: NetworkType = NetworkType.WIFI) = NetworkProfile(
        type = type, validatedInternet = true, metered = false, roaming = false,
        captivePortal = false, ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
    )

    private fun sampleOutcome(result: ConnectionOutcomeResult) = ConnectionOutcome(
        transport = TransportKind.AMNEZIA_WG,
        gatewayId = ProductionGateway.ID,
        result = result,
        handshakeDurationMs = 1200L,
        errorCategory = if (result == ConnectionOutcomeResult.SUCCESS) ConnectionErrorCategory.NONE else ConnectionErrorCategory.HANDSHAKE_TIMEOUT,
        timestampEpochMillis = 1_000L,
    )

    @Test
    fun `production candidates for a configured gateway is exactly Frankfurt`() {
        val candidates = SmartConnectCandidateSelector.productionGatewayCandidates(configuredGateway())

        assertEquals(1, candidates.size)
        assertEquals(ProductionGateway.ID, candidates.single().id)
        assertEquals("Germany / Frankfurt", candidates.single().region)
    }

    @Test
    fun `the current single production decision is truthfully AWG plus Frankfurt plus ONLY_AVAILABLE_CANDIDATE`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }

        val decision = SmartConnectCandidateSelector.decide(
            networkProfile = usableProfile(),
            gatewayCandidates = SmartConnectCandidateSelector.productionGatewayCandidates(configuredGateway()),
            registry = registry,
        )

        assertTrue(decision is SmartConnectDecision.Selected)
        val selected = decision as SmartConnectDecision.Selected
        assertEquals(TransportKind.AMNEZIA_WG, selected.score.candidate.transport.kind)
        assertEquals(ProductionGateway.ID, selected.score.candidate.gateway.id)
        assertEquals(ConnectionScoreReason.ONLY_AVAILABLE_CANDIDATE, selected.score.reason)
    }

    @Test
    fun `no gateway configured yields NoCandidateAvailable - never a fabricated one`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }

        assertTrue(SmartConnectCandidateSelector.productionGatewayCandidates(GatewayConfiguration.Missing).isEmpty())

        val decision = SmartConnectCandidateSelector.decide(usableProfile(), emptyList(), registry)
        assertEquals(SmartConnectDecision.NoCandidateAvailable, decision)
    }

    @Test
    fun `when the reused SmartConnectDecisionEngine has no transport available, this boundary agrees - never overrides it`() {
        val emptyRegistry = TransportRegistry.build(emptyList())

        // The SAME inputs handed directly to the reused engine independently confirm what it would say.
        val engineDecision = SmartConnectDecisionEngine.decide(usableProfile(), emptyRegistry)
        assertEquals(TransportSelectionDecision.NoTransportAvailable, engineDecision)

        val decision = SmartConnectCandidateSelector.decide(
            networkProfile = usableProfile(),
            gatewayCandidates = SmartConnectCandidateSelector.productionGatewayCandidates(configuredGateway()),
            registry = emptyRegistry,
        )

        // No independent "pick AWG anyway" fallback - agrees with the one authority.
        assertEquals(SmartConnectDecision.NoCandidateAvailable, decision)
    }

    @Test
    fun `an unusable network yields NoCandidateAvailable via the same network gating the reused engine already applies`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }

        val decision = SmartConnectCandidateSelector.decide(
            networkProfile = NetworkProfile.unavailable(0),
            gatewayCandidates = SmartConnectCandidateSelector.productionGatewayCandidates(configuredGateway()),
            registry = registry,
        )

        assertEquals(SmartConnectDecision.NoCandidateAvailable, decision)
    }

    @Test
    fun `computing a decision never itself calls connect or disconnect on the underlying transport - across changing network profiles`() {
        val fakeTransport = FakeVpnTransport()
        val registry = TransportRegistry.defaults { fakeTransport }
        val gateways = SmartConnectCandidateSelector.productionGatewayCandidates(configuredGateway())

        SmartConnectCandidateSelector.decide(usableProfile(NetworkType.WIFI), gateways, registry)
        SmartConnectCandidateSelector.decide(usableProfile(NetworkType.CELLULAR), gateways, registry)
        SmartConnectCandidateSelector.decide(NetworkProfile.unavailable(0), gateways, registry)
        SmartConnectCandidateSelector.decide(usableProfile(NetworkType.WIFI), gateways, registry)

        assertEquals(0, fakeTransport.connectCallCount)
        assertEquals(0, fakeTransport.disconnectCallCount)
    }

    @Test
    fun `ConnectionOutcome history can be supplied to the decision boundary without changing today's trivial decision or crashing`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        val gateways = SmartConnectCandidateSelector.productionGatewayCandidates(configuredGateway())
        val history = listOf(sampleOutcome(ConnectionOutcomeResult.SUCCESS), sampleOutcome(ConnectionOutcomeResult.FAILURE))

        val withHistory = SmartConnectCandidateSelector.decide(usableProfile(), gateways, registry, connectionHistory = history)
        val withoutHistory = SmartConnectCandidateSelector.decide(usableProfile(), gateways, registry, connectionHistory = emptyList())

        // Nothing in ConnectionOutcome is sensitive (see ConnectionOutcomeStoreTest's
        // own field-closure proof) - passing real history through is always safe,
        // and today's single-candidate decision is unaffected by it either way.
        assertEquals(withoutHistory, withHistory)
    }
}
