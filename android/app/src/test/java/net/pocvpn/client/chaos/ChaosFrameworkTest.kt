package net.pocvpn.client.chaos

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.ManifestFetchFailureKind
import net.pocvpn.client.reachability.ManifestFetchResult
import net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy
import net.pocvpn.client.smartconnect.AwgXrayFailoverPolicy
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RestrictionClassifier
import net.pocvpn.client.smartconnect.RestrictionEvidence
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ChaosFrameworkTest {
    @Test fun `script preserves order repetition typed failure and logical time`() {
        val op = ChaosOperation("awg", "gateway-a", "AMNEZIA_WG")
        val engine = ScriptedChaosEngine(listOf(ChaosStep(op, ChaosOutcome.Failure(B48SimulationProfiles.AWG_SILENT_DROP), delayMillis = 8_000, repeat = 2)))
        repeat(2) { assertEquals(B48SimulationProfiles.AWG_SILENT_DROP, (engine.next(op) as ChaosOutcome.Failure).failure) }
        assertEquals(16_000, engine.logicalTimeMillis)
        assertEquals(listOf(1, 2), engine.evidence().map { it.sequence })
        engine.assertExhausted()
    }

    @Test fun `B49-A restriction observations are consumed by production classifier`() {
        assertEquals(RestrictionClass.NO_NETWORK, RestrictionClassifier.classify(evidence(NetworkProfile.unavailable(1), null, null)))
        assertEquals(RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, RestrictionClassifier.classify(evidence(online(), false, true)))
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, RestrictionClassifier.classify(evidence(online(), false, false, false)))
        assertEquals(RestrictionClass.UNKNOWN, RestrictionClassifier.classify(evidence(online(), null, null)))
    }

    @Test fun `B49-B AWG silent timeout reaches normal REALITY fallback policy`() {
        val op = ChaosOperation("vpn-transport", "gateway-a", "AMNEZIA_WG")
        val engine = ScriptedChaosEngine(listOf(ChaosStep(op, ChaosOutcome.Failure(B48SimulationProfiles.AWG_SILENT_DROP), expectedTransition = ExpectedTransition.FALLBACK_TRANSPORT)))
        assertTrue(engine.next(op) is ChaosOutcome.Failure)
        assertTrue(AwgXrayFailoverPolicy.isEligibleForXrayFallback(TransportKind.AMNEZIA_WG, UserTransportPreference.Auto, TransportState.HandshakeFailed, VpnError.HandshakeTimeout, true))
        assertFalse(AwgXrayFailoverPolicy.isEligibleForXrayFallback(TransportKind.AMNEZIA_WG, UserTransportPreference.Manual(TransportKind.AMNEZIA_WG), TransportState.HandshakeFailed, VpnError.HandshakeTimeout, true))
        assertEquals(ExpectedTransition.FALLBACK_TRANSPORT, engine.evidence().single().expectedTransition)
    }

    @Test fun `B49-C actual policy stops after REALITY failure and does not invent TLS fallback`() {
        val awg = ChaosOperation("vpn-transport", "gateway-a", "AMNEZIA_WG")
        val reality = ChaosOperation("vpn-transport", "gateway-a", "XRAY_REALITY")
        val engine = ScriptedChaosEngine(listOf(
            ChaosStep(awg, ChaosOutcome.Failure(B48SimulationProfiles.AWG_SILENT_DROP), expectedTransition = ExpectedTransition.FALLBACK_TRANSPORT),
            ChaosStep(reality, ChaosOutcome.Failure(B48SimulationProfiles.REALITY_TLS_ALERT_OR_CLOSE), expectedTransition = ExpectedTransition.FAIL_CLOSED),
        ))
        engine.next(awg); engine.next(reality); engine.assertExhausted()
        assertEquals(listOf("AMNEZIA_WG", "XRAY_REALITY"), engine.evidence().map { it.operation.transport })
    }

    @Test fun `B49-D and E gateway failover is bounded and terminal failure fails closed`() {
        val first = ChaosOperation("gateway-attempt", "gateway-a", "AMNEZIA_WG")
        val second = ChaosOperation("gateway-attempt", "gateway-b", "AMNEZIA_WG")
        val engine = ScriptedChaosEngine(listOf(
            ChaosStep(first, ChaosOutcome.Failure(ChaosFailure.Infrastructure(ChaosFailure.InfrastructureKind.PRIMARY_GATEWAY_UNREACHABLE)), expectedTransition = ExpectedTransition.NEXT_GATEWAY),
            ChaosStep(second, ChaosOutcome.Failure(ChaosFailure.Infrastructure(ChaosFailure.InfrastructureKind.ALL_GATEWAYS_UNREACHABLE)), expectedTransition = ExpectedTransition.FAIL_CLOSED),
        ))
        assertTrue(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.HandshakeFailed, VpnError.HandshakeTimeout))
        engine.next(first); engine.next(second)
        assertEquals(listOf("gateway-a", "gateway-b"), engine.evidence().map { it.operation.gatewayId })
        assertEquals(ExpectedTransition.FAIL_CLOSED, engine.evidence().last().expectedTransition)
    }

    @Test fun `B49-F and G manifest and control plane failures remain typed`() = runTest {
        val operation = ChaosOperation("manifest-live-origin")
        val engine = ScriptedChaosEngine(listOf(ChaosStep(operation, ChaosOutcome.Failure(ChaosFailure.Http(ChaosFailure.HttpKind.STATUS_503)))))
        val result = ScriptedRemoteManifestFetcher(engine, operation).fetch() as ManifestFetchResult.Failed
        assertEquals(ManifestFetchFailureKind.HTTP_ERROR, result.kind)
        assertEquals("HTTP_STATUS_503", result.reason)
    }

    @Test fun `B49-H and I ingress relay and XHTTP profiles retain typed identity`() {
        assertEquals("INFRASTRUCTURE_STOCKHOLM_2093_CONNECTION_REFUSED", ChaosFailure.Infrastructure(ChaosFailure.InfrastructureKind.STOCKHOLM_2093_CONNECTION_REFUSED).safeCode())
        assertEquals("TRANSPORT_XHTTP_PATH_HTTP_ERROR", B48SimulationProfiles.XHTTP_EXPECTED_PATH_HTTP_ERROR.safeCode())
        assertEquals("INFRASTRUCTURE_RELAY_DIED", ChaosFailure.Infrastructure(ChaosFailure.InfrastructureKind.RELAY_DIED).safeCode())
    }

    @Test fun `B49-J recovery consumes fresh success without stale poison`() {
        val op = ChaosOperation("xhttp", "gateway-a", "XRAY_XHTTP")
        val engine = ScriptedChaosEngine(listOf(
            ChaosStep(op, ChaosOutcome.Failure(B48SimulationProfiles.XHTTP_EXPECTED_PATH_HTTP_ERROR), expectedTransition = ExpectedTransition.RETRY),
            ChaosStep(op, ChaosOutcome.Success, expectedTransition = ExpectedTransition.RECOVERED),
        ))
        assertTrue(engine.next(op) is ChaosOutcome.Failure)
        assertTrue(engine.next(op) is ChaosOutcome.Success)
        assertEquals(ExpectedTransition.RECOVERED, engine.evidence().last().expectedTransition)
    }

    @Test(expected = IllegalStateException::class)
    fun `unexpected operation fails immediately instead of silently skipping`() {
        ScriptedChaosEngine(listOf(ChaosStep(ChaosOperation("dns"), ChaosOutcome.Success))).next(ChaosOperation("tcp"))
    }

    private fun online() = NetworkProfile(NetworkType.WIFI, true, false, false, false, true, true, false, 1)
    private fun evidence(profile: NetworkProfile, awg: Boolean?, gateway: Boolean?, diverse: Boolean? = true) = RestrictionEvidence(profile, TransportState.Disconnected, awg, gateway, diverse)
}
