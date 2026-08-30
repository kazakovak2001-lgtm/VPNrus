@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.smartconnect

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private fun profile(type: NetworkType, generation: Long) = NetworkProfile(
    type = type, validatedInternet = true, metered = false, roaming = false,
    captivePortal = false, ipv4Available = true, ipv6Available = false, vpnActive = false, generation = generation,
)

/** In-memory GatewayReachabilityProbe double; counts calls for assertions. */
private class FakeGatewayReachabilityProbe(private val result: Boolean = true) : GatewayReachabilityProbe {
    var callCount = 0
        private set

    override suspend fun isReachable(): Boolean {
        callCount++
        return result
    }
}

private fun fakeDiverseProbes(vararg results: Boolean): List<GatewayReachabilityProbe> =
    results.map { FakeGatewayReachabilityProbe(it) }

/**
 * B8J - narrow tests for probe SCHEDULING: this feature's own required
 * cases 12 (never touches a VpnTransport - true by construction, no import
 * of VpnTransport anywhere in this file) and 13 (healthy network/transport
 * callbacks never cause aggressive probing).
 */
class RestrictionMonitorTest {

    @Test
    fun `an ordinary healthy transport-state sequence never triggers a probe`() {
        assertFalse(isMeaningfulProbeTrigger(TransportState.Disconnected, TransportState.Connecting))
        assertFalse(isMeaningfulProbeTrigger(TransportState.Connecting, TransportState.Connected))
        assertFalse(isMeaningfulProbeTrigger(TransportState.Connected, TransportState.Connected))
        assertFalse(isMeaningfulProbeTrigger(TransportState.Connected, TransportState.Disconnecting))
        assertFalse(isMeaningfulProbeTrigger(TransportState.Disconnecting, TransportState.Disconnected))
        assertFalse(isMeaningfulProbeTrigger(TransportState.Connected, TransportState.Reconnecting(1)))
        assertFalse(isMeaningfulProbeTrigger(TransportState.Reconnecting(1), TransportState.Reconnecting(2)))
        // Recovering back to Connected is good news, not a trigger either.
        assertFalse(isMeaningfulProbeTrigger(TransportState.Reconnecting(3), TransportState.Connected))
    }

    @Test
    fun `initial handshake failure and reconnect exhaustion DO trigger, repeats of the same failure do not`() {
        assertTrue(isMeaningfulProbeTrigger(TransportState.Connecting, TransportState.HandshakeFailed))
        assertFalse("a repeat HandshakeFailed->HandshakeFailed is not a NEW failure", isMeaningfulProbeTrigger(TransportState.HandshakeFailed, TransportState.HandshakeFailed))
        assertTrue(isMeaningfulProbeTrigger(TransportState.Reconnecting(8), TransportState.Error("Reconnect attempts exhausted")))
        // An Error NOT reached via Reconnecting (e.g. permission denied) is a different situation, not reconnect exhaustion.
        assertFalse(isMeaningfulProbeTrigger(TransportState.Connecting, TransportState.Error("permission denied")))
    }

    @Test
    fun `ordinary metered-flag or captive-portal churn at the same network type never triggers a probe`() {
        assertFalse(isMeaningfulNetworkChange(NetworkType.WIFI, NetworkType.WIFI, TransportState.Reconnecting(1)))
        assertFalse(isMeaningfulNetworkChange(null, NetworkType.WIFI, TransportState.Reconnecting(1)))
    }

    @Test
    fun `a real network type change only triggers while NOT Connected - healthy Wi-Fi to cellular roaming while Protected does not probe`() {
        assertFalse(isMeaningfulNetworkChange(NetworkType.WIFI, NetworkType.CELLULAR, TransportState.Connected))
        assertTrue(isMeaningfulNetworkChange(NetworkType.WIFI, NetworkType.CELLULAR, TransportState.Reconnecting(1)))
    }

    @Test
    fun `a healthy connect-and-stay-connected sequence produces zero probe calls`() = runTest {
        val fakeProbe = FakeGatewayReachabilityProbe()
        val monitor = RestrictionMonitor(fakeProbe, backgroundScope)
        val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val networkProfile = MutableStateFlow(profile(NetworkType.WIFI, 1))

        monitor.start(transportState, networkProfile)
        runCurrent()

        transportState.value = TransportState.Connecting
        runCurrent()
        transportState.value = TransportState.Connected
        runCurrent()
        networkProfile.value = profile(NetworkType.WIFI, 2) // metered flag flip, same type
        runCurrent()

        assertEquals(0, fakeProbe.callCount)
        assertNull(monitor.lastProbeResult.value)
    }

    @Test
    fun `a real handshake failure triggers exactly one probe, and the result is published`() = runTest {
        val fakeProbe = FakeGatewayReachabilityProbe(result = true)
        val monitor = RestrictionMonitor(fakeProbe, backgroundScope)
        val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val networkProfile = MutableStateFlow(profile(NetworkType.WIFI, 1))

        monitor.start(transportState, networkProfile)
        runCurrent()

        transportState.value = TransportState.Connecting
        runCurrent()
        transportState.value = TransportState.HandshakeFailed
        runCurrent()

        assertEquals(1, fakeProbe.callCount)
        assertEquals(true, monitor.lastProbeResult.value)
    }

    @Test
    fun `an empty diverseProbes list stays byte-for-byte the same as before B8M - null result, gateway probe unaffected`() = runTest {
        val fakeProbe = FakeGatewayReachabilityProbe(result = true)
        val monitor = RestrictionMonitor(fakeProbe, backgroundScope) // no diverseProbes arg - default emptyList()
        val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val networkProfile = MutableStateFlow(profile(NetworkType.WIFI, 1))

        monitor.start(transportState, networkProfile)
        runCurrent()
        transportState.value = TransportState.HandshakeFailed
        runCurrent()

        assertEquals(1, fakeProbe.callCount)
        assertEquals(true, monitor.lastProbeResult.value)
        assertNull(monitor.lastDiverseReachabilityResult.value)
    }

    @Test
    fun `diverse probes run on the SAME trigger as the gateway probe and publish a real majority result`() = runTest {
        val fakeProbe = FakeGatewayReachabilityProbe(result = false)
        val diverseProbes = fakeDiverseProbes(true, true, false) // 2/3 reachable -> majority true
        val monitor = RestrictionMonitor(fakeProbe, backgroundScope, diverseProbes)
        val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val networkProfile = MutableStateFlow(profile(NetworkType.WIFI, 1))

        monitor.start(transportState, networkProfile)
        runCurrent()
        transportState.value = TransportState.HandshakeFailed
        runCurrent()

        assertEquals(1, fakeProbe.callCount)
        assertEquals(false, monitor.lastProbeResult.value)
        assertEquals(true, monitor.lastDiverseReachabilityResult.value)
        diverseProbes.forEach { assertEquals(1, (it as FakeGatewayReachabilityProbe).callCount) }
    }

    @Test
    fun `a healthy connect-and-stay-connected sequence triggers zero diverse probes either`() = runTest {
        val fakeProbe = FakeGatewayReachabilityProbe()
        val diverseProbes = fakeDiverseProbes(true, true, true)
        val monitor = RestrictionMonitor(fakeProbe, backgroundScope, diverseProbes)
        val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val networkProfile = MutableStateFlow(profile(NetworkType.WIFI, 1))

        monitor.start(transportState, networkProfile)
        runCurrent()
        transportState.value = TransportState.Connecting
        runCurrent()
        transportState.value = TransportState.Connected
        runCurrent()

        diverseProbes.forEach { assertEquals(0, (it as FakeGatewayReachabilityProbe).callCount) }
        assertNull(monitor.lastDiverseReachabilityResult.value)
    }

    @Test
    fun `stop cancels any in-flight probe and the observe loop, no further probing after stop`() = runTest {
        val fakeProbe = FakeGatewayReachabilityProbe()
        val monitor = RestrictionMonitor(fakeProbe, backgroundScope)
        val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val networkProfile = MutableStateFlow(profile(NetworkType.WIFI, 1))

        monitor.start(transportState, networkProfile)
        runCurrent()
        monitor.stop()

        transportState.value = TransportState.HandshakeFailed
        runCurrent()

        assertEquals(0, fakeProbe.callCount)
    }
}
