@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.smartconnect.AttemptStageOutcome
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.TransportAttemptProtocol
import net.pocvpn.client.smartconnect.TransportObservationStore
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL1 - proves VpnController writes real, authoritative connect-outcome
 * evidence into TransportObservationStore, network-scoped, from the SAME
 * authoritative call sites [VpnControllerPathHistoryTest] already proves for
 * PathHistoryStore - never a second, independently-timed writer.
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val fakeUsableNetworkProfile = NetworkProfile(
    type = NetworkType.WIFI,
    validatedInternet = true,
    metered = false,
    roaming = false,
    captivePortal = false,
    ipv4Available = true,
    ipv6Available = false,
    vpnActive = false,
    generation = 1,
    dnsServerAddresses = listOf("1.1.1.1"),
)

class VpnControllerTransportObservationTest {

    private fun newController(
        transport: FakeVpnTransport,
        transportObservationStore: TransportObservationStore?,
        gateway: GatewayConfiguration = configuredGateway(),
        scope: kotlinx.coroutines.CoroutineScope,
    ) = VpnController(
        transport, FakeClientKeyRepository(),
        FakeGatewayConfigurationRepository(gateway),
        FakeReconnectManager(), DiagnosticsStore(), scope,
        transportObservationStore = transportObservationStore,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        networkProfileProvider = { fakeUsableNetworkProfile },
    )

    private fun fingerprintFor(profile: NetworkProfile) = net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
        net.pocvpn.client.reachability.CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
        byteArrayOf(1, 2, 3, 4),
    )

    @Test
    fun `a real fresh handshake records exactly one observation, scoped to this network, as a real UDP success`() = runTest {
        val transport = FakeVpnTransport()
        val store = TransportObservationStore()
        val controller = newController(transport, store, scope = backgroundScope)

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        val fingerprint = fingerprintFor(fakeUsableNetworkProfile)
        val recorded = store.recent(fingerprint)
        assertEquals(1, recorded.size)
        val observation = recorded.single()
        assertEquals(ProductionGateway.ID, observation.destinationKey)
        assertEquals(TransportAttemptProtocol.UDP, observation.protocol)
        assertEquals(AttemptStageOutcome.SUCCEEDED, observation.handshake)
    }

    @Test
    fun `a handshake timeout records exactly one FAILED-handshake observation`() = runTest {
        val transport = FakeVpnTransport()
        transport.handshakeAvailable = false
        val store = TransportObservationStore()
        val controller = newController(transport, store, scope = backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(10_000)
        runCurrent()

        val fingerprint = fingerprintFor(fakeUsableNetworkProfile)
        val recorded = store.recent(fingerprint)
        assertEquals(1, recorded.size)
        assertEquals(AttemptStageOutcome.FAILED, recorded.single().handshake)
    }

    @Test
    fun `an observation for one network is never returned for a different network's read`() = runTest {
        val transport = FakeVpnTransport()
        val store = TransportObservationStore()
        val controller = newController(transport, store, scope = backgroundScope)

        controller.connect()
        runCurrent()

        val otherFingerprint = net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
            net.pocvpn.client.reachability.CoarseNetworkSignals(NetworkType.CELLULAR, listOf("8.8.8.8")),
            byteArrayOf(1, 2, 3, 4),
        )
        assertTrue(store.recent(otherFingerprint).isEmpty())
    }

    @Test
    fun `no transportObservationStore wired records nothing - purely additive, no crash`() = runTest {
        val transport = FakeVpnTransport()
        val controller = newController(transport, transportObservationStore = null, scope = backgroundScope)

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
    }
}
