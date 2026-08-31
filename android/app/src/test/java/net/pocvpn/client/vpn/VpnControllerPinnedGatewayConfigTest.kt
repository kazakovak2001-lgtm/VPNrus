@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B16 consolidated review fix (Blocker 1) - proves the "Candidate identity"
 * hard invariant this repository's own docs specify: an automatic-gateway-
 * selection candidate's already-resolved GatewayConfigSnapshot is EXECUTED
 * verbatim (never reconstructed from GatewayConfigurationRepository/
 * SelectedGatewayStore/ClientTunnelIdentityStore after the attempt starts).
 * These are VpnController-level tests (not MainViewModel-level) because the
 * invariant is enforced entirely inside VpnController.connect()/
 * doConnectAttempt()/onVpnPermissionResult() - see
 * TransportOrchestrator.Resolution.Resolved.gatewayConfigSnapshot's own docs.
 */
private fun repositoryGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.9",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private fun pinnedSnapshot(host: String, clientTunnelIp: String) = GatewayConfigSnapshot(
    endpointHost = host,
    endpointPort = "51820",
    serverPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
    clientTunnelIp = clientTunnelIp,
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = "",
    profile = AwgProfile.none(),
)

class VpnControllerPinnedGatewayConfigTest {

    @Test
    fun `pinned candidate snapshot is executed - never the repository's own value`() = runTest {
        val transport = FakeVpnTransport()
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        val pinned = pinnedSnapshot(host = "16.170.208.231", clientTunnelIp = "10.77.0.2")

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("stockholm"), pinned))
        runCurrent()

        val sent = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("16.170.208.231", sent.peer.endpointHost)
        assertEquals(listOf("10.77.0.2/32"), sent.localAddresses)
        // The repository was never consulted at all for this attempt - not
        // merely "consulted but ignored".
        assertEquals(0, repository.getCallCount)
    }

    @Test
    fun `mutating the repository after connect() cannot change an in-flight pinned attempt`() = runTest {
        val transport = FakeVpnTransport()
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        val pinned = pinnedSnapshot(host = "16.170.208.231", clientTunnelIp = "10.77.0.2")

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("stockholm"), pinned))
        runCurrent()

        // Simulate the underlying selected-gateway/client-identity source
        // changing AFTER this attempt already resolved and connected.
        repository.set(
            repositoryGateway().copy(endpointHost = "152.70.43.1", clientTunnelIp = "10.77.0.5"),
        )
        runCurrent()

        val sent = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("still the pinned candidate's own host", "16.170.208.231", sent.peer.endpointHost)
        assertEquals(listOf("10.77.0.2/32"), sent.localAddresses)
        assertEquals(0, repository.getCallCount)
    }

    @Test
    fun `permission-resume path executes the same pinned candidate config the initial request resolved`() = runTest {
        val transport = FakeVpnTransport(permission = Intent())
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        val pinned = pinnedSnapshot(host = "16.170.208.231", clientTunnelIp = "10.77.0.2")

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("stockholm"), pinned))
        runCurrent()
        // Permission required - no real attempt executed yet.
        assertEquals(0, transport.connectCallCount)

        // A mutation in the gap between the initial request and the
        // permission result arriving must never leak into the resumed attempt.
        repository.set(repositoryGateway().copy(endpointHost = "152.70.43.1", clientTunnelIp = "10.77.0.5"))

        controller.onVpnPermissionResult(true)
        runCurrent()

        assertEquals(1, transport.connectCallCount)
        val sent = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("16.170.208.231", sent.peer.endpointHost)
        assertEquals(listOf("10.77.0.2/32"), sent.localAddresses)
        assertEquals(0, repository.getCallCount)
    }

    @Test
    fun `gatewayStatus reflects the pinned candidate config while it is active`() = runTest {
        val transport = FakeVpnTransport()
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        val pinned = pinnedSnapshot(host = "16.170.208.231", clientTunnelIp = "10.77.0.2")

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("stockholm"), pinned))
        runCurrent()

        val status = controller.gatewayStatus() as GatewayConfiguration.Configured
        assertEquals("16.170.208.231", status.endpointHost)
        assertEquals(0, repository.getCallCount)
    }

    @Test
    fun `disconnect clears the pinned config - a later status read falls back to the repository`() = runTest {
        val transport = FakeVpnTransport()
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        val pinned = pinnedSnapshot(host = "16.170.208.231", clientTunnelIp = "10.77.0.2")
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("stockholm"), pinned))
        runCurrent()

        controller.disconnect()
        runCurrent()

        val status = controller.gatewayStatus() as GatewayConfiguration.Configured
        assertEquals(repositoryGateway().endpointHost, status.endpointHost)
        assertEquals(1, repository.getCallCount)
    }

    @Test
    fun `manual mode (no pinned snapshot) still reads the repository fresh - unchanged`() = runTest {
        val transport = FakeVpnTransport()
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("frankfurt")))
        runCurrent()

        val sent = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals(repositoryGateway().endpointHost, sent.peer.endpointHost)
        assertTrue(repository.getCallCount >= 1)
    }

    @Test
    fun `a second connect() for a different candidate uses ONLY that candidate's own pinned snapshot`() = runTest {
        val transport = FakeVpnTransport()
        val repository = FakeGatewayConfigurationRepository(repositoryGateway())
        val controller = VpnController(
            transport, FakeClientKeyRepository(), repository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        val germany = pinnedSnapshot(host = "152.70.43.1", clientTunnelIp = "10.77.0.5")
        val stockholm = pinnedSnapshot(host = "16.170.208.231", clientTunnelIp = "10.77.0.2")

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("frankfurt"), germany))
        runCurrent()
        controller.disconnect()
        runCurrent()

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, EndpointId("stockholm"), stockholm))
        runCurrent()

        val sent = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("16.170.208.231", sent.peer.endpointHost)
        assertEquals(listOf("10.77.0.2/32"), sent.localAddresses)
    }
}
