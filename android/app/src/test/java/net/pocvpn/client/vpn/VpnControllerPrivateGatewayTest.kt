@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B22 - proves the ONE new pinning mechanism (test list item 8: "correct
 * private snapshot reaches existing AmneziaWgTransport") end to end through
 * the REAL VpnController/AwgConfigMapper wiring, against the SAME
 * FakeVpnTransport/FakeClientKeyRepository fakes VpnControllerTest already
 * uses - no second test harness. Also proves items 1/6/9's VpnController-
 * level facet: a Resolution with no privateKeyRepository (every AUTO/
 * MANUAL_MANAGED resolution, unconditionally) is byte-for-byte unaffected -
 * see [not carrying a private key repository is unaffected] below.
 */
class VpnControllerPrivateGatewayTest {

    private fun privateSnapshot() = GatewayConfigSnapshot(
        endpointHost = "203.0.113.77",
        endpointPort = "51820",
        serverPublicKey = "zK3h+3F0K1cZ8v3nQyN2b0aXG5Q3vJ2c1sE6dT8pR3o=",
        clientTunnelIp = "10.99.0.2",
        gatewayTunnelIp = "10.99.0.1",
        allowedIps = "",
        profile = AwgProfile(
            initPacketMagicHeader = "1111111111",
            responsePacketMagicHeader = "2222222222",
            underloadPacketMagicHeader = "3333333333",
            transportPacketMagicHeader = "4444444444",
        ),
    )

    @Test
    fun `a resolution carrying a private key repository builds AwgConfig from the private snapshot and private key, not the managed defaults`() = runTest {
        val transport = FakeVpnTransport()
        val managedKeyRepository = FakeClientKeyRepository(privateKey = "MANAGED_PRIVATE_KEY==", publicKey = "MANAGED_PUBLIC_KEY==")
        val privateGatewayKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_GATEWAY_PRIVATE_KEY==", publicKey = "PRIVATE_GATEWAY_PUBLIC_KEY==")
        // Managed config repository deliberately returns a DIFFERENT config
        // than the private snapshot - if this leaked through, the assertions
        // below would catch it immediately.
        val managedConfigRepository = FakeGatewayConfigurationRepository(
            GatewayConfiguration.Configured(
                endpointHost = "managed.example.invalid",
                endpointPort = 12345,
                serverPublicKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                clientTunnelIp = "10.1.1.1",
                gatewayTunnelIp = "10.1.1.254",
                allowedIps = listOf("0.0.0.0/0"),
                profile = AwgProfile.none(),
            ),
        )
        val controller = VpnController(
            transport, managedKeyRepository, managedConfigRepository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        val resolved = TransportOrchestrator.Resolution.Resolved(
            transport = transport,
            kind = transport.kind,
            gatewayConfigSnapshot = privateSnapshot(),
            privateKeyRepository = privateGatewayKeyRepository,
        )
        controller.connect(resolved)
        runCurrent()

        assertEquals(1, transport.connectCallCount)
        // The managed repository must never have been consulted at all for
        // a pinned private-gateway attempt.
        assertEquals(0, managedConfigRepository.getCallCount)

        val awgConfig = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("PRIVATE_GATEWAY_PRIVATE_KEY==", awgConfig.privateKeyBase64)
        assertEquals("zK3h+3F0K1cZ8v3nQyN2b0aXG5Q3vJ2c1sE6dT8pR3o=", awgConfig.peer.publicKeyBase64)
        assertEquals("203.0.113.77", awgConfig.peer.endpointHost)
        assertEquals(51820, awgConfig.peer.endpointPort)
        assertEquals(listOf("10.99.0.2/32"), awgConfig.localAddresses)
        assertEquals("1111111111", awgConfig.profile.initPacketMagicHeader)
    }

    @Test
    fun `a resolution with no private key repository is unaffected - uses the managed clientKeyRepository exactly as before B22`() = runTest {
        val transport = FakeVpnTransport()
        val managedKeyRepository = FakeClientKeyRepository(privateKey = "MANAGED_PRIVATE_KEY==")
        val managedConfigRepository = FakeGatewayConfigurationRepository(
            GatewayConfiguration.Configured(
                endpointHost = "managed.example.invalid",
                endpointPort = 51820,
                serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
                clientTunnelIp = "10.1.1.1",
                gatewayTunnelIp = "10.1.1.254",
                allowedIps = listOf("0.0.0.0/0"),
                profile = AwgProfile.none(),
            ),
        )
        val controller = VpnController(
            transport, managedKeyRepository, managedConfigRepository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        // Byte-for-byte the pre-B22 manual-mode call shape - no Resolution override at all.
        controller.connect()
        runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertEquals(1, managedConfigRepository.getCallCount)
        val awgConfig = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("MANAGED_PRIVATE_KEY==", awgConfig.privateKeyBase64)
        assertEquals("managed.example.invalid", awgConfig.peer.endpointHost)
    }

    @Test
    fun `the pinned private key repository does not leak into the next unrelated connect attempt`() = runTest {
        val transport = FakeVpnTransport()
        val managedKeyRepository = FakeClientKeyRepository(privateKey = "MANAGED_PRIVATE_KEY==")
        val privateGatewayKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_GATEWAY_PRIVATE_KEY==")
        val managedConfigRepository = FakeGatewayConfigurationRepository(
            GatewayConfiguration.Configured(
                endpointHost = "managed.example.invalid",
                endpointPort = 51820,
                serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
                clientTunnelIp = "10.1.1.1",
                gatewayTunnelIp = "10.1.1.254",
                allowedIps = listOf("0.0.0.0/0"),
                profile = AwgProfile.none(),
            ),
        )
        val controller = VpnController(
            transport, managedKeyRepository, managedConfigRepository,
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                transport = transport,
                kind = transport.kind,
                gatewayConfigSnapshot = privateSnapshot(),
                privateKeyRepository = privateGatewayKeyRepository,
            ),
        )
        runCurrent()
        controller.disconnect()
        runCurrent()

        // A later plain connect() (no override at all) must fall back to the
        // managed identity again - the pinned private repository must not
        // linger past the attempt/session it belonged to.
        controller.connect()
        runCurrent()

        val awgConfig = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("MANAGED_PRIVATE_KEY==", awgConfig.privateKeyBase64)
    }
}
