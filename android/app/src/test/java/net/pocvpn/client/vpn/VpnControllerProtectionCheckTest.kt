@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.smartconnect.TransportObservationStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.protection.TunnelLinkSnapshot
import net.pocvpn.client.vpn.protection.TunnelProtectionFinding
import net.pocvpn.client.vpn.protection.TunnelProtectionLog
import net.pocvpn.client.vpn.protection.TunnelProtectionStatus
import net.pocvpn.client.vpn.xray.XrayVlessRealityConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private val PROTECTION_TEST_XRAY_PROFILE = XrayProfile(
    server = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
    fingerprint = "chrome",
    realityPublicKey = "A".repeat(43),
    shortId = "a1b2c3d4",
)

private val protectionTestNetwork = NetworkProfile(
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

/**
 * B-WL7 layer 3a - once per Connected session VpnController reads the VPN
 * network, records the evaluation, and the recording never changes the
 * session (a suspected leak does not tear it down in this slice).
 */
class VpnControllerProtectionCheckTest {

    private class Harness(val controller: VpnController, val xray: FakeVpnTransport, val log: TunnelProtectionLog)

    private fun TestScope.harness(reader: suspend () -> TunnelLinkSnapshot?): Harness {
        val log = TunnelProtectionLog { testScheduler.currentTime }
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(
                GatewayConfiguration.Configured(
                    endpointHost = "203.0.113.10",
                    endpointPort = 51820,
                    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
                    clientTunnelIp = "10.77.0.2",
                    gatewayTunnelIp = "10.77.0.1",
                    allowedIps = listOf("0.0.0.0/0", "::/0"),
                    profile = AwgProfile.none(),
                ),
            ),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(PROTECTION_TEST_XRAY_PROFILE),
            transportObservationStore = TransportObservationStore(),
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { protectionTestNetwork },
            tunnelLinkReader = reader,
            tunnelProtectionLog = log,
        )
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        // Healthy, growing counters in both directions: the B-WL7 gate keeps the session.
        var polls = 0
        xray.dataPlaneProvider = { polls++; TransportStats.Counters(bytesReceived = polls * 500L, bytesSent = polls * 300L, lastHandshakeEpochMillis = null) }
        return Harness(controller, xray, log)
    }

    /** Connects and lets the first (delayed) read happen. */
    private suspend fun TestScope.connect(h: Harness) {
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
        runCurrent()
        advanceTimeBy(1_100)
        runCurrent()
    }

    @Test
    fun `a Connected session records one VERIFIED check for its transport`() = runTest {
        // The DNS the Xray service actually installs (its config's list), not VpnDnsPolicy's.
        val h = harness { TunnelLinkSnapshot(listOf("0.0.0.0/0"), XrayVlessRealityConfig.DEFAULT_DNS_SERVERS, false) }
        connect(h)
        val r = h.log.snapshot().single()
        assertEquals(TransportKind.XRAY_REALITY, r.transport)
        assertEquals(TunnelProtectionStatus.VERIFIED, r.result.status)
        assertEquals(1, r.reads)
    }

    @Test
    fun `an Xray session whose system DNS is not its own config's list is flagged`() = runTest {
        val h = harness { TunnelLinkSnapshot(listOf("0.0.0.0/0"), listOf("1.1.1.1", "1.0.0.1"), false) }
        connect(h)
        val r = h.log.snapshot().single()
        assertEquals(TunnelProtectionStatus.LEAK_SUSPECTED, r.result.status)
        assertEquals(listOf(TunnelProtectionFinding.DNS_SERVERS_UNEXPECTED), r.result.findings)
    }

    @Test
    fun `a suspected leak is recorded and the session stays Connected`() = runTest {
        val h = harness { TunnelLinkSnapshot(listOf("10.77.0.0/24"), listOf("192.168.1.1"), false) }
        connect(h)
        val r = h.log.snapshot().single()
        assertEquals(TunnelProtectionStatus.LEAK_SUSPECTED, r.result.status)
        assertTrue(TunnelProtectionFinding.IPV4_PUBLIC_NOT_COVERED in r.result.findings)
        assertTrue(h.controller.state.value is TransportState.Connected)
    }

    @Test
    fun `a late link snapshot is retried, and none at all is NOT_VERIFIABLE after the bounded reads`() = runTest {
        var calls = 0
        val late = harness { if (++calls < 2) null else TunnelLinkSnapshot(listOf("0.0.0.0/0"), XrayVlessRealityConfig.DEFAULT_DNS_SERVERS, false) }
        connect(late)
        advanceTimeBy(1_500)
        runCurrent()
        assertEquals(2, late.log.snapshot().single().reads)
        assertEquals(TunnelProtectionStatus.VERIFIED, late.log.snapshot().single().result.status)

        val never = harness { null }
        connect(never)
        advanceTimeBy(5_000)
        runCurrent()
        val r = never.log.snapshot().single()
        assertEquals(TunnelProtectionStatus.NOT_VERIFIABLE, r.result.status)
        assertEquals(3, r.reads)
    }

    @Test
    fun `a throwing reader is NOT_VERIFIABLE and never breaks the session`() = runTest {
        val h = harness { throw IllegalStateException("no ConnectivityManager") }
        connect(h)
        advanceTimeBy(5_000)
        runCurrent()
        assertEquals(TunnelProtectionStatus.NOT_VERIFIABLE, h.log.snapshot().single().result.status)
        assertTrue(h.controller.state.value is TransportState.Connected)
    }

    @Test
    fun `a disconnect before the system publishes the network records nothing`() = runTest {
        val h = harness { null }
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
        runCurrent()
        advanceTimeBy(1_500) // one empty read done, more pending
        runCurrent()
        h.controller.disconnect()
        runCurrent()
        advanceTimeBy(5_000)
        runCurrent()
        assertTrue(h.log.snapshot().isEmpty())
    }
}
