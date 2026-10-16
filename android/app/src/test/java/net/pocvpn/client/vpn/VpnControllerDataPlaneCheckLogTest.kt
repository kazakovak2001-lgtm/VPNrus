@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.smartconnect.DataPlaneCheckLog
import net.pocvpn.client.smartconnect.DataPlaneCheckStatus
import net.pocvpn.client.smartconnect.TrafficProgressCheckEnd
import net.pocvpn.client.smartconnect.TrafficProgressVerdict
import net.pocvpn.client.smartconnect.TransportObservationStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private val LOG_TEST_XRAY_PROFILE = XrayProfile(
    server = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
    fingerprint = "chrome",
    realityPublicKey = "A".repeat(43),
    shortId = "a1b2c3d4",
)

private val logTestNetwork = NetworkProfile(
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
 * B-WL7 report - VpnController writes every post-connect data-plane check into
 * the DataPlaneCheckLog the field report reads, independently of logcat, and
 * the recording never changes the check's own outcome.
 */
class VpnControllerDataPlaneCheckLogTest {

    private class Harness(val controller: VpnController, val xray: FakeVpnTransport, val diagnostics: DiagnosticsStore, val log: DataPlaneCheckLog)

    private fun TestScope.connectXray(log: DataPlaneCheckLog = DataPlaneCheckLog { testScheduler.currentTime }, dataPlane: (Int) -> TransportStats): Harness {
        val diagnostics = DiagnosticsStore()
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
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(LOG_TEST_XRAY_PROFILE),
            transportObservationStore = TransportObservationStore(),
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { logTestNetwork },
            dataPlaneCheckLog = log,
        )
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        var polls = 0
        xray.dataPlaneProvider = { polls++; dataPlane(polls) }
        return Harness(controller, xray, diagnostics, log)
    }

    private suspend fun TestScope.start(h: Harness) {
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
        runCurrent()
    }

    private val txOnly: (Int) -> TransportStats = { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }

    @Test
    fun `a running check is visible as RUNNING and completes with the same fields the log line reports`() = runTest {
        val h = connectXray(dataPlane = txOnly)
        start(h)
        advanceTimeBy(30_000)
        runCurrent()
        val running = h.log.snapshot().single()
        assertEquals(DataPlaneCheckStatus.RUNNING, running.status)
        assertEquals(TransportKind.XRAY_REALITY, running.transport)
        assertEquals(65_000L, running.stallWindowMs)
        assertEquals(150, running.maxPolls)

        advanceTimeBy(36_000) // past index 130 = 65_000ms
        runCurrent()
        val done = h.log.snapshot().single()
        assertEquals(running.checkId, done.checkId)
        assertEquals(DataPlaneCheckStatus.COMPLETED, done.status)
        assertEquals(TrafficProgressVerdict.NO_PAYLOAD, done.verdict)
        assertEquals(TrafficProgressCheckEnd.DECISIVE_VERDICT, done.end)
        assertEquals(65_000L, done.silentForMs)
        assertEquals(131, done.samples)
        assertEquals(131, done.polls)
        assertEquals(10_000L, done.verificationWindowMs)
        // Recording did not change the outcome: the dead data plane still ends the session.
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `a user disconnect during the window records CANCELLED with no end and no teardown verdict`() = runTest {
        val h = connectXray(dataPlane = txOnly)
        start(h)
        advanceTimeBy(5_000)
        runCurrent()
        h.controller.disconnect()
        runCurrent()
        advanceTimeBy(76_000)
        runCurrent()

        val r = h.log.snapshot().single()
        assertEquals(DataPlaneCheckStatus.CANCELLED, r.status)
        assertEquals(TrafficProgressVerdict.VERIFYING, r.verdict)
        assertNull(r.end)
        assertTrue("cancelled within the window: ${r.polls}", r.polls in 1..12)
        assertTrue(h.controller.state.value is TransportState.Disconnected)
    }

    @Test
    fun `unsupported counters complete at once with COUNTERS_UNSUPPORTED`() = runTest {
        val h = connectXray { _ -> TransportStats.Unsupported }
        start(h)
        val r = h.log.snapshot().single()
        assertEquals(DataPlaneCheckStatus.COMPLETED, r.status)
        assertEquals(TrafficProgressCheckEnd.COUNTERS_UNSUPPORTED, r.end)
        assertEquals(0, r.samples)
        assertEquals(1, r.polls)
        assertNull(r.silentForMs)
    }

    @Test
    fun `a new session gets its own record - the cancelled earlier check is never reused`() = runTest {
        val log = DataPlaneCheckLog { testScheduler.currentTime }
        val first = connectXray(log, txOnly)
        start(first)
        advanceTimeBy(5_000)
        runCurrent()
        first.controller.disconnect()
        runCurrent()

        val healthy = connectXray(log) { n -> TransportStats.Counters(bytesReceived = n * 100L, bytesSent = n * 50L, lastHandshakeEpochMillis = null) }
        start(healthy)
        advanceTimeBy(11_000)
        runCurrent()

        val (old, new) = log.snapshot()
        assertTrue(new.checkId > old.checkId)
        assertEquals(DataPlaneCheckStatus.CANCELLED, old.status)
        assertEquals(DataPlaneCheckStatus.COMPLETED, new.status)
        assertEquals(TrafficProgressVerdict.VERIFIED, new.verdict)
        assertTrue(healthy.controller.state.value is TransportState.Connected)
    }

    @Test
    fun `a controller without a log behaves exactly as before`() = runTest {
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(
                GatewayConfiguration.Configured(
                    endpointHost = "203.0.113.10", endpointPort = 51820,
                    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
                    clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
                    allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
                ),
            ),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(LOG_TEST_XRAY_PROFILE),
            networkProfileProvider = { logTestNetwork },
        )
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        var n = 0
        xray.dataPlaneProvider = { n++; txOnly(n) }
        controller.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY))
        runCurrent()
        advanceTimeBy(66_000)
        runCurrent()
        assertEquals(VpnError.DataPlaneNoTraffic, diagnostics.snapshot.value.lastError)
    }
}
