@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.ui.hasPendingRoutingPolicyChange
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.policy.AppRoutingMode
import net.pocvpn.client.vpn.policy.AppRoutingPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8H - narrow tests for how AppRoutingPolicy is wired into VpnController:
 * this feature's own required cases 1, 2, 6, 8, 9, 10, 11, 12
 * (3/4/5 are covered directly against resolveAppRoutingLists in
 * AppRoutingPolicyTest - these instead prove the SAME resolution actually
 * reaches transport.connect() end to end).
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    dnsServers = listOf("1.1.1.1", "1.0.0.1"),
    profile = AwgProfile.none(),
)

private fun lastAwgConfig(transport: FakeVpnTransport) = (transport.lastConfig as TransportConfig.Awg).config

class VpnControllerSplitTunnelingTest {

    @Test
    fun `no appRoutingPolicyStore wired - existing call sites - behaves exactly like ALL_APPS`() = runTest {
        val transport = FakeVpnTransport()
        // Deliberately the SAME constructor shape every pre-B8H test uses -
        // no appRoutingPolicyStore/installedPackageChecker argument at all.
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        val awg = lastAwgConfig(transport)
        assertTrue(awg.includedApplications.isEmpty())
        assertTrue(awg.excludedApplications.isEmpty())
    }

    @Test
    fun `ALL_APPS preserves the exact current full-tunnel DNS and AllowedIPs configuration`() = runTest {
        val transport = FakeVpnTransport()
        val store = FakeAppRoutingPolicyStore(AppRoutingPolicy(AppRoutingMode.ALL_APPS, setOf("stale.selection.ignored")))
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = store,
        )

        controller.connect()
        runCurrent()

        val awg = lastAwgConfig(transport)
        assertTrue(awg.includedApplications.isEmpty())
        assertTrue(awg.excludedApplications.isEmpty())
        assertEquals(listOf("1.1.1.1", "1.0.0.1"), awg.dnsServers)
        assertEquals(listOf("0.0.0.0/0", "::/0"), awg.peer.allowedIps)
    }

    @Test
    fun `BYPASS_SELECTED and VPN_ONLY_SELECTED reach transport connect as the correct disjoint list`() = runTest {
        val checker = FakeInstalledPackageChecker().apply { markInstalled("ru.bank.example") }

        val bypassTransport = FakeVpnTransport()
        val bypassController = VpnController(
            bypassTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = FakeAppRoutingPolicyStore(AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("ru.bank.example"))),
            installedPackageChecker = checker,
        )
        bypassController.connect()
        runCurrent()
        val bypassAwg = lastAwgConfig(bypassTransport)
        assertEquals(setOf("ru.bank.example"), bypassAwg.excludedApplications)
        assertTrue(bypassAwg.includedApplications.isEmpty())

        val vpnOnlyTransport = FakeVpnTransport()
        val vpnOnlyController = VpnController(
            vpnOnlyTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = FakeAppRoutingPolicyStore(AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("ru.bank.example"))),
            installedPackageChecker = checker,
        )
        vpnOnlyController.connect()
        runCurrent()
        val vpnOnlyAwg = lastAwgConfig(vpnOnlyTransport)
        assertEquals(setOf("ru.bank.example"), vpnOnlyAwg.includedApplications)
        assertTrue(vpnOnlyAwg.excludedApplications.isEmpty())
    }

    @Test
    fun `VPN_ONLY_SELECTED with zero installed apps fails safely without ever calling transport connect`() = runTest {
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            appRoutingPolicyStore = FakeAppRoutingPolicyStore(AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, emptySet())),
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(VpnError.SplitTunnelingNoAppsSelected, diagnostics.snapshot.value.lastError)
        assertEquals(0, transport.connectCallCount)
        assertNull(controller.appliedRoutingPolicy.value)
    }

    @Test
    fun `a stale uninstalled package in the selection is dropped, connect still succeeds`() = runTest {
        val transport = FakeVpnTransport()
        val checker = FakeInstalledPackageChecker().apply { markInstalled("com.still.installed") }
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = FakeAppRoutingPolicyStore(
                AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("com.still.installed", "com.long.uninstalled")),
            ),
            installedPackageChecker = checker,
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(setOf("com.still.installed"), lastAwgConfig(transport).excludedApplications)
    }

    @Test
    fun `changing the saved policy while connected does NOT rebuild the active tunnel`() = runTest {
        val transport = FakeVpnTransport()
        val checker = FakeInstalledPackageChecker().apply { markInstalled("com.bank.app") }
        val store = FakeAppRoutingPolicyStore(AppRoutingPolicy.Default)
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = store,
            installedPackageChecker = checker,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(1, transport.connectCallCount)
        assertEquals(AppRoutingPolicy.Default, controller.appliedRoutingPolicy.value)

        // The user opens Settings and saves a DIFFERENT policy while still connected.
        val newPolicy = AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("com.bank.app"))
        store.write(newPolicy)
        runCurrent()

        // B8G/B8H: no automatic rebuild - the active tunnel keeps running
        // whatever was actually applied at connect time.
        assertEquals(1, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(AppRoutingPolicy.Default, controller.appliedRoutingPolicy.value)
        assertTrue(hasPendingRoutingPolicyChange(controller.appliedRoutingPolicy.value, store.read()))
    }

    @Test
    fun `explicit disconnect then reconnect applies the newly saved policy`() = runTest {
        val transport = FakeVpnTransport()
        val checker = FakeInstalledPackageChecker().apply { markInstalled("com.bank.app") }
        val store = FakeAppRoutingPolicyStore(AppRoutingPolicy.Default)
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = store,
            installedPackageChecker = checker,
        )

        controller.connect()
        runCurrent()
        val newPolicy = AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("com.bank.app"))
        store.write(newPolicy)
        runCurrent()

        controller.disconnect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Disconnected)
        assertNull(controller.appliedRoutingPolicy.value)

        controller.connect()
        runCurrent()

        assertEquals(2, transport.connectCallCount)
        assertEquals(newPolicy, controller.appliedRoutingPolicy.value)
        assertEquals(setOf("com.bank.app"), lastAwgConfig(transport).excludedApplications)
        assertFalse(hasPendingRoutingPolicyChange(controller.appliedRoutingPolicy.value, store.read()))
    }

    @Test
    fun `automatic reconnect preserves the ALREADY-applied routing policy, never substitutes a newer saved one`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val checker = FakeInstalledPackageChecker().apply { markInstalled("com.bank.app") }
        val originalPolicy = AppRoutingPolicy(AppRoutingMode.BYPASS_SELECTED, setOf("com.bank.app"))
        val store = FakeAppRoutingPolicyStore(originalPolicy)
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            appRoutingPolicyStore = store,
            installedPackageChecker = checker,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(originalPolicy, controller.appliedRoutingPolicy.value)

        // Network drops; a real automatic reconnect cycle begins.
        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        // Mid-recovery, the user (or another session) saves a DIFFERENT
        // policy - it must NOT be picked up by this automatic cycle.
        store.write(AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("com.other.app")))
        reconnectManager.networkAvailable = true

        advanceTimeBy(45_000)
        runCurrent()

        // B8G1: recovery never re-calls transport.connect() at all - so it
        // is structurally impossible for it to have picked up the new
        // policy; appliedRoutingPolicy must still read the ORIGINAL one.
        assertEquals(1, transport.connectCallCount)
        assertEquals(originalPolicy, controller.appliedRoutingPolicy.value)
    }
}
