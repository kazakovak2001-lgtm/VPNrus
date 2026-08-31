@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.ui.AppScreen
import net.pocvpn.client.ui.screenFor
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.PersistedProfile
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.ProfileSource
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * B13 THIRD consolidated review fix (finding 1) - a structurally valid
 * PersistedProfile must NOT unlock Home unless it is ALSO accepted by the
 * SAME canonical authority the real connect path uses: it must
 * unambiguously match a known catalog gateway
 * (ProductionGatewayCatalog.matchGatewayId) AND this device must actually
 * be provisioned for that exact gateway (isGatewayProvisioned -
 * ClientTunnelIdentityStore). Anything short of both leaves
 * ProfileSource at its DEV_FALLBACK default, routing to Activation - never
 * a fabricated/migrated identity.
 */
class MainViewModelRestoredProfileAuthorityTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun germanyProfile(clientTunnelIp: String = "10.77.0.5") = PersistedProfile(
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        clientTunnelIp = clientTunnelIp,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
    )

    private fun newViewModel(
        profile: PersistedProfile?,
        identity: FakeClientTunnelIdentityStore? = null,
        folderName: String,
    ): MainViewModel {
        val profileStore = FileProfileStore(tmp.newFolder(folderName))
        if (profile != null) profileStore.write(profile)
        return MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            profileStore = profileStore,
            clientTunnelIdentityStore = identity,
        )
    }

    @Test
    fun `a valid Germany legacy profile on a device actually provisioned for Germany restores to Home`() = runTest {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5"))
        val viewModel = newViewModel(germanyProfile(), identity, "germany-provisioned")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.RESTORED_PERSISTED, viewModel.profileSource.value)
        assertEquals(AppScreen.HOME, screenFor(viewModel.profileSource.value))
    }

    @Test
    fun `a structurally valid profile for an unknown endpoint never unlocks Home`() = runTest {
        val unknown = PersistedProfile(
            endpointHost = "203.0.113.9",
            endpointPort = 51820,
            gatewayPublicKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
            clientTunnelIp = "10.77.0.5",
            gatewayTunnelIp = "10.77.0.1",
        )
        val viewModel = newViewModel(unknown, identity = null, folderName = "unknown-endpoint")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.DEV_FALLBACK, viewModel.profileSource.value)
        assertEquals(AppScreen.ACTIVATION, screenFor(viewModel.profileSource.value))
    }

    @Test
    fun `correct host but a wrong key never unlocks Home`() = runTest {
        val wrongKey = germanyProfile().copy(gatewayPublicKey = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64)
        val viewModel = newViewModel(wrongKey, identity = null, folderName = "wrong-key")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.DEV_FALLBACK, viewModel.profileSource.value)
        assertEquals(AppScreen.ACTIVATION, screenFor(viewModel.profileSource.value))
    }

    @Test
    fun `correct host and key but a wrong port never unlocks Home`() = runTest {
        val wrongPort = germanyProfile().copy(endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort + 1)
        val viewModel = newViewModel(wrongPort, identity = null, folderName = "wrong-port")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.DEV_FALLBACK, viewModel.profileSource.value)
        assertEquals(AppScreen.ACTIVATION, screenFor(viewModel.profileSource.value))
    }

    @Test
    fun `a corrupt persisted profile never unlocks Home`() = runTest {
        val directory = tmp.newFolder("corrupt-profile")
        java.io.File(directory, "provisioned_profile.bin").writeBytes(byteArrayOf(1, 2, 3, 4, 5))
        val profileStore = net.pocvpn.client.vpn.config.FileProfileStore(directory)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            profileStore = profileStore,
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.DEV_FALLBACK, viewModel.profileSource.value)
        assertEquals(AppScreen.ACTIVATION, screenFor(viewModel.profileSource.value))
    }

    @Test
    fun `a Germany-matching profile on a device NOT provisioned for Germany never unlocks Home - the real B13 gap`() = runTest {
        // The profile itself is structurally perfect and matches Germany's
        // real facts exactly - but ClientTunnelIdentityStore has no entry
        // for Germany on THIS device (e.g. migration never ran, or ran
        // against a different profile). The canonical connect-time
        // authority (SelectedProductionGatewaySource) would resolve this to
        // Invalid, so Home must not be unlocked either.
        val identity = FakeClientTunnelIdentityStore() // empty - nothing provisioned
        val viewModel = newViewModel(germanyProfile(), identity, "not-provisioned")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.DEV_FALLBACK, viewModel.profileSource.value)
        assertEquals(AppScreen.ACTIVATION, screenFor(viewModel.profileSource.value))
    }

    @Test
    fun `a Germany-matching profile on a device provisioned for Stockholm only never unlocks Home`() = runTest {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.STOCKHOLM to "10.77.0.2"))
        val viewModel = newViewModel(germanyProfile(), identity, "provisioned-other-endpoint")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.DEV_FALLBACK, viewModel.profileSource.value)
    }
}
