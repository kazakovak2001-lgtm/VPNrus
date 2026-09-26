@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.activation.ActivationPackageFixtures
import net.pocvpn.client.activation.ActivationPackageRejectionKind
import net.pocvpn.client.activation.ActivationPackageUiState
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * B67.3 - proves the ONE real, previously-untested lifecycle/authority
 * invariant this slice's audit found: a server-side rejection of the
 * envelope's own carried [net.pocvpn.client.activation.ActivationCredential]
 * (revoked/expired/etc. - the SAME AUTHORIZATION_REJECTED taxonomy the raw
 * credential path already uses, see B30's ActivationResilienceCoordinatorTest)
 * is authoritative over a locally-valid [net.pocvpn.client.activation
 * .ActivationEnvelope], through the REAL `MainViewModel.activateDevice()` ->
 * `ActivationResilienceCoordinator` mapping this codebase actually runs -
 * not a stand-in `activate` lambda (see [ActivationPackageRedeemerTest] for
 * that narrower, already-existing coverage of the redeemer's OWN state
 * machine in isolation).
 *
 * Also proves there is no second authorization engine: the raw-credential
 * path and the package-redeemed path reach the identical
 * `activationClient`/`activationResilienceCoordinator` call for the SAME
 * underlying credential value, and produce the SAME terminal outcome.
 */
class MainViewModelActivationPackageAuthorityTest {

    private val testDispatcher = StandardTestDispatcher()

    @get:Rule val tmp = TemporaryFolder()
    private lateinit var fixtures: ActivationPackageFixtures

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        fixtures = ActivationPackageFixtures(tmp.newFolder())
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newViewModel(activationResult: ProvisioningResult): MainViewModel {
        val calls = mutableListOf<String>()
        return MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            activationClient = { _, _, cred -> calls += cred; activationResult },
            nowProvider = { fixtures.now },
            activationPackageImporter = fixtures.importer(),
            ioDispatcher = testDispatcher,
        )
    }

    @Test
    fun `server-side rejection of a locally-valid envelope's credential is authoritative - package activation fails closed`() = runTest {
        val viewModel = newViewModel(ProvisioningResult.Revoked)
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete

        viewModel.importActivationPackage(fixtures.packageText())
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(ActivationPackageUiState.ActivationFailed, viewModel.activationPackageState.value)
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Revoked)
    }

    @Test
    fun `a revoked credential never gets locally marked redeemed - the same package can still be re-attempted`() = runTest {
        val viewModel = newViewModel(ProvisioningResult.Revoked)
        testDispatcher.scheduler.runCurrent()

        val packageText = fixtures.packageText()
        viewModel.importActivationPackage(packageText)
        testDispatcher.scheduler.advanceUntilIdle()
        assertEquals(ActivationPackageUiState.ActivationFailed, viewModel.activationPackageState.value)

        // A second import of the EXACT SAME package must reach the network
        // again (never ALREADY_REDEEMED) - a server-side rejection is never
        // conflated with "this envelope was already successfully used",
        // since markRedeemed() is only ever called after a real success.
        viewModel.importActivationPackage(packageText)
        testDispatcher.scheduler.advanceUntilIdle()

        assertFalse(viewModel.activationPackageState.value == ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.ALREADY_REDEEMED))
        assertEquals(ActivationPackageUiState.ActivationFailed, viewModel.activationPackageState.value)
    }

    @Test
    fun `raw credential and package-redeemed credential reach the same single activation engine for the same rejection`() = runTest {
        val rawCalls = mutableListOf<String>()
        val rawViewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            activationClient = { _, _, cred -> rawCalls += cred; ProvisioningResult.Revoked },
            nowProvider = { fixtures.now },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()
        rawViewModel.activateDevice(fixtures.credential)
        testDispatcher.scheduler.runCurrent()

        val packageCalls = mutableListOf<String>()
        val packageViewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            activationClient = { _, _, cred -> packageCalls += cred; ProvisioningResult.Revoked },
            nowProvider = { fixtures.now },
            activationPackageImporter = fixtures.importer(),
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()
        packageViewModel.importActivationPackage(fixtures.packageText())
        testDispatcher.scheduler.advanceUntilIdle()

        // Same underlying credential value reached the same activationClient
        // seam exactly once each - never a second, package-specific
        // authorization path, and never more than one attempt (bounded).
        assertEquals(listOf(fixtures.credential), rawCalls)
        assertEquals(listOf(fixtures.credential), packageCalls)
        assertTrue(rawViewModel.provisioningState.value is ProvisioningUiState.Revoked)
        assertTrue(packageViewModel.provisioningState.value is ProvisioningUiState.Revoked)
    }
}
