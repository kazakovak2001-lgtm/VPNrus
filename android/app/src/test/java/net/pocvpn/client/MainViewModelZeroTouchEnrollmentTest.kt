@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.FieldCredential
import net.pocvpn.client.provisioning.FieldCredentialStore
import net.pocvpn.client.provisioning.FieldEnrollmentResult
import net.pocvpn.client.provisioning.InMemoryFieldCredentialStore
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.PersistedProfile
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Russia field-test zero-touch enrollment - [MainViewModel.ensureZeroTouchEnrollment]
 * (called from connect()). Covers test requirements #1-3, #7-9, #15 from the
 * zero-touch enrollment task: fresh device has no credential, Connect
 * triggers enrollment automatically, disabled/cap-reached/revoked fail
 * closed, no activation UI/prompt is ever driven by this path.
 */
class MainViewModelZeroTouchEnrollmentTest {

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

    private fun germanyMatchingActivateSuccess(clientTunnelIp: String = "10.77.0.5") = ProvisioningResult.Success(
        clientTunnelIp = clientTunnelIp,
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    private fun newViewModel(
        fieldEnrollmentClient: (publicKey: String, endpointHost: String) -> FieldEnrollmentResult,
        fieldCredentialStore: FieldCredentialStore = InMemoryFieldCredentialStore(),
        zeroTouchEnrollmentEnabled: Boolean = true,
        activateResult: ProvisioningResult = germanyMatchingActivateSuccess(),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        activationClient = { _, _, _ -> activateResult },
        stockholmActivationClient = { _, _, _ -> activateResult },
        ioDispatcher = testDispatcher,
        fieldEnrollmentClient = fieldEnrollmentClient,
        fieldCredentialStore = fieldCredentialStore,
        zeroTouchEnrollmentEnabled = zeroTouchEnrollmentEnabled,
    )

    private fun fieldEnrollSuccess(credential: String = "device-specific-credential") = FieldEnrollmentResult.Success(
        activationCredential = credential,
        clientTunnelIp = "10.77.0.5",
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    // --- #1/#2: fresh install has no credential; Connect triggers enrollment automatically ---

    @Test
    fun `fresh device with zero-touch enabled calls field-enroll automatically and succeeds`() = runTest {
        var callCount = 0
        val credentialStore = InMemoryFieldCredentialStore()
        val viewModel = newViewModel(
            fieldEnrollmentClient = { _, _ -> callCount++; fieldEnrollSuccess() },
            fieldCredentialStore = credentialStore,
        )
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete

        val proceed = viewModel.ensureZeroTouchEnrollment()
        testDispatcher.scheduler.runCurrent()

        assertTrue(proceed)
        assertEquals(1, callCount)
        assertEquals("device-specific-credential", credentialStore.getOrNull()?.credential)
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
    }

    @Test
    fun `zero-touch disabled is a complete no-op - field-enroll is never called`() = runTest {
        var callCount = 0
        val viewModel = newViewModel(
            fieldEnrollmentClient = { _, _ -> callCount++; fieldEnrollSuccess() },
            zeroTouchEnrollmentEnabled = false,
        )
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()

        assertTrue(proceed)
        assertEquals(0, callCount)
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Idle)
    }

    @Test
    fun `an already-provisioned device never calls field-enroll again`() = runTest {
        var callCount = 0
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5"))
        val profileStore = FileProfileStore(tmp.newFolder("already-provisioned")).apply {
            write(
                PersistedProfile(
                    endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
                    endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
                    gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
                    clientTunnelIp = "10.77.0.5",
                    gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
                ),
            )
        }
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            profileStore = profileStore,
            selectedGatewayStore = FakeSelectedGatewayStore(),
            ioDispatcher = testDispatcher,
            fieldEnrollmentClient = { _, _ -> callCount++; fieldEnrollSuccess() },
            zeroTouchEnrollmentEnabled = true,
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(net.pocvpn.client.vpn.config.ProfileSource.RESTORED_PERSISTED, viewModel.profileSource.value)
        val proceed = viewModel.ensureZeroTouchEnrollment()

        assertTrue(proceed)
        assertEquals(0, callCount)
    }

    // --- reuse a previously-stored credential without calling field-enroll again ---

    @Test
    fun `a previously stored credential is reused - field-enroll is not called again`() = runTest {
        var callCount = 0
        val credentialStore = InMemoryFieldCredentialStore()
        credentialStore.save(FieldCredential("already-stored", ProductionGatewayCatalog.GERMANY.awg.endpointHost))
        val viewModel = newViewModel(
            fieldEnrollmentClient = { _, _ -> callCount++; fieldEnrollSuccess() },
            fieldCredentialStore = credentialStore,
        )
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()
        testDispatcher.scheduler.runCurrent()

        assertTrue(proceed)
        assertEquals(0, callCount)
    }

    // --- #7/#8/#9/#15: fail-closed cases, no activation UI is ever shown ---

    @Test
    fun `field enrollment disabled server-side (ServiceUnavailable) fails closed with a simple error state`() = runTest {
        val viewModel = newViewModel(fieldEnrollmentClient = { _, _ -> FieldEnrollmentResult.ServiceUnavailable })
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()

        assertFalse(proceed)
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
        assertNull(viewModel.relayActivationNeeded.value)
    }

    @Test
    fun `device cap reached fails closed`() = runTest {
        val viewModel = newViewModel(fieldEnrollmentClient = { _, _ -> FieldEnrollmentResult.DeviceLimitReached })
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()

        assertFalse(proceed)
        assertEquals(ProvisioningUiState.DeviceLimitReached, viewModel.provisioningState.value)
    }

    @Test
    fun `a revoked field-enrollment record fails closed`() = runTest {
        val viewModel = newViewModel(fieldEnrollmentClient = { _, _ -> FieldEnrollmentResult.Revoked })
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()

        assertFalse(proceed)
        assertEquals(ProvisioningUiState.Revoked, viewModel.provisioningState.value)
    }

    @Test
    fun `a revoked STORED credential (later revoked by an operator) fails closed on retry`() = runTest {
        val credentialStore = InMemoryFieldCredentialStore()
        credentialStore.save(FieldCredential("later-revoked", ProductionGatewayCatalog.GERMANY.awg.endpointHost))
        val viewModel = newViewModel(
            fieldEnrollmentClient = { _, _ -> fieldEnrollSuccess() }, // must not be called
            fieldCredentialStore = credentialStore,
            activateResult = ProvisioningResult.Revoked,
        )
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()
        testDispatcher.scheduler.runCurrent()

        assertFalse(proceed)
        assertEquals(ProvisioningUiState.Revoked, viewModel.provisioningState.value)
    }

    @Test
    fun `malformed field-enroll response fails closed`() = runTest {
        val viewModel = newViewModel(
            fieldEnrollmentClient = { _, _ -> FieldEnrollmentResult.MalformedResponse("bad") },
        )
        testDispatcher.scheduler.runCurrent()

        val proceed = viewModel.ensureZeroTouchEnrollment()

        assertFalse(proceed)
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
    }
}
