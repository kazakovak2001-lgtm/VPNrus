package net.pocvpn.client.fieldtest

import android.content.Intent
import java.nio.file.Files
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.ProfileLoadResult
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

private class FixedTransport(private val shouldHandshake: Boolean) : VpnTransport {
    override val name: String = "fixed"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    override fun preparePermissionIntent(): Intent? = null
    override suspend fun connect(config: TransportConfig) {
        if (!shouldHandshake) throw RuntimeException("simulated failure")
        stateFlow.value = TransportState.Connected
    }
    override suspend fun disconnect() { stateFlow.value = TransportState.Disconnected }
    override fun observeState(): Flow<TransportState> = stateFlow
    override suspend fun stats(): TransportStats =
        if (shouldHandshake) TransportStats.Counters(0, 0, 0L) else TransportStats.Unavailable
}

private class RecordingUploader(private val succeed: Boolean, private val throwInstead: Boolean = false) : FieldTestReportUploader {
    var callCount = 0
        private set
    var lastReport: FieldTestReport? = null
        private set

    override suspend fun uploadThroughTunnel(report: FieldTestReport): Boolean {
        callCount++
        lastReport = report
        if (throwInstead) throw RuntimeException("simulated upload transport error")
        return succeed
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class FieldTestViewModelTest {

    @Before
    fun setUp() {
        kotlinx.coroutines.Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @After
    fun tearDown() {
        kotlinx.coroutines.Dispatchers.resetMain()
    }

    private fun newViewModel(
        allHandshake: Boolean,
        uploader: FieldTestReportUploader = NoOpFieldTestReportUploader,
        // Defaults to "already granted" (matches FixedTransport's own
        // preparePermissionIntent() == null) - every pre-existing test
        // below is unaffected by the PR #61 permission-gating fix unless
        // it explicitly overrides this.
        preparePermissionIntent: () -> Intent? = { null },
    ) = FieldTestViewModel(
        transportFactory = { FixedTransport(shouldHandshake = allHandshake) },
        appVersionName = "0.1-fieldtest",
        appVersionCode = 1L,
        reportUploader = uploader,
        networkTypeProvider = { NetworkType.WIFI },
        nowProvider = { 0L },
        preparePermissionIntent = preparePermissionIntent,
    )

    // Test A - field-test build skips activation completely: FieldTestViewModel
    // has no activation/provisioning dependency at all (no ProvisioningClient,
    // no BootstrapActivationOrchestrator, no activation code param) - a
    // successful connect() reaches Protected directly from a Connect tap,
    // proving no activation step exists anywhere in this path.
    @Test
    fun `A - connect reaches Protected with no activation step`() = runTest {
        val vm = newViewModel(allHandshake = true)
        assertEquals(FieldTestUiState.Idle, vm.uiState.value)
        vm.connect()
        assertEquals(FieldTestUiState.Protected, vm.uiState.value)
    }

    // Test D - successful real transport/data-plane state becomes Protected (ViewModel level).
    @Test
    fun `D - successful connect exposes Protected ui state and a PROTECTED report`() = runTest {
        val vm = newViewModel(allHandshake = true)
        vm.connect()
        assertEquals(FieldTestUiState.Protected, vm.uiState.value)
        val report = vm.lastReport.value
        assertTrue(report != null)
        assertEquals(FieldTestOutcome.PROTECTED, report!!.outcome)
        assertEquals(ProductionGatewayId.GERMANY, report.finalGateway)
        assertEquals(TransportKind.AMNEZIA_WG, report.finalTransportKind)
        assertEquals(FieldTestBuildInfo.BUILD_LABEL, report.buildLabel)
    }

    // Test E - both fail -> Connection failed (ViewModel level), and a complete local report still exists.
    @Test
    fun `E - both gateways fail exposes Failed ui state and a FAILED report`() = runTest {
        val vm = newViewModel(allHandshake = false)
        vm.connect()
        assertEquals(FieldTestUiState.Failed, vm.uiState.value)
        val report = vm.lastReport.value
        assertTrue(report != null)
        assertEquals(FieldTestOutcome.FAILED, report!!.outcome)
        assertNull(report.finalGateway)
        assertEquals(FieldTestFailureCategory.ALL_CANDIDATES_EXHAUSTED, report.failureCategory)
    }

    // Reporting requirement - a successful connection triggers report upload AFTER tunnel establishment.
    @Test
    fun `reporting - successful connection triggers upload attempt after Protected`() = runTest {
        val uploader = RecordingUploader(succeed = true)
        val vm = newViewModel(allHandshake = true, uploader = uploader)
        vm.connect()
        assertEquals(1, uploader.callCount)
        assertEquals(FieldTestOutcome.PROTECTED, uploader.lastReport?.outcome)
    }

    // Reporting requirement - a failed connection never even attempts upload (nothing to upload through - no tunnel exists).
    @Test
    fun `reporting - failed connection never attempts upload`() = runTest {
        val uploader = RecordingUploader(succeed = true)
        val vm = newViewModel(allHandshake = false, uploader = uploader)
        vm.connect()
        assertEquals(0, uploader.callCount)
    }

    // Reporting requirement - reporting failure does not tear down or fail an otherwise healthy VPN.
    @Test
    fun `reporting - upload failure never changes an already-Protected ui state`() = runTest {
        val uploader = RecordingUploader(succeed = false, throwInstead = true)
        val vm = newViewModel(allHandshake = true, uploader = uploader)
        vm.connect()
        assertEquals(1, uploader.callCount)
        assertEquals("upload throwing must never affect the connected ui state", FieldTestUiState.Protected, vm.uiState.value)
        assertEquals(FieldTestOutcome.PROTECTED, vm.lastReport.value?.outcome)
    }

    // Reporting requirement - both-gateway failure produces a complete local report even with zero upload attempts.
    @Test
    fun `reporting - both-gateway failure still produces a complete local report`() = runTest {
        val uploader = RecordingUploader(succeed = true)
        val vm = newViewModel(allHandshake = false, uploader = uploader)
        vm.connect()
        assertEquals(0, uploader.callCount)
        val report = vm.lastReport.value
        assertTrue(report != null)
        assertTrue(report!!.events.isNotEmpty())
    }

    // No secrets in serialized diagnostic output - the report's JSON never contains this build's own embedded private key, public key, or tunnel address.
    @Test
    fun `no secrets in serialized diagnostic output`() = runTest {
        val vm = newViewModel(allHandshake = true)
        vm.connect()
        val json = vm.lastReport.value!!.toJson()
        assertFalse(json.contains(FieldTestIdentity.FIELD_TEST_PRIVATE_KEY_BASE64))
        assertFalse(json.contains(FieldTestIdentity.FIELD_TEST_PUBLIC_KEY_BASE64))
        assertFalse(json.contains(FieldTestIdentity.CLIENT_TUNNEL_ADDRESS_CIDR))
        assertFalse(json.contains("152.70.43.1"))
        assertFalse(json.contains("16.170.208.231"))
    }

    // Test G - the field-test profile can never be stored as a normal provisioned production profile:
    // a full connect() cycle (success and failure) never writes anything into
    // ProvisionedProfileStore - the ONE place a real activated profile is
    // durably persisted. FieldTestViewModel/FieldTestTunnelController have no
    // dependency on this store at all; this test proves it behaviorally, not
    // merely by absence of an import.
    @Test
    fun `G - connect never writes a ProvisionedProfileStore profile, success or failure`() = runTest {
        val dir = Files.createTempDirectory("field-test-store-proof").toFile()
        try {
            val store = FileProfileStore(dir)

            val vmSuccess = newViewModel(allHandshake = true)
            vmSuccess.connect()
            assertTrue(store.read() is ProfileLoadResult.NotFound)

            val vmFailure = newViewModel(allHandshake = false)
            vmFailure.connect()
            assertTrue(store.read() is ProfileLoadResult.NotFound)
        } finally {
            dir.deleteRecursively()
        }
    }

    // --- PR #61 follow-up: real Android VPN permission flow -------------
    // Root cause fixed here: FieldTestTunnelController used to call
    // transport.preparePermissionIntent() PER CANDIDATE and mark it failed
    // without ever launching the system dialog - a fresh install therefore
    // always reported "GERMANY failed" / "STOCKHOLM failed" within
    // milliseconds, never a real AWG/network result. Permission is now
    // resolved exactly once, before any candidate is attempted.

    // "fresh install / permission required -> dialog requested, no gateway failure recorded"
    @Test
    fun `permission - fresh install surfaces the system dialog and records no gateway attempt yet`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { permissionIntent })
        vm.connect()

        // The coroutine is genuinely suspended awaiting the tester's real
        // answer - Connecting… is shown, the dialog intent is surfaced, and
        // NEITHER gateway has been touched (task's own "never mark
        // Frankfurt or Stockholm as failed merely because permission is
        // pending").
        assertEquals(FieldTestUiState.Connecting, vm.uiState.value)
        assertEquals(permissionIntent, vm.permissionRequest.value)
        assertNull("no report/outcome must exist while permission is merely pending", vm.lastReport.value)
    }

    // "permission granted -> automatically proceeds to Frankfurt"
    @Test
    fun `permission - granted automatically continues into Frankfurt with no second tap`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { permissionIntent })
        vm.connect()
        assertEquals(FieldTestUiState.Connecting, vm.uiState.value)

        vm.onVpnPermissionResult(true)

        assertNull("the dialog request must be cleared once answered", vm.permissionRequest.value)
        assertEquals(FieldTestUiState.Protected, vm.uiState.value)
        assertEquals(ProductionGatewayId.GERMANY, vm.lastReport.value?.finalGateway)
    }

    // "permission denied -> terminal failure with VPN_PERMISSION_DENIED"
    @Test
    fun `permission - denied is a terminal failure with VPN_PERMISSION_DENIED, no gateway attempted`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { permissionIntent })
        vm.connect()

        vm.onVpnPermissionResult(false)

        assertEquals(FieldTestUiState.Failed, vm.uiState.value)
        val report = vm.lastReport.value
        assertTrue(report != null)
        assertEquals(FieldTestOutcome.FAILED, report!!.outcome)
        assertEquals(FieldTestFailureCategory.VPN_PERMISSION_DENIED, report.failureCategory)
        assertTrue("permission denial must never count as an attempted gateway", report.gatewaysAttempted.isEmpty())
        assertNull(report.finalGateway)
    }

    // "already granted -> Connect goes directly to Frankfurt"
    @Test
    fun `permission - already granted skips the dialog entirely and goes straight to Frankfurt`() = runTest {
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { null })
        vm.connect()

        assertNull("nothing to launch when permission is already granted", vm.permissionRequest.value)
        assertEquals(FieldTestUiState.Protected, vm.uiState.value)
        assertEquals(ProductionGatewayId.GERMANY, vm.lastReport.value?.finalGateway)
    }

    // Diagnostics ordering - VPN_PERMISSION_REQUESTED, then GRANTED, then (only after that) the GERMANY attempt.
    @Test
    fun `permission - diagnostics record requested then granted before any gateway attempt`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { permissionIntent })
        vm.connect()
        vm.onVpnPermissionResult(true)

        val events = vm.lastReport.value!!.events
        val requestedIndex = events.indexOfFirst { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_REQUESTED }
        val grantedIndex = events.indexOfFirst { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_GRANTED }
        val attemptIndex = events.indexOfFirst {
            it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_ATTEMPT_STARTED &&
                it.tags[FieldTestDiagnosticTags.TAG_CANDIDATE] == ProductionGatewayId.GERMANY.name
        }
        assertTrue(requestedIndex >= 0 && grantedIndex >= 0 && attemptIndex >= 0)
        assertTrue("REQUESTED must precede GRANTED", requestedIndex < grantedIndex)
        assertTrue("GRANTED must precede the GERMANY attempt", grantedIndex < attemptIndex)
    }

    // Diagnostics - a denied permission records DENIED, never a GRANTED, and never any gateway attempt event.
    @Test
    fun `permission - diagnostics record denied and no gateway attempt events at all`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { permissionIntent })
        vm.connect()
        vm.onVpnPermissionResult(false)

        val events = vm.lastReport.value!!.events
        assertTrue(events.any { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_DENIED })
        assertTrue(events.none { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_GRANTED })
        assertTrue(events.none { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_ATTEMPT_STARTED })
    }

    // "already granted" must never even record a REQUESTED/GRANTED event pair - nothing was ever asked.
    @Test
    fun `permission - already granted records no permission events at all`() = runTest {
        val vm = newViewModel(allHandshake = true, preparePermissionIntent = { null })
        vm.connect()

        val events = vm.lastReport.value!!.events
        assertTrue(events.none { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_REQUESTED })
        assertTrue(events.none { it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_GRANTED })
    }

    // "Frankfurt/Stockholm fallback behavior unchanged" - once permission is granted, a Frankfurt failure still falls back to Stockholm exactly as before this fix.
    @Test
    fun `permission - granted then Frankfurt failure still falls back to Stockholm`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val vm = FieldTestViewModel(
            transportFactory = { candidate -> FixedTransport(shouldHandshake = candidate == ProductionGatewayId.STOCKHOLM) },
            appVersionName = "0.1-fieldtest",
            appVersionCode = 1L,
            networkTypeProvider = { NetworkType.WIFI },
            nowProvider = { 0L },
            preparePermissionIntent = { permissionIntent },
        )
        vm.connect()
        vm.onVpnPermissionResult(true)

        assertEquals(FieldTestUiState.Protected, vm.uiState.value)
        assertEquals(ProductionGatewayId.STOCKHOLM, vm.lastReport.value?.finalGateway)
        assertEquals(listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), vm.lastReport.value?.gatewaysAttempted)
    }
}
