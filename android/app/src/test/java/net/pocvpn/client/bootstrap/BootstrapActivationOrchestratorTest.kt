package net.pocvpn.client.bootstrap

import android.content.Intent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Always connects with a fresh handshake, or always fails, depending on [shouldConnect]. */
private class FixedBootstrapTransport(private val shouldConnect: Boolean) : VpnTransport {
    override val name: String = "fixed-bootstrap"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var disconnectCalled = false
        private set

    override fun preparePermissionIntent(): Intent? = null
    override suspend fun connect(config: TransportConfig) {
        if (!shouldConnect) throw RuntimeException("simulated failure")
        stateFlow.value = TransportState.Connected
    }
    override suspend fun disconnect() {
        disconnectCalled = true
        stateFlow.value = TransportState.Disconnected
    }
    override fun observeState(): Flow<TransportState> = stateFlow
    override suspend fun stats(): TransportStats =
        if (shouldConnect) TransportStats.Counters(0, 0, 0L) else TransportStats.Unavailable
}

private val successResult = ProvisioningResult.Success(
    clientTunnelIp = "10.77.0.5",
    gatewayPublicKey = "gw-pub-key",
    gatewayTunnelIp = "10.77.0.1",
    endpointHost = "152.70.43.1",
    endpointPort = 51820,
)

private fun newOrchestrator(
    hasAnyProvisionedProfile: () -> Boolean = { false },
    isGatewayProvisioned: (ProductionGatewayId) -> Boolean = { false },
    candidates: List<ProductionGatewayId> = BootstrapCatalog.candidatesInOrder,
    connectableCandidates: Set<ProductionGatewayId> = setOf(ProductionGatewayId.GERMANY),
    activate: suspend (ProductionGatewayId, String) -> ProvisioningUiState = { _, _ -> ProvisioningUiState.Success(successResult) },
): BootstrapActivationOrchestrator {
    val tunnelController = BootstrapTunnelController(
        transportFactory = { candidate -> FixedBootstrapTransport(shouldConnect = candidate in connectableCandidates) },
        candidates = candidates,
        nowProvider = { 0L },
        delayMs = { },
    )
    return BootstrapActivationOrchestrator(
        tunnelController = tunnelController,
        hasAnyProvisionedProfile = hasAnyProvisionedProfile,
        isGatewayProvisioned = isGatewayProvisioned,
        activate = activate,
    )
}

class BootstrapActivationOrchestratorTest {

    // Test A - full path: unactivated -> Frankfurt bootstrap succeeds -> activation succeeds -> profile persisted -> PROVISIONED.
    @Test
    fun `A - frankfurt bootstrap succeeds, activation succeeds, profile persisted, provisioned`() = runTest {
        var persisted = false
        val orchestrator = newOrchestrator(
            connectableCandidates = setOf(ProductionGatewayId.GERMANY),
            isGatewayProvisioned = { persisted },
            activate = { _, _ -> persisted = true; ProvisioningUiState.Success(successResult) },
        )

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertTrue(outcome is BootstrapActivationOutcome.Success)
        assertEquals(ProductionGatewayId.GERMANY, (outcome as BootstrapActivationOutcome.Success).gatewayId)
    }

    // Test B - Frankfurt bootstrap fails, Stockholm succeeds, activation succeeds.
    @Test
    fun `B - frankfurt bootstrap fails, stockholm succeeds, activation succeeds`() = runTest {
        val orchestrator = newOrchestrator(
            connectableCandidates = setOf(ProductionGatewayId.STOCKHOLM),
            isGatewayProvisioned = { true },
        )

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertTrue(outcome is BootstrapActivationOutcome.Success)
        assertEquals(ProductionGatewayId.STOCKHOLM, (outcome as BootstrapActivationOutcome.Success).gatewayId)
    }

    // Test C - both bootstrap candidates fail -> BootstrapUnavailable, activation request never attempted.
    @Test
    fun `C - both candidates fail - BootstrapUnavailable, activation never attempted`() = runTest {
        var activateCalled = false
        val orchestrator = newOrchestrator(
            connectableCandidates = emptySet(),
            activate = { _, _ -> activateCalled = true; ProvisioningUiState.Success(successResult) },
        )

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertTrue(outcome is BootstrapActivationOutcome.BootstrapUnavailable)
        assertEquals(
            listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
            (outcome as BootstrapActivationOutcome.BootstrapUnavailable).attempted,
        )
        assertFalse("activation must never be attempted when no bootstrap candidate connected", activateCalled)
    }

    // Test D - bootstrap connected, activation Unauthorized -> Invalid-activation-shaped outcome, never confused with a network error.
    @Test
    fun `D - bootstrap connected, activation Unauthorized - Unauthorized outcome`() = runTest {
        val orchestrator = newOrchestrator(activate = { _, _ -> ProvisioningUiState.Unauthorized })

        val outcome = orchestrator.activateViaBootstrap("wrong-code")

        assertEquals(BootstrapActivationOutcome.Unauthorized, outcome)
    }

    // Test E - bootstrap connected, network failure during activation -> a network/bootstrap error, NOT Unauthorized/Invalid activation.
    @Test
    fun `E - bootstrap connected, network failure during activation - NetworkOrProvisioningError, never Unauthorized`() = runTest {
        val orchestrator = newOrchestrator(activate = { _, _ -> ProvisioningUiState.Error("connection reset") })

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertEquals(BootstrapActivationOutcome.NetworkOrProvisioningError, outcome)
        assertTrue(outcome != BootstrapActivationOutcome.Unauthorized)
    }

    @Test
    fun `E2 - the bootstrap tunnel dying mid-activation (activate throws) is also a network error, not a credential rejection`() = runTest {
        val orchestrator = newOrchestrator(activate = { _, _ -> throw RuntimeException("tunnel dropped mid-request") })

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertEquals(BootstrapActivationOutcome.NetworkOrProvisioningError, outcome)
    }

    // Test F - a successful persisted profile already exists on app restart -> bootstrap is skipped entirely.
    @Test
    fun `F - already-provisioned device skips bootstrap entirely`() = runTest {
        var activateCalled = false
        val orchestrator = newOrchestrator(
            hasAnyProvisionedProfile = { true },
            activate = { _, _ -> activateCalled = true; ProvisioningUiState.Success(successResult) },
        )

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertEquals(BootstrapActivationOutcome.AlreadyProvisioned, outcome)
        assertFalse("bootstrap/activation must never run when a profile is already provisioned", activateCalled)
    }

    // Activation succeeds at the wire level but persistence never actually happened - fail closed, never report Success.
    @Test
    fun `activation succeeds but profile persistence did not happen - ProfilePersistFailed, not Success`() = runTest {
        val orchestrator = newOrchestrator(
            isGatewayProvisioned = { false }, // persistence never actually took effect
            activate = { _, _ -> ProvisioningUiState.Success(successResult) },
        )

        val outcome = orchestrator.activateViaBootstrap("real-code")

        assertTrue(outcome is BootstrapActivationOutcome.ProfilePersistFailed)
    }

    // Test I - bootstrap teardown occurs before the final outcome is returned, on every outcome shape (success and failure alike).
    @Test
    fun `I - teardown completes before activateViaBootstrap returns, on success and on failure`() = runTest {
        val successTransport = FixedBootstrapTransport(shouldConnect = true)
        val tunnelController = BootstrapTunnelController(
            transportFactory = { successTransport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            nowProvider = { 0L },
            delayMs = { },
        )
        val orchestrator = BootstrapActivationOrchestrator(
            tunnelController = tunnelController,
            hasAnyProvisionedProfile = { false },
            isGatewayProvisioned = { true },
            activate = { _, _ -> ProvisioningUiState.Success(successResult) },
        )

        orchestrator.activateViaBootstrap("real-code")

        assertTrue("teardown must have disconnected the real active transport before returning", successTransport.disconnectCalled)
        assertEquals(BootstrapState.Idle, tunnelController.state.value)

        // Failure path (Unauthorized) - teardown must ALSO have completed.
        val failTransport = FixedBootstrapTransport(shouldConnect = true)
        val failController = BootstrapTunnelController(
            transportFactory = { failTransport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            nowProvider = { 0L },
            delayMs = { },
        )
        val failOrchestrator = BootstrapActivationOrchestrator(
            tunnelController = failController,
            hasAnyProvisionedProfile = { false },
            isGatewayProvisioned = { false },
            activate = { _, _ -> ProvisioningUiState.Unauthorized },
        )

        failOrchestrator.activateViaBootstrap("wrong-code")

        assertTrue(failTransport.disconnectCalled)
        assertEquals(BootstrapState.Idle, failController.state.value)
    }

    @Test
    fun `diagnostics record the full lifecycle without ever carrying the activation credential`() = runTest {
        val recorder = BootstrapDiagnosticsRecorder(nowProvider = { 0L })
        val transport = FixedBootstrapTransport(shouldConnect = true)
        val tunnelController = BootstrapTunnelController(
            transportFactory = { transport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            diagnostics = recorder,
            nowProvider = { 0L },
            delayMs = { },
        )
        val orchestrator = BootstrapActivationOrchestrator(
            tunnelController = tunnelController,
            hasAnyProvisionedProfile = { false },
            isGatewayProvisioned = { true },
            activate = { _, _ -> ProvisioningUiState.Success(successResult) },
            diagnostics = recorder,
        )

        orchestrator.activateViaBootstrap("super-secret-activation-code")

        val snapshot = recorder.snapshot()
        assertTrue(snapshot.isNotEmpty())
        val allTagValues = snapshot.flatMap { it.tags.values }
        assertFalse(allTagValues.any { it.contains("super-secret-activation-code") })
        assertNull(snapshot.firstOrNull { it.tags.values.any { v -> v.contains("secret") } })
    }
}
