package net.pocvpn.client.ui

import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.ProfileSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8D - narrow tests for the new product-flow decision/wording logic only.
 * Pure JVM tests (no Robolectric/instrumentation) - see
 * ProductFlowPresentation.kt's own doc for why this logic lives in a
 * framework-free file at all.
 */
class ProductFlowPresentationTest {

    // 1 & 3: no/corrupt profile -> activation; persisted/provisioned -> home
    @Test
    fun `DEV_FALLBACK (no profile ever provisioned or restored) routes to ACTIVATION`() {
        assertEquals(AppScreen.ACTIVATION, screenFor(ProfileSource.DEV_FALLBACK))
    }

    @Test
    fun `RESTORED_PERSISTED routes to HOME directly - no re-activation required`() {
        assertEquals(AppScreen.HOME, screenFor(ProfileSource.RESTORED_PERSISTED))
    }

    // 2: successful activation -> home screen
    @Test
    fun `PROVISIONED_LIVE (successful activation) routes to HOME`() {
        assertEquals(AppScreen.HOME, screenFor(ProfileSource.PROVISIONED_LIVE))
    }

    // 4: activation credential cleared after success
    @Test
    fun `credential input is cleared only on Success, never on Idle, Provisioning, or an error`() {
        val success = ProvisioningUiState.Success(
            ProvisioningResult.Success(
                clientTunnelIp = "10.77.0.2",
                gatewayPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
                gatewayTunnelIp = "10.77.0.1",
                endpointHost = "152.70.43.1",
                endpointPort = 51820,
            )
        )
        assertTrue(shouldClearCredentialInput(success))
        assertFalse(shouldClearCredentialInput(ProvisioningUiState.Idle))
        assertFalse(shouldClearCredentialInput(ProvisioningUiState.Provisioning))
        assertFalse(shouldClearCredentialInput(ProvisioningUiState.Unauthorized))
        assertFalse(shouldClearCredentialInput(ProvisioningUiState.Error("service temporarily unavailable")))
    }

    // 5: Connected -> Protected
    @Test
    fun `Connected maps to Protected`() {
        assertEquals("Protected", TransportState.Connected.toHomeStatusText())
    }

    // 6: Connecting must not display Protected
    @Test
    fun `Connecting never displays Protected`() {
        val text = TransportState.Connecting.toHomeStatusText()
        assertEquals("Connecting…", text)
        assertTrue(text != "Protected")
    }

    // 7: HandshakeFailed -> Connection failed
    @Test
    fun `HandshakeFailed maps to Connection failed`() {
        assertEquals("Connection failed", TransportState.HandshakeFailed.toHomeStatusText())
    }

    @Test
    fun `every other transport state maps to its truthful non-technical wording, never Protected unless Connected`() {
        assertEquals("Disconnected", TransportState.Disconnected.toHomeStatusText())
        assertEquals("Disconnecting…", TransportState.Disconnecting.toHomeStatusText())
        assertEquals("Reconnecting…", TransportState.Reconnecting(attempt = 3).toHomeStatusText())
        assertEquals("Connection failed", TransportState.Error("boom").toHomeStatusText())
    }

    // 8: debug technical controls do not appear in the normal release-facing UI path
    @Test
    fun `diagnostics are shown only for a debug build, never for a release build`() {
        assertTrue(shouldShowDiagnostics(isDebugBuild = true))
        assertFalse(shouldShowDiagnostics(isDebugBuild = false))
    }

    @Test
    fun `activation errors map to simple user-facing text, not raw provisioning detail`() {
        assertEquals("Invalid activation", ProvisioningUiState.Unauthorized.toActivationErrorText())
        assertEquals("Activation revoked", ProvisioningUiState.Revoked.toActivationErrorText())
        assertEquals("Activation expired", ProvisioningUiState.Expired.toActivationErrorText())
        assertEquals("Device limit reached", ProvisioningUiState.DeviceLimitReached.toActivationErrorText())
        assertEquals(
            "Service temporarily unavailable",
            ProvisioningUiState.Error("service temporarily unavailable").toActivationErrorText(),
        )
        assertEquals(null, ProvisioningUiState.Idle.toActivationErrorText())
        assertEquals(null, ProvisioningUiState.Provisioning.toActivationErrorText())
    }
}
