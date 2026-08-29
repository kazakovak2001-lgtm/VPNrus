package net.pocvpn.client.ui

import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.ProfileSource
import net.pocvpn.client.vpn.policy.AppRoutingMode
import net.pocvpn.client.vpn.policy.AppRoutingPolicy
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

    // --- B8G: app-session kill-switch presentation ---

    @Test
    fun `kill switch notice shows during in-flight or failed states, never while Connected, Disconnected, or Disconnecting`() {
        assertTrue(TransportState.Connecting.showsKillSwitchNotice())
        assertTrue(TransportState.Reconnecting(attempt = 1).showsKillSwitchNotice())
        assertTrue(TransportState.HandshakeFailed.showsKillSwitchNotice())
        assertTrue(TransportState.Error("boom").showsKillSwitchNotice())

        assertFalse(TransportState.Connected.showsKillSwitchNotice())
        assertFalse(TransportState.Disconnected.showsKillSwitchNotice())
        assertFalse(TransportState.Disconnecting.showsKillSwitchNotice())
    }

    @Test
    fun `session is active for every state except Disconnected`() {
        assertFalse(TransportState.Disconnected.isSessionActive())

        assertTrue(TransportState.Connecting.isSessionActive())
        assertTrue(TransportState.Connected.isSessionActive())
        assertTrue(TransportState.Reconnecting(attempt = 2).isSessionActive())
        assertTrue(TransportState.HandshakeFailed.isSessionActive())
        assertTrue(TransportState.Error("boom").isSessionActive())
        assertTrue(TransportState.Disconnecting.isSessionActive())
    }

    // --- B8H1: truthful Home CONNECTED subtitle by APPLIED routing policy ---

    @Test
    fun `ALL_APPS applied policy shows the plain secure wording`() {
        assertEquals(HomeConnectedSubtitle.ALL_APPS_SECURE, homeConnectedSubtitle(AppRoutingMode.ALL_APPS))
    }

    @Test
    fun `BYPASS_SELECTED applied policy shows the bypass wording`() {
        assertEquals(HomeConnectedSubtitle.BYPASS_SELECTED_APPS, homeConnectedSubtitle(AppRoutingMode.BYPASS_SELECTED))
    }

    @Test
    fun `VPN_ONLY_SELECTED applied policy shows the vpn-only wording`() {
        assertEquals(HomeConnectedSubtitle.VPN_ONLY_SELECTED_APPS, homeConnectedSubtitle(AppRoutingMode.VPN_ONLY_SELECTED))
    }

    @Test
    fun `a pending saved policy never changes Home wording before reconnect - only the APPLIED policy is read`() {
        // The live tunnel was built with ALL_APPS; the user has since saved
        // a DIFFERENT policy that has not been applied yet (no reconnect).
        // homeConnectedSubtitle only ever receives the applied mode - a
        // caller wiring the SAVED policy in by mistake is exactly what this
        // guards against, so this asserts against the applied value only.
        val appliedMode = AppRoutingMode.ALL_APPS
        val pendingSavedPolicy = AppRoutingPolicy(AppRoutingMode.VPN_ONLY_SELECTED, setOf("com.example.app"))

        assertEquals(HomeConnectedSubtitle.ALL_APPS_SECURE, homeConnectedSubtitle(appliedMode))
        // The saved policy differing doesn't change the fact above - it's
        // simply never consulted by this function.
        assertTrue(hasPendingRoutingPolicyChange(AppRoutingPolicy(appliedMode), pendingSavedPolicy))
    }
}
