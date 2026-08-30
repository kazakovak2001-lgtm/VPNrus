package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8I8/B8I8A - proof of the ONE eligibility rule, covering every VpnError
 * variant that is individually reachable at this callsite:
 * doConnectAttempt()/rejectPreflight() can produce (all exercised below),
 * plus VpnError.ReconnectExhausted (recorded only by the async, post-Connected
 * reconnectLoop() - never this attempt's own outcome, but still given an
 * explicit non-eligible case here rather than left to the catch-all). NOT
 * exercised, because they are unreachable/dead at this callsite:
 * VpnError.NetworkUnavailable and VpnError.BackendStopFailure are never
 * actually recorded anywhere in production code (confirmed dead). This is
 * NOT a catch-all "any Error is eligible" assumption for the cases it does
 * cover.
 */
class AwgXrayFailoverPolicyTest {

    private fun eligible(
        initialKind: TransportKind = TransportKind.AMNEZIA_WG,
        preference: UserTransportPreference = UserTransportPreference.Auto,
        awgState: TransportState = TransportState.HandshakeFailed,
        awgError: VpnError? = VpnError.HandshakeTimeout,
        xrayAvailable: Boolean = true,
    ): Boolean = AwgXrayFailoverPolicy.isEligibleForXrayFallback(initialKind, preference, awgState, awgError, xrayAvailable)

    @Test
    fun `handshake timeout is eligible`() {
        assertTrue(eligible(awgState = TransportState.HandshakeFailed, awgError = VpnError.HandshakeTimeout))
    }

    @Test
    fun `backend start failure is eligible`() {
        assertTrue(
            eligible(
                awgState = TransportState.Error("Backend failed to start"),
                awgError = VpnError.BackendStartFailure("RuntimeException"),
            ),
        )
    }

    @Test
    fun `AWG success is never eligible`() {
        assertFalse(eligible(awgState = TransportState.Connected, awgError = null))
    }

    @Test
    fun `initial selection of XRAY_REALITY is never eligible - nothing to fall back from`() {
        assertFalse(eligible(initialKind = TransportKind.XRAY_REALITY))
    }

    @Test
    fun `Xray unavailable is never eligible`() {
        assertFalse(eligible(xrayAvailable = false))
    }

    @Test
    fun `Manual AWG preference is never eligible`() {
        assertFalse(eligible(preference = UserTransportPreference.Manual(TransportKind.AMNEZIA_WG)))
    }

    @Test
    fun `Manual Xray preference is never eligible`() {
        assertFalse(eligible(preference = UserTransportPreference.Manual(TransportKind.XRAY_REALITY)))
    }

    @Test
    fun `gateway missing is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("Gateway configuration is not configured. Real VPS required."),
                awgError = VpnError.GatewayConfigurationMissing,
            ),
        )
    }

    @Test
    fun `invalid gateway configuration is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("Invalid gateway configuration: bad"),
                awgError = VpnError.InvalidGatewayConfiguration("bad"),
            ),
        )
    }

    @Test
    fun `split tunneling no apps selected is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("VPN-only mode has no apps selected - select at least one app"),
                awgError = VpnError.SplitTunnelingNoAppsSelected,
            ),
        )
    }

    @Test
    fun `configuration mapping failure (e_g_ corrupted local identity) is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("Failed to build tunnel configuration"),
                awgError = VpnError.ConfigurationMappingFailure("IdentityCorruptedException"),
            ),
        )
    }

    @Test
    fun `permission denied is never eligible`() {
        assertFalse(eligible(awgState = TransportState.Error("VPN permission denied"), awgError = VpnError.PermissionDenied))
    }

    @Test
    fun `already in progress is never eligible`() {
        assertFalse(eligible(awgState = TransportState.Disconnected, awgError = VpnError.AlreadyInProgress))
    }

    @Test
    fun `no candidate available is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("No connection candidate available"),
                awgError = VpnError.NoCandidateAvailable,
            ),
        )
    }

    @Test
    fun `reconnect exhausted (async, post-Connected retry signal) is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("Reconnect attempts exhausted"),
                awgError = VpnError.ReconnectExhausted,
            ),
        )
    }

    @Test
    fun `unsupported transport selected is never eligible`() {
        assertFalse(
            eligible(
                awgState = TransportState.Error("unsupported"),
                awgError = VpnError.UnsupportedTransportSelected("XRAY_REALITY"),
            ),
        )
    }

    @Test
    fun `a non-terminal state (still Connecting, e_g_ awaiting permission) is never eligible even with a stale eligible error`() {
        // Guards against a stale lastError from an EARLIER attempt being
        // mistaken for the outcome of a DIFFERENT, still-in-flight attempt.
        assertFalse(eligible(awgState = TransportState.Connecting, awgError = VpnError.HandshakeTimeout))
    }

    @Test
    fun `Disconnected (e_g_ user cancelled) is never eligible even with a stale eligible error`() {
        assertFalse(eligible(awgState = TransportState.Disconnected, awgError = VpnError.HandshakeTimeout))
    }
}
