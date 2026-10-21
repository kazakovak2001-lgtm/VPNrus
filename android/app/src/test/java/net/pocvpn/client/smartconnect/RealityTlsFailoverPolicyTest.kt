package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RealityTlsFailoverPolicyTest {

    private fun eligible(
        initialKind: TransportKind = TransportKind.XRAY_REALITY,
        preference: UserTransportPreference = UserTransportPreference.Auto,
        state: TransportState = TransportState.Error("remote handshake not confirmed"),
        error: VpnError? = VpnError.HandshakeTimeout,
        tlsAvailable: Boolean = true,
    ) = RealityTlsFailoverPolicy.isEligibleForTlsFallback(initialKind, preference, state, error, tlsAvailable)

    @Test
    fun `Auto REALITY connection failures are eligible`() {
        assertTrue(eligible())
        assertTrue(eligible(state = TransportState.HandshakeFailed))
        assertTrue(eligible(error = VpnError.DataPlaneNoTraffic))
        assertTrue(eligible(error = VpnError.BackendStartFailure("IllegalStateException")))
    }

    @Test
    fun `a pinned transport is never substituted`() {
        assertFalse(eligible(preference = UserTransportPreference.Manual(TransportKind.XRAY_REALITY)))
    }

    @Test
    fun `only an initial REALITY attempt qualifies`() {
        assertFalse(eligible(initialKind = TransportKind.AMNEZIA_WG))
        assertFalse(eligible(initialKind = TransportKind.TLS_TCP))
        assertFalse(eligible(initialKind = TransportKind.XRAY_XHTTP))
        assertFalse(eligible(initialKind = TransportKind.HYSTERIA2))
    }

    @Test
    fun `no TLS_TCP on this gateway means no fallback`() {
        assertFalse(eligible(tlsAvailable = false))
    }

    @Test
    fun `non-terminal states are never eligible`() {
        assertFalse(eligible(state = TransportState.Connected))
        assertFalse(eligible(state = TransportState.Connecting))
        assertFalse(eligible(state = TransportState.Disconnected))
    }

    @Test
    fun `configuration, permission, preflight and post-connect errors stay ineligible`() {
        assertFalse(eligible(error = null))
        assertFalse(eligible(error = VpnError.ConfigurationMappingFailure("invalid profile")))
        assertFalse(eligible(error = VpnError.GatewayConfigurationMissing))
        assertFalse(eligible(error = VpnError.PermissionDenied))
        assertFalse(eligible(error = VpnError.NoCandidateAvailable))
        assertFalse(eligible(error = VpnError.ReconnectExhausted))
    }
}
