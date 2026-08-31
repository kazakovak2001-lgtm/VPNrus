package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoGatewayFailoverPolicyTest {

    @Test
    fun `HandshakeFailed with HandshakeTimeout is eligible`() {
        assertTrue(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.HandshakeFailed, VpnError.HandshakeTimeout))
    }

    @Test
    fun `Error with BackendStartFailure is eligible`() {
        assertTrue(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.Error("boom"), VpnError.BackendStartFailure("RuntimeException")))
    }

    @Test
    fun `Error with ReconnectExhausted is never eligible - that is a post-success async signal, not this attempt`() {
        assertFalse(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.Error("x"), VpnError.ReconnectExhausted))
    }

    @Test
    fun `Connected is never eligible`() {
        assertFalse(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.Connected, null))
    }

    @Test
    fun `Connecting is never eligible - not a completed attempt`() {
        assertFalse(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.Connecting, null))
    }

    @Test
    fun `an unrecognized error alongside a terminal state is never eligible`() {
        assertFalse(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.Error("x"), VpnError.PermissionDenied))
    }
}
