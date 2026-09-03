package net.pocvpn.client.provisioning

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class ActivationFailureMessageTest {

    @Test
    fun `first-run UX exposes a simple, human-readable failure only - never a raw exception, hostname, port, or TLS detail`() {
        val secretShapedMessages = listOf(
            ProvisioningUiState.Error("NetworkError: java.net.UnknownHostException: 152.70.43.1"),
            ProvisioningUiState.Error("malformed response: server_address missing or blank"),
            ProvisioningUiState.Error("SSLHandshakeException: PKIX path building failed at host 152.70.43.1:443"),
            ProvisioningUiState.Error("service temporarily unavailable"),
        )
        secretShapedMessages.forEach { state ->
            val message = friendlyActivationFailureMessage(state)
            assertEquals("VPN setup could not be completed on this network. Try another network or send diagnostics.", message)
            assertFalse(message!!.contains("152.70.43.1"))
            assertFalse(message.contains(":443"))
            assertFalse(message.contains("Exception"))
        }
    }

    @Test
    fun `idle, provisioning, and success states have no failure message`() {
        assertNull(friendlyActivationFailureMessage(ProvisioningUiState.Idle))
        assertNull(friendlyActivationFailureMessage(ProvisioningUiState.Provisioning))
        assertNull(
            friendlyActivationFailureMessage(
                ProvisioningUiState.Success(
                    ProvisioningResult.Success(
                        clientTunnelIp = "10.77.0.5",
                        gatewayPublicKey = "pk",
                        gatewayTunnelIp = "10.77.0.1",
                        endpointHost = "152.70.43.1",
                        endpointPort = 51820,
                    ),
                ),
            ),
        )
    }

    @Test
    fun `credential-shaped rejections get their own distinct, still non-technical copy`() {
        assertEquals(
            "That activation code wasn't accepted. Check the code and try again.",
            friendlyActivationFailureMessage(ProvisioningUiState.Unauthorized),
        )
        assertEquals("This activation code is no longer valid. Ask for a new one.", friendlyActivationFailureMessage(ProvisioningUiState.Revoked))
        assertEquals("This activation code has expired. Ask for a new one.", friendlyActivationFailureMessage(ProvisioningUiState.Expired))
        assertEquals(
            "This activation code has already reached its device limit.",
            friendlyActivationFailureMessage(ProvisioningUiState.DeviceLimitReached),
        )
    }

    @Test
    fun `classifyProvisioningResultFailure is null only for Success`() {
        val success = ProvisioningResult.Success("10.77.0.5", "pk", "10.77.0.1", "152.70.43.1", 51820)
        org.junit.Assert.assertNull(classifyProvisioningResultFailure(success))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyProvisioningResultFailure(ProvisioningResult.Unauthorized))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyProvisioningResultFailure(ProvisioningResult.Revoked))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyProvisioningResultFailure(ProvisioningResult.Expired))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyProvisioningResultFailure(ProvisioningResult.DeviceLimitReached))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyProvisioningResultFailure(ProvisioningResult.BadRequest))
        assertEquals(ControlPlaneFailureReason.HTTP_UNAVAILABLE, classifyProvisioningResultFailure(ProvisioningResult.ServiceUnavailable))
        assertEquals(
            ControlPlaneFailureReason.MALFORMED_RESPONSE,
            classifyProvisioningResultFailure(ProvisioningResult.MalformedResponse("bad")),
        )
        assertEquals(
            ControlPlaneFailureReason.DNS_RESOLUTION_FAILED,
            classifyProvisioningResultFailure(ProvisioningResult.NetworkError("UnknownHostException: x")),
        )
    }
}
