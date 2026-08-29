package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8J - narrow tests for RestrictionClassifier.classify(): this feature's
 * own required cases 1-7, plus 16 (no sensitive fields in RestrictionEvidence).
 */
class RestrictionClassifierTest {

    private fun profile(
        type: NetworkType = NetworkType.WIFI,
        validatedInternet: Boolean = true,
        captivePortal: Boolean? = false,
    ) = NetworkProfile(
        type = type, validatedInternet = validatedInternet, metered = false, roaming = false,
        captivePortal = captivePortal, ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
    )

    private fun evidence(
        networkProfile: NetworkProfile = profile(),
        transportState: TransportState = TransportState.Disconnected,
        awgHandshakeFresh: Boolean? = null,
        gatewayHttpsReachable: Boolean? = null,
    ) = RestrictionEvidence(networkProfile, transportState, awgHandshakeFresh, gatewayHttpsReachable)

    @Test
    fun `no network yields NO_NETWORK regardless of any other evidence`() {
        val result = RestrictionClassifier.classify(
            evidence(networkProfile = NetworkProfile.unavailable(0), awgHandshakeFresh = true, gatewayHttpsReachable = true),
        )
        assertEquals(RestrictionClass.NO_NETWORK, result)
    }

    @Test
    fun `captive portal yields CAPTIVE_PORTAL`() {
        val result = RestrictionClassifier.classify(evidence(networkProfile = profile(captivePortal = true, validatedInternet = false)))
        assertEquals(RestrictionClass.CAPTIVE_PORTAL, result)
    }

    @Test
    fun `unvalidated internet yields INTERNET_NOT_VALIDATED`() {
        val result = RestrictionClassifier.classify(evidence(networkProfile = profile(validatedInternet = false, captivePortal = false)))
        assertEquals(RestrictionClass.INTERNET_NOT_VALIDATED, result)
    }

    @Test
    fun `validated internet plus gateway HTTPS unreachable yields GATEWAY_HTTPS_UNREACHABLE`() {
        val result = RestrictionClassifier.classify(evidence(gatewayHttpsReachable = false))
        assertEquals(RestrictionClass.GATEWAY_HTTPS_UNREACHABLE, result)
    }

    @Test
    fun `validated internet plus HTTPS reachable plus AWG handshake failure yields POSSIBLE_UDP_OR_AWG_FILTERING`() {
        val result = RestrictionClassifier.classify(evidence(gatewayHttpsReachable = true, awgHandshakeFresh = false))
        assertEquals(RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, result)
    }

    @Test
    fun `a fresh AWG handshake yields NO_RESTRICTION_OBSERVED`() {
        val result = RestrictionClassifier.classify(evidence(awgHandshakeFresh = true))
        assertEquals(RestrictionClass.NO_RESTRICTION_OBSERVED, result)
    }

    @Test
    fun `insufficient or contradictory evidence yields UNKNOWN, never a guess`() {
        // Validated internet, but neither the probe nor a handshake has told us anything yet.
        val result = RestrictionClassifier.classify(evidence(awgHandshakeFresh = null, gatewayHttpsReachable = null))
        assertEquals(RestrictionClass.UNKNOWN, result)
    }

    @Test
    fun `an active but not-yet-exhausted reconnect yields NETWORK_RECOVERING, never a premature filtering conclusion`() {
        val result = RestrictionClassifier.classify(
            evidence(transportState = TransportState.Reconnecting(attempt = 2), gatewayHttpsReachable = true, awgHandshakeFresh = false),
        )
        assertEquals(RestrictionClass.NETWORK_RECOVERING, result)
    }

    @Test
    fun `the enum never contains a DPI, TSPU, or country-level block claim - those classes cannot exist here`() {
        val names = RestrictionClass.entries.map { it.name }
        listOf("DPI_BLOCKED", "TSPU_BLOCKED", "RUSSIA_BLOCK").forEach { forbidden ->
            assertTrue("RestrictionClass must never gain a $forbidden value", forbidden !in names)
        }
    }

    @Test
    fun `RestrictionEvidence carries only the closed, non-sensitive field set - no IP, SSID, destination, or credential field exists`() {
        val fieldNames = RestrictionEvidence::class.java.declaredFields
            .map { it.name }
            .filterNot { it.contains('$') } // compiler-synthetic (e.g. Compose's stability marker), holds no data
            .toSet()
        val expected = setOf("networkProfile", "transportState", "awgHandshakeFresh", "gatewayHttpsReachable")
        assertEquals(expected, fieldNames)
    }
}
