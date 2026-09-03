package net.pocvpn.client.controlplane

import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.diagnostics.support.InMemoryDiagnosticSessionStore
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.provisioning.XrayProfileResult
import net.pocvpn.client.provisioning.XrayTlsProfileResult
import net.pocvpn.client.provisioning.classifyXrayProfileResultFailure
import net.pocvpn.client.provisioning.classifyXrayTlsProfileResultFailure
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** B30 review fix (blocker 2) - proves gateway-scoped profile fetch is genuinely wired through TrustedOriginRequestExecutor, not only instrumented. */
class TrustedOriginProfileFetchTest {

    private val origins = listOf(
        ControlPlaneOrigin(ProductionGatewayId.GERMANY, "origin-a"),
        ControlPlaneOrigin(ProductionGatewayId.GERMANY, "origin-b"),
    )

    @Test
    fun `primary origin fails, secondary origin succeeds - through the SAME generic executor`() {
        var attempts = 0
        val result = fetchThroughTrustedOrigins(
            gatewayId = ProductionGatewayId.GERMANY,
            diagnosticsRecorder = null,
            classify = { r: String -> if (r == "fail") ControlPlaneFailureReason.HTTP_UNAVAILABLE else null },
            origins = origins,
            fetch = { attempts++; if (attempts == 1) "fail" else "ok" },
        )
        assertEquals("ok", result)
        assertEquals(2, attempts)
    }

    @Test
    fun `all origins exhausted returns the LAST attempted result, never a synthesized value`() {
        val result = fetchThroughTrustedOrigins(
            gatewayId = ProductionGatewayId.GERMANY,
            diagnosticsRecorder = null,
            classify = { r: Int -> ControlPlaneFailureReason.HTTP_UNAVAILABLE },
            origins = origins,
            fetch = { origin -> if (origin.host == "origin-a") 1 else 2 },
        )
        assertEquals(2, result)
    }

    @Test
    fun `diagnostics record PROFILE_FETCH events and CONTROL_ORIGIN attempts with no origin host leaking`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(store, "1.0", 1L)
        recorder.startSession(startContext())
        fetchThroughTrustedOrigins(
            gatewayId = ProductionGatewayId.GERMANY,
            diagnosticsRecorder = recorder,
            classify = { r: String -> if (r == "fail") ControlPlaneFailureReason.CONNECT_TIMEOUT else null },
            origins = origins,
            fetch = { origin -> if (origin.host == "origin-a") "fail" else "ok" },
        )
        recorder.finishProtected()
        val events = store.recent().single().events
        assertTrue(events.any { it.type == DiagnosticEventType.PROFILE_FETCH_STARTED })
        assertTrue(events.any { it.type == DiagnosticEventType.PROFILE_FETCH_SUCCEEDED })
        assertTrue(events.any { it.type == DiagnosticEventType.CONTROL_ORIGIN_FAILED })
        assertTrue(events.any { it.type == DiagnosticEventType.CONTROL_ORIGIN_SUCCEEDED })
        events.flatMap { it.tags.values }.forEach {
            assertTrue(!it.contains("origin-a"))
            assertTrue(!it.contains("origin-b"))
        }
    }

    @Test
    fun `classifyXrayProfileResultFailure classifies every branch, null only for Success`() {
        assertNull(
            classifyXrayProfileResultFailure(
                XrayProfileResult.Success("1.2.3.4", 443, "u", "f", "n", "fp", "k", "id"),
            ),
        )
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyXrayProfileResultFailure(XrayProfileResult.Unauthorized))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyXrayProfileResultFailure(XrayProfileResult.Revoked))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyXrayProfileResultFailure(XrayProfileResult.DeviceNotBound))
        assertEquals(ControlPlaneFailureReason.HTTP_UNAVAILABLE, classifyXrayProfileResultFailure(XrayProfileResult.ServiceUnavailable))
        assertEquals(
            ControlPlaneFailureReason.MALFORMED_RESPONSE,
            classifyXrayProfileResultFailure(XrayProfileResult.MalformedResponse("bad")),
        )
        assertEquals(
            ControlPlaneFailureReason.DNS_RESOLUTION_FAILED,
            classifyXrayProfileResultFailure(XrayProfileResult.NetworkError("UnknownHostException: x")),
        )
    }

    @Test
    fun `classifyXrayTlsProfileResultFailure classifies every branch, null only for Success`() {
        assertNull(classifyXrayTlsProfileResultFailure(XrayTlsProfileResult.Success("1.2.3.4", 443, "u", "n", "fp")))
        assertEquals(ControlPlaneFailureReason.AUTHORIZATION_REJECTED, classifyXrayTlsProfileResultFailure(XrayTlsProfileResult.Unauthorized))
        assertEquals(ControlPlaneFailureReason.HTTP_UNAVAILABLE, classifyXrayTlsProfileResultFailure(XrayTlsProfileResult.ServiceUnavailable))
        assertEquals(
            ControlPlaneFailureReason.MALFORMED_RESPONSE,
            classifyXrayTlsProfileResultFailure(XrayTlsProfileResult.MalformedResponse("bad")),
        )
    }

    private fun startContext() = SupportDiagnosticsRecorder.StartContext(
        networkType = net.pocvpn.client.network.NetworkType.WIFI,
        networkValidatedInternet = true,
        networkCaptivePortal = false,
        networkIpv4Available = true,
        networkIpv6Available = false,
        networkFingerprintId = null,
        rawRestrictionClass = net.pocvpn.client.smartconnect.RestrictionClass.UNKNOWN,
        stabilizedRestrictionClass = net.pocvpn.client.smartconnect.RestrictionClass.UNKNOWN,
        routingMode = RoutingMode.FULL_VPN,
        gatewaySelectionMode = net.pocvpn.client.vpn.config.GatewaySelectionMode.AUTO,
    )
}
