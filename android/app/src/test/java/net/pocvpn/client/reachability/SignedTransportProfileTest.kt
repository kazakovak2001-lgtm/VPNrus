package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SignedTransportProfileTest {
    private val endpointId = EndpointId("edge-a")

    @Test
    fun `legacy binding remains a typed legacy profile`() {
        val binding = EndpointTransportBinding(TransportKind.TLS_TCP, "tls.example", 443)
        val result = binding.signedTransportProfile(endpointId)
        assertTrue(result is SignedTransportProfileReadResult.Parsed)
        assertEquals(SignedTransportProfile.Legacy(endpointId, TransportKind.TLS_TCP), (result as SignedTransportProfileReadResult.Parsed).profile)
    }

    @Test
    fun `unsupported signed CDN profile fails closed`() {
        val binding = EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443)
            .withIngressKind(IngressKind.CDN_FRONTED)
            .copy(metadata = mapOf("ingressKind" to IngressKind.CDN_FRONTED.name, "cdnProviderProfile" to "{\"version\":999}"))
        assertEquals(SignedTransportProfileReadResult.Unsupported, binding.signedTransportProfile(endpointId))
    }

    @Test
    fun `invalid signed CDN profile fails closed`() {
        val binding = EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443)
            .withIngressKind(IngressKind.CDN_FRONTED)
            .copy(metadata = mapOf("ingressKind" to IngressKind.CDN_FRONTED.name, "cdnProviderProfile" to "{\"version\":2}"))
        assertEquals(SignedTransportProfileReadResult.Invalid, binding.signedTransportProfile(endpointId))
    }

    @Test
    fun `typed CDN profile is bound to the exact endpoint identity supplied by caller`() {
        val profile = CdnProviderCapabilityProfileTestFixtures.profile()
        val binding = CdnProviderCapabilityProfileTestFixtures.binding().withCdnProviderProfile(profile)
        val result = binding.signedTransportProfile(endpointId) as SignedTransportProfileReadResult.Parsed
        assertEquals(endpointId, result.profile.endpointId)
        assertEquals(TransportKind.XRAY_XHTTP, result.profile.transportKind)
    }
}

private object CdnProviderCapabilityProfileTestFixtures {
    fun profile() = CdnProviderCapabilityProfile(
        provider = "example", asn = 64512,
        hosts = CdnHostnames("edge.example", "cdn.example", "origin.example", "origin-tls.example", "control.example"),
        xhttp = CdnXhttpPolicy(CdnXhttpMode.PACKET_UP, "/xhttp/", CdnUplinkHttpMethod.POST, CdnPaddingPlacement.QUERY, 1, 64, emptyMap(), emptyMap(), emptyMap()),
        tls = CdnTlsPolicy(CdnMinimumTlsVersion.TLS_1_3, setOf("h2"), "edge.example", "chrome"),
        requests = CdnRequestPolicy("origin.example", CdnCachePolicy.BYPASS_REQUIRED, true, 1024, 1000),
        supportedExits = setOf(EndpointId("exit-a")), minimumClientVersionCode = 1,
        minimumXrayCoreVersion = "26.7.28", requiredClientCapabilities = setOf("xhttp"),
    )

    fun binding() = EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443)
        .withIngressKind(IngressKind.CDN_FRONTED)
}
