package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.reachability.CdnCachePolicy
import net.pocvpn.client.reachability.CdnClientRuntimeCapabilities
import net.pocvpn.client.reachability.CdnHostnames
import net.pocvpn.client.reachability.CdnMinimumTlsVersion
import net.pocvpn.client.reachability.CdnPaddingPlacement
import net.pocvpn.client.reachability.CdnProviderCapabilityProfile
import net.pocvpn.client.reachability.CdnRequestPolicy
import net.pocvpn.client.reachability.CdnTlsPolicy
import net.pocvpn.client.reachability.CdnUplinkHttpMethod
import net.pocvpn.client.reachability.CdnXhttpMode
import net.pocvpn.client.reachability.CdnXhttpPolicy
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.withCdnProviderProfile
import net.pocvpn.client.reachability.withIngressKind
import net.pocvpn.client.relay.IngressClientProfile
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CdnXhttpRuntimeConfigResolverTest {
    private val exitId = EndpointId("exit-a")

    private fun provider(
        mode: CdnXhttpMode = CdnXhttpMode.PACKET_UP,
        method: CdnUplinkHttpMethod = CdnUplinkHttpMethod.POST,
        alpn: String = "h2",
    ) = CdnProviderCapabilityProfile(
        provider = "provider-a",
        asn = 64512,
        hosts = CdnHostnames(
            "edge.example.org",
            "technical.example.org",
            "origin.example.org",
            "origin.example.org",
            "control.example.org",
        ),
        xhttp = CdnXhttpPolicy(
            mode = mode,
            path = "/xhttp/",
            uplinkHttpMethod = method,
            paddingPlacement = CdnPaddingPlacement.QUERY,
            paddingMinBytes = 1,
            paddingMaxBytes = 64,
            queryParameters = emptyMap(),
            headers = emptyMap(),
            extraParameters = emptyMap(),
        ),
        tls = CdnTlsPolicy(
            minimumVersion = CdnMinimumTlsVersion.TLS_1_3,
            alpn = setOf(alpn),
            clientServerName = "edge.example.org",
            clientFingerprint = "chrome",
        ),
        requests = CdnRequestPolicy(
            originHostHeader = "origin.example.org",
            cachePolicy = CdnCachePolicy.BYPASS_REQUIRED,
            streamingSupported = true,
            maxRequestBodyBytes = 524288,
            requestTimeoutMillis = 30000,
        ),
        supportedExits = setOf(exitId),
        minimumClientVersionCode = 1,
        minimumXrayCoreVersion = "26.7.28",
        requiredClientCapabilities = setOf("xhttp", "cdn-profile-v2"),
    )

    private fun runtime(profile: CdnProviderCapabilityProfile) = CdnClientRuntimeCapabilities(
        clientVersionCode = 1,
        xrayCoreVersion = "26.7.28",
        clientCapabilities = setOf("xhttp", "cdn-profile-v2"),
        xhttpModes = setOf(profile.xhttp.mode),
        uplinkHttpMethods = setOf(profile.xhttp.uplinkHttpMethod),
        paddingPlacements = setOf(CdnPaddingPlacement.QUERY),
        tlsFingerprints = setOf("chrome"),
        alpn = profile.tls.alpn,
        minimumTlsVersions = setOf(CdnMinimumTlsVersion.TLS_1_3),
        supportsStreaming = true,
        maxRequestBodyBytes = 524288,
        maxRequestTimeoutMillis = 30000,
    )

    private fun ingressProfile(profile: CdnProviderCapabilityProfile): IngressClientProfile {
        val binding = EndpointTransportBinding(
            TransportKind.XRAY_XHTTP,
            "edge.example.org",
            443,
        )
            .withIngressKind(IngressKind.CDN_FRONTED)
            .withCdnProviderProfile(profile)

        return IngressClientProfile(
            ingressEndpointId = EndpointId("ingress-a"),
            ingressBinding = binding,
            transport = TransportKind.XRAY_XHTTP,
            ingressKind = IngressKind.CDN_FRONTED,
            tlsProfile = XrayTlsProfile(
                server = binding.host,
                serverPort = binding.port,
                uuid = "11111111-1111-1111-1111-111111111111",
                serverName = profile.tls.clientServerName,
                fingerprint = profile.tls.clientFingerprint,
            ),
            profileVersion = 1,
            issuedAtEpochMillis = 1000L,
        )
    }

    private fun resolve(profile: CdnProviderCapabilityProfile): CdnXhttpRuntimeResolution =
        CdnXhttpRuntimeConfigResolver.resolve(
            ingressProfile(profile),
            exitId,
            runtime(profile),
        )

    @Test
    fun `packet-up POST over h2 is the executable B35 slice`() {
        assertTrue(resolve(provider()) is CdnXhttpRuntimeResolution.Ready)
    }

    @Test
    fun `stream-up is rejected even when runtime advertises it`() {
        assertEquals(
            CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.XHTTP_MODE_NOT_EXECUTABLE,
            ),
            resolve(provider(mode = CdnXhttpMode.STREAM_UP)),
        )
    }

    @Test
    fun `PUT is rejected even when runtime advertises it`() {
        assertEquals(
            CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.XHTTP_UPLINK_METHOD_NOT_EXECUTABLE,
            ),
            resolve(provider(method = CdnUplinkHttpMethod.PUT)),
        )
    }

    @Test
    fun `h3 is rejected until QUIC establishment is bounded`() {
        assertEquals(
            CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.HTTP3_DIAL_NOT_BOUNDED,
            ),
            resolve(provider(alpn = "h3")),
        )
    }
}