package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Test

class CdnCachePolicyCompatibilityTest {
    private val exit = EndpointId("exit-a")

    private fun profile(cachePolicy: CdnCachePolicy) = CdnProviderCapabilityProfile(
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
            CdnXhttpMode.PACKET_UP,
            "/xhttp/",
            CdnUplinkHttpMethod.POST,
            CdnPaddingPlacement.QUERY,
            1,
            64,
            emptyMap(),
            emptyMap(),
            emptyMap(),
        ),
        tls = CdnTlsPolicy(
            CdnMinimumTlsVersion.TLS_1_3,
            setOf("h2"),
            "edge.example.org",
            "chrome",
        ),
        requests = CdnRequestPolicy(
            "origin.example.org",
            cachePolicy,
            true,
            524288,
            30000,
        ),
        supportedExits = setOf(exit),
        minimumClientVersionCode = 1,
        minimumXrayCoreVersion = "26.7.28",
        requiredClientCapabilities = setOf("cdn-profile-v1", "xhttp"),
    )

    private fun binding(cachePolicy: CdnCachePolicy) =
        EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example.org", 443)
            .withIngressKind(IngressKind.CDN_FRONTED)
            .withCdnProviderProfile(profile(cachePolicy))

    private val runtime = CdnClientRuntimeCapabilities(
        clientVersionCode = 1,
        xrayCoreVersion = "26.7.28",
        clientCapabilities = setOf("cdn-profile-v1", "xhttp"),
        xhttpModes = setOf(CdnXhttpMode.PACKET_UP),
        uplinkHttpMethods = setOf(CdnUplinkHttpMethod.POST),
        paddingPlacements = setOf(CdnPaddingPlacement.QUERY),
        tlsFingerprints = setOf("chrome"),
        alpn = setOf("h2"),
        minimumTlsVersions = setOf(CdnMinimumTlsVersion.TLS_1_3),
        supportsStreaming = true,
        maxRequestBodyBytes = 524288,
        maxRequestTimeoutMillis = 30000,
    )

    @Test
    fun `UNKNOWN and UNSUPPORTED cache policy are fail closed`() {
        for (policy in listOf(CdnCachePolicy.UNKNOWN, CdnCachePolicy.UNSUPPORTED)) {
            assertEquals(
                CdnClientCompatibility.Incompatible(CdnClientCompatibilityFailure.CACHE_POLICY_UNSAFE),
                binding(policy).cdnClientCompatibility(exit, runtime),
            )
        }
    }

    @Test
    fun `NONE padding is fail closed even if runtime accidentally advertises it`() {
        val noneProfile = profile(CdnCachePolicy.BYPASS_REQUIRED).copy(
            xhttp = profile(CdnCachePolicy.BYPASS_REQUIRED).xhttp.copy(
                paddingPlacement = CdnPaddingPlacement.NONE,
                paddingMinBytes = 0,
                paddingMaxBytes = 0,
            ),
        )
        val noneBinding = EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example.org", 443)
            .withIngressKind(IngressKind.CDN_FRONTED)
            .withCdnProviderProfile(noneProfile)
        val mistakenRuntime = runtime.copy(
            paddingPlacements = runtime.paddingPlacements + CdnPaddingPlacement.NONE,
        )

        assertEquals(
            CdnClientCompatibility.Incompatible(CdnClientCompatibilityFailure.PADDING_UNSUPPORTED),
            noneBinding.cdnClientCompatibility(exit, mistakenRuntime),
        )
    }

    @Test
    fun `BYPASS_REQUIRED remains compatible when all other requirements match`() {
        assertEquals(
            CdnClientCompatibility.Compatible(profile(CdnCachePolicy.BYPASS_REQUIRED)),
            binding(CdnCachePolicy.BYPASS_REQUIRED).cdnClientCompatibility(exit, runtime),
        )
    }
}
