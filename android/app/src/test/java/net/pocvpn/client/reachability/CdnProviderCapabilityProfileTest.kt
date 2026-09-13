package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class CdnProviderCapabilityProfileTest {
    private fun profile() = CdnProviderCapabilityProfile(
        provider = "example-provider", asn = 64512,
        hosts = CdnHostnames("edge.example.org", "edge.cdn.example.org", "origin.example.org", "tls.origin.example.org"),
        xhttp = CdnXhttpPolicy(CdnXhttpMode.PACKET_UP, "/tunnel/", CdnUplinkHttpMethod.POST,
            CdnPaddingPlacement.QUERY, 0, 64, mapOf("padding" to "bounded"),
            mapOf("User-Agent" to "Nova-test"), mapOf("policy" to "test-only")),
        tls = CdnTlsPolicy(CdnMinimumTlsVersion.TLS_1_3, setOf("h2"), "edge.example.org", "chrome"),
        requests = CdnRequestPolicy("origin.example.org", CdnCachePolicy.BYPASS_REQUIRED, true, 1048576, 30000),
        supportedExits = setOf(EndpointId("exit-b"), EndpointId("exit-a")),
        minimumClientVersionCode = 1, minimumXrayCoreVersion = "25.8.3",
        requiredClientCapabilities = setOf("xhttp", "cdn-profile-v1"),
    )

    private fun binding() = EndpointTransportBinding(TransportKind.QUIC, "edge.example.org", 443,
        mapOf("unrelated" to "preserved")).withIngressKind(IngressKind.CDN_FRONTED)

    private fun mutate(change: (JSONObject) -> Unit): EndpointTransportBinding {
        val b = binding().withCdnProviderProfile(profile())
        val json = JSONObject(b.metadata.getValue("cdnProviderProfile"))
        change(json)
        return b.copy(metadata = b.metadata + ("cdnProviderProfile" to json.toString()))
    }

    @Test fun `complete profile round trips without changing unrelated metadata`() {
        val b = binding().withCdnProviderProfile(profile())
        assertEquals(CdnProviderProfileReadResult.Parsed(profile()), b.cdnProviderProfile())
        assertEquals("preserved", b.metadata["unrelated"])
        assertEquals(IngressKind.CDN_FRONTED, b.ingressKind())
        assertEquals("origin.example.org", (b.cdnProviderProfile() as CdnProviderProfileReadResult.Parsed).profile.hosts.originHostname)
    }

    @Test fun `legacy binding is missing not invalid and its canonical bytes are unchanged`() {
        val b = binding()
        val m = manifest(b)
        val before = ManifestCanonicalizer.canonicalBytes(m)
        assertEquals(CdnProviderProfileReadResult.Missing, b.cdnProviderProfile())
        assertArrayEquals(before, ManifestCanonicalizer.canonicalBytes(m))
        assertEquals(m, ManifestCanonicalizer.decode(before))
    }

    @Test fun `profile is covered by existing canonical format and content changes signed bytes`() {
        val b = binding().withCdnProviderProfile(profile())
        val m = manifest(b)
        val bytes = ManifestCanonicalizer.canonicalBytes(m)
        assertEquals(m, ManifestCanonicalizer.decode(bytes))
        val changed = b.withCdnProviderProfile(profile().copy(requests = profile().requests.copy(cachePolicy = CdnCachePolicy.UNKNOWN)))
        assertFalse(bytes.contentEquals(ManifestCanonicalizer.canonicalBytes(manifest(changed))))
    }

    @Test fun `collection ordering does not change signed profile bytes`() {
        val p = profile()
        val reordered = p.copy(supportedExits = p.supportedExits.reversed().toSet(),
            requiredClientCapabilities = p.requiredClientCapabilities.reversed().toSet(),
            xhttp = p.xhttp.copy(headers = linkedMapOf("X-Z" to "z", "X-A" to "a")))
        val otherOrder = reordered.copy(xhttp = reordered.xhttp.copy(headers = linkedMapOf("X-A" to "a", "X-Z" to "z")))
        assertEquals(binding().withCdnProviderProfile(reordered), binding().withCdnProviderProfile(otherOrder))
        assertEquals(binding().withCdnProviderProfile(p), binding().withCdnProviderProfile(
            p.copy(supportedExits = p.supportedExits.reversed().toSet(), requiredClientCapabilities = p.requiredClientCapabilities.reversed().toSet())))
    }

    @Test fun `unknown version is distinct and malformed versions never coerce`() {
        assertEquals(CdnProviderProfileReadResult.UnsupportedVersion, mutate { it.put("version", 2) }.cdnProviderProfile())
        for (v in listOf<Any>("1", true, 1.5, JSONObject.NULL)) {
            assertEquals(CdnProviderProfileReadResult.Invalid, mutate { it.put("version", v) }.cdnProviderProfile())
        }
    }

    @Test fun `missing unknown and mistyped policy fields fail closed`() {
        val changes: List<(JSONObject) -> Unit> = listOf(
            { it.remove("requests") }, { it.put("futurePolicy", true) },
            { it.getJSONObject("xhttp").put("mode", "FUTURE_MODE") },
            { it.getJSONObject("requests").put("streamingSupported", "true") },
            { it.getJSONObject("xhttp").put("paddingMaxBytes", 4294967296L) },
            { it.put("minimumClientVersionCode", 0) },
            { it.put("asn", 4294967296L) },
            { it.getJSONObject("tls").put("alpn", org.json.JSONArray(listOf("h2", "h2"))) },
        )
        changes.forEach { assertEquals(CdnProviderProfileReadResult.Invalid, mutate(it).cdnProviderProfile()) }
    }

    @Test fun `profile cannot migrate to a direct binding or a different public host`() {
        val b = binding().withCdnProviderProfile(profile())
        assertEquals(CdnProviderProfileReadResult.Invalid, b.withIngressKind(IngressKind.DIRECT_IP).cdnProviderProfile())
        assertEquals(CdnProviderProfileReadResult.Invalid, b.copy(host = "other.example.org").cdnProviderProfile())
        assertEquals(CdnProviderProfileReadResult.Invalid, b.copy(metadata = b.metadata - "ingressKind").cdnProviderProfile())
        assertThrows(IllegalArgumentException::class.java) { binding().withIngressKind(IngressKind.DIRECT_IP).withCdnProviderProfile(profile()) }
        assertEquals(CdnProviderProfileReadResult.Parsed(profile()), b.copy(host = "EDGE.EXAMPLE.ORG").cdnProviderProfile())
    }

    @Test fun `hostname URL path and header injection are rejected`() {
        for (host in listOf("https://edge.example.org", "edge.example.org:443", "*.example.org", "a..org", "127.0.0.1", "a\r\nb.org")) {
            assertThrows(IllegalArgumentException::class.java) { profile().hosts.copy(clientFacingHostname = host) }
        }
        for (path in listOf("relative", "//other.example.org/", "/path?token=x", "/path#fragment", "/a\r\nb")) {
            assertThrows(IllegalArgumentException::class.java) { profile().xhttp.copy(path = path) }
        }
        for (name in listOf("Authorization", "COOKIE", "Host", "Transfer-Encoding")) {
            assertThrows(IllegalArgumentException::class.java) { profile().xhttp.copy(headers = mapOf(name to "value")) }
        }
        assertThrows(IllegalArgumentException::class.java) { profile().xhttp.copy(headers = mapOf("X-Test" to "a\r\nb")) }
        assertThrows(IllegalArgumentException::class.java) { profile().xhttp.copy(headers = mapOf("X-Test" to "a", "x-test" to "b")) }
    }

    @Test fun `invalid padding range and oversized metadata cannot be published`() {
        assertThrows(IllegalArgumentException::class.java) { profile().xhttp.copy(paddingMinBytes = 65) }
        assertThrows(IllegalArgumentException::class.java) { profile().xhttp.copy(paddingPlacement = CdnPaddingPlacement.NONE) }
        val oversized = profile().copy(xhttp = profile().xhttp.copy(extraParameters = (1..16).associate { "item$it" to "x".repeat(256) }))
        assertThrows(IllegalArgumentException::class.java) { binding().withCdnProviderProfile(oversized) }
        assertEquals(CdnProviderProfileReadResult.Invalid,
            binding().copy(metadata = binding().metadata + ("cdnProviderProfile" to "x".repeat(4097))).cdnProviderProfile())
    }

    @Test fun `malformed JSON is invalid without disclosing input`() {
        assertEquals(CdnProviderProfileReadResult.Invalid,
            binding().copy(metadata = binding().metadata + ("cdnProviderProfile" to "{broken")).cdnProviderProfile())
        val valid = binding().withCdnProviderProfile(profile())
        assertEquals(CdnProviderProfileReadResult.Invalid, valid.copy(metadata = valid.metadata +
            ("cdnProviderProfile" to (valid.metadata.getValue("cdnProviderProfile") + " {}"))).cdnProviderProfile())
    }

    @Test fun `mutating constructor input cannot bypass validation when publishing`() {
        val headers = mutableMapOf("X-Test" to "value")
        val p = profile().copy(xhttp = profile().xhttp.copy(headers = headers))
        headers["Authorization"] = "not-a-real-credential"
        assertThrows(IllegalArgumentException::class.java) { binding().withCdnProviderProfile(p) }
    }

    private fun manifest(b: EndpointTransportBinding) = EndpointManifest(1, 1000, 2000,
        listOf(EndpointDescriptor(EndpointId("ingress"), setOf(EndpointRole.INGRESS), "test", "test", transports = listOf(b))), "test-key")
}
