package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.xray.XrayXhttpMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** B-WL-R6 - the signed XHTTP facts of a REALITY+XHTTP binding: parsed only when valid, fail closed otherwise. */
class RealityXhttpBindingMetadataTest {

    private fun binding(metadata: Map<String, String>, kind: TransportKind = TransportKind.XRAY_REALITY_XHTTP) =
        EndpointTransportBinding(kind, "203.0.113.77", 2083, metadata)

    @Test
    fun `valid path and every supported mode parse`() {
        mapOf("auto" to XrayXhttpMode.AUTO, "packet-up" to XrayXhttpMode.PACKET_UP, "stream-up" to XrayXhttpMode.STREAM_UP, "stream-one" to XrayXhttpMode.STREAM_ONE)
            .forEach { (wire, mode) ->
                val r = binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/", REALITY_XHTTP_MODE_METADATA_KEY to wire)).realityXhttpProfile()
                assertEquals(RealityXhttpBindingReadResult.Parsed(RealityXhttpBindingProfile("/nx7/", mode)), r)
            }
    }

    @Test
    fun `missing mode defaults to auto (xray-core's own default), missing path is Missing - no default path`() {
        assertEquals(XrayXhttpMode.AUTO, (binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/")).realityXhttpProfile() as RealityXhttpBindingReadResult.Parsed).profile.mode)
        assertEquals(RealityXhttpBindingReadResult.Missing, binding(emptyMap()).realityXhttpProfile())
    }

    @Test
    fun `malformed path, unknown mode and wrong binding kind are Invalid`() {
        assertEquals(RealityXhttpBindingReadResult.Invalid, binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/a?b=c/")).realityXhttpProfile())
        assertEquals(RealityXhttpBindingReadResult.Invalid, binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/", REALITY_XHTTP_MODE_METADATA_KEY to "grpc")).realityXhttpProfile())
        assertEquals(RealityXhttpBindingReadResult.Invalid, binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/"), TransportKind.XRAY_REALITY).realityXhttpProfile())
    }

    @Test
    fun `signedTransportProfile - a new kind never gets Legacy semantics - missing facts are Invalid`() {
        val id = EndpointId("gw1")
        assertEquals(SignedTransportProfileReadResult.Invalid, binding(emptyMap()).signedTransportProfile(id))
        val parsed = binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/")).signedTransportProfile(id)
        assertTrue(parsed is SignedTransportProfileReadResult.Parsed && parsed.profile is SignedTransportProfile.RealityXhttp)
    }

    @Test
    fun `the new kind is appended last - every existing signed-manifest ordinal is unchanged`() {
        assertEquals(TransportKind.entries.last(), TransportKind.XRAY_REALITY_XHTTP)
        assertEquals(listOf("AMNEZIA_WG", "XRAY_REALITY", "QUIC", "TLS_TCP", "XRAY_XHTTP", "SHADOWSOCKS_2022"), TransportKind.entries.dropLast(1).map { it.name })
    }
}
