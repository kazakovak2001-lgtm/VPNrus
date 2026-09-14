package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class XhttpSessionConfigStoreTest {
    private fun config() = XrayVlessXhttpConfig(
        server = "edge.aknova.pp.ua", serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        tlsServerName = "edge.aknova.pp.ua", fingerprint = "chrome",
        minimumTlsVersion = XrayXhttpMinimumTlsVersion.TLS_1_3, alpn = "h2",
        xhttpHost = "edge.aknova.pp.ua", xhttpPath = "/nova-xhttp/",
        queryParameters = emptyMap(), headers = emptyMap(),
        mode = XrayXhttpMode.PACKET_UP,
        uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST,
        maxEachPostBytes = 524288,
        paddingPlacement = XrayXhttpPaddingPlacement.QUERY,
        paddingMinBytes = 1, paddingMaxBytes = 64,
    )

    @Test
    fun `handoff consumes only the matching session once`() {
        val sessionId = Long.MIN_VALUE
        val value = config()
        XhttpSessionConfigStore.put(sessionId, value)
        try {
            assertNull(XhttpSessionConfigStore.consume(sessionId + 1))
            assertEquals(value, XhttpSessionConfigStore.consume(sessionId))
            assertNull(XhttpSessionConfigStore.consume(sessionId))
        } finally {
            XhttpSessionConfigStore.remove(sessionId)
        }
    }

    @Test
    fun `failed start can remove unconsumed config`() {
        val sessionId = Long.MIN_VALUE + 2
        XhttpSessionConfigStore.put(sessionId, config())
        XhttpSessionConfigStore.remove(sessionId)
        assertNull(XhttpSessionConfigStore.consume(sessionId))
    }
}
