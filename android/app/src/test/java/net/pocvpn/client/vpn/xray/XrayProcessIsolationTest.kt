package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.AesGcmKeyEncryptor
import net.pocvpn.client.identity.EncryptedPayload
import net.pocvpn.client.vpn.TransportFailureKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Xray runs in its own process (one Go runtime per process). These pin the
 * two things that now cross the process boundary: lifecycle events (codec)
 * and the XHTTP session config (encrypted file handoff, never plaintext).
 */
class XrayProcessIsolationTest {

    @Test
    fun `every runtime event survives the broadcast codec unchanged`() {
        val events = listOf(
            XrayRuntimeEvent.Started(42),
            XrayRuntimeEvent.Stopped(-7),
            XrayRuntimeEvent.Failed(Long.MAX_VALUE, "core failed", null),
            XrayRuntimeEvent.Failed(1, "relay data-plane health check failed", TransportFailureKind.RELAY_DATA_PLANE_LOST),
            XrayRuntimeState.relayHealthLostEvent(9, net.pocvpn.client.transport.TransportKind.XRAY_XHTTP),
        )
        events.forEach { e -> assertEquals(e, XrayProcessBridge.decode(XrayProcessBridge.encode(e))) }
    }

    @Test
    fun `unknown event type or failure kind fails safe`() {
        assertNull(XrayProcessBridge.decode(XrayProcessBridge.Encoded("bogus", 1, null, null)))
        val failed = XrayProcessBridge.decode(XrayProcessBridge.Encoded("failed", 1, null, "NOT_A_KIND")) as XrayRuntimeEvent.Failed
        assertNull(failed.failureKind)
        assertEquals("unknown", failed.reason)
    }

    private fun config() = XrayVlessXhttpConfig(
        server = "edge.aknova.pp.ua", serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        tlsServerName = "edge.aknova.pp.ua", fingerprint = "chrome",
        minimumTlsVersion = XrayXhttpMinimumTlsVersion.TLS_1_3, alpn = "h2",
        xhttpHost = "edge.aknova.pp.ua", xhttpPath = "/nova-xhttp/",
        queryParameters = mapOf("a" to "1"), headers = mapOf("X-Test" to "v"),
        mode = XrayXhttpMode.PACKET_UP,
        uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST,
        maxEachPostBytes = 524288,
        paddingPlacement = XrayXhttpPaddingPlacement.QUERY,
        paddingMinBytes = 1, paddingMaxBytes = 64,
    )

    @Test
    fun `xhttp config codec is lossless, including null padding`() {
        assertEquals(config(), decodeXhttpConfig(encodeXhttpConfig(config())))
        val noPadding = config().copy(paddingPlacement = null, paddingMinBytes = null, paddingMaxBytes = null)
        assertEquals(noPadding, decodeXhttpConfig(encodeXhttpConfig(noPadding)))
        assertNull(decodeXhttpConfig("{not json"))
    }

    /** Reversible fake: XOR "encryption" so the test can prove the file is not plaintext. */
    private class XorEncryptor : AesGcmKeyEncryptor {
        override fun encrypt(plaintext: ByteArray) = EncryptedPayload(byteArrayOf(7), plaintext.map { (it.toInt() xor 0x5A).toByte() }.toByteArray())
        override fun decrypt(payload: EncryptedPayload) = payload.ciphertext.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
    }

    @Test
    fun `file handoff is consumed exactly once and never stores the uuid in plaintext`() {
        val dir = createTempDir("xhttp")
        try {
            val handoff = XhttpSessionConfigStore.FileHandoff(File(dir, "xhttp-sessions"), XorEncryptor())
            handoff.write(5, encodeXhttpConfig(config()))
            val raw = File(dir, "xhttp-sessions/5.bin").readText()
            assertFalse(raw.contains("3fa85f64"))
            assertEquals(config(), handoff.readAndDelete(5)?.let(::decodeXhttpConfig))
            assertNull(handoff.readAndDelete(5))
            assertFalse(File(dir, "xhttp-sessions/5.bin").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `remove deletes an unconsumed handoff and stale files are swept`() {
        val dir = createTempDir("xhttp")
        try {
            val handoff = XhttpSessionConfigStore.FileHandoff(File(dir, "xhttp-sessions"), XorEncryptor())
            handoff.write(6, encodeXhttpConfig(config()))
            handoff.delete(6)
            assertNull(handoff.readAndDelete(6))
            handoff.write(7, encodeXhttpConfig(config()))
            handoff.deleteStale(maxAgeMs = 0, now = System.currentTimeMillis() + 1_000)
            assertNull(handoff.readAndDelete(7))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a corrupted handoff file yields no config and is removed`() {
        val dir = createTempDir("xhttp")
        try {
            val sub = File(dir, "xhttp-sessions").apply { mkdirs() }
            File(sub, "8.bin").writeText("garbage")
            val handoff = XhttpSessionConfigStore.FileHandoff(sub, XorEncryptor())
            assertNull(handoff.readAndDelete(8))
            assertTrue(!File(sub, "8.bin").exists())
        } finally {
            dir.deleteRecursively()
        }
    }
}
