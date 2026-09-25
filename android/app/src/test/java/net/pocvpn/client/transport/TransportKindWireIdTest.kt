package net.pocvpn.client.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * B-WL-R6 - TransportKind's stable wire ids are a protocol contract (signed
 * manifests, persisted local stores). Explicitness is enforced at compile time
 * (wireId is a mandatory enum constructor argument); these tests pin the
 * values and keep ordinal out of every codec.
 */
class TransportKindWireIdTest {

    /** FROZEN. Append new rows only; never edit or delete one. */
    private val frozen = linkedMapOf(
        "AMNEZIA_WG" to 0,
        "XRAY_REALITY" to 1,
        "QUIC" to 2,
        "TLS_TCP" to 3,
        "XRAY_XHTTP" to 4,
        "SHADOWSOCKS_2022" to 5,
        "XRAY_REALITY_XHTTP" to 6,
    )

    @Test
    fun `every historical wire id is unchanged and every kind has a frozen id`() {
        assertEquals(frozen.keys, TransportKind.entries.map { it.name }.toSet())
        TransportKind.entries.forEach { assertEquals(it.name, frozen.getValue(it.name), it.wireId) }
    }

    @Test
    fun `wire ids are unique and non-negative`() {
        val ids = TransportKind.entries.map { it.wireId }
        assertEquals("duplicate wire id in $ids", ids.size, ids.toSet().size)
        assertTrue(ids.all { it >= 0 })
    }

    @Test
    fun `ids 0-5 equal the values every existing manifest already carries`() {
        // Historical wire value == declaration ordinal at the time each kind was introduced.
        listOf("AMNEZIA_WG", "XRAY_REALITY", "QUIC", "TLS_TCP", "XRAY_XHTTP", "SHADOWSOCKS_2022").forEachIndexed { historicalOrdinal, name ->
            assertEquals(name, historicalOrdinal, TransportKind.valueOf(name).wireId)
        }
    }

    @Test
    fun `fromWireId round-trips every kind and returns null for an unknown id`() {
        TransportKind.entries.forEach { assertEquals(it, TransportKind.fromWireId(it.wireId)) }
        listOf(-1, 7, 42, Int.MAX_VALUE, Int.MIN_VALUE).forEach { assertNull("id $it", TransportKind.fromWireId(it)) }
    }

    @Test
    fun `no codec or persisted store derives a TransportKind wire value from ordinal`() {
        val main = File("src/main/java/net/pocvpn/client")
        val codecFiles = listOf(
            "reachability/EndpointManifest.kt",
            "reachability/PathHistoryStore.kt",
            "smartconnect/ConnectionOutcomeStore.kt",
        )
        val forbidden = listOf(
            Regex("""\b(kind|transport)\.ordinal\b"""),
            Regex("""TransportKind\.(entries|values\(\))\s*(\.getOrNull\(|\[)"""),
        )
        codecFiles.forEach { path ->
            val file = File(main, path)
            assertTrue("missing ${file.absolutePath}", file.isFile)
            val text = file.readText()
            forbidden.forEach { pattern -> assertTrue("$path uses ${pattern.pattern}", pattern.find(text) == null) }
        }
    }
}
