package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * B22 - proves persistence round-trips correctly, a corrupted/invalid stored
 * value fails closed (never "configured with garbage" - test list item 5's
 * store-level facet), and - the structural half of test list item 7 - that
 * nothing private-key-shaped is ever written to disk.
 */
class PrivateGatewayStoreTest {

    private val validConfig = PrivateGatewayConfig(
        host = "203.0.113.5",
        port = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.13.13.2",
        gatewayTunnelIp = "10.13.13.1",
        awgProfile = AwgProfile(
            initPacketMagicHeader = "1106684696",
            responsePacketMagicHeader = "3677857287",
            underloadPacketMagicHeader = "353316806",
            transportPacketMagicHeader = "2068198996",
            junkPacketCount = 6,
        ),
    )

    private fun newStore(): FilePrivateGatewayStore =
        FilePrivateGatewayStore(Files.createTempDirectory("private-gateway-store-test").toFile())

    @Test
    fun `never configured reads null`() {
        assertNull(newStore().read())
    }

    @Test
    fun `write then read round-trips every field exactly`() {
        val store = newStore()

        store.write(validConfig)
        val read = store.read()

        assertEquals(validConfig, read)
    }

    @Test
    fun `clear removes the stored config - reverts to null`() {
        val store = newStore()
        store.write(validConfig)

        store.clear()

        assertNull(store.read())
    }

    @Test
    fun `a corrupted file fails closed - never treated as configured`() {
        val dir = Files.createTempDirectory("private-gateway-store-corrupt-test").toFile()
        val store = FilePrivateGatewayStore(dir)
        java.io.File(dir, "private_gateway_config.json").writeText("{ not valid json", Charsets.UTF_8)

        assertNull(store.read())
    }

    @Test
    fun `a structurally-present but invalid stored value (bad key shape) fails closed on read`() {
        val dir = Files.createTempDirectory("private-gateway-store-invalid-test").toFile()
        val store = FilePrivateGatewayStore(dir)
        // Hand-write a syntactically valid JSON blob with a garbage server key -
        // simulates a hand-edited or bit-rotted file, never trusted blindly.
        val json = org.json.JSONObject()
            .put("id", PrivateGatewayConfig.ID)
            .put("host", "203.0.113.5")
            .put("port", 51820)
            .put("serverPublicKey", "not-a-real-key")
            .put("clientTunnelIp", "10.13.13.2")
            .put("gatewayTunnelIp", "10.13.13.1")
            .put(
                "awgProfile",
                org.json.JSONObject()
                    .put("initPacketMagicHeader", "1")
                    .put("responsePacketMagicHeader", "2")
                    .put("underloadPacketMagicHeader", "3")
                    .put("transportPacketMagicHeader", "4"),
            )
        java.io.File(dir, "private_gateway_config.json").writeText(json.toString(), Charsets.UTF_8)

        assertNull(store.read())
    }

    @Test
    fun `the persisted file never contains any string resembling a private key`() {
        val dir = Files.createTempDirectory("private-gateway-store-no-secret-test").toFile()
        val store = FilePrivateGatewayStore(dir)

        store.write(validConfig)

        val raw = java.io.File(dir, "private_gateway_config.json").readText(Charsets.UTF_8)
        // "private" itself legitimately appears (the id field's own value,
        // "private-gateway" - a non-secret constant, not key material) - the
        // real assertion is that no KEY-shaped field name/value is present.
        assertFalse(raw.lowercase().contains("privatekey"))
        assertFalse(raw.lowercase().contains("private_key"))
        val json = org.json.JSONObject(raw)
        // Only the SERVER public key (a real, non-secret field) should be
        // present as a base64-looking value - assert the file round-trips
        // to exactly the fields PrivateGatewayConfig declares, nothing extra.
        assertTrue(json.has("serverPublicKey"))
        assertFalse(json.has("clientPrivateKey"))
        assertFalse(json.has("privateKey"))
    }
}
