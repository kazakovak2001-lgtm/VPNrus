package net.pocvpn.client.vpn.shadowsocks

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ShadowsocksRuntimeConfigWriterTest {

    private fun tempDir() = kotlin.io.path.createTempDirectory("shadowsocks-config-test").toFile().apply { deleteOnExit() }

    @Test
    fun `write produces the flat single-server JSON schema sslocal's -c flag expects`() {
        val dir = tempDir()
        val file = ShadowsocksRuntimeConfigWriter.write(dir, "runtime_config.json", "203.0.113.10", 8388, "2022-blake3-aes-256-gcm", "a-base64-key==")

        val json = JSONObject(file.readText())
        assertEquals("203.0.113.10", json.getString("server"))
        assertEquals(8388, json.getInt("server_port"))
        assertEquals("2022-blake3-aes-256-gcm", json.getString("method"))
        assertEquals("a-base64-key==", json.getString("password"))
    }

    @Test
    fun `delete removes the file`() {
        val dir = tempDir()
        val file = ShadowsocksRuntimeConfigWriter.write(dir, "runtime_config.json", "h", 1, "m", "k")
        assertTrue(file.exists())

        ShadowsocksRuntimeConfigWriter.delete(file)

        assertFalse(file.exists())
    }

    @Test
    fun `delete on an already-deleted file does not throw`() {
        val dir = tempDir()
        val file = ShadowsocksRuntimeConfigWriter.write(dir, "runtime_config.json", "h", 1, "m", "k")
        file.delete()

        ShadowsocksRuntimeConfigWriter.delete(file) // must not throw
    }
}
