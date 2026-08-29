package net.pocvpn.client.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayProfileTest {

    private val profile = XrayProfile(
        server = "vless.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "ab12cd34",
    )

    @Test
    fun `toJson then fromJson round-trips every field`() {
        val restored = XrayProfile.fromJson(profile.toJson())
        assertEquals(profile, restored)
    }

    @Test
    fun `toString never contains the raw uuid, reality public key, or short id`() {
        val rendered = profile.toString()
        assertFalse(rendered.contains(profile.uuid))
        assertFalse(rendered.contains(profile.realityPublicKey))
        assertFalse(rendered.contains(profile.shortId))
        assertTrue(rendered.contains("<redacted>"))
    }

    @Test
    fun `toJson does contain the raw credential fields - that is what gets encrypted before storage`() {
        val json = profile.toJson()
        assertTrue(json.contains(profile.uuid))
    }
}
