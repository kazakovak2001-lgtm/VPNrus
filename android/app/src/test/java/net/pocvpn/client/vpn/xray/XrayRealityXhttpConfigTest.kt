package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayRealityXhttpProfileStore
import net.pocvpn.client.identity.SecureXrayRealityXhttpProfileRepository
import net.pocvpn.client.identity.XrayRealityXhttpProfile
import net.pocvpn.client.reachability.EndpointId
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** VLESS over XHTTP secured by REALITY: stored profile -> config -> rendered Xray JSON. */
class XrayRealityXhttpConfigTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val uuid = "11111111-2222-3333-4444-555555555555"
    private val publicKey = "A".repeat(43)

    private val profile = XrayRealityXhttpProfile(
        server = "16.170.208.231",
        serverPort = 8443,
        uuid = uuid,
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = publicKey,
        shortId = "ab12cd34",
        xhttpPath = "/nova-rx/",
        mode = "packet-up",
        uplinkHttpMethod = "POST",
    )

    private fun outbound(config: XrayVlessRealityXhttpConfig): JSONObject =
        JSONObject(XrayConfigRenderer.render(config)).getJSONArray("outbounds").getJSONObject(0)

    @Test
    fun `renders a vless outbound with xhttp network and reality security`() {
        val out = outbound(profile.toXrayVlessRealityXhttpConfig()!!)
        assertEquals("vless", out.getString("protocol"))
        val stream = out.getJSONObject("streamSettings")
        assertEquals("xhttp", stream.getString("network"))
        assertEquals("reality", stream.getString("security"))
        assertFalse(stream.has("tlsSettings"))

        val reality = stream.getJSONObject("realitySettings")
        assertEquals("www.microsoft.com", reality.getString("serverName"))
        assertEquals(publicKey, reality.getString("publicKey"))
        assertEquals("ab12cd34", reality.getString("shortId"))
        assertEquals("chrome", reality.getString("fingerprint"))

        val xhttp = stream.getJSONObject("xhttpSettings")
        assertEquals("/nova-rx/", xhttp.getString("path"))
        assertEquals("packet-up", xhttp.getString("mode"))
        assertEquals("POST", xhttp.getString("uplinkHTTPMethod"))
        assertFalse("REALITY dials the server address directly", xhttp.has("host"))

        val vnext = out.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals("16.170.208.231", vnext.getString("address"))
        assertEquals(8443, vnext.getInt("port"))
    }

    @Test
    fun `never renders an XTLS flow - Vision is not valid over XHTTP`() {
        val user = outbound(profile.toXrayVlessRealityXhttpConfig()!!)
            .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
            .getJSONArray("users").getJSONObject(0)
        assertEquals(uuid, user.getString("id"))
        assertFalse(user.has("flow"))
    }

    @Test
    fun `its outbound is counted as tunnel traffic for the data-plane check`() {
        val tag = outbound(profile.toXrayVlessRealityXhttpConfig()!!).getString("tag")
        assertTrue(tag in XrayConfigRenderer.TUNNEL_OUTBOUND_TAGS)
    }

    @Test
    fun `an unknown stored mode or uplink method fails closed`() {
        assertNull(profile.copy(mode = "stream-two").toXrayVlessRealityXhttpConfig())
        assertNull(profile.copy(uplinkHttpMethod = "PATCH").toXrayVlessRealityXhttpConfig())
    }

    @Test
    fun `validation reuses the REALITY rules and checks the xhttp path`() {
        val valid = profile.toXrayVlessRealityXhttpConfig()!!
        assertTrue(validateXrayVlessRealityXhttpConfig(valid) is XrayRealityXhttpValidationResult.Valid)

        val badReality = validateXrayVlessRealityXhttpConfig(valid.copy(realityPublicKey = "short", fingerprint = "opera"))
            as XrayRealityXhttpValidationResult.Invalid
        assertTrue(XrayConfigValidationError.InvalidRealityPublicKey in badReality.realityErrors)
        assertTrue(XrayConfigValidationError.UnsupportedFingerprint in badReality.realityErrors)
        assertFalse(badReality.invalidPath)

        val badPath = validateXrayVlessRealityXhttpConfig(valid.copy(xhttpPath = "nova-rx"))
            as XrayRealityXhttpValidationResult.Invalid
        assertTrue(badPath.invalidPath)
    }

    @Test
    fun `toString never reveals the uuid, public key or short id`() {
        for (text in listOf(profile.toString(), profile.toXrayVlessRealityXhttpConfig().toString())) {
            assertFalse(text.contains(uuid))
            assertFalse(text.contains(publicKey))
            assertFalse(text.contains("ab12cd34"))
        }
    }

    @Test
    fun `profile round-trips through the encrypted endpoint-scoped store`() = runTest {
        val dir = tmp.newFolder()
        val repository = SecureXrayRealityXhttpProfileRepository(
            FileXrayRealityXhttpProfileStore(dir, EndpointId("stockholm")),
            FakeAesGcmKeyEncryptor(),
        )
        assertNull(repository.getProfileOrNull())
        repository.saveProfile(profile)
        assertEquals(profile, repository.getProfileOrNull())
        val files = dir.list()!!.toList()
        assertEquals(1, files.size)
        assertTrue(files.single().startsWith("xray_reality_xhttp_profile_stockholm-"))
        repository.clearProfile()
        assertNull(repository.getProfileOrNull())
    }
}
