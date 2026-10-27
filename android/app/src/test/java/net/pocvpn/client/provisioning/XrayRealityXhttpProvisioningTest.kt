package net.pocvpn.client.provisioning

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** POST /v1/xray-profile, transport "reality-xhttp": request shape and response mapping. */
class XrayRealityXhttpProvisioningTest {

    private val uuid = "11111111-2222-3333-4444-555555555555"
    private val publicKey = "A".repeat(43)

    private fun body(vararg drop: String, overrides: Map<String, Any> = emptyMap()): String {
        val json = JSONObject()
            .put("server_address", "16.170.208.231")
            .put("server_port", 8443)
            .put("uuid", uuid)
            .put("server_name", "www.microsoft.com")
            .put("fingerprint", "chrome")
            .put("reality_public_key", publicKey)
            .put("short_id", "ab12cd34")
            .put("xhttp_path", "/nova-rx/")
            .put("mode", "packet-up")
            .put("uplink_http_method", "POST")
        drop.forEach { json.remove(it) }
        overrides.forEach { (k, v) -> json.put(k, v) }
        return json.toString()
    }

    @Test
    fun `request asks the endpoint's own xray-profile for the reality-xhttp transport`() {
        val request = ProvisioningClient.buildXrayRealityXhttpProfileRequest("pk", "cred", "16.170.208.231")
        assertEquals("https://16.170.208.231/v1/xray-profile", request.url)
        assertEquals("Bearer cred", request.headers["Authorization"])
        val json = JSONObject(request.body)
        assertEquals("reality-xhttp", json.getString("transport"))
        assertEquals("pk", json.getString("public_key"))
    }

    @Test
    fun `a complete response becomes Success with every field`() {
        val success = ProvisioningClient.mapXrayRealityXhttpProfileResponse(200, body())
            as XrayRealityXhttpProfileResult.Success
        val profile = success.toXrayRealityXhttpProfile()
        assertEquals("16.170.208.231", profile.server)
        assertEquals(8443, profile.serverPort)
        assertEquals("www.microsoft.com", profile.serverName)
        assertEquals(publicKey, profile.realityPublicKey)
        assertEquals("ab12cd34", profile.shortId)
        assertEquals("/nova-rx/", profile.xhttpPath)
        assertEquals("packet-up", profile.mode)
        assertEquals("POST", profile.uplinkHttpMethod)
    }

    @Test
    fun `every missing or malformed field is rejected without echoing its value`() {
        val cases = listOf(
            body("server_address"),
            body("server_port"),
            body(overrides = mapOf("uuid" to "not-a-uuid")),
            body("server_name"),
            body("fingerprint"),
            body(overrides = mapOf("reality_public_key" to "short")),
            body(overrides = mapOf("short_id" to "abc")),
            body(overrides = mapOf("xhttp_path" to "nova-rx")),
            body(overrides = mapOf("mode" to "stream-two")),
            body(overrides = mapOf("uplink_http_method" to "PATCH")),
            "not json",
        )
        for (raw in cases) {
            val result = ProvisioningClient.mapXrayRealityXhttpProfileResponse(200, raw)
            assertTrue(raw, result is XrayRealityXhttpProfileResult.MalformedResponse)
            val reason = (result as XrayRealityXhttpProfileResult.MalformedResponse).reason
            assertFalse(reason.contains("not-a-uuid"))
        }
    }

    @Test
    fun `status codes map like the other xray profile transports`() {
        assertEquals(XrayRealityXhttpProfileResult.Unauthorized, ProvisioningClient.mapXrayRealityXhttpProfileResponse(401, ""))
        assertEquals(
            XrayRealityXhttpProfileResult.Revoked,
            ProvisioningClient.mapXrayRealityXhttpProfileResponse(403, """{"error":"revoked"}"""),
        )
        assertEquals(
            XrayRealityXhttpProfileResult.DeviceNotBound,
            ProvisioningClient.mapXrayRealityXhttpProfileResponse(403, """{"error":"device_not_bound"}"""),
        )
        assertEquals(
            XrayRealityXhttpProfileResult.ServiceUnavailable,
            ProvisioningClient.mapXrayRealityXhttpProfileResponse(503, """{"error":"xray_reality_xhttp_not_configured"}"""),
        )
        assertTrue(ProvisioningClient.mapXrayRealityXhttpProfileResponse(500, "") is XrayRealityXhttpProfileResult.NetworkError)
    }

    @Test
    fun `Success toString never reveals the uuid, public key or short id`() {
        val text = ProvisioningClient.mapXrayRealityXhttpProfileResponse(200, body()).toString()
        assertFalse(text.contains(uuid))
        assertFalse(text.contains(publicKey))
        assertFalse(text.contains("ab12cd34"))
    }
}
