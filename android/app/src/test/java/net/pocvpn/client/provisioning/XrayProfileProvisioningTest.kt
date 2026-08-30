package net.pocvpn.client.provisioning

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8K4A - narrow tests for POST /v1/xray-profile only: exact request shape,
 * successful snake_case -> XrayProfileResult mapping, malformed/missing
 * fields, invalid port, 401, 403 revoked/device_not_bound, 503. Not a live
 * network test.
 */
class XrayProfileProvisioningTest {

    private val validKey = "e2sIl+TFOY99CMiZqodvjKVS2UM1pY3H7wHfZuBChF0="
    // B8K6A - REALITY's public key is url-safe base64, UNPADDED (the exact
    // shape the pinned `xray x25519` tool emits and the server's own
    // config.py/gateway_config_renderer validate against - see
    // XrayVlessRealityConfig.REALITY_PUBLIC_KEY_REGEX for the client-side
    // config validator already using this same shape). Deliberately NOT an
    // AWG/WireGuard-shaped standard-base64-with-padding string (a prior,
    // now-fixed bug used exactly that wrong shape here, which happened to
    // still satisfy ProvisioningClient's own then-incorrect regex - masking
    // that every real server response was actually being rejected).
    private val validRealityPublicKey = "SyAfSiFzknNPgsUS8_guGt3-N9_0DRFnUPKNuruEuEU"
    private val validUuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f"

    private fun validSuccessBody(): JSONObject = JSONObject()
        .put("server_address", "152.70.43.1")
        .put("server_port", 443)
        .put("uuid", validUuid)
        .put("flow", "xtls-rprx-vision")
        .put("server_name", "www.microsoft.com")
        .put("fingerprint", "chrome")
        .put("reality_public_key", validRealityPublicKey)
        .put("short_id", "a1b2c3d4")

    // --- request contract ---

    @Test
    fun `xray-profile request targets the xray-profile endpoint with POST semantics`() {
        val request = ProvisioningClient.buildXrayProfileRequest(validKey, "some-credential")
        assertEquals("https://152.70.43.1/v1/xray-profile", request.url)
    }

    @Test
    fun `xray-profile request Authorization header is exactly Bearer plus the credential`() {
        val request = ProvisioningClient.buildXrayProfileRequest(validKey, "my-activation-credential-123")
        assertEquals("Bearer my-activation-credential-123", request.headers["Authorization"])
        assertEquals("application/json", request.headers["Content-Type"])
    }

    @Test
    fun `xray-profile request body contains exactly the supplied public_key and nothing else`() {
        val request = ProvisioningClient.buildXrayProfileRequest(validKey, "irrelevant-credential")
        val parsed = JSONObject(request.body)
        assertEquals(setOf("public_key"), parsed.keys().asSequence().toSet())
        assertEquals(validKey, parsed.getString("public_key"))
    }

    @Test
    fun `xray-profile request body never contains the credential`() {
        val credential = "SHOULD-NEVER-APPEAR-IN-BODY"
        val request = ProvisioningClient.buildXrayProfileRequest(validKey, credential)
        assertTrue(!request.body.contains(credential))
    }

    // --- success mapping ---

    @Test
    fun `valid success body maps into Success with all eight fields`() {
        val result = ProvisioningClient.mapXrayProfileResponse(200, validSuccessBody().toString())
        assertTrue(result is XrayProfileResult.Success)
        val success = result as XrayProfileResult.Success
        assertEquals("152.70.43.1", success.serverAddress)
        assertEquals(443, success.serverPort)
        assertEquals(validUuid, success.uuid)
        assertEquals("xtls-rprx-vision", success.flow)
        assertEquals("www.microsoft.com", success.serverName)
        assertEquals("chrome", success.fingerprint)
        assertEquals(validRealityPublicKey, success.realityPublicKey)
        assertEquals("a1b2c3d4", success.shortId)
    }

    @Test
    fun `201 status also parses as success`() {
        val result = ProvisioningClient.mapXrayProfileResponse(201, validSuccessBody().toString())
        assertTrue(result is XrayProfileResult.Success)
    }

    @Test
    fun `success body maps to net_pocvpn_client_identity_XrayProfile via toXrayProfile`() {
        val result = ProvisioningClient.mapXrayProfileResponse(200, validSuccessBody().toString()) as XrayProfileResult.Success
        val profile = result.toXrayProfile()
        assertEquals("152.70.43.1", profile.server)
        assertEquals(443, profile.serverPort)
        assertEquals(validUuid, profile.uuid)
        assertEquals("xtls-rprx-vision", profile.flow)
        assertEquals("www.microsoft.com", profile.serverName)
        assertEquals("chrome", profile.fingerprint)
        assertEquals(validRealityPublicKey, profile.realityPublicKey)
        assertEquals("a1b2c3d4", profile.shortId)
    }

    // --- malformed / missing fields ---

    @Test
    fun `non-JSON success body is rejected as malformed`() {
        val result = ProvisioningClient.mapXrayProfileResponse(200, "not json")
        assertTrue(result is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing server_address is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("server_address") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing uuid is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("uuid") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body with malformed uuid is rejected as malformed`() {
        val body = validSuccessBody().put("uuid", "not-a-uuid").toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing flow is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("flow") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing server_name is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("server_name") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing fingerprint is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("fingerprint") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing reality_public_key is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("reality_public_key") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body with malformed reality_public_key is rejected as malformed`() {
        val body = validSuccessBody().put("reality_public_key", "not-a-key").toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing short_id is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("short_id") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body with non-hex short_id is rejected as malformed`() {
        val body = validSuccessBody().put("short_id", "not-hex!!").toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    // --- invalid port ---

    @Test
    fun `success body with out-of-range server_port is rejected as malformed`() {
        val body = validSuccessBody().put("server_port", 70000).toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body missing server_port is rejected as malformed`() {
        val body = validSuccessBody().apply { remove("server_port") }.toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    @Test
    fun `success body with zero server_port is rejected as malformed`() {
        val body = validSuccessBody().put("server_port", 0).toString()
        assertTrue(ProvisioningClient.mapXrayProfileResponse(200, body) is XrayProfileResult.MalformedResponse)
    }

    // --- status mapping ---

    @Test
    fun `401 maps to Unauthorized regardless of body`() {
        val result = ProvisioningClient.mapXrayProfileResponse(401, """{"error":"unauthorized"}""")
        assertEquals(XrayProfileResult.Unauthorized, result)
    }

    @Test
    fun `403 revoked maps to Revoked`() {
        val result = ProvisioningClient.mapXrayProfileResponse(403, """{"error":"revoked"}""")
        assertEquals(XrayProfileResult.Revoked, result)
    }

    @Test
    fun `403 device_not_bound maps to DeviceNotBound`() {
        val result = ProvisioningClient.mapXrayProfileResponse(403, """{"error":"device_not_bound"}""")
        assertEquals(XrayProfileResult.DeviceNotBound, result)
    }

    @Test
    fun `403 with unrecognized or missing error code falls back to Unauthorized`() {
        assertEquals(XrayProfileResult.Unauthorized, ProvisioningClient.mapXrayProfileResponse(403, """{"error":"something_new"}"""))
        assertEquals(XrayProfileResult.Unauthorized, ProvisioningClient.mapXrayProfileResponse(403, "not json"))
    }

    @Test
    fun `503 maps to ServiceUnavailable`() {
        val result = ProvisioningClient.mapXrayProfileResponse(503, """{"error":"xray_profile_store_unavailable"}""")
        assertEquals(XrayProfileResult.ServiceUnavailable, result)
    }

    @Test
    fun `other non-mapped status falls back to NetworkError`() {
        val result = ProvisioningClient.mapXrayProfileResponse(500, """{"error":"internal_error"}""")
        assertTrue(result is XrayProfileResult.NetworkError)
    }
}
