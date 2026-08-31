package net.pocvpn.client.provisioning

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8B3A - narrow tests for the new boundary only: exact request field
 * shape, response parsing, 401 mapping, malformed-response rejection. Not
 * a live network test - see the manual live-test procedure instead for
 * that.
 */
class ProvisioningClientTest {

    private val validKey = "e2sIl+TFOY99CMiZqodvjKVS2UM1pY3H7wHfZuBChF0="
    private val validSuccessBody = JSONObject()
        .put("client_tunnel_ip", "10.77.0.2")
        .put("gateway_public_key", "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=")
        .put("gateway_tunnel_ip", "10.77.0.1")
        .put("endpoint_host", "152.70.43.1")
        .put("endpoint_port", 51820)
        .toString()

    @Test
    fun `request body is exactly the single public_key field`() {
        val body = ProvisioningClient.buildRequestBody(validKey)
        val parsed = JSONObject(body)
        assertEquals(setOf("public_key"), parsed.keys().asSequence().toSet())
        assertEquals(validKey, parsed.getString("public_key"))
    }

    @Test
    fun `valid success body parses into Success with all five fields`() {
        val result = ProvisioningClient.mapHttpResponse(200, validSuccessBody)
        assertTrue(result is ProvisioningResult.Success)
        val success = result as ProvisioningResult.Success
        assertEquals("10.77.0.2", success.clientTunnelIp)
        assertEquals("9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=", success.gatewayPublicKey)
        assertEquals("10.77.0.1", success.gatewayTunnelIp)
        assertEquals("152.70.43.1", success.endpointHost)
        assertEquals(51820, success.endpointPort)
    }

    @Test
    fun `201 status also parses as success`() {
        val result = ProvisioningClient.mapHttpResponse(201, validSuccessBody)
        assertTrue(result is ProvisioningResult.Success)
    }

    @Test
    fun `401 maps to Unauthorized regardless of body`() {
        val result = ProvisioningClient.mapHttpResponse(401, """{"error":"unauthorized"}""")
        assertEquals(ProvisioningResult.Unauthorized, result)
    }

    @Test
    fun `other non-2xx status maps to NetworkError`() {
        val result = ProvisioningClient.mapHttpResponse(503, "")
        assertTrue(result is ProvisioningResult.NetworkError)
    }

    @Test
    fun `non-JSON success body is rejected as malformed`() {
        val result = ProvisioningClient.mapHttpResponse(200, "not json")
        assertTrue(result is ProvisioningResult.MalformedResponse)
    }

    @Test
    fun `success body missing a required field is rejected as malformed`() {
        val incomplete = JSONObject()
            .put("client_tunnel_ip", "10.77.0.2")
            .put("gateway_tunnel_ip", "10.77.0.1")
            .put("endpoint_host", "152.70.43.1")
            .put("endpoint_port", 51820)
            .toString() // missing gateway_public_key
        val result = ProvisioningClient.mapHttpResponse(200, incomplete)
        assertTrue(result is ProvisioningResult.MalformedResponse)
    }

    @Test
    fun `success body with malformed IPv4 is rejected as malformed`() {
        val bad = JSONObject()
            .put("client_tunnel_ip", "not-an-ip")
            .put("gateway_public_key", "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=")
            .put("gateway_tunnel_ip", "10.77.0.1")
            .put("endpoint_host", "152.70.43.1")
            .put("endpoint_port", 51820)
            .toString()
        val result = ProvisioningClient.mapHttpResponse(200, bad)
        assertTrue(result is ProvisioningResult.MalformedResponse)
    }

    @Test
    fun `success body with an out-of-range IPv4 octet is rejected as malformed - not merely shape-matched`() {
        // B13 consolidated review fix (finding 7) - "999.999.999.999" has
        // the RIGHT shape but is not a real IPv4 address; a looser
        // regex-only check used to admit it, which would then reach
        // ClientTunnelIdentityStore.write()'s own strict validation and
        // throw deep inside MainViewModel.activateDevice() instead of
        // being rejected cleanly here.
        val bad = JSONObject()
            .put("client_tunnel_ip", "999.999.999.999")
            .put("gateway_public_key", "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=")
            .put("gateway_tunnel_ip", "10.77.0.1")
            .put("endpoint_host", "152.70.43.1")
            .put("endpoint_port", 51820)
            .toString()
        val result = ProvisioningClient.mapHttpResponse(200, bad)
        assertTrue(result is ProvisioningResult.MalformedResponse)
    }

    @Test
    fun `success body with out-of-range port is rejected as malformed`() {
        val bad = JSONObject()
            .put("client_tunnel_ip", "10.77.0.2")
            .put("gateway_public_key", "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=")
            .put("gateway_tunnel_ip", "10.77.0.1")
            .put("endpoint_host", "152.70.43.1")
            .put("endpoint_port", 70000)
            .toString()
        val result = ProvisioningClient.mapHttpResponse(200, bad)
        assertTrue(result is ProvisioningResult.MalformedResponse)
    }

    // --- B8C2A: POST /v1/activate outgoing request contract ---

    @Test
    fun `activate request targets the activate endpoint with POST semantics`() {
        val request = ProvisioningClient.buildActivateRequest(validKey, "some-activation-credential")
        assertEquals("https://152.70.43.1/v1/activate", request.url)
    }

    @Test
    fun `activate request Authorization header is exactly Bearer plus the activation credential`() {
        val request = ProvisioningClient.buildActivateRequest(validKey, "my-activation-credential-123")
        assertEquals("Bearer my-activation-credential-123", request.headers["Authorization"])
        assertEquals("application/json", request.headers["Content-Type"])
    }

    @Test
    fun `activate request body contains exactly the supplied public_key and nothing else`() {
        val request = ProvisioningClient.buildActivateRequest(validKey, "irrelevant-credential")
        val parsed = JSONObject(request.body)
        assertEquals(setOf("public_key"), parsed.keys().asSequence().toSet())
        assertEquals(validKey, parsed.getString("public_key"))
    }

    @Test
    fun `activate request body never contains the activation credential`() {
        val credential = "SHOULD-NEVER-APPEAR-IN-BODY"
        val request = ProvisioningClient.buildActivateRequest(validKey, credential)
        assertTrue(!request.body.contains(credential))
    }

    // --- B8C2: POST /v1/activate response mapping ---

    @Test
    fun `activate 200 status parses into Success just like provision`() {
        val result = ProvisioningClient.mapActivateResponse(200, validSuccessBody)
        assertTrue(result is ProvisioningResult.Success)
    }

    @Test
    fun `activate 401 maps to Unauthorized regardless of body`() {
        val result = ProvisioningClient.mapActivateResponse(401, """{"error":"unauthorized"}""")
        assertEquals(ProvisioningResult.Unauthorized, result)
    }

    @Test
    fun `activate 403 revoked maps to Revoked`() {
        val result = ProvisioningClient.mapActivateResponse(403, """{"error":"revoked"}""")
        assertEquals(ProvisioningResult.Revoked, result)
    }

    @Test
    fun `activate 403 expired maps to Expired`() {
        val result = ProvisioningClient.mapActivateResponse(403, """{"error":"expired"}""")
        assertEquals(ProvisioningResult.Expired, result)
    }

    @Test
    fun `activate 403 device_limit_reached maps to DeviceLimitReached`() {
        val result = ProvisioningClient.mapActivateResponse(403, """{"error":"device_limit_reached"}""")
        assertEquals(ProvisioningResult.DeviceLimitReached, result)
    }

    @Test
    fun `activate 403 with unrecognized or missing error code falls back to Unauthorized`() {
        assertEquals(ProvisioningResult.Unauthorized, ProvisioningClient.mapActivateResponse(403, """{"error":"something_new"}"""))
        assertEquals(ProvisioningResult.Unauthorized, ProvisioningClient.mapActivateResponse(403, "not json"))
    }

    @Test
    fun `activate 400 maps to BadRequest`() {
        val result = ProvisioningClient.mapActivateResponse(400, """{"error":"invalid_public_key"}""")
        assertEquals(ProvisioningResult.BadRequest, result)
    }

    @Test
    fun `activate 503 and 504 map to ServiceUnavailable`() {
        assertEquals(ProvisioningResult.ServiceUnavailable, ProvisioningClient.mapActivateResponse(503, """{"error":"activation_store_unavailable"}"""))
        assertEquals(ProvisioningResult.ServiceUnavailable, ProvisioningClient.mapActivateResponse(504, """{"error":"provisioning_timeout"}"""))
    }

    @Test
    fun `activate other non-mapped status falls back to NetworkError`() {
        val result = ProvisioningClient.mapActivateResponse(500, """{"error":"internal_error"}""")
        assertTrue(result is ProvisioningResult.NetworkError)
    }

    // --- B14: endpoint-aware activation/Xray-fetch requests target the requested host ---

    @Test
    fun `the 2-arg activate request still targets Germany's own edge - byte-for-byte unchanged`() {
        val request = ProvisioningClient.buildActivateRequest(validKey, "cred")
        assertEquals("https://152.70.43.1/v1/activate", request.url)
    }

    @Test
    fun `the 3-arg activate request targets the given endpoint host, not Germany's`() {
        val request = ProvisioningClient.buildActivateRequest(validKey, "cred", "16.170.208.231")
        assertEquals("https://16.170.208.231/v1/activate", request.url)
    }

    @Test
    fun `the 3-arg xray-profile request targets the given endpoint host`() {
        val request = ProvisioningClient.buildXrayProfileRequest(validKey, "cred", "16.170.208.231")
        assertEquals("https://16.170.208.231/v1/xray-profile", request.url)
    }

    @Test
    fun `the 3-arg xray-tls-profile request targets the given endpoint host and still carries the tls transport field`() {
        val request = ProvisioningClient.buildXrayTlsProfileRequest(validKey, "cred", "16.170.208.231")
        assertEquals("https://16.170.208.231/v1/xray-profile", request.url)
        assertEquals("tls", JSONObject(request.body).getString("transport"))
    }
}
