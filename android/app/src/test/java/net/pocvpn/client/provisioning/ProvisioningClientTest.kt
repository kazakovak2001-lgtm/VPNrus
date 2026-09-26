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

    @Test
    fun `XHTTP ingress request targets signed control plane and names xhttp explicitly`() {
        val request = ProvisioningClient.buildIngressProfileRequest(
            validKey, "cred", "control.example.org", IngressProfileTransport.XHTTP,
        )
        assertEquals("https://control.example.org/v1/ingress-profile", request.url)
        assertEquals("xhttp", JSONObject(request.body).getString("transport"))
    }

    @Test
    fun `XHTTP ingress response accepts identity plus pinned edge coordinates only`() {
        val body = JSONObject()
            .put("ingress_endpoint_id", "cdn-ingress-1")
            .put("ingress_kind", "CDN_FRONTED")
            .put("transport", "xhttp")
            .put("server_address", "edge.example.org")
            .put("server_port", 443)
            .put("uuid", "11111111-1111-1111-1111-111111111111")
            .put("profile_version", 1)
            .put("issued_at", 1000L)
            .put("expires_at", JSONObject.NULL)
            .put("probe_url", "https://exit.example.org/v1/relay-health")
            .put("probe_token", "opaque")
            .toString()

        val result = ProvisioningClient.mapIngressProfileResponse(200, body)
        assertTrue(result is IngressProfileResult.Success)
        val success = result as IngressProfileResult.Success
        assertEquals(IngressProfileTransport.XHTTP, success.transport)
        assertEquals("edge.example.org", success.serverAddress)
        assertEquals("", success.serverName)
        assertEquals("", success.fingerprint)
    }

    @Test
    fun `XHTTP ingress response rejects unsigned TLS policy injection`() {
        val body = JSONObject()
            .put("ingress_endpoint_id", "cdn-ingress-1")
            .put("ingress_kind", "CDN_FRONTED")
            .put("transport", "xhttp")
            .put("server_address", "edge.example.org")
            .put("server_port", 443)
            .put("uuid", "11111111-1111-1111-1111-111111111111")
            .put("server_name", "unsigned.example.org")
            .put("profile_version", 1)
            .put("issued_at", 1000L)
            .put("expires_at", JSONObject.NULL)
            .put("probe_url", "https://exit.example.org/v1/relay-health")
            .put("probe_token", "opaque")
            .toString()

        assertTrue(
            ProvisioningClient.mapIngressProfileResponse(200, body)
                is IngressProfileResult.MalformedResponse,
        )
    }

    // --- B64: Direct/EXIT XHTTP profile fetch (POST /v1/xray-profile, transport=xhttp) ---

    private val validXhttpKey = validKey
    private val validXhttpSuccessBody = JSONObject()
        .put("server_address", "edge.aknova.pp.ua")
        .put("server_port", 443)
        .put("uuid", "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f")
        .put("xhttp_host", "edge.aknova.pp.ua")
        .put("xhttp_path", "/nova-xhttp/")
        .put("mode", "packet-up")
        .put("uplink_http_method", "POST")
        .put("fingerprint", "chrome")
        .toString()

    @Test
    fun `the 3-arg xray-xhttp-profile request targets the given endpoint host and carries the xhttp transport field`() {
        val request = ProvisioningClient.buildXrayXhttpProfileRequest(validXhttpKey, "cred", "16.170.208.231")
        assertEquals("https://16.170.208.231/v1/xray-profile", request.url)
        assertEquals("xhttp", JSONObject(request.body).getString("transport"))
    }

    @Test
    fun `the 2-arg xray-xhttp-profile request still targets Germany's own edge`() {
        val request = ProvisioningClient.buildXrayXhttpProfileRequest(validXhttpKey, "cred")
        assertEquals("https://152.70.43.1/v1/xray-profile", request.url)
    }

    @Test
    fun `valid XHTTP success body parses into Success with all eight fields`() {
        val result = ProvisioningClient.mapXrayXhttpProfileResponse(200, validXhttpSuccessBody)
        assertTrue(result is XrayXhttpProfileResult.Success)
        val success = result as XrayXhttpProfileResult.Success
        assertEquals("edge.aknova.pp.ua", success.serverAddress)
        assertEquals(443, success.serverPort)
        assertEquals("3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f", success.uuid)
        assertEquals("edge.aknova.pp.ua", success.xhttpHost)
        assertEquals("/nova-xhttp/", success.xhttpPath)
        assertEquals("packet-up", success.mode)
        assertEquals("POST", success.uplinkHttpMethod)
        assertEquals("chrome", success.fingerprint)
    }

    @Test
    fun `Success maps strictly into XrayXhttpProfile via toXrayXhttpProfile`() {
        val success = ProvisioningClient.mapXrayXhttpProfileResponse(200, validXhttpSuccessBody) as XrayXhttpProfileResult.Success
        val profile = success.toXrayXhttpProfile()
        assertEquals("edge.aknova.pp.ua", profile.server)
        assertEquals(443, profile.serverPort)
        assertEquals("3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f", profile.uuid)
        assertEquals("edge.aknova.pp.ua", profile.xhttpHost)
        assertEquals("/nova-xhttp/", profile.xhttpPath)
        assertEquals("packet-up", profile.mode)
        assertEquals("POST", profile.uplinkHttpMethod)
        assertEquals("chrome", profile.fingerprint)
    }

    @Test
    fun `XHTTP response missing a required field is MalformedResponse`() {
        val missingXhttpPath = JSONObject(validXhttpSuccessBody).apply { remove("xhttp_path") }.toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, missingXhttpPath) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with a blank uuid is rejected`() {
        val blankUuid = JSONObject(validXhttpSuccessBody).put("uuid", "").toString()
        val result = ProvisioningClient.mapXrayXhttpProfileResponse(200, blankUuid)
        assertTrue(result is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with a malformed (non-UUID) uuid is rejected`() {
        val badUuid = JSONObject(validXhttpSuccessBody).put("uuid", "not-a-uuid").toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, badUuid) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with an out-of-range server_port is rejected`() {
        val badPort = JSONObject(validXhttpSuccessBody).put("server_port", 70000).toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, badPort) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with a missing server_port is rejected`() {
        val missingPort = JSONObject(validXhttpSuccessBody).apply { remove("server_port") }.toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, missingPort) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with a blank xhttp_host is rejected`() {
        val blankHost = JSONObject(validXhttpSuccessBody).put("xhttp_host", "").toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, blankHost) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with a blank xhttp_path is rejected`() {
        val blankPath = JSONObject(validXhttpSuccessBody).put("xhttp_path", "").toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, blankPath) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with an unrecognized mode value is rejected`() {
        val badMode = JSONObject(validXhttpSuccessBody).put("mode", "not-a-real-mode").toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, badMode) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with an unrecognized uplink_http_method value is rejected`() {
        val badMethod = JSONObject(validXhttpSuccessBody).put("uplink_http_method", "DELETE").toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, badMethod) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response with a blank fingerprint is rejected`() {
        val blankFingerprint = JSONObject(validXhttpSuccessBody).put("fingerprint", "").toString()
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(200, blankFingerprint) is XrayXhttpProfileResult.MalformedResponse)
    }

    @Test
    fun `XHTTP response body that is not valid JSON is MalformedResponse, never a raw-body leak`() {
        val result = ProvisioningClient.mapXrayXhttpProfileResponse(200, "not json") as XrayXhttpProfileResult.MalformedResponse
        assertTrue(!result.reason.contains("not json"))
    }

    @Test
    fun `XHTTP 401 maps to Unauthorized`() {
        assertEquals(XrayXhttpProfileResult.Unauthorized, ProvisioningClient.mapXrayXhttpProfileResponse(401, ""))
    }

    @Test
    fun `XHTTP 403 revoked maps to Revoked`() {
        assertEquals(XrayXhttpProfileResult.Revoked, ProvisioningClient.mapXrayXhttpProfileResponse(403, """{"error":"revoked"}"""))
    }

    @Test
    fun `XHTTP 403 device_not_bound maps to DeviceNotBound`() {
        assertEquals(XrayXhttpProfileResult.DeviceNotBound, ProvisioningClient.mapXrayXhttpProfileResponse(403, """{"error":"device_not_bound"}"""))
    }

    @Test
    fun `XHTTP 403 with unrecognized or missing error code falls back to Unauthorized`() {
        assertEquals(XrayXhttpProfileResult.Unauthorized, ProvisioningClient.mapXrayXhttpProfileResponse(403, """{"error":"something_new"}"""))
    }

    @Test
    fun `XHTTP 503 (including xray_xhttp_not_configured) maps to ServiceUnavailable`() {
        assertEquals(XrayXhttpProfileResult.ServiceUnavailable, ProvisioningClient.mapXrayXhttpProfileResponse(503, """{"error":"xray_xhttp_not_configured"}"""))
    }

    @Test
    fun `XHTTP unexpected status maps to NetworkError, never treated as success`() {
        assertTrue(ProvisioningClient.mapXrayXhttpProfileResponse(500, "") is XrayXhttpProfileResult.NetworkError)
    }

    // --- Russia field-test zero-touch enrollment: POST /v1/field-enroll ---

    private val validFieldEnrollSuccessBody = JSONObject()
        .put("activation_credential", "aVeryLongRandomLookingCredentialValue1234567890")
        .put("client_tunnel_ip", "10.77.0.2")
        .put("gateway_public_key", "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=")
        .put("gateway_tunnel_ip", "10.77.0.1")
        .put("endpoint_host", "152.70.43.1")
        .put("endpoint_port", 51820)
        .toString()

    @Test
    fun `field-enroll request carries no Authorization header at all`() {
        val request = ProvisioningClient.buildFieldEnrollRequest(validKey, "152.70.43.1")
        assertTrue(request.headers.keys.none { it.equals("Authorization", ignoreCase = true) })
    }

    @Test
    fun `field-enroll request body is exactly the single public_key field`() {
        val request = ProvisioningClient.buildFieldEnrollRequest(validKey, "152.70.43.1")
        val parsed = JSONObject(request.body)
        assertEquals(setOf("public_key"), parsed.keys().asSequence().toSet())
        assertEquals(validKey, parsed.getString("public_key"))
    }

    @Test
    fun `field-enroll request targets the given endpoint host's own field-enroll path`() {
        val request = ProvisioningClient.buildFieldEnrollRequest(validKey, "16.170.208.231")
        assertEquals("https://16.170.208.231/v1/field-enroll", request.url)
    }

    @Test
    fun `field-enroll valid success body parses into Success including the new credential field`() {
        val result = ProvisioningClient.mapFieldEnrollResponse(200, validFieldEnrollSuccessBody)
        assertTrue(result is FieldEnrollmentResult.Success)
        val success = result as FieldEnrollmentResult.Success
        assertEquals("aVeryLongRandomLookingCredentialValue1234567890", success.activationCredential)
        assertEquals("10.77.0.2", success.clientTunnelIp)
        assertEquals("152.70.43.1", success.endpointHost)
    }

    @Test
    fun `field-enroll success body missing the credential is rejected as malformed`() {
        val body = JSONObject(validFieldEnrollSuccessBody).apply { remove("activation_credential") }.toString()
        val result = ProvisioningClient.mapFieldEnrollResponse(200, body)
        assertTrue(result is FieldEnrollmentResult.MalformedResponse)
    }

    @Test
    fun `field-enroll 400 maps to BadRequest`() {
        assertEquals(FieldEnrollmentResult.BadRequest, ProvisioningClient.mapFieldEnrollResponse(400, """{"error":"invalid_public_key"}"""))
    }

    @Test
    fun `field-enroll 403 device_limit_reached maps to DeviceLimitReached`() {
        assertEquals(
            FieldEnrollmentResult.DeviceLimitReached,
            ProvisioningClient.mapFieldEnrollResponse(403, """{"error":"device_limit_reached"}"""),
        )
    }

    @Test
    fun `field-enroll 403 revoked maps to Revoked`() {
        assertEquals(FieldEnrollmentResult.Revoked, ProvisioningClient.mapFieldEnrollResponse(403, """{"error":"revoked"}"""))
    }

    @Test
    fun `field-enroll 503 maps to ServiceUnavailable`() {
        assertEquals(FieldEnrollmentResult.ServiceUnavailable, ProvisioningClient.mapFieldEnrollResponse(503, ""))
    }

    @Test
    fun `field-enroll non-JSON success body is rejected as malformed`() {
        assertTrue(ProvisioningClient.mapFieldEnrollResponse(200, "not json") is FieldEnrollmentResult.MalformedResponse)
    }
}
