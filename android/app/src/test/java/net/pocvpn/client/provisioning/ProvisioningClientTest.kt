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
}
