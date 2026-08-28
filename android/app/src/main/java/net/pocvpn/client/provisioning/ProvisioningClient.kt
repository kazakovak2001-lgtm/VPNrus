package net.pocvpn.client.provisioning

import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * B8B3A - the smallest client for the one real endpoint this slice needs:
 * POST https://152.70.43.1/v1/peers, the B8B2A production HTTPS edge in
 * front of the existing, unchanged B8B1 pocvpn-api. Deliberately plain
 * `HttpsURLConnection`, not a new networking dependency (OkHttp/Retrofit/
 * Ktor) - this app makes exactly one outbound HTTP request today, and one
 * request does not justify a framework.
 *
 * TLS: standard platform CA validation only. No custom TrustManager, no
 * hostname-verifier override, no `trustAll` - B8B2A's certificate is a
 * publicly trusted Let's Encrypt IP-address certificate, so the platform
 * default is exactly what should be used, and deliberately weakening it
 * here would undermine the whole point of B8B2A.
 *
 * Never logs: the bearer token, the Authorization header, the request
 * body, or the raw response body - only the structural ProvisioningResult
 * is ever returned to a caller. Nothing in this file calls android.util.Log.
 */
object ProvisioningClient {

    private const val ENDPOINT_URL = "https://152.70.43.1/v1/peers"
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 10_000

    // Mirrors the server's own validation shape (gateway/api/wgkey.py,
    // gateway/lib/common.sh's is_valid_wg_key): 32 raw bytes, base64,
    // trailing '='. Not the authoritative check - the server is - but
    // catches a malformed/truncated field before it is ever trusted here.
    private val WG_KEY_REGEX = Regex("^[A-Za-z0-9+/]{43}=$")
    private val IPV4_REGEX = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")

    /**
     * Synchronous - the caller (MainViewModel) is responsible for running
     * this off the main thread (e.g. Dispatchers.IO).
     */
    fun provision(publicKey: String, bearerToken: String): ProvisioningResult {
        val connection = try {
            URL(ENDPOINT_URL).openConnection() as HttpsURLConnection
        } catch (e: IOException) {
            return ProvisioningResult.NetworkError("could not open connection: ${e.javaClass.simpleName}")
        }

        return try {
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Authorization", "Bearer $bearerToken")

            val requestBody = buildRequestBody(publicKey)
            connection.outputStream.use { it.write(requestBody.toByteArray(Charsets.UTF_8)) }

            val status = connection.responseCode
            val rawBody = if (status == 200 || status == 201) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                ""
            }
            mapHttpResponse(status, rawBody)
        } catch (e: IOException) {
            // Covers connection refused, TLS handshake/certificate failure,
            // DNS (n/a here - literal IP), and read/connect timeouts alike.
            ProvisioningResult.NetworkError("${e.javaClass.simpleName}: ${e.message ?: "I/O failure"}")
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Exactly one field, exactly "public_key" - the server rejects any
     * additional field (gateway/api/handler.py) - built directly rather
     * than through a generic serializer that might one day add more.
     * `internal` (not private) so the narrow request-shape test can assert
     * on it directly instead of only indirectly through a live connection.
     */
    internal fun buildRequestBody(publicKey: String): String =
        JSONObject().put("public_key", publicKey).toString()

    /**
     * Pure status-code + body -> ProvisioningResult mapping, with no
     * network I/O of its own - `internal` so 401 mapping and malformed-body
     * rejection are unit-testable without a live HTTP connection.
     */
    internal fun mapHttpResponse(status: Int, rawBody: String): ProvisioningResult = when (status) {
        200, 201 -> parseSuccessBody(rawBody)
        401 -> ProvisioningResult.Unauthorized
        else -> ProvisioningResult.NetworkError("unexpected HTTP status $status")
    }

    private fun parseSuccessBody(raw: String): ProvisioningResult {
        val json = try {
            JSONObject(raw)
        } catch (e: JSONException) {
            return ProvisioningResult.MalformedResponse("response body is not valid JSON")
        }

        val clientTunnelIp = json.optString("client_tunnel_ip", "")
        val gatewayPublicKey = json.optString("gateway_public_key", "")
        val gatewayTunnelIp = json.optString("gateway_tunnel_ip", "")
        val endpointHost = json.optString("endpoint_host", "")
        val endpointPort = json.optInt("endpoint_port", -1)

        if (!IPV4_REGEX.matches(clientTunnelIp)) {
            return ProvisioningResult.MalformedResponse("client_tunnel_ip missing or not a valid IPv4 address")
        }
        if (!WG_KEY_REGEX.matches(gatewayPublicKey)) {
            return ProvisioningResult.MalformedResponse("gateway_public_key missing or not a well-formed public key")
        }
        if (!IPV4_REGEX.matches(gatewayTunnelIp)) {
            return ProvisioningResult.MalformedResponse("gateway_tunnel_ip missing or not a valid IPv4 address")
        }
        if (endpointHost.isBlank()) {
            return ProvisioningResult.MalformedResponse("endpoint_host missing or blank")
        }
        if (endpointPort !in 1..65535) {
            return ProvisioningResult.MalformedResponse("endpoint_port missing or out of range")
        }

        return ProvisioningResult.Success(
            clientTunnelIp = clientTunnelIp,
            gatewayPublicKey = gatewayPublicKey,
            gatewayTunnelIp = gatewayTunnelIp,
            endpointHost = endpointHost,
            endpointPort = endpointPort,
        )
    }
}
