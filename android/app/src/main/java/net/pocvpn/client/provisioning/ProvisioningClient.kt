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
    // B8C2 - POST /v1/activate (gateway/api/handler.py's _handle_activate):
    // same B8B2A HTTPS edge, same {"public_key": "..."} body shape and
    // Authorization: Bearer <credential> header shape as ENDPOINT_URL above,
    // reused verbatim via buildRequestBody/parseSuccessBody - only the path
    // and the error-status mapping differ.
    private const val ACTIVATE_ENDPOINT_URL = "https://152.70.43.1/v1/activate"
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
    fun provision(publicKey: String, bearerToken: String): ProvisioningResult =
        execute(buildProvisionRequest(publicKey, bearerToken), ::mapHttpResponse)

    /**
     * B8C2 - POST /v1/activate: activation credential -> existing device
     * public key -> validated provisioning response, exactly like
     * provision() above but against the activation endpoint and with
     * mapActivateResponse's richer error mapping. Never logs
     * activationCredential - only the structural ProvisioningResult is
     * ever returned.
     */
    fun activate(publicKey: String, activationCredential: String): ProvisioningResult =
        execute(buildActivateRequest(publicKey, activationCredential), ::mapActivateResponse)

    /**
     * B8C2 - the exact outgoing request shape (url/headers/body), built as
     * plain data with NO network I/O. `internal` so the request CONTRACT
     * (method target, exact Authorization header, exact JSON body) is
     * unit-testable directly, the same reasoning as buildRequestBody below -
     * instead of only indirectly through a live connection.
     */
    internal data class OutgoingRequest(
        val url: String,
        val headers: Map<String, String>,
        val body: String,
    )

    internal fun buildProvisionRequest(publicKey: String, bearerToken: String): OutgoingRequest =
        OutgoingRequest(url = ENDPOINT_URL, headers = authHeaders(bearerToken), body = buildRequestBody(publicKey))

    internal fun buildActivateRequest(publicKey: String, activationCredential: String): OutgoingRequest =
        OutgoingRequest(
            url = ACTIVATE_ENDPOINT_URL,
            headers = authHeaders(activationCredential),
            body = buildRequestBody(publicKey),
        )

    private fun authHeaders(credential: String): Map<String, String> = mapOf(
        "Content-Type" to "application/json",
        "Authorization" to "Bearer $credential",
    )

    private fun execute(request: OutgoingRequest, mapResponse: (Int, String) -> ProvisioningResult): ProvisioningResult {
        val connection = try {
            URL(request.url).openConnection() as HttpsURLConnection
        } catch (e: IOException) {
            return ProvisioningResult.NetworkError("could not open connection: ${e.javaClass.simpleName}")
        }

        return try {
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "POST"
            connection.doOutput = true
            request.headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }

            connection.outputStream.use { it.write(request.body.toByteArray(Charsets.UTF_8)) }

            val status = connection.responseCode
            val rawBody = if (status == 200 || status == 201) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                connection.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            }
            mapResponse(status, rawBody)
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

    /**
     * POST /v1/activate response mapping (gateway/api/handler.py's
     * _handle_activate) - `internal` so each status/error_code combination
     * is unit-testable without a live HTTP connection. The 403 body's
     * "error" field is the ONLY thing distinguishing revoked/expired/
     * device_limit_reached, since all three share HTTP 403.
     */
    internal fun mapActivateResponse(status: Int, rawBody: String): ProvisioningResult = when (status) {
        200, 201 -> parseSuccessBody(rawBody)
        401 -> ProvisioningResult.Unauthorized
        403 -> when (errorCode(rawBody)) {
            "revoked" -> ProvisioningResult.Revoked
            "expired" -> ProvisioningResult.Expired
            "device_limit_reached" -> ProvisioningResult.DeviceLimitReached
            else -> ProvisioningResult.Unauthorized
        }
        400 -> ProvisioningResult.BadRequest
        503, 504 -> ProvisioningResult.ServiceUnavailable
        else -> ProvisioningResult.NetworkError("unexpected HTTP status $status")
    }

    /** Reads {"error": "..."} - the shape every _error() response uses (gateway/api/handler.py). */
    private fun errorCode(rawBody: String): String? = try {
        JSONObject(rawBody).optString("error", "").ifBlank { null }
    } catch (e: JSONException) {
        null
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
