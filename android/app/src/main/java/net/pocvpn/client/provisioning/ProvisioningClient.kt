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
    // B14 - the production/Germany gateway's own edge host, kept as the
    // default target for every 2-arg overload below (::activate,
    // ::fetchXrayProfile, ::fetchXrayTlsProfile used as bare function
    // references, which cannot bind a defaulted extra parameter) so every
    // pre-B14 call site stays byte-for-byte unchanged. Sourced from
    // ProductionGatewayCatalog - the SAME single fact every other
    // Germany-targeting call site already reads, never a second, separately
    // maintained literal that could drift from it.
    private val GERMANY_HOST = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.GERMANY.awg.endpointHost
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 10_000

    // Mirrors the server's own validation shape (gateway/api/wgkey.py,
    // gateway/lib/common.sh's is_valid_wg_key): 32 raw bytes, base64,
    // trailing '='. Not the authoritative check - the server is - but
    // catches a malformed/truncated field before it is ever trusted here.
    private val WG_KEY_REGEX = Regex("^[A-Za-z0-9+/]{43}=$")

    // B8K6A fix - REALITY's public key is also a 32-byte X25519 key, but
    // NOT encoded the same way as an AWG key: xray-core's own `xray x25519`
    // tool (and this server's config.py/gateway_config_renderer validation)
    // emit it as url-safe base64, UNPADDED (43 chars) - never standard
    // base64-with-padding. Confirmed against a real server response: the
    // previous `= WG_KEY_REGEX` alias rejected EVERY real Reality profile
    // this server has ever issued as "malformed", so no device has ever
    // been able to save a working Xray profile - this is the same shape
    // XrayVlessRealityConfig.REALITY_PUBLIC_KEY_REGEX already validates
    // correctly on the config side; this is the one place that disagreed.
    private val REALITY_KEY_REGEX = Regex("^[A-Za-z0-9_-]{43}$")

    // REALITY's short_id: 1-8 raw bytes, hex-encoded (an even number of hex
    // digits, 2 to 16 of them) - matches Xray-core's own short_id validation.
    // Required non-blank here since a real provisioned profile always carries one.
    private val SHORT_ID_REGEX = Regex("^([0-9a-fA-F]{2}){1,8}$")

    // Standard RFC 4122 textual UUID form - the shape the server's own
    // uuid generation/validation produces.
    private val UUID_REGEX = Regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )

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
     * ever returned. Targets Germany's own edge - see the 3-arg overload
     * below for a live, per-endpoint activation request.
     */
    fun activate(publicKey: String, activationCredential: String): ProvisioningResult =
        activate(publicKey, activationCredential, GERMANY_HOST)

    /**
     * B14 - the real endpoint-aware activation request: identical
     * request/response contract to the 2-arg [activate] above, but posted
     * to [endpointHost]'s own `pocvpn-api` edge instead of always
     * Germany's. The caller (MainViewModel.activateDevice) is responsible
     * for resolving [endpointHost] from the SAME
     * ProductionGatewayCatalog entry the client will later validate the
     * response against (matchGatewayId) - this function performs no
     * gateway-identity validation of its own, it only sends the request to
     * where it was told to. A gateway with no deployed control-plane at
     * this host simply produces a real [ProvisioningResult.NetworkError]
     * (connection refused/TLS failure/timeout) - never a fabricated
     * success.
     */
    fun activate(publicKey: String, activationCredential: String, endpointHost: String): ProvisioningResult =
        execute(buildActivateRequest(publicKey, activationCredential, endpointHost), ::mapActivateResponse)

    /**
     * B8K4A - POST /v1/xray-profile: existing activation credential ->
     * existing device AWG public key -> validated VLESS+REALITY profile.
     * Same request shape as [activate], a distinct response shape and
     * [XrayProfileResult] outcome type. Does not persist the result - the
     * caller decides whether/when to save it. Targets Germany's own edge -
     * see the 3-arg overload below for a live, per-endpoint request.
     */
    fun fetchXrayProfile(publicKey: String, bearerToken: String): XrayProfileResult =
        fetchXrayProfile(publicKey, bearerToken, GERMANY_HOST)

    /** B14 - same reasoning as the 3-arg [activate] overload above, for the REALITY profile fetch. */
    fun fetchXrayProfile(publicKey: String, bearerToken: String, endpointHost: String): XrayProfileResult =
        executeXrayProfile(buildXrayProfileRequest(publicKey, bearerToken, endpointHost))

    /**
     * B8O2 - POST /v1/xray-profile with `{"transport": "tls"}`: same
     * endpoint/credential/public-key shape as [fetchXrayProfile] above, a
     * SECOND transport option on the SAME identity (see
     * gateway/api/handler.py's own optional `transport` field) - never a
     * second endpoint, never a second credential. Targets Germany's own
     * edge - see the 3-arg overload below for a live, per-endpoint request.
     */
    fun fetchXrayTlsProfile(publicKey: String, bearerToken: String): XrayTlsProfileResult =
        fetchXrayTlsProfile(publicKey, bearerToken, GERMANY_HOST)

    /** B14 - same reasoning as the 3-arg [activate] overload above, for the TLS profile fetch. */
    fun fetchXrayTlsProfile(publicKey: String, bearerToken: String, endpointHost: String): XrayTlsProfileResult =
        executeXrayTlsProfile(buildXrayTlsProfileRequest(publicKey, bearerToken, endpointHost))

    /**
     * B26 (task D) - POST /v1/ingress-profile: the SAME request shape as
     * [fetchXrayProfile]/[fetchXrayTlsProfile] (existing activation
     * credential + existing device public key, optional `transport`
     * field), against an ingress endpoint's own edge. Never persists
     * anything itself - the caller ([net.pocvpn.client.relay.IngressProfileProvisioner])
     * decides whether/how to save a [IngressProfileResult.Success] into
     * [net.pocvpn.client.relay.IngressProfileStore].
     */
    fun fetchIngressProfile(publicKey: String, bearerToken: String, endpointHost: String, useTls: Boolean): IngressProfileResult =
        executeIngressProfile(
            if (useTls) {
                buildXrayTlsProfileRequest(publicKey, bearerToken, endpointHost).copy(url = "https://$endpointHost/v1/ingress-profile")
            } else {
                buildXrayProfileRequest(publicKey, bearerToken, endpointHost).copy(url = "https://$endpointHost/v1/ingress-profile")
            },
        )

    private fun executeIngressProfile(request: OutgoingRequest): IngressProfileResult =
        executeGeneric(request, IngressProfileResult::NetworkError, ::mapIngressProfileResponse)

    /**
     * POST /v1/ingress-profile response mapping (gateway/api/handler.py's
     * _handle_ingress_profile_inner) - `internal` so each status/error_code
     * combination is unit-testable without a live HTTP connection. Mirrors
     * [mapXrayProfileResponse]/[mapXrayTlsProfileResponse]'s own shape, plus
     * the "expired"/"ingress_not_configured"/"ingress_tls_not_configured"
     * cases those endpoints don't have.
     */
    internal fun mapIngressProfileResponse(status: Int, rawBody: String): IngressProfileResult = when (status) {
        200, 201 -> parseIngressProfileSuccessBody(rawBody)
        401 -> IngressProfileResult.Unauthorized
        403 -> when (errorCode(rawBody)) {
            "revoked" -> IngressProfileResult.Revoked
            "expired" -> IngressProfileResult.Expired
            "device_not_bound" -> IngressProfileResult.DeviceNotBound
            else -> IngressProfileResult.Unauthorized
        }
        503 -> IngressProfileResult.ServiceUnavailable
        else -> IngressProfileResult.NetworkError("unexpected HTTP status $status")
    }

    private fun parseIngressProfileSuccessBody(raw: String): IngressProfileResult {
        val json = try {
            JSONObject(raw)
        } catch (e: JSONException) {
            return IngressProfileResult.MalformedResponse("response body is not valid JSON")
        }

        val ingressEndpointId = json.optString("ingress_endpoint_id", "")
        val serverAddress = json.optString("server_address", "")
        val serverPort = json.optInt("server_port", -1)
        val uuid = json.optString("uuid", "")
        val serverName = json.optString("server_name", "")
        val fingerprint = json.optString("fingerprint", "")
        val flow = json.optString("flow", "")
        val realityPublicKey = json.optString("reality_public_key", "")
        val shortId = json.optString("short_id", "")
        val profileVersion = json.optInt("profile_version", -1)
        val issuedAt = if (json.isNull("issued_at")) null else json.optLong("issued_at", -1L)
        val expiresAt = if (json.has("expires_at") && !json.isNull("expires_at")) json.optLong("expires_at", -1L) else null
        val probeUrl = if (json.has("probe_url") && !json.isNull("probe_url")) json.optString("probe_url", "") else null
        val probeToken = if (json.has("probe_token") && !json.isNull("probe_token")) json.optString("probe_token", "") else null

        if (ingressEndpointId.isBlank()) {
            return IngressProfileResult.MalformedResponse("ingress_endpoint_id missing or blank")
        }
        if (serverAddress.isBlank()) {
            return IngressProfileResult.MalformedResponse("server_address missing or blank")
        }
        if (serverPort !in 1..65535) {
            return IngressProfileResult.MalformedResponse("server_port missing or out of range")
        }
        if (!UUID_REGEX.matches(uuid)) {
            return IngressProfileResult.MalformedResponse("uuid missing or not a well-formed UUID")
        }
        if (serverName.isBlank()) {
            return IngressProfileResult.MalformedResponse("server_name missing or blank")
        }
        if (fingerprint.isBlank()) {
            return IngressProfileResult.MalformedResponse("fingerprint missing or blank")
        }
        if (profileVersion < 0) {
            return IngressProfileResult.MalformedResponse("profile_version missing")
        }
        if (issuedAt == null || issuedAt < 0) {
            return IngressProfileResult.MalformedResponse("issued_at missing or invalid")
        }
        if (probeUrl.isNullOrBlank() || !probeUrl.startsWith("https://")) {
            return IngressProfileResult.MalformedResponse("probe_url missing or not HTTPS")
        }
        if (probeToken.isNullOrBlank()) {
            return IngressProfileResult.MalformedResponse("probe_token missing")
        }

        // TLS responses carry no flow/realityPublicKey/shortId at all (see
        // handler.py's own transport-shaped payload) - only validate those
        // three when the caller actually asked for REALITY (useTls=false),
        // exactly mirroring parseXrayProfileSuccessBody/parseXrayTlsProfileSuccessBody's
        // own split, just folded into one response shape here since a
        // single ingress-profile response always carries exactly the
        // fields its own transport implies.
        val isRealityShaped = json.has("flow") || json.has("reality_public_key") || json.has("short_id")
        if (isRealityShaped) {
            if (flow.isBlank()) return IngressProfileResult.MalformedResponse("flow missing or blank")
            if (!REALITY_KEY_REGEX.matches(realityPublicKey)) {
                return IngressProfileResult.MalformedResponse("reality_public_key missing or not a well-formed public key")
            }
            if (!SHORT_ID_REGEX.matches(shortId)) {
                return IngressProfileResult.MalformedResponse("short_id missing or not well-formed hex")
            }
        }

        return IngressProfileResult.Success(
            ingressEndpointId = ingressEndpointId,
            serverAddress = serverAddress,
            serverPort = serverPort,
            uuid = uuid,
            serverName = serverName,
            fingerprint = fingerprint,
            flow = flow.ifBlank { null },
            realityPublicKey = realityPublicKey.ifBlank { null },
            shortId = shortId.ifBlank { null },
            isRealityShaped = isRealityShaped,
            profileVersion = profileVersion,
            issuedAtEpochSeconds = issuedAt,
            expiresAtEpochSeconds = expiresAt,
            probeUrl = probeUrl,
            probeToken = probeToken,
        )
    }

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
        buildActivateRequest(publicKey, activationCredential, GERMANY_HOST)

    /**
     * B14 - same request shape as the 2-arg overload above, targeted at
     * [endpointHost]'s own edge rather than always Germany's - see
     * [activate]'s own 3-arg overload for why.
     */
    internal fun buildActivateRequest(publicKey: String, activationCredential: String, endpointHost: String): OutgoingRequest =
        OutgoingRequest(
            url = "https://$endpointHost/v1/activate",
            headers = authHeaders(activationCredential),
            body = buildRequestBody(publicKey),
        )

    internal fun buildXrayProfileRequest(publicKey: String, bearerToken: String): OutgoingRequest =
        buildXrayProfileRequest(publicKey, bearerToken, GERMANY_HOST)

    internal fun buildXrayProfileRequest(publicKey: String, bearerToken: String, endpointHost: String): OutgoingRequest =
        OutgoingRequest(
            url = "https://$endpointHost/v1/xray-profile",
            headers = authHeaders(bearerToken),
            body = buildRequestBody(publicKey),
        )

    internal fun buildXrayTlsProfileRequest(publicKey: String, bearerToken: String): OutgoingRequest =
        buildXrayTlsProfileRequest(publicKey, bearerToken, GERMANY_HOST)

    internal fun buildXrayTlsProfileRequest(publicKey: String, bearerToken: String, endpointHost: String): OutgoingRequest =
        OutgoingRequest(
            url = "https://$endpointHost/v1/xray-profile",
            headers = authHeaders(bearerToken),
            body = buildXrayTlsRequestBody(publicKey),
        )

    private fun authHeaders(credential: String): Map<String, String> = mapOf(
        "Content-Type" to "application/json",
        "Authorization" to "Bearer $credential",
    )

    private fun execute(request: OutgoingRequest, mapResponse: (Int, String) -> ProvisioningResult): ProvisioningResult =
        executeGeneric(request, ProvisioningResult::NetworkError, mapResponse)

    private fun executeXrayProfile(request: OutgoingRequest): XrayProfileResult =
        executeGeneric(request, XrayProfileResult::NetworkError, ::mapXrayProfileResponse)

    private fun executeXrayTlsProfile(request: OutgoingRequest): XrayTlsProfileResult =
        executeGeneric(request, XrayTlsProfileResult::NetworkError, ::mapXrayTlsProfileResponse)

    private fun <T> executeGeneric(
        request: OutgoingRequest,
        networkError: (String) -> T,
        mapResponse: (Int, String) -> T,
    ): T {
        val connection = try {
            URL(request.url).openConnection() as HttpsURLConnection
        } catch (e: IOException) {
            return networkError("could not open connection: ${e.javaClass.simpleName}")
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
            networkError("${e.javaClass.simpleName}: ${e.message ?: "I/O failure"}")
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

    /** B8O2 - same shape as [buildRequestBody] plus the explicit `"transport": "tls"` field the gateway's optional-field parsing accepts. */
    internal fun buildXrayTlsRequestBody(publicKey: String): String =
        JSONObject().put("public_key", publicKey).put("transport", "tls").toString()

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

    /**
     * POST /v1/xray-profile response mapping - `internal` so each status/
     * error_code combination is unit-testable without a live HTTP
     * connection. The 403 body's "error" field is the ONLY thing
     * distinguishing revoked/device_not_bound, since both share HTTP 403.
     */
    internal fun mapXrayProfileResponse(status: Int, rawBody: String): XrayProfileResult = when (status) {
        200, 201 -> parseXrayProfileSuccessBody(rawBody)
        401 -> XrayProfileResult.Unauthorized
        403 -> when (errorCode(rawBody)) {
            "revoked" -> XrayProfileResult.Revoked
            "device_not_bound" -> XrayProfileResult.DeviceNotBound
            else -> XrayProfileResult.Unauthorized
        }
        503 -> XrayProfileResult.ServiceUnavailable
        else -> XrayProfileResult.NetworkError("unexpected HTTP status $status")
    }

    /**
     * B8O2 - POST /v1/xray-profile?transport=tls response mapping -
     * `internal` so each status/error_code combination is unit-testable
     * without a live HTTP connection. Mirrors [mapXrayProfileResponse]'s own
     * shape, plus "xray_tls_not_configured" mapping to [XrayTlsProfileResult.ServiceUnavailable]
     * (same as any other 503).
     */
    internal fun mapXrayTlsProfileResponse(status: Int, rawBody: String): XrayTlsProfileResult = when (status) {
        200, 201 -> parseXrayTlsProfileSuccessBody(rawBody)
        401 -> XrayTlsProfileResult.Unauthorized
        403 -> when (errorCode(rawBody)) {
            "revoked" -> XrayTlsProfileResult.Revoked
            "device_not_bound" -> XrayTlsProfileResult.DeviceNotBound
            else -> XrayTlsProfileResult.Unauthorized
        }
        503 -> XrayTlsProfileResult.ServiceUnavailable
        else -> XrayTlsProfileResult.NetworkError("unexpected HTTP status $status")
    }

    private fun parseXrayTlsProfileSuccessBody(raw: String): XrayTlsProfileResult {
        val json = try {
            JSONObject(raw)
        } catch (e: JSONException) {
            return XrayTlsProfileResult.MalformedResponse("response body is not valid JSON")
        }

        val serverAddress = json.optString("server_address", "")
        val serverPort = json.optInt("server_port", -1)
        val uuid = json.optString("uuid", "")
        val serverName = json.optString("server_name", "")
        val fingerprint = json.optString("fingerprint", "")

        if (serverAddress.isBlank()) {
            return XrayTlsProfileResult.MalformedResponse("server_address missing or blank")
        }
        if (serverPort !in 1..65535) {
            return XrayTlsProfileResult.MalformedResponse("server_port missing or out of range")
        }
        if (!UUID_REGEX.matches(uuid)) {
            return XrayTlsProfileResult.MalformedResponse("uuid missing or not a well-formed UUID")
        }
        if (serverName.isBlank()) {
            return XrayTlsProfileResult.MalformedResponse("server_name missing or blank")
        }
        if (fingerprint.isBlank()) {
            return XrayTlsProfileResult.MalformedResponse("fingerprint missing or blank")
        }

        return XrayTlsProfileResult.Success(
            serverAddress = serverAddress,
            serverPort = serverPort,
            uuid = uuid,
            serverName = serverName,
            fingerprint = fingerprint,
        )
    }

    private fun parseXrayProfileSuccessBody(raw: String): XrayProfileResult {
        val json = try {
            JSONObject(raw)
        } catch (e: JSONException) {
            return XrayProfileResult.MalformedResponse("response body is not valid JSON")
        }

        val serverAddress = json.optString("server_address", "")
        val serverPort = json.optInt("server_port", -1)
        val uuid = json.optString("uuid", "")
        val flow = json.optString("flow", "")
        val serverName = json.optString("server_name", "")
        val fingerprint = json.optString("fingerprint", "")
        val realityPublicKey = json.optString("reality_public_key", "")
        val shortId = json.optString("short_id", "")

        if (serverAddress.isBlank()) {
            return XrayProfileResult.MalformedResponse("server_address missing or blank")
        }
        if (serverPort !in 1..65535) {
            return XrayProfileResult.MalformedResponse("server_port missing or out of range")
        }
        if (!UUID_REGEX.matches(uuid)) {
            return XrayProfileResult.MalformedResponse("uuid missing or not a well-formed UUID")
        }
        if (flow.isBlank()) {
            return XrayProfileResult.MalformedResponse("flow missing or blank")
        }
        if (serverName.isBlank()) {
            return XrayProfileResult.MalformedResponse("server_name missing or blank")
        }
        if (fingerprint.isBlank()) {
            return XrayProfileResult.MalformedResponse("fingerprint missing or blank")
        }
        if (!REALITY_KEY_REGEX.matches(realityPublicKey)) {
            return XrayProfileResult.MalformedResponse("reality_public_key missing or not a well-formed public key")
        }
        if (!SHORT_ID_REGEX.matches(shortId)) {
            return XrayProfileResult.MalformedResponse("short_id missing or not well-formed hex")
        }

        return XrayProfileResult.Success(
            serverAddress = serverAddress,
            serverPort = serverPort,
            uuid = uuid,
            flow = flow,
            serverName = serverName,
            fingerprint = fingerprint,
            realityPublicKey = realityPublicKey,
            shortId = shortId,
        )
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

        // B13 consolidated review fix (finding 7) - Ipv4Format.isValid (all
        // octets 0..255), not a shape-only regex: this response's
        // client_tunnel_ip flows straight into ClientTunnelIdentityStore.write()
        // (MainViewModel.activateDevice), which now enforces the SAME strict
        // check and would throw on anything this looser regex used to admit
        // (e.g. "999.1.1.1") - reject it here, as a clean MalformedResponse,
        // rather than let a structurally-wrong value reach that boundary.
        if (!net.pocvpn.client.vpn.config.Ipv4Format.isValid(clientTunnelIp)) {
            return ProvisioningResult.MalformedResponse("client_tunnel_ip missing or not a valid IPv4 address")
        }
        if (!WG_KEY_REGEX.matches(gatewayPublicKey)) {
            return ProvisioningResult.MalformedResponse("gateway_public_key missing or not a well-formed public key")
        }
        if (!net.pocvpn.client.vpn.config.Ipv4Format.isValid(gatewayTunnelIp)) {
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
