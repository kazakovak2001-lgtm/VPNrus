package net.pocvpn.client.reachability

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener

private const val CDN_PROFILE_KEY = "cdnProviderProfile"
private const val CDN_PROFILE_VERSION = 1L
private const val MAX_PROFILE_BYTES = 4096 // Existing manifest string-field limit.

sealed interface CdnProviderProfileReadResult {
    data object Missing : CdnProviderProfileReadResult
    data object Invalid : CdnProviderProfileReadResult
    data object UnsupportedVersion : CdnProviderProfileReadResult
    data class Parsed(val profile: CdnProviderCapabilityProfile) : CdnProviderProfileReadResult
}

/** Parse only; this is neither a signature verifier nor a runtime capability/reachability gate. */
fun EndpointTransportBinding.cdnProviderProfile(): CdnProviderProfileReadResult {
    val raw = metadata[CDN_PROFILE_KEY] ?: return CdnProviderProfileReadResult.Missing
    if (ingressKind() != IngressKind.CDN_FRONTED || raw.toByteArray(Charsets.UTF_8).size > MAX_PROFILE_BYTES) {
        return CdnProviderProfileReadResult.Invalid
    }
    return try {
        val tokens = JSONTokener(raw)
        val json = tokens.nextValue() as? JSONObject ?: return CdnProviderProfileReadResult.Invalid
        require(tokens.nextClean() == '\u0000')
        if (json.integer("version") != CDN_PROFILE_VERSION) return CdnProviderProfileReadResult.UnsupportedVersion
        val profile = decodeProfile(json)
        if (!host.equals(profile.hosts.clientFacingHostname, ignoreCase = true)) {
            CdnProviderProfileReadResult.Invalid
        } else CdnProviderProfileReadResult.Parsed(profile)
    } catch (_: IllegalArgumentException) {
        CdnProviderProfileReadResult.Invalid
    } catch (_: JSONException) {
        CdnProviderProfileReadResult.Invalid
    }
}

/** Preserves unrelated metadata and the existing signed manifest schema. New content still needs signing. */
fun EndpointTransportBinding.withCdnProviderProfile(profile: CdnProviderCapabilityProfile): EndpointTransportBinding {
    require(ingressKind() == IngressKind.CDN_FRONTED)
    require(host.equals(profile.hosts.clientFacingHostname, ignoreCase = true))
    val encoded = encodeProfile(profile)
    require(encoded.toByteArray(Charsets.UTF_8).size <= MAX_PROFILE_BYTES)
    require((metadata.keys + CDN_PROFILE_KEY).size <= 64)
    val binding = copy(metadata = metadata + (CDN_PROFILE_KEY to encoded))
    // Revalidate serialized collections too: Kotlin's read-only Map/Set types may wrap mutable data.
    require(binding.cdnProviderProfile() is CdnProviderProfileReadResult.Parsed)
    return binding
}

private fun encodeProfile(p: CdnProviderCapabilityProfile): String {
    val fields = mapOf(
        "version" to CDN_PROFILE_VERSION, "provider" to p.provider, "asn" to p.asn,
        "hosts" to mapOf(
            "clientFacingHostname" to p.hosts.clientFacingHostname,
            "cdnTechnicalHostname" to p.hosts.cdnTechnicalHostname,
            "originHostname" to p.hosts.originHostname,
            "originTlsServerName" to p.hosts.originTlsServerName,
        ),
        "xhttp" to mapOf(
            "mode" to p.xhttp.mode.name, "path" to p.xhttp.path,
            "uplinkHttpMethod" to p.xhttp.uplinkHttpMethod.name,
            "paddingPlacement" to p.xhttp.paddingPlacement.name,
            "paddingMinBytes" to p.xhttp.paddingMinBytes, "paddingMaxBytes" to p.xhttp.paddingMaxBytes,
            "queryParameters" to p.xhttp.queryParameters, "headers" to p.xhttp.headers,
            "extraParameters" to p.xhttp.extraParameters,
        ),
        "tls" to mapOf(
            "minimumVersion" to p.tls.minimumVersion.name, "alpn" to p.tls.alpn.sorted(),
            "clientServerName" to p.tls.clientServerName, "clientFingerprint" to p.tls.clientFingerprint,
        ),
        "requests" to mapOf(
            "originHostHeader" to p.requests.originHostHeader, "cachePolicy" to p.requests.cachePolicy.name,
            "streamingSupported" to p.requests.streamingSupported,
            "maxRequestBodyBytes" to p.requests.maxRequestBodyBytes,
            "requestTimeoutMillis" to p.requests.requestTimeoutMillis,
        ),
        "supportedExits" to p.supportedExits.map { it.value }.sorted(),
        "minimumClientVersionCode" to p.minimumClientVersionCode,
        "minimumXrayCoreVersion" to p.minimumXrayCoreVersion,
        "requiredClientCapabilities" to p.requiredClientCapabilities.sorted(),
    )
    return sortedJson(fields)
}

private fun sortedJson(value: Any): String = when (value) {
    is Map<*, *> -> value.entries.sortedBy { it.key as String }.joinToString(",", "{", "}") { (k, v) ->
        JSONObject.quote(k as String) + ":" + sortedJson(requireNotNull(v))
    }
    is List<*> -> value.joinToString(",", "[", "]") { sortedJson(requireNotNull(it)) }
    is String -> JSONObject.quote(value)
    is Int, is Long, is Boolean -> value.toString()
    else -> throw IllegalArgumentException("Unsupported profile value type")
}

private fun decodeProfile(j: JSONObject): CdnProviderCapabilityProfile {
    j.requireFields("version", "provider", "asn", "hosts", "xhttp", "tls", "requests", "supportedExits",
        "minimumClientVersionCode", "minimumXrayCoreVersion", "requiredClientCapabilities")
    val h = j.getJSONObject("hosts").apply {
        requireFields("clientFacingHostname", "cdnTechnicalHostname", "originHostname", "originTlsServerName")
    }
    val x = j.getJSONObject("xhttp").apply {
        requireFields("mode", "path", "uplinkHttpMethod", "paddingPlacement", "paddingMinBytes", "paddingMaxBytes",
            "queryParameters", "headers", "extraParameters")
    }
    val t = j.getJSONObject("tls").apply {
        requireFields("minimumVersion", "alpn", "clientServerName", "clientFingerprint")
    }
    val r = j.getJSONObject("requests").apply {
        requireFields("originHostHeader", "cachePolicy", "streamingSupported", "maxRequestBodyBytes", "requestTimeoutMillis")
    }
    return CdnProviderCapabilityProfile(
        provider = j.string("provider"), asn = j.integer("asn"),
        hosts = CdnHostnames(h.string("clientFacingHostname"), h.string("cdnTechnicalHostname"),
            h.string("originHostname"), h.string("originTlsServerName")),
        xhttp = CdnXhttpPolicy(
            CdnXhttpMode.valueOf(x.string("mode")), x.string("path"),
            CdnUplinkHttpMethod.valueOf(x.string("uplinkHttpMethod")),
            CdnPaddingPlacement.valueOf(x.string("paddingPlacement")),
            x.boundedInt("paddingMinBytes"), x.boundedInt("paddingMaxBytes"),
            x.stringMap("queryParameters"), x.stringMap("headers"), x.stringMap("extraParameters"),
        ),
        tls = CdnTlsPolicy(CdnMinimumTlsVersion.valueOf(t.string("minimumVersion")), t.stringSet("alpn"),
            t.string("clientServerName"), t.string("clientFingerprint")),
        requests = CdnRequestPolicy(r.string("originHostHeader"), CdnCachePolicy.valueOf(r.string("cachePolicy")),
            r.get("streamingSupported") as? Boolean ?: throw IllegalArgumentException("Expected boolean"),
            r.integer("maxRequestBodyBytes"), r.integer("requestTimeoutMillis")),
        supportedExits = j.stringSet("supportedExits").map(::EndpointId).toSet(),
        minimumClientVersionCode = j.integer("minimumClientVersionCode"),
        minimumXrayCoreVersion = j.string("minimumXrayCoreVersion"),
        requiredClientCapabilities = j.stringSet("requiredClientCapabilities"),
    )
}

private fun JSONObject.requireFields(vararg names: String) {
    require(keys().asSequence().toSet() == names.toSet())
}

private fun JSONObject.string(key: String): String =
    get(key) as? String ?: throw IllegalArgumentException("Expected string")

private fun JSONObject.integer(key: String): Long = when (val value = get(key)) {
    is Int -> value.toLong()
    is Long -> value
    else -> throw IllegalArgumentException("Expected integer")
}

private fun JSONObject.boundedInt(key: String): Int = integer(key).also {
    require(it in 0..65536)
}.toInt()

private fun JSONObject.stringMap(key: String): Map<String, String> = getJSONObject(key).let { j ->
    require(j.length() <= 16)
    j.keys().asSequence().associateWith { j.string(it) }
}

private fun JSONObject.stringSet(key: String): Set<String> {
    val array: JSONArray = getJSONArray(key)
    require(array.length() <= 16)
    val values = (0 until array.length()).map {
        array.get(it) as? String ?: throw IllegalArgumentException("Expected string")
    }
    require(values.size == values.toSet().size)
    return values.toSet()
}
