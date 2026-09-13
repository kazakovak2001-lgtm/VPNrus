package net.pocvpn.client.reachability

/**
 * Operator-declared CDN constraints, not measured reachability or an executable Xray config.
 * Only read metadata from an already trusted manifest. Local health remains owned by the
 * existing ReachabilityEngine/relay proof pipeline; declaring a profile never makes it usable.
 */
data class CdnProviderCapabilityProfile(
    val provider: String,
    val asn: Long,
    val hosts: CdnHostnames,
    val xhttp: CdnXhttpPolicy,
    val tls: CdnTlsPolicy,
    val requests: CdnRequestPolicy,
    val supportedExits: Set<EndpointId>,
    val minimumClientVersionCode: Long,
    val minimumXrayCoreVersion: String,
    val requiredClientCapabilities: Set<String>,
) {
    init {
        require(provider.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")))
        require(asn in 1..4_294_967_295L)
        require(supportedExits.size in 1..16)
        require(minimumClientVersionCode > 0)
        require(minimumXrayCoreVersion.matches(Regex("[0-9]{1,8}\\.[0-9]{1,8}\\.[0-9]{1,8}")))
        require(requiredClientCapabilities.size in 1..16)
        require(requiredClientCapabilities.all { it.matches(Regex("[a-z][a-z0-9._-]{0,63}")) })
    }
}

/** All four names are explicit; origin identities must never be substituted for the public edge. */
data class CdnHostnames(
    val clientFacingHostname: String,
    val cdnTechnicalHostname: String,
    val originHostname: String,
    val originTlsServerName: String,
) {
    init {
        listOf(clientFacingHostname, cdnTechnicalHostname, originHostname, originTlsServerName)
            .forEach(::requireCdnHostname)
    }
}

enum class CdnXhttpMode { AUTO, PACKET_UP, STREAM_UP, STREAM_ONE }
enum class CdnUplinkHttpMethod { GET, POST, PUT, HEAD }
enum class CdnPaddingPlacement { NONE, HEADER, QUERY }
enum class CdnMinimumTlsVersion { TLS_1_2, TLS_1_3 }
enum class CdnCachePolicy { BYPASS_REQUIRED, UNSUPPORTED, UNKNOWN }

data class CdnXhttpPolicy(
    val mode: CdnXhttpMode,
    val path: String,
    val uplinkHttpMethod: CdnUplinkHttpMethod,
    val paddingPlacement: CdnPaddingPlacement,
    val paddingMinBytes: Int,
    val paddingMaxBytes: Int,
    val queryParameters: Map<String, String>,
    val headers: Map<String, String>,
    val extraParameters: Map<String, String>,
) {
    init {
        require(path.length in 1..512 && path.startsWith('/') && !path.startsWith("//"))
        require(path.all { it.code in 33..126 } && '?' !in path && '#' !in path && '\\' !in path)
        require(paddingMinBytes in 0..65536 && paddingMaxBytes in paddingMinBytes..65536)
        require(paddingPlacement != CdnPaddingPlacement.NONE || paddingMaxBytes == 0)
        listOf(queryParameters, headers, extraParameters).forEach(::requireCdnParameters)
        require(headers.keys.map { it.lowercase(java.util.Locale.ROOT) }.toSet().size == headers.size)
        // Credentials/framing/host identity belong to their own trusted configuration boundary.
        require(headers.keys.none { it.lowercase(java.util.Locale.ROOT) in setOf(
            "authorization", "proxy-authorization", "cookie", "set-cookie", "host",
            "content-length", "transfer-encoding", "connection", "upgrade",
        ) })
    }
}

data class CdnTlsPolicy(
    val minimumVersion: CdnMinimumTlsVersion,
    val alpn: Set<String>,
    val clientServerName: String,
    val clientFingerprint: String,
) {
    init {
        requireCdnHostname(clientServerName)
        require(alpn.isNotEmpty() && alpn.all { it in setOf("h2", "h3", "http/1.1") })
        require(clientFingerprint.matches(Regex("[a-z][a-z0-9_-]{0,63}")))
    }
}

data class CdnRequestPolicy(
    val originHostHeader: String,
    val cachePolicy: CdnCachePolicy,
    val streamingSupported: Boolean,
    val maxRequestBodyBytes: Long,
    val requestTimeoutMillis: Long,
) {
    init {
        requireCdnHostname(originHostHeader)
        require(maxRequestBodyBytes > 0)
        require(requestTimeoutMillis in 1..86_400_000)
    }
}

private fun requireCdnHostname(value: String) {
    // ASCII DNS names only; IDNs must be supplied as A-labels. No URL, port, path, or wildcard.
    require(value.length in 1..253 && value.any { it.isLetter() })
    require(value.split('.').all { label ->
        label.length in 1..63 && label.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"))
    })
}

private fun requireCdnParameters(values: Map<String, String>) {
    require(values.size <= 16)
    require(values.all { (key, value) ->
        key.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) &&
            value.length <= 256 && value.all { it.code in 32..126 }
    })
}
