package net.pocvpn.client.reachability

/**
 * Local runtime facts required before a signed CDN profile may become an
 * executable client-facing candidate. These are client/core capabilities, not
 * reachability evidence; the existing PathScorer/relay-proof pipeline remains
 * the authority for whether a compatible path actually works.
 */
data class CdnClientRuntimeCapabilities(
    val clientVersionCode: Long,
    val xrayCoreVersion: String,
    val clientCapabilities: Set<String>,
    val xhttpModes: Set<CdnXhttpMode>,
    val uplinkHttpMethods: Set<CdnUplinkHttpMethod>,
    val paddingPlacements: Set<CdnPaddingPlacement>,
    val tlsFingerprints: Set<String>,
    val alpn: Set<String>,
    val minimumTlsVersions: Set<CdnMinimumTlsVersion>,
    val supportsStreaming: Boolean,
    val maxRequestBodyBytes: Long,
    val maxRequestTimeoutMillis: Long,
) {
    init {
        require(clientVersionCode >= 0)
        require(xrayCoreVersion.matches(Regex("[0-9]{1,8}\\.[0-9]{1,8}\\.[0-9]{1,8}")))
        require(clientCapabilities.size <= 64)
        require(clientCapabilities.all { it.matches(Regex("[a-z][a-z0-9._-]{0,63}")) })
        require(tlsFingerprints.size <= 64)
        require(tlsFingerprints.all { it.matches(Regex("[a-z][a-z0-9_-]{0,63}")) })
        require(alpn.size <= 16)
        require(alpn.all { it in setOf("h2", "h3", "http/1.1") })
        require(maxRequestBodyBytes >= 0)
        require(maxRequestTimeoutMillis >= 0)
    }

    companion object {
        /** Conservative default: a caller must opt in with measured local runtime support. */
        fun unsupported(): CdnClientRuntimeCapabilities = CdnClientRuntimeCapabilities(
            clientVersionCode = 0,
            xrayCoreVersion = "0.0.0",
            clientCapabilities = emptySet(),
            xhttpModes = emptySet(),
            uplinkHttpMethods = emptySet(),
            paddingPlacements = emptySet(),
            tlsFingerprints = emptySet(),
            alpn = emptySet(),
            minimumTlsVersions = emptySet(),
            supportsStreaming = false,
            maxRequestBodyBytes = 0,
            maxRequestTimeoutMillis = 0,
        )
    }
}

enum class CdnClientCompatibilityFailure {
    PROFILE_MISSING,
    PROFILE_INVALID,
    PROFILE_VERSION_UNSUPPORTED,
    EXIT_NOT_SUPPORTED,
    CLIENT_VERSION_TOO_OLD,
    XRAY_CORE_TOO_OLD,
    CLIENT_CAPABILITY_MISSING,
    XHTTP_MODE_UNSUPPORTED,
    HTTP_METHOD_UNSUPPORTED,
    PADDING_UNSUPPORTED,
    TLS_VERSION_UNSUPPORTED,
    TLS_FINGERPRINT_UNSUPPORTED,
    ALPN_UNSUPPORTED,
    STREAMING_UNSUPPORTED,
    CACHE_POLICY_UNSAFE,
    REQUEST_BODY_TOO_LARGE,
    REQUEST_TIMEOUT_TOO_LARGE,
}

sealed interface CdnClientCompatibility {
    data class Compatible(val profile: CdnProviderCapabilityProfile) : CdnClientCompatibility
    data class Incompatible(val reason: CdnClientCompatibilityFailure) : CdnClientCompatibility
}

fun EndpointTransportBinding.cdnClientCompatibility(
    exitEndpointId: EndpointId,
    runtime: CdnClientRuntimeCapabilities,
): CdnClientCompatibility {
    val profile = when (val read = cdnProviderProfile()) {
        CdnProviderProfileReadResult.Missing -> return CdnClientCompatibility.Incompatible(CdnClientCompatibilityFailure.PROFILE_MISSING)
        CdnProviderProfileReadResult.Invalid -> return CdnClientCompatibility.Incompatible(CdnClientCompatibilityFailure.PROFILE_INVALID)
        CdnProviderProfileReadResult.UnsupportedVersion -> return CdnClientCompatibility.Incompatible(CdnClientCompatibilityFailure.PROFILE_VERSION_UNSUPPORTED)
        is CdnProviderProfileReadResult.Parsed -> read.profile
    }
    return profile.compatibilityWith(exitEndpointId, runtime)
}

private fun CdnProviderCapabilityProfile.compatibilityWith(
    exitEndpointId: EndpointId,
    runtime: CdnClientRuntimeCapabilities,
): CdnClientCompatibility {
    fun incompatible(reason: CdnClientCompatibilityFailure) = CdnClientCompatibility.Incompatible(reason)

    if (exitEndpointId !in supportedExits) return incompatible(CdnClientCompatibilityFailure.EXIT_NOT_SUPPORTED)
    if (runtime.clientVersionCode < minimumClientVersionCode) return incompatible(CdnClientCompatibilityFailure.CLIENT_VERSION_TOO_OLD)
    if (compareSemver(runtime.xrayCoreVersion, minimumXrayCoreVersion) < 0) return incompatible(CdnClientCompatibilityFailure.XRAY_CORE_TOO_OLD)
    if (!runtime.clientCapabilities.containsAll(requiredClientCapabilities)) return incompatible(CdnClientCompatibilityFailure.CLIENT_CAPABILITY_MISSING)
    if (xhttp.mode !in runtime.xhttpModes) return incompatible(CdnClientCompatibilityFailure.XHTTP_MODE_UNSUPPORTED)
    if (xhttp.uplinkHttpMethod !in runtime.uplinkHttpMethods) return incompatible(CdnClientCompatibilityFailure.HTTP_METHOD_UNSUPPORTED)
    // Pinned Xray-core v26.7.28 normalizes omitted/zero xPaddingBytes to
    // 100..1000. It therefore cannot truthfully execute a signed NONE policy.
    if (xhttp.paddingPlacement == CdnPaddingPlacement.NONE) {
        return incompatible(CdnClientCompatibilityFailure.PADDING_UNSUPPORTED)
    }
    if (xhttp.paddingPlacement !in runtime.paddingPlacements) return incompatible(CdnClientCompatibilityFailure.PADDING_UNSUPPORTED)
    if (tls.minimumVersion !in runtime.minimumTlsVersions) return incompatible(CdnClientCompatibilityFailure.TLS_VERSION_UNSUPPORTED)
    if (tls.clientFingerprint !in runtime.tlsFingerprints) return incompatible(CdnClientCompatibilityFailure.TLS_FINGERPRINT_UNSUPPORTED)
    if (tls.alpn.intersect(runtime.alpn).isEmpty()) return incompatible(CdnClientCompatibilityFailure.ALPN_UNSUPPORTED)
    if (requests.streamingSupported && !runtime.supportsStreaming) return incompatible(CdnClientCompatibilityFailure.STREAMING_UNSUPPORTED)
    if (requests.cachePolicy != CdnCachePolicy.BYPASS_REQUIRED) {
        return incompatible(CdnClientCompatibilityFailure.CACHE_POLICY_UNSAFE)
    }
    if (requests.maxRequestBodyBytes > runtime.maxRequestBodyBytes) return incompatible(CdnClientCompatibilityFailure.REQUEST_BODY_TOO_LARGE)
    if (requests.requestTimeoutMillis > runtime.maxRequestTimeoutMillis) return incompatible(CdnClientCompatibilityFailure.REQUEST_TIMEOUT_TOO_LARGE)
    return CdnClientCompatibility.Compatible(this)
}

private fun compareSemver(left: String, right: String): Int {
    val l = left.split('.').map { it.toLong() }
    val r = right.split('.').map { it.toLong() }
    for (i in 0..2) {
        val c = l[i].compareTo(r[i])
        if (c != 0) return c
    }
    return 0
}
