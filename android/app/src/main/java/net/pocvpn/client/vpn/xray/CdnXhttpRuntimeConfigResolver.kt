package net.pocvpn.client.vpn.xray

import net.pocvpn.client.reachability.CdnClientCompatibility
import net.pocvpn.client.reachability.CdnClientRuntimeCapabilities
import net.pocvpn.client.reachability.CdnMinimumTlsVersion
import net.pocvpn.client.reachability.CdnPaddingPlacement
import net.pocvpn.client.reachability.CdnProviderProfileReadResult
import net.pocvpn.client.reachability.CdnUplinkHttpMethod
import net.pocvpn.client.reachability.CdnXhttpMode
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.cdnClientCompatibility
import net.pocvpn.client.reachability.cdnProviderProfile
import net.pocvpn.client.relay.IngressClientProfile
import net.pocvpn.client.transport.TransportKind

enum class CdnXhttpRuntimeFailure {
    NOT_XHTTP_PROFILE,
    NOT_CDN_FRONTED,
    SIGNED_PROFILE_INVALID,
    CLIENT_RUNTIME_INCOMPATIBLE,
    CREDENTIAL_SHAPE_INVALID,
    DATA_PLANE_BINDING_MISMATCH,
    SIGNED_TLS_POLICY_MISMATCH,
    MULTI_ALPN_NOT_EXECUTABLE,
    REQUEST_BODY_LIMIT_UNREPRESENTABLE,
    PADDING_NONE_UNREPRESENTABLE,
    RENDER_CONFIG_INVALID,
}

sealed interface CdnXhttpRuntimeResolution {
    data class Ready(
        val config: XrayVlessXhttpConfig,
        val renderedConfig: String,
    ) : CdnXhttpRuntimeResolution

    data class Rejected(val reason: CdnXhttpRuntimeFailure) : CdnXhttpRuntimeResolution
}

/**
 * One authority boundary for CDN/XHTTP execution:
 * persisted per-device UUID + already-signed provider metadata + measured
 * local runtime capabilities -> validated Xray wire config.
 */
object CdnXhttpRuntimeConfigResolver {
    fun resolve(
        ingressProfile: IngressClientProfile,
        exitEndpointId: EndpointId,
        runtime: CdnClientRuntimeCapabilities,
    ): CdnXhttpRuntimeResolution {
        if (
            ingressProfile.transport != TransportKind.XRAY_XHTTP ||
            ingressProfile.ingressBinding.kind != TransportKind.XRAY_XHTTP
        ) {
            return CdnXhttpRuntimeResolution.Rejected(CdnXhttpRuntimeFailure.NOT_XHTTP_PROFILE)
        }
        if (ingressProfile.ingressKind != IngressKind.CDN_FRONTED) {
            return CdnXhttpRuntimeResolution.Rejected(CdnXhttpRuntimeFailure.NOT_CDN_FRONTED)
        }

        val provider = when (val read = ingressProfile.ingressBinding.cdnProviderProfile()) {
            is CdnProviderProfileReadResult.Parsed -> read.profile
            else -> return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.SIGNED_PROFILE_INVALID,
            )
        }

        if (
            ingressProfile.ingressBinding.cdnClientCompatibility(exitEndpointId, runtime)
                !is CdnClientCompatibility.Compatible
        ) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.CLIENT_RUNTIME_INCOMPATIBLE,
            )
        }

        val credential = ingressProfile.tlsProfile
            ?: return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.CREDENTIAL_SHAPE_INVALID,
            )
        if (ingressProfile.realityProfile != null) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.CREDENTIAL_SHAPE_INVALID,
            )
        }
        if (
            credential.server != ingressProfile.ingressBinding.host ||
            credential.serverPort != ingressProfile.ingressBinding.port
        ) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.DATA_PLANE_BINDING_MISMATCH,
            )
        }
        if (
            credential.serverName != provider.tls.clientServerName ||
            credential.fingerprint != provider.tls.clientFingerprint
        ) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.SIGNED_TLS_POLICY_MISMATCH,
            )
        }
        if (provider.tls.alpn.size != 1) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.MULTI_ALPN_NOT_EXECUTABLE,
            )
        }
        if (provider.requests.maxRequestBodyBytes !in 1..Int.MAX_VALUE.toLong()) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.REQUEST_BODY_LIMIT_UNREPRESENTABLE,
            )
        }
        // v26.7.28 normalizes absent/zero xPaddingBytes to 100..1000.
        // A signed provider profile that says NONE therefore cannot be
        // represented truthfully by this pinned core.
        if (provider.xhttp.paddingPlacement == CdnPaddingPlacement.NONE) {
            return CdnXhttpRuntimeResolution.Rejected(
                CdnXhttpRuntimeFailure.PADDING_NONE_UNREPRESENTABLE,
            )
        }

        val config = XrayVlessXhttpConfig(
            server = ingressProfile.ingressBinding.host,
            serverPort = ingressProfile.ingressBinding.port,
            uuid = credential.uuid,
            tlsServerName = provider.tls.clientServerName,
            fingerprint = provider.tls.clientFingerprint,
            minimumTlsVersion = when (provider.tls.minimumVersion) {
                CdnMinimumTlsVersion.TLS_1_2 -> XrayXhttpMinimumTlsVersion.TLS_1_2
                CdnMinimumTlsVersion.TLS_1_3 -> XrayXhttpMinimumTlsVersion.TLS_1_3
            },
            alpn = provider.tls.alpn.single(),
            xhttpHost = provider.hosts.clientFacingHostname,
            xhttpPath = provider.xhttp.path,
            queryParameters = provider.xhttp.queryParameters.toMap(),
            headers = provider.xhttp.headers.toMap(),
            mode = when (provider.xhttp.mode) {
                CdnXhttpMode.AUTO -> XrayXhttpMode.AUTO
                CdnXhttpMode.PACKET_UP -> XrayXhttpMode.PACKET_UP
                CdnXhttpMode.STREAM_UP -> XrayXhttpMode.STREAM_UP
                CdnXhttpMode.STREAM_ONE -> XrayXhttpMode.STREAM_ONE
            },
            uplinkHttpMethod = when (provider.xhttp.uplinkHttpMethod) {
                CdnUplinkHttpMethod.GET -> XrayXhttpUplinkHttpMethod.GET
                CdnUplinkHttpMethod.POST -> XrayXhttpUplinkHttpMethod.POST
                CdnUplinkHttpMethod.PUT -> XrayXhttpUplinkHttpMethod.PUT
                CdnUplinkHttpMethod.HEAD -> XrayXhttpUplinkHttpMethod.HEAD
            },
            maxEachPostBytes = provider.requests.maxRequestBodyBytes.toInt(),
            paddingPlacement = when (provider.xhttp.paddingPlacement) {
                CdnPaddingPlacement.NONE ->
                    return CdnXhttpRuntimeResolution.Rejected(
                        CdnXhttpRuntimeFailure.PADDING_NONE_UNREPRESENTABLE,
                    )
                CdnPaddingPlacement.HEADER -> XrayXhttpPaddingPlacement.HEADER
                CdnPaddingPlacement.QUERY -> XrayXhttpPaddingPlacement.QUERY
            },
            paddingMinBytes = provider.xhttp.paddingMinBytes,
            paddingMaxBytes = provider.xhttp.paddingMaxBytes,
        )

        return when (val validated = validateXrayVlessXhttpConfig(config)) {
            is XrayXhttpConfigValidationResult.Invalid ->
                CdnXhttpRuntimeResolution.Rejected(CdnXhttpRuntimeFailure.RENDER_CONFIG_INVALID)
            is XrayXhttpConfigValidationResult.Valid ->
                CdnXhttpRuntimeResolution.Ready(
                    validated.config,
                    XrayConfigRenderer.render(validated.config),
                )
        }
    }
}
