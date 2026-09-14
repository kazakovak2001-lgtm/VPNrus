package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind

/**
 * B42 - typed view of safe transport facts carried by the already signed
 * EndpointManifest binding. It deliberately contains no credential-bearing
 * material. Legacy bindings remain representable and keep their existing
 * execution semantics; profile-bearing bindings are validated before use.
 */
sealed interface SignedTransportProfile {
    val endpointId: EndpointId
    val transportKind: TransportKind

    data class Legacy(
        override val endpointId: EndpointId,
        override val transportKind: TransportKind,
    ) : SignedTransportProfile

    data class CdnXhttp(
        override val endpointId: EndpointId,
        val profile: CdnProviderCapabilityProfile,
    ) : SignedTransportProfile {
        override val transportKind: TransportKind = TransportKind.XRAY_XHTTP
    }
}

sealed interface SignedTransportProfileReadResult {
    data class Parsed(val profile: SignedTransportProfile) : SignedTransportProfileReadResult
    data object Missing : SignedTransportProfileReadResult
    data object Unsupported : SignedTransportProfileReadResult
    data object Invalid : SignedTransportProfileReadResult
}

/** Reads only the typed, safe facts for this exact endpoint/binding pair. */
fun EndpointTransportBinding.signedTransportProfile(endpointId: EndpointId): SignedTransportProfileReadResult {
    return when (val cdn = cdnProviderProfile()) {
        CdnProviderProfileReadResult.Missing -> SignedTransportProfileReadResult.Parsed(
            SignedTransportProfile.Legacy(endpointId, kind),
        )
        CdnProviderProfileReadResult.UnsupportedVersion -> SignedTransportProfileReadResult.Unsupported
        CdnProviderProfileReadResult.Invalid -> SignedTransportProfileReadResult.Invalid
        is CdnProviderProfileReadResult.Parsed -> {
            if (kind != TransportKind.XRAY_XHTTP || ingressKind() != IngressKind.CDN_FRONTED) {
                SignedTransportProfileReadResult.Invalid
            } else {
                SignedTransportProfileReadResult.Parsed(SignedTransportProfile.CdnXhttp(endpointId, cdn.profile))
            }
        }
    }
}
