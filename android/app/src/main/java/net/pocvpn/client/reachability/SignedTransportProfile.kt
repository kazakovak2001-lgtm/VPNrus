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

    /**
     * B45B-1 - PUBLIC/SIGNED Shadowsocks 2022 facts only (see
     * [Shadowsocks2022Profile]'s own doc for the public/secret split). TYPES
     * ONLY as of B45B-1 - constructing this value does not activate any
     * runtime consumption; no code path reads it to drive a real connection
     * yet.
     */
    data class Shadowsocks2022(
        override val endpointId: EndpointId,
        val profile: Shadowsocks2022Profile,
    ) : SignedTransportProfile {
        override val transportKind: TransportKind = TransportKind.SHADOWSOCKS_2022
    }

    /** B-WL-R6 - PUBLIC/SIGNED REALITY+XHTTP facts only (path, mode); REALITY credentials stay in the device's Xray profile. */
    data class RealityXhttp(
        override val endpointId: EndpointId,
        val profile: RealityXhttpBindingProfile,
    ) : SignedTransportProfile {
        override val transportKind: TransportKind = TransportKind.XRAY_REALITY_XHTTP
    }
}

sealed interface SignedTransportProfileReadResult {
    data class Parsed(val profile: SignedTransportProfile) : SignedTransportProfileReadResult
    data object Missing : SignedTransportProfileReadResult
    data object Unsupported : SignedTransportProfileReadResult
    data object Invalid : SignedTransportProfileReadResult
}

/**
 * Reads only the typed, safe facts for this exact endpoint/binding pair.
 * Dispatches by [EndpointTransportBinding.kind] first: a kind with no typed
 * profile reader of its own (everything except [TransportKind.XRAY_XHTTP]
 * and, as of B45B-1, [TransportKind.SHADOWSOCKS_2022]) always reads as
 * [SignedTransportProfile.Legacy] - the existing, already-established
 * fail-closed/not-yet-wired fallback, unchanged by adding a new kind.
 */
fun EndpointTransportBinding.signedTransportProfile(endpointId: EndpointId): SignedTransportProfileReadResult {
    if (kind == TransportKind.XRAY_XHTTP) {
        return when (val cdn = cdnProviderProfile()) {
            CdnProviderProfileReadResult.Missing -> SignedTransportProfileReadResult.Parsed(
                SignedTransportProfile.Legacy(endpointId, kind),
            )
            CdnProviderProfileReadResult.UnsupportedVersion -> SignedTransportProfileReadResult.Unsupported
            CdnProviderProfileReadResult.Invalid -> SignedTransportProfileReadResult.Invalid
            is CdnProviderProfileReadResult.Parsed -> {
                if (ingressKind() != IngressKind.CDN_FRONTED) {
                    SignedTransportProfileReadResult.Invalid
                } else {
                    SignedTransportProfileReadResult.Parsed(SignedTransportProfile.CdnXhttp(endpointId, cdn.profile))
                }
            }
        }
    }

    if (kind == TransportKind.SHADOWSOCKS_2022) {
        return when (val ss = shadowsocks2022Profile()) {
            Shadowsocks2022ProfileReadResult.Missing -> SignedTransportProfileReadResult.Parsed(
                SignedTransportProfile.Legacy(endpointId, kind),
            )
            Shadowsocks2022ProfileReadResult.UnsupportedVersion -> SignedTransportProfileReadResult.Unsupported
            Shadowsocks2022ProfileReadResult.Invalid -> SignedTransportProfileReadResult.Invalid
            is Shadowsocks2022ProfileReadResult.Parsed -> SignedTransportProfileReadResult.Parsed(
                SignedTransportProfile.Shadowsocks2022(endpointId, ss.profile),
            )
        }
    }

    // B-WL-R6 - a brand-new kind has no legacy semantics to preserve: its
    // signed XHTTP facts are required, so a missing path is Invalid (fail
    // closed), never a Legacy fallback.
    if (kind == TransportKind.XRAY_REALITY_XHTTP) {
        return when (val profile = realityXhttpProfile()) {
            is RealityXhttpBindingReadResult.Parsed -> SignedTransportProfileReadResult.Parsed(
                SignedTransportProfile.RealityXhttp(endpointId, profile.profile),
            )
            RealityXhttpBindingReadResult.Missing, RealityXhttpBindingReadResult.Invalid -> SignedTransportProfileReadResult.Invalid
        }
    }

    return SignedTransportProfileReadResult.Parsed(SignedTransportProfile.Legacy(endpointId, kind))
}
