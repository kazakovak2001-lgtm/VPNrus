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

    /**
     * B46-4A - PUBLIC/SIGNED Hysteria2 facts only (see [Hysteria2Profile]'s
     * own doc for the public/secret split). TYPES ONLY as of B46-4A in the
     * sense that constructing this value alone never activates a real
     * connection: a binding must also pass
     * [net.pocvpn.client.MainViewModel.isHysteria2AvailableFor]'s full
     * eligibility (trusted binding + credential + ABI/binary) before
     * `TransportRegistry` ever reports HYSTERIA2 AVAILABLE.
     */
    data class Hysteria2(
        override val endpointId: EndpointId,
        val profile: Hysteria2Profile,
    ) : SignedTransportProfile {
        override val transportKind: TransportKind = TransportKind.HYSTERIA2
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

    if (kind == TransportKind.HYSTERIA2) {
        return when (val hy = hysteria2Profile()) {
            Hysteria2ProfileReadResult.Missing -> SignedTransportProfileReadResult.Parsed(
                SignedTransportProfile.Legacy(endpointId, kind),
            )
            Hysteria2ProfileReadResult.UnsupportedVersion -> SignedTransportProfileReadResult.Unsupported
            Hysteria2ProfileReadResult.Invalid -> SignedTransportProfileReadResult.Invalid
            is Hysteria2ProfileReadResult.Parsed -> SignedTransportProfileReadResult.Parsed(
                SignedTransportProfile.Hysteria2(endpointId, hy.profile),
            )
        }
    }

    return SignedTransportProfileReadResult.Parsed(SignedTransportProfile.Legacy(endpointId, kind))
}
