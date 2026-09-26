package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.identity.XrayXhttpProfile

/** The one place a stored [XrayProfile] becomes a renderer/service-ready [XrayVlessRealityConfig]. */
fun XrayProfile.toXrayVlessRealityConfig(): XrayVlessRealityConfig = XrayVlessRealityConfig(
    server = server,
    serverPort = serverPort,
    uuid = uuid,
    flow = flow,
    serverName = serverName,
    fingerprint = fingerprint,
    realityPublicKey = realityPublicKey,
    shortId = shortId,
)

/** B8O2 - the TLS/TCP counterpart: a stored [XrayTlsProfile] becomes a renderer/service-ready [XrayVlessTlsConfig]. */
fun XrayTlsProfile.toXrayVlessTlsConfig(): XrayVlessTlsConfig = XrayVlessTlsConfig(
    server = server,
    serverPort = serverPort,
    uuid = uuid,
    serverName = serverName,
    fingerprint = fingerprint,
)

/**
 * B61.4 - the EXIT-role's fixed `minimumTlsVersion`/`alpn`/`maxEachPostBytes`
 * values, each backed by evidence read directly from the pinned Xray-core
 * v26.7.28 source (commit `5ca6f4b`, see B61.3's audit) - never copied from
 * the Stockholm/B35 CDN-ingress signed provider profile
 * ([net.pocvpn.client.reachability.CdnClientCapabilityPolicy.pinnedXhttp]),
 * which is a different, provider-negotiated trust surface.
 *
 * - [EXIT_XHTTP_MINIMUM_TLS_VERSION] = TLS_1_3: `transport/internet/tls/tls.go`'s
 *   `copyConfig()` never copies `MinVersion`/`MaxVersion` into the uTLS
 *   config the SplitHTTP dialer actually uses whenever `fingerprint` is set
 *   (`transport/internet/splithttp/dialer.go` - this EXIT config always
 *   sets `fingerprint`) - this field is proven inert on the real dial path,
 *   so any valid value is safe; TLS_1_3 is used for label consistency.
 * - [EXIT_XHTTP_ALPN] = "h2": `infra/conf/transport_security.go`'s
 *   `TLSConfig.Build()` defaults `NextProtos` to `["h2", "http/1.1"]` when
 *   unset, and that value DOES reach the real uTLS ClientHello (`copyConfig`
 *   copies `NextProtos`, unlike MinVersion) - "h2" is Xray's own
 *   first-preference default, not an invented value.
 * - [EXIT_XHTTP_MAX_EACH_POST_BYTES] = 1000000: `transport/internet/splithttp/config.go`'s
 *   `GetNormalizedScMaxEachPostBytes()` returns exactly `{From: 1000000, To:
 *   1000000}` when the field is omitted - Xray-core's own real, general
 *   default (never the Stockholm ingress profile's own `524288`).
 *
 * `paddingPlacement`/`paddingMinBytes`/`paddingMaxBytes` are deliberately
 * NOT set here (left null - see [XrayVlessXhttpConfig]'s own docs): the
 * SAME pinned source (`splithttp/config.go`'s `FillPacketRequest`) proves
 * omitting them is real, defined behavior (Xray-core's own
 * `PlacementQueryInHeader` default), and that placement has no equivalent
 * member in [XrayXhttpPaddingPlacement] - never approximated as HEADER or
 * QUERY.
 */
val EXIT_XHTTP_MINIMUM_TLS_VERSION = XrayXhttpMinimumTlsVersion.TLS_1_3
const val EXIT_XHTTP_ALPN = "h2"
const val EXIT_XHTTP_MAX_EACH_POST_BYTES = 1_000_000

/**
 * B61/B61.4 - the EXIT-role (Frankfurt, B60) counterpart of
 * [toXrayVlessRealityConfig]/[toXrayVlessTlsConfig]. Deliberately NOT
 * [net.pocvpn.client.vpn.xray.CdnXhttpRuntimeConfigResolver] - that
 * resolver belongs to the Stockholm/B35 CDN-fronted INGRESS relay flow (a
 * signed [net.pocvpn.client.reachability.CdnProviderCapabilityProfile]
 * negotiation), a genuinely different trust/config surface from this
 * EXIT's own fixed B58/B59/B60 identity.
 *
 * Maps the fields B60's wire response actually supplies
 * ([server]/[serverPort]/[uuid]/[xhttpHost]/[xhttpPath]/[mode]/
 * [uplinkHttpMethod]/[fingerprint]) plus [tlsServerName] (B60/B61 §2.5: the
 * SAME public hostname as [server]) and [queryParameters]/[headers] (empty
 * - B57 proved packet-up needs neither), and fills
 * [minimumTlsVersion]/[alpn]/[maxEachPostBytes] with the evidence-backed
 * EXIT constants above (B61.4 - see B61.3's audit for the source). Padding
 * fields are left null (omitted) - see [XrayVlessXhttpConfig]'s own docs.
 */
fun XrayXhttpProfile.toXrayVlessXhttpConfig(): XrayVlessXhttpConfig? {
    val resolvedMode = XrayXhttpMode.entries.firstOrNull { it.wireValue == mode } ?: return null
    val resolvedUplinkHttpMethod = XrayXhttpUplinkHttpMethod.entries.firstOrNull { it.wireValue == uplinkHttpMethod } ?: return null

    return XrayVlessXhttpConfig(
        server = server,
        serverPort = serverPort,
        uuid = uuid,
        tlsServerName = server,
        fingerprint = fingerprint,
        minimumTlsVersion = EXIT_XHTTP_MINIMUM_TLS_VERSION,
        alpn = EXIT_XHTTP_ALPN,
        xhttpHost = xhttpHost,
        xhttpPath = xhttpPath,
        queryParameters = emptyMap(),
        headers = emptyMap(),
        mode = resolvedMode,
        uplinkHttpMethod = resolvedUplinkHttpMethod,
        maxEachPostBytes = EXIT_XHTTP_MAX_EACH_POST_BYTES,
        paddingPlacement = null,
        paddingMinBytes = null,
        paddingMaxBytes = null,
    )
}
