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
 * B61 - xray-core v26.7.28's own documented internal default for omitted
 * `xPaddingBytes` (see [XhttpServerConfig]'s own docstring, gateway-side,
 * and this exact figure's cross-reference to this Kotlin file). A real,
 * cited project fact - never an invented number - but see
 * [XrayXhttpProfile.toXrayVlessXhttpConfig]'s own docs for why
 * [paddingPlacement] still has NO equivalent source of truth.
 */
const val XRAY_CORE_DEFAULT_PADDING_MIN_BYTES = 100
const val XRAY_CORE_DEFAULT_PADDING_MAX_BYTES = 1000

/**
 * B61 - the EXIT-role (Frankfurt, B60) counterpart of [toXrayVlessRealityConfig]/
 * [toXrayVlessTlsConfig]. Deliberately NOT [net.pocvpn.client.vpn.xray.CdnXhttpRuntimeConfigResolver] -
 * that resolver belongs to the Stockholm/B35 CDN-fronted INGRESS relay flow
 * (a signed [net.pocvpn.client.reachability.CdnProviderCapabilityProfile]
 * negotiation), a genuinely different trust/config surface from this EXIT's
 * own fixed B58/B59/B60 identity - see docs/B58/B59/B60 for why Frankfurt's
 * own values are NOT provider-negotiated.
 *
 * Maps ONLY the fields B60's wire response actually supplies
 * ([server]/[serverPort]/[uuid]/[xhttpHost]/[xhttpPath]/[mode]/
 * [uplinkHttpMethod]/[fingerprint]) plus [tlsServerName] (B60/B61 §2.5:
 * the SAME public hostname as [server] - Cloudflare's single-hostname front
 * for this deployment, never a second, independently-invented value) and
 * [queryParameters]/[headers] (empty - B57 proved packet-up needs neither).
 *
 * [minimumTlsVersion]/[alpn]/[maxEachPostBytes]/[paddingPlacement] have NO
 * existing project source of truth for the EXIT role (unlike the CDN
 * ingress flow's own [net.pocvpn.client.reachability.CdnClientCapabilityPolicy.pinnedXhttp],
 * which is a DIFFERENT, provider-negotiated surface this function
 * deliberately does not read from - see this function's own docs above).
 * `docs/ROADMAP.md`'s own XHTTP Traffic-Shape row is explicit that this
 * class of value requires real per-deployment validation, "never a copied
 * community claim." B61 therefore takes these as explicit, nullable
 * parameters with NO default and NO fallback: this function returns null
 * (never a fabricated config) whenever any of them is null - callers MUST
 * supply real, owner-decided values before this can ever produce a
 * connectable config. [paddingMinBytes]/[paddingMaxBytes] are the ONE
 * exception: xray-core's own documented default (100..1000, see
 * [XRAY_CORE_DEFAULT_PADDING_MIN_BYTES]) is a real, cited fact, not an
 * invention.
 */
fun XrayXhttpProfile.toXrayVlessXhttpConfig(
    minimumTlsVersion: XrayXhttpMinimumTlsVersion?,
    alpn: String?,
    maxEachPostBytes: Int?,
    paddingPlacement: XrayXhttpPaddingPlacement?,
): XrayVlessXhttpConfig? {
    val resolvedMode = XrayXhttpMode.entries.firstOrNull { it.wireValue == mode } ?: return null
    val resolvedUplinkHttpMethod = XrayXhttpUplinkHttpMethod.entries.firstOrNull { it.wireValue == uplinkHttpMethod } ?: return null
    if (minimumTlsVersion == null || alpn == null || maxEachPostBytes == null || paddingPlacement == null) return null

    return XrayVlessXhttpConfig(
        server = server,
        serverPort = serverPort,
        uuid = uuid,
        tlsServerName = server,
        fingerprint = fingerprint,
        minimumTlsVersion = minimumTlsVersion,
        alpn = alpn,
        xhttpHost = xhttpHost,
        xhttpPath = xhttpPath,
        queryParameters = emptyMap(),
        headers = emptyMap(),
        mode = resolvedMode,
        uplinkHttpMethod = resolvedUplinkHttpMethod,
        maxEachPostBytes = maxEachPostBytes,
        paddingPlacement = paddingPlacement,
        paddingMinBytes = XRAY_CORE_DEFAULT_PADDING_MIN_BYTES,
        paddingMaxBytes = XRAY_CORE_DEFAULT_PADDING_MAX_BYTES,
    )
}
