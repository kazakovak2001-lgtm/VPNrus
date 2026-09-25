package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.xray.XrayXhttpMode
import net.pocvpn.client.vpn.xray.isXhttpPath

/**
 * B-WL-R6 - the public, SIGNED transport facts a VLESS + REALITY + XHTTP
 * binding carries in its manifest metadata: the XHTTP path and mode. The
 * REALITY material (uuid, public key, short id, serverName, fingerprint)
 * stays in the per-device provisioned Xray profile - nothing secret lives in
 * the manifest. host/port come from the binding itself.
 */
data class RealityXhttpBindingProfile(val xhttpPath: String, val mode: XrayXhttpMode)

sealed interface RealityXhttpBindingReadResult {
    data class Parsed(val profile: RealityXhttpBindingProfile) : RealityXhttpBindingReadResult
    data object Missing : RealityXhttpBindingReadResult
    data object Invalid : RealityXhttpBindingReadResult
}

const val REALITY_XHTTP_PATH_METADATA_KEY: String = "realityXhttpPath"
const val REALITY_XHTTP_MODE_METADATA_KEY: String = "realityXhttpMode"

/**
 * Fail-closed reader: only an [TransportKind.XRAY_REALITY_XHTTP] binding with
 * a normalized XHTTP path (same rules as the client/server validators) and a
 * mode the pinned xray-core v26.7.28 accepts parses. A missing path is
 * [RealityXhttpBindingReadResult.Missing] - there is deliberately no default
 * path; a missing mode defaults to "auto", which is also xray-core's own
 * default for an empty mode.
 */
fun EndpointTransportBinding.realityXhttpProfile(): RealityXhttpBindingReadResult {
    if (kind != TransportKind.XRAY_REALITY_XHTTP) return RealityXhttpBindingReadResult.Invalid
    val path = metadata[REALITY_XHTTP_PATH_METADATA_KEY] ?: return RealityXhttpBindingReadResult.Missing
    if (!isXhttpPath(path)) return RealityXhttpBindingReadResult.Invalid
    val rawMode = metadata[REALITY_XHTTP_MODE_METADATA_KEY]
    val mode = if (rawMode == null) XrayXhttpMode.AUTO else XrayXhttpMode.entries.firstOrNull { it.wireValue == rawMode }
        ?: return RealityXhttpBindingReadResult.Invalid
    return RealityXhttpBindingReadResult.Parsed(RealityXhttpBindingProfile(path, mode))
}
