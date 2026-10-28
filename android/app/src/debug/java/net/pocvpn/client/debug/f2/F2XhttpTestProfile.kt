package net.pocvpn.client.debug.f2

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.policy.RoutingMode
import net.pocvpn.client.vpn.xray.XrayVlessXhttpConfig
import net.pocvpn.client.vpn.xray.XrayXhttpConfigValidationResult
import net.pocvpn.client.vpn.xray.XrayXhttpMinimumTlsVersion
import net.pocvpn.client.vpn.xray.XrayXhttpMode
import net.pocvpn.client.vpn.xray.XrayXhttpUplinkHttpMethod
import net.pocvpn.client.vpn.xray.validateXrayVlessXhttpConfig

/**
 * F2A - debug-only, test-endpoint-only construction of an XHTTP config for the REAL
 * VlessXhttpTransport / splithttp dialer. Pure (no Android, no I/O) so it is unit-testable.
 *
 * The three names the dialer works with stay independent: [XrayVlessXhttpConfig.server] is
 * the dial target (`vnext.address`), `tlsServerName` the TLS SNI, `xhttpHost` the HTTP Host.
 *
 * Production cannot be reached from here: the dial target must be a loopback/private IPv4
 * literal or an RFC 6761 reserved test hostname, and SNI/Host must be reserved test
 * hostnames. No production credential exists in this file; the UUID is a fixed dummy. TLS
 * verification is never relaxed (XrayConfigRenderer always renders `allowInsecure=false`).
 */
object F2XhttpTestProfile {
    const val ENDPOINT_ID = "f2-xhttp-harness"
    const val DEFAULT_PATH = "/f2-xhttp/"
    const val DEFAULT_UUID = "00000000-0000-4000-8000-0000000000f2"
    const val DEFAULT_MAX_SECONDS = 20
    const val MIN_MAX_SECONDS = 5
    const val MAX_MAX_SECONDS = 60

    private val RESERVED_SUFFIXES = listOf(".invalid", ".test", ".example", ".localhost")
    private val LABEL = Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
    private val IPV4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")

    enum class Reason {
        DIAL_HOST_NOT_TEST_ONLY,
        SNI_NOT_TEST_ONLY,
        HTTP_HOST_NOT_TEST_ONLY,
        INVALID_PORT,
        UNSUPPORTED_ALPN,
        INVALID_MODE,
        CONFIG_INVALID,
    }

    sealed interface BuildResult {
        data class Ok(val transportConfig: TransportConfig.XrayXhttp, val maxMillis: Long) : BuildResult
        data class Rejected(val reason: Reason) : BuildResult
    }

    fun build(
        dialHost: String?,
        port: Int?,
        sni: String?,
        httpHost: String? = null,
        path: String? = null,
        alpn: String? = null,
        mode: String? = null,
        maxSeconds: Int? = null,
    ): BuildResult {
        val dial = dialHost?.trim()?.lowercase().orEmpty()
        if (!isTestOnlyDialHost(dial)) return BuildResult.Rejected(Reason.DIAL_HOST_NOT_TEST_ONLY)
        if (port == null || port !in 1..65535) return BuildResult.Rejected(Reason.INVALID_PORT)
        val tlsName = sni?.trim()?.lowercase().orEmpty()
        if (!isReservedTestHostname(tlsName)) return BuildResult.Rejected(Reason.SNI_NOT_TEST_ONLY)
        val host = httpHost?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: tlsName
        if (!isReservedTestHostname(host)) return BuildResult.Rejected(Reason.HTTP_HOST_NOT_TEST_ONLY)
        // h3 is refused by the production resolver (HTTP3_DIAL_NOT_BOUNDED): the 5 s dial bound does not cover QUIC.
        val chosenAlpn = alpn?.trim()?.takeIf { it.isNotEmpty() } ?: "h2"
        if (chosenAlpn != "h2" && chosenAlpn != "http/1.1") return BuildResult.Rejected(Reason.UNSUPPORTED_ALPN)
        val chosenMode = if (mode.isNullOrBlank()) {
            XrayXhttpMode.PACKET_UP
        } else {
            XrayXhttpMode.entries.firstOrNull { it.wireValue == mode.trim() }
                ?: return BuildResult.Rejected(Reason.INVALID_MODE)
        }

        val config = XrayVlessXhttpConfig(
            server = dial,
            serverPort = port,
            uuid = DEFAULT_UUID,
            tlsServerName = tlsName,
            fingerprint = "chrome",
            minimumTlsVersion = XrayXhttpMinimumTlsVersion.TLS_1_3,
            alpn = chosenAlpn,
            xhttpHost = host,
            xhttpPath = path?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_PATH,
            queryParameters = emptyMap(),
            headers = emptyMap(),
            mode = chosenMode,
            uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST,
            maxEachPostBytes = 1_000_000,
        )
        if (validateXrayVlessXhttpConfig(config) !is XrayXhttpConfigValidationResult.Valid) {
            return BuildResult.Rejected(Reason.CONFIG_INVALID)
        }
        val seconds = (maxSeconds ?: DEFAULT_MAX_SECONDS).coerceIn(MIN_MAX_SECONDS, MAX_MAX_SECONDS)
        return BuildResult.Ok(
            TransportConfig.XrayXhttp(
                config = config,
                endpointId = EndpointId(ENDPOINT_ID),
                routingMode = RoutingMode.FULL_VPN,
                // Direct: the relayed variant needs a relay exit probe host this harness never has.
                isRelayed = false,
            ),
            seconds * 1_000L,
        )
    }

    fun isTestOnlyDialHost(host: String): Boolean = isPrivateOrLoopbackIpv4(host) || isReservedTestHostname(host)

    fun isPrivateOrLoopbackIpv4(host: String): Boolean {
        val m = IPV4.matchEntire(host) ?: return false
        val o = m.groupValues.drop(1).map { it.toInt() }
        if (o.any { it > 255 }) return false
        return o[0] == 127 || o[0] == 10 || (o[0] == 172 && o[1] in 16..31) || (o[0] == 192 && o[1] == 168)
    }

    fun isReservedTestHostname(host: String): Boolean =
        host.length in 1..253 &&
            RESERVED_SUFFIXES.any { host.endsWith(it) && host.length > it.length } &&
            host.split('.').all { LABEL.matches(it) }
}
