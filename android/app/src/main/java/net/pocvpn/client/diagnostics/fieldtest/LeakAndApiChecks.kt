package net.pocvpn.client.diagnostics.fieldtest

import android.net.Network
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Leak checks run while the tunnel is up.
 *
 *  - DNS: `whoami.akamai.net` resolves to the address of the recursive
 *    resolver that asked Akamai. Resolved through the VPN network it must
 *    NOT be the same resolver seen with the VPN off; the same resolver means
 *    the queries still leave through the ISP (leak suspected).
 *  - IPv6: our exits have no IPv6 egress, so any successful request to an
 *    IPv6-only endpoint while connected left outside the tunnel. Only the
 *    yes/no outcome is stored, never the address.
 */
object LeakChecks {
    const val RESOLVER_WHOAMI = "whoami.akamai.net"
    const val IPV6_ONLY_URL = "https://api6.ipify.org/"

    suspend fun resolverIdentity(network: Network?): DnsProbeResult = FieldProbes.dns(RESOLVER_WHOAMI, network)

    /**
     * [baselineHasGlobalIpv6] - whether the network seen before the test had
     * a global IPv6 address (null = not known). When it is known to be
     * false the IPv6 request is not made at all: its result could not mean
     * anything, and B54 Scope A reports that as NOT_RUN instead.
     */
    suspend fun inTunnel(vpn: Network?, directResolver: List<String>, baselineHasGlobalIpv6: Boolean?): JSONObject {
        val resolver = resolverIdentity(vpn)
        val v6Default = if (baselineHasGlobalIpv6 == false) {
            null
        } else {
            FieldProbes.https("IPv6-only (app default network)", IPV6_ONLY_URL, null, maxBytes = 256)
        }
        return report(vpnBound = vpn != null, resolver, directResolver, baselineHasGlobalIpv6, v6Default)
    }

    /**
     * Pure: the `leaks` JSON. The historical keys (`dnsLeakSuspected`,
     * `ipv6EgressWhileConnected`, `ipv6Error`, `verdict`) keep their exact
     * pre-Scope-A meaning - including `NO_LEAK_OBSERVED` for a failed
     * measurement - so older consumers and report comparisons are unchanged.
     * The B54 Scope A keys (`dnsResult`/`dnsReason`, `ipv6Result`/`ipv6Reason`,
     * `dnsEvidence`) are the ones that tell a failed measurement apart.
     */
    internal fun report(
        vpnBound: Boolean,
        resolver: DnsProbeResult,
        directResolver: List<String>,
        baselineHasGlobalIpv6: Boolean?,
        v6Default: HttpProbeResult?,
    ): JSONObject {
        val dns = classifyDns(vpnBound, resolver, directResolver)
        val ipv6 = classifyIpv6(baselineHasGlobalIpv6, v6Default)
        val o = JSONObject()
            .put("resolverViaVpn", JSONArray(resolver.addresses))
            .put("resolverDirect", JSONArray(directResolver))
            .put("dnsLeakSuspected", resolver.ok && directResolver.isNotEmpty() && resolver.addresses.any { it in directResolver })
            .put("ipv6EgressWhileConnected", v6Default?.httpStatus != null)
            .put("ipv6Error", v6Default?.error ?: JSONObject.NULL)
        o.put("verdict", leakVerdict(o.getBoolean("dnsLeakSuspected"), o.getBoolean("ipv6EgressWhileConnected")))
        o.put("dnsResult", dns.result.name).put("dnsReason", dns.reason?.name ?: JSONObject.NULL)
        // A VPN-bound lookup shows which socket the query used, not the path
        // every packet took - the strongest DNS claim this check can carry.
        o.put("dnsEvidence", if (vpnBound) DNS_EVIDENCE_SOCKET_BINDING else JSONObject.NULL)
        o.put("ipv6Result", ipv6.result.name).put("ipv6Reason", ipv6.reason?.name ?: JSONObject.NULL)
        return o
    }

    const val DNS_EVIDENCE_SOCKET_BINDING = "VPN_NETWORK_SOCKET_BINDING_ONLY"

    /**
     * B54 Scope A - DNS: a leak or no-leak result needs a working lookup
     * bound to the VPN network AND a direct-resolver baseline. Anything
     * less is INCONCLUSIVE, never "no leak".
     */
    internal fun classifyDns(vpnBound: Boolean, resolver: DnsProbeResult, directResolver: List<String>): LeakCheck = when {
        !vpnBound -> LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.NO_VPN_NETWORK)
        !resolver.ok -> LeakCheck(LeakCheckResult.INCONCLUSIVE, reasonFor(resolver.failureKind))
        resolver.addresses.isEmpty() -> LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.LOOKUP_FAILED)
        directResolver.isEmpty() -> LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.NO_BASELINE)
        resolver.addresses.any { it in directResolver } -> LeakCheck(LeakCheckResult.LEAK_DETECTED, null)
        else -> LeakCheck(LeakCheckResult.NO_LEAK_DETECTED, null)
    }

    /**
     * B54 Scope A - IPv6: the probe runs unbound on the default network and
     * never reads the address it reached, so it can prove neither a leak
     * nor its absence. Every result it ran for is INCONCLUSIVE; only a
     * baseline network without global IPv6 skips it (NOT_RUN).
     */
    internal fun classifyIpv6(baselineHasGlobalIpv6: Boolean?, probe: HttpProbeResult?): LeakCheck = when {
        baselineHasGlobalIpv6 == false -> LeakCheck(LeakCheckResult.NOT_RUN, LeakCheckReason.NO_IPV6_ON_NETWORK)
        probe == null -> LeakCheck(LeakCheckResult.NOT_RUN, null)
        probe.httpStatus != null -> LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.EGRESS_NOT_VERIFIED)
        else -> LeakCheck(LeakCheckResult.INCONCLUSIVE, reasonFor(probe.failureKind))
    }

    private fun reasonFor(kind: ProbeFailureKind?): LeakCheckReason = when (kind) {
        ProbeFailureKind.TIMEOUT -> LeakCheckReason.TIMEOUT
        ProbeFailureKind.UNKNOWN_HOST -> LeakCheckReason.LOOKUP_FAILED
        ProbeFailureKind.OTHER, null -> LeakCheckReason.REQUEST_FAILED
    }

    /**
     * B54 Scope B - a copy of [leaks] whose typed results no longer count:
     * every check that ran becomes INCONCLUSIVE/SESSION_CHANGED. A NOT_RUN
     * check stays as it was; the historical keys are left untouched.
     */
    fun invalidatedBySessionChange(leaks: JSONObject): JSONObject {
        val o = JSONObject(leaks.toString())
        listOf("dns", "ipv6").forEach { check ->
            if (storedResult(o, "${check}Result") != LeakCheckResult.NOT_RUN) {
                o.put("${check}Result", LeakCheckResult.INCONCLUSIVE.name).put("${check}Reason", LeakCheckReason.SESSION_CHANGED.name)
            }
        }
        return o
    }

    /**
     * Reads a Scope A result back from a report's `leaks` object. Null means
     * UNKNOWN: a report from before Scope A (no such key) or a value this
     * build does not know - never a no-leak result.
     */
    fun storedResult(leaks: JSONObject?, key: String): LeakCheckResult? {
        val name = leaks?.optString(key, "").orEmpty()
        return LeakCheckResult.entries.firstOrNull { it.name == name }
    }

    /** Summary text: the historical verdict, plus the Scope A results when the report has them. */
    fun summaryText(leaks: JSONObject): String {
        val dns = storedResult(leaks, "dnsResult") ?: return leaks.optString("verdict")
        val ipv6 = storedResult(leaks, "ipv6Result")
        fun part(result: LeakCheckResult?, reasonKey: String) =
            (result?.name ?: "UNKNOWN") + (leaks.optString(reasonKey, "").takeIf { it.isNotEmpty() && it != "null" }?.let { "/$it" } ?: "")
        return "${leaks.optString("verdict")} (DNS ${part(dns, "dnsReason")}, IPv6 ${part(ipv6, "ipv6Reason")})"
    }

    internal fun leakVerdict(dnsLeak: Boolean, ipv6Egress: Boolean): String = when {
        dnsLeak && ipv6Egress -> "DNS_LEAK_SUSPECTED+IPV6_LEAK"
        dnsLeak -> "DNS_LEAK_SUSPECTED"
        ipv6Egress -> "IPV6_LEAK"
        else -> "NO_LEAK_OBSERVED"
    }
}

/** B54 Scope A - outcome of one leak check. */
enum class LeakCheckResult {
    /** The measurement worked and found evidence of a leak. */
    LEAK_DETECTED,

    /** The measurement worked, a baseline existed and no leak evidence was found. */
    NO_LEAK_DETECTED,

    /** The measurement ran but proves neither a leak nor its absence. */
    INCONCLUSIVE,

    /** The measurement was not made. */
    NOT_RUN,
}

/** B54 Scope A - why a check is INCONCLUSIVE or NOT_RUN. Closed list, never exception text. */
enum class LeakCheckReason {
    /** The lookup failed (unknown host) or returned no address. */
    LOOKUP_FAILED,
    TIMEOUT,

    /** The request failed for a reason other than a lookup failure or timeout. */
    REQUEST_FAILED,

    /** No VPN network was available, so the lookup was not bound to the tunnel. */
    NO_VPN_NETWORK,

    /** B54 Scope B - the session left Connected or was replaced while the check ran. */
    SESSION_CHANGED,
    NO_IPV6_ON_NETWORK,

    /** No direct-resolver baseline to compare with. */
    NO_BASELINE,

    /** The request got an answer, but the address it reached was not read or checked. */
    EGRESS_NOT_VERIFIED,
}

data class LeakCheck(val result: LeakCheckResult, val reason: LeakCheckReason?)

/**
 * Activation/profile API reachability without side effects: the same
 * POST /v1/activate and /v1/xray-profile the app sends, with an
 * intentionally invalid public key, so the server answers 400 before any
 * credential lookup, store read or write (B57 limiter verification used the
 * same shape). A 400/401/403 = TLS + nginx + API path works from this
 * network; a timeout/reset = the activation path itself is blocked.
 */
object ApiReachability {
    private const val INVALID_KEY_BODY = """{"public_key":"field-test-invalid-key"}"""

    suspend fun check(origins: List<String>): JSONArray {
        val out = JSONArray()
        origins.forEach { origin ->
            listOf("/v1/activate", "/v1/xray-profile").forEach { path ->
                out.put(post(origin, path))
            }
            val manifest = FieldProbes.https("$origin manifest", "https://$origin/v1/manifest", null, maxBytes = 16 * 1024)
            out.put(
                JSONObject().put("origin", origin).put("path", "/v1/manifest").put("httpStatus", manifest.httpStatus ?: JSONObject.NULL)
                    .put("bytes", manifest.bytesRead).put("elapsedMs", manifest.elapsedMs).put("error", manifest.error ?: JSONObject.NULL)
                    .put("verdict", apiVerdict(manifest.httpStatus)),
            )
        }
        return out
    }

    private suspend fun post(origin: String, path: String): JSONObject = withContext(Dispatchers.IO) {
        val start = System.nanoTime()
        val o = JSONObject().put("origin", origin).put("path", path)
        try {
            val c = URL("https://$origin$path").openConnection() as HttpsURLConnection
            c.requestMethod = "POST"
            c.connectTimeout = 10_000
            c.readTimeout = 10_000
            c.doOutput = true
            c.instanceFollowRedirects = false
            c.setRequestProperty("Content-Type", "application/json")
            c.setRequestProperty("Authorization", "Bearer field-test-invalid")
            try {
                c.outputStream.use { it.write(INVALID_KEY_BODY.toByteArray()) }
                val status = c.responseCode
                val body = (if (status >= 400) c.errorStream else c.inputStream)?.bufferedReader()?.use { it.readText().take(300) }
                o.put("httpStatus", status).put("body", body?.let(LogSanitizer::sanitize) ?: JSONObject.NULL)
                    .put("verdict", apiVerdict(status))
            } finally {
                c.disconnect()
            }
        } catch (e: Exception) {
            o.put("httpStatus", JSONObject.NULL).put("error", describeError(e)).put("verdict", apiVerdict(null))
        }
        o.put("elapsedMs", (System.nanoTime() - start) / 1_000_000)
    }

    internal fun apiVerdict(status: Int?): String = when {
        status == null -> "API_UNREACHABLE"
        status in 200..499 && status != 429 -> "API_REACHABLE"
        status == 429 -> "API_RATE_LIMITED"
        else -> "API_SERVER_ERROR"
    }
}
