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

    suspend fun inTunnel(vpn: Network?, directResolver: List<String>): JSONObject {
        val resolver = resolverIdentity(vpn)
        val v6Default = FieldProbes.https("IPv6-only (app default network)", IPV6_ONLY_URL, null, maxBytes = 256)
        val o = JSONObject()
            .put("resolverViaVpn", JSONArray(resolver.addresses))
            .put("resolverDirect", JSONArray(directResolver))
            .put("dnsLeakSuspected", resolver.ok && directResolver.isNotEmpty() && resolver.addresses.any { it in directResolver })
            .put("ipv6EgressWhileConnected", v6Default.httpStatus != null)
            .put("ipv6Error", v6Default.error ?: JSONObject.NULL)
        o.put("verdict", leakVerdict(o.getBoolean("dnsLeakSuspected"), o.getBoolean("ipv6EgressWhileConnected")))
        return o
    }

    internal fun leakVerdict(dnsLeak: Boolean, ipv6Egress: Boolean): String = when {
        dnsLeak && ipv6Egress -> "DNS_LEAK_SUSPECTED+IPV6_LEAK"
        dnsLeak -> "DNS_LEAK_SUSPECTED"
        ipv6Egress -> "IPV6_LEAK"
        else -> "NO_LEAK_OBSERVED"
    }
}

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
