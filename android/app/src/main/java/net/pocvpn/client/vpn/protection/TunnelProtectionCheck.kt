package net.pocvpn.client.vpn.protection

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.VpnDnsPolicy
import net.pocvpn.client.vpn.policy.Ipv4RouteExclusion
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress

/**
 * B-WL7 layer 3a - what Android actually installed for this app's VPN
 * network once a session is Connected: its routes, DNS servers and whether
 * the interface carries a global IPv6 address. Read from the system
 * (`ConnectivityManager.getLinkProperties`), never from our own plan, so the
 * check sees the interface as the OS routes it. Destinations are CIDR text
 * ("0.0.0.0/0", "::/0").
 */
data class TunnelLinkSnapshot(
    val routeDestinations: List<String>,
    val dnsServers: List<String>,
    val hasGlobalIpv6Address: Boolean,
)

enum class TunnelProtectionStatus {
    /** Every check below passed against the system's view of the VPN network. */
    VERIFIED,

    /** At least one finding: some traffic class could leave outside the tunnel. */
    LEAK_SUSPECTED,

    /** No VPN network was visible to read; nothing is claimed either way. */
    NOT_VERIFIABLE,
}

enum class TunnelProtectionFinding {
    /** A public IPv4 destination is not covered by any tunnel route. */
    IPV4_PUBLIC_NOT_COVERED,

    /** The VPN network's DNS servers are not the ones VpnDnsPolicy sets. */
    DNS_SERVERS_UNEXPECTED,

    /** A DNS server is not itself reachable through a tunnel route. */
    DNS_SERVER_NOT_IN_TUNNEL,

    /** IPv6 is enabled on the tunnel but public IPv6 is not fully captured. */
    IPV6_NOT_FULLY_CAPTURED,
}

data class TunnelProtectionResult(
    val status: TunnelProtectionStatus,
    val findings: List<TunnelProtectionFinding>,
    /** "CAPTURED" (::/0 in the tunnel), "BLOCKED" (no IPv6 on the tunnel: Android drops the family) or "PARTIAL". */
    val ipv6: String?,
)

/**
 * Pure evaluation. Observational in this slice: the result is recorded, it
 * never ends a session or changes Protected (an unexpected reading on one
 * device must not tear down a working tunnel before field evidence exists).
 */
object TunnelProtectionCheck {

    /**
     * Public addresses that every full-tunnel route set must cover: FULL_VPN
     * (0.0.0.0/0) and ADAPTIVE (0.0.0.0/0 minus [Ipv4RouteExclusion.LOCAL_PRIVATE_RANGES])
     * both do. Spread over the address space so a route set missing a large
     * block is caught; none is in a local private range.
     */
    val PUBLIC_IPV4_SAMPLES = listOf(
        "1.1.1.1", "8.8.8.8", "9.9.9.9", "45.90.28.0", "77.88.8.8",
        "104.16.0.1", "142.250.0.1", "185.199.108.1", "203.0.113.1", "223.5.5.5",
    )
    /** Spread over the whole global-unicast block 2000::/3 (2000:: .. 3fff::), so a route set covering only part of it is caught. */
    val PUBLIC_IPV6_SAMPLES = listOf(
        "2001:4860:4860::8888", "2606:4700:4700::1111", "2a02:6b8::feed:0ff", "2c0f:fb50:4003::1", "3fff:ffff::1",
    )

    fun evaluate(snapshot: TunnelLinkSnapshot?, expectedDns: List<String> = VpnDnsPolicy.servers): TunnelProtectionResult {
        if (snapshot == null) return TunnelProtectionResult(TunnelProtectionStatus.NOT_VERIFIABLE, emptyList(), null)
        val v4Routes = snapshot.routeDestinations.filter { ':' !in it }
        val v6Routes = snapshot.routeDestinations.filter { ':' in it }
        val findings = mutableListOf<TunnelProtectionFinding>()

        if (PUBLIC_IPV4_SAMPLES.any { ip -> v4Routes.none { cidrContains(it, ip) } }) {
            findings += TunnelProtectionFinding.IPV4_PUBLIC_NOT_COVERED
        }
        if (snapshot.dnsServers.toSet() != expectedDns.toSet()) {
            findings += TunnelProtectionFinding.DNS_SERVERS_UNEXPECTED
        }
        if (snapshot.dnsServers.any { dns -> snapshot.routeDestinations.none { cidrContains(it, dns) } }) {
            findings += TunnelProtectionFinding.DNS_SERVER_NOT_IN_TUNNEL
        }
        val ipv6 = when {
            // VpnService.Builder: a family with no address, route or DNS is blocked for apps on the VPN.
            v6Routes.isEmpty() && !snapshot.hasGlobalIpv6Address && snapshot.dnsServers.none { ':' in it } -> "BLOCKED"
            PUBLIC_IPV6_SAMPLES.all { ip -> v6Routes.any { cidrContains(it, ip) } } -> "CAPTURED"
            else -> "PARTIAL"
        }
        if (ipv6 == "PARTIAL") findings += TunnelProtectionFinding.IPV6_NOT_FULLY_CAPTURED

        val status = if (findings.isEmpty()) TunnelProtectionStatus.VERIFIED else TunnelProtectionStatus.LEAK_SUSPECTED
        return TunnelProtectionResult(status, findings, ipv6)
    }

    /** True when [address] lies in [cidr]; false for malformed input or a family mismatch. */
    fun cidrContains(cidr: String, address: String): Boolean {
        val (base, prefixText) = cidr.split('/', limit = 2).takeIf { it.size == 2 } ?: return false
        val prefix = prefixText.toIntOrNull() ?: return false
        val net = literalBytes(base) ?: return false
        val ip = literalBytes(address) ?: return false
        if (net.size != ip.size || prefix !in 0..net.size * 8) return false
        for (bit in 0 until prefix) {
            val mask = 0x80 ushr (bit % 8)
            if ((net[bit / 8].toInt() and mask) != (ip[bit / 8].toInt() and mask)) return false
        }
        return true
    }

    /** Parses IP literals only - never a hostname lookup. */
    private fun literalBytes(text: String): ByteArray? {
        val t = text.trim()
        val looksLiteral = t.isNotEmpty() && (':' in t || t.all { it.isDigit() || it == '.' })
        if (!looksLiteral) return null
        return try {
            InetAddress.getByName(t).address
        } catch (_: Exception) {
            null
        }
    }
}

data class TunnelProtectionRecord(
    val checkId: Long,
    val transport: TransportKind,
    val result: TunnelProtectionResult,
    val reads: Int,
    val atEpochMillis: Long,
    val generation: Long?,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("checkId", checkId)
        .put("transport", transport.name)
        .put("status", result.status.name)
        .put("findings", JSONArray(result.findings.map { it.name }))
        .put("ipv6", result.ipv6 ?: JSONObject.NULL)
        .put("reads", reads)
        .put("atEpochMillis", atEpochMillis)
        .put("generation", generation ?: JSONObject.NULL)
}

/**
 * Bounded, thread-safe in-memory log of the most recent layer-3a checks,
 * same discipline as DataPlaneCheckLog: written only by VpnController, read
 * only by the field report; reading never changes it.
 */
class TunnelProtectionLog(
    private val capacity: Int = DEFAULT_CAPACITY,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    private val lock = Any()
    private val records = ArrayDeque<TunnelProtectionRecord>()
    private var nextId = 1L

    fun record(transport: TransportKind, result: TunnelProtectionResult, reads: Int, generation: Long?): TunnelProtectionRecord =
        synchronized(lock) {
            val r = TunnelProtectionRecord(nextId++, transport, result, reads, clock(), generation)
            records.addLast(r)
            while (records.size > capacity) records.removeFirst()
            r
        }

    fun snapshot(): List<TunnelProtectionRecord> = synchronized(lock) { records.toList() }

    companion object {
        const val DEFAULT_CAPACITY = 10

        fun reportJson(records: List<TunnelProtectionRecord>): JSONObject = JSONObject()
            .put("status", if (records.isEmpty()) "EMPTY" else "RECORDED")
            .put("items", JSONArray(records.map { it.toJson() }))
    }
}
