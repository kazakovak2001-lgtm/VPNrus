package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONObject

/**
 * R1-S2 - what a field-test run may claim about its IPv4 network path, kept as
 * three SEPARATE questions with separate evidence. "VPN Protected", an existing
 * `tun0`, a successful HTTPS request and a verified egress address are four
 * different facts; none of them stands in for another.
 *
 *  - [ReachabilityResult]: did an HTTPS request (platform certificate
 *    validation, never disabled) get an HTTP answer?
 *  - [TunnelPathResult]: did that request demonstrably use the VPN network?
 *  - [EgressResult]: is the public address the far end saw different from the
 *    device's own physical WAN address, obtained independently BEFORE the tunnel
 *    was connected?
 *
 * Pure: no Android types, no clock, no network. Unit-tested in
 * PathVerificationTest. IPv6 is judged separately (see [LeakChecks.classifyIpv6]).
 */
enum class ReachabilityResult {
    /** An HTTP answer arrived over a validated TLS session. */
    REACHABLE,

    /** Positive evidence the destination cannot be reached (an OS-level "no route" errno). */
    UNREACHABLE,

    /** Timeout, lookup/TLS failure, no probe, or a result that no longer matches the session. */
    INCONCLUSIVE,
}

enum class TunnelPathResult {
    /** VPN-bound socket AND an observed public address that differs from the independent physical one. */
    CONFIRMED,

    /** The observed public address equals the physical WAN address: the request left outside the tunnel. */
    VIOLATED,
    INCONCLUSIVE,
}

enum class EgressResult {
    /**
     * Only a verified DIFFERENCE from the physical WAN address. It is not a
     * claim that the address is a particular gateway's.
     */
    DIFFERS_FROM_PHYSICAL,
    SAME_AS_PHYSICAL,
    INCONCLUSIVE,
}

/** How the reachability answer was obtained. */
enum class ReachabilityVia {
    /** A socket the app bound to the captured VPN network. */
    VPN_BOUND_SOCKET,

    /** The Xray core measured through its own outbound; the app itself is outside that tunnel. */
    XRAY_CORE_OUTBOUND,
    NONE,
}

/** The strongest path evidence a run holds - a label, not a verdict. */
enum class PathEvidence {
    NONE,

    /** A socket bound to the VPN network: the OS routed it there, but no far-end address was compared. */
    SOCKET_BOUND_ONLY,
    SOCKET_BOUND_AND_EGRESS_DIFFERS,
    EGRESS_SAME_AS_PHYSICAL,
}

/** Whether the session the measurement was made in is still the current one. */
enum class SessionValidity { STABLE, CHANGED, UNKNOWN }

/** Closed list of reasons - never exception text. */
enum class PathReason {
    /** The transport, the VPN network or the Connected state changed while measuring. */
    SESSION_CHANGED,
    APP_EXCLUDED,
    CORE_MEASUREMENT_ONLY,
    NOT_VPN_BOUND,
    NO_PROBE,
    TIMEOUT,
    LOOKUP_FAILED,
    TLS_FAILED,
    REQUEST_FAILED,

    /** An OS-level "network/host unreachable" errno on connect. */
    NO_ROUTE,

    /** No independently obtained physical WAN address. */
    NO_REFERENCE,

    /** The physical WAN address is older than [PathVerification.MAX_REFERENCE_AGE_MS]. */
    REFERENCE_STALE,
    REFERENCE_INVALID,
    NO_OBSERVED_IP,
    OBSERVED_INVALID,

    /** One address is IPv6 and the other IPv4 - they cannot be compared. */
    FAMILY_MISMATCH,
}

/**
 * The device's own public address as seen outside the tunnel. Held in memory
 * for the duration of one field test only - never serialized, never logged.
 */
data class PhysicalReference(val ip: String, val measuredAtEpochMillis: Long) {
    override fun toString(): String = "PhysicalReference(measuredAt=$measuredAtEpochMillis)"
}

data class PathInput(
    val via: ReachabilityVia,
    /** The HTTPS probe whose body carried [observedExitIp]; null when none ran. */
    val probe: HttpProbeResult?,
    /** For [ReachabilityVia.XRAY_CORE_OUTBOUND]: whether any core measurement succeeded. */
    val coreAnyOk: Boolean? = null,
    val appExcluded: Boolean = false,
    /** The address the far end reported for the request in [probe]. */
    val observedExitIp: String? = null,
    val reference: PhysicalReference? = null,
    val nowEpochMillis: Long = 0L,
    val session: SessionValidity = SessionValidity.UNKNOWN,
)

data class PathVerdict(
    val reachability: ReachabilityResult,
    val reachabilityReason: PathReason?,
    val reachabilityVia: ReachabilityVia,
    val tunnelPath: TunnelPathResult,
    val tunnelReason: PathReason?,
    val evidence: PathEvidence,
    val egress: EgressResult,
    val egressReason: PathReason?,
    val session: SessionValidity,
) {
    /** Names only - no address of any kind is stored. */
    fun toJson(): JSONObject = JSONObject()
        .put("reachability", reachability.name).put("reachabilityReason", reachabilityReason?.name ?: JSONObject.NULL)
        .put("reachabilityVia", reachabilityVia.name)
        .put("tunnelPath", tunnelPath.name).put("tunnelReason", tunnelReason?.name ?: JSONObject.NULL)
        .put("evidence", evidence.name)
        .put("egress", egress.name).put("egressReason", egressReason?.name ?: JSONObject.NULL)
        .put("session", session.name)

    fun summaryText(): String =
        "reach ${reachability.name}${reachabilityReason?.let { "/$it" } ?: ""}, " +
            "tunnel ${tunnelPath.name}${tunnelReason?.let { "/$it" } ?: ""}, " +
            "egress ${egress.name}${egressReason?.let { "/$it" } ?: ""}"
}

object PathVerification {
    /**
     * A WAN address read once before the tunnel was connected is only trusted
     * for this long. It bounds the exposure to a dynamic WAN address; it is not
     * a proof that the address stayed the same.
     */
    const val MAX_REFERENCE_AGE_MS = 30L * 60_000L

    fun evaluate(input: PathInput): PathVerdict {
        if (input.session == SessionValidity.CHANGED) return allInconclusive(input, PathReason.SESSION_CHANGED, input.via)
        if (input.appExcluded) return allInconclusive(input, PathReason.APP_EXCLUDED, ReachabilityVia.NONE)
        return when (input.via) {
            ReachabilityVia.NONE -> allInconclusive(input, PathReason.NOT_VPN_BOUND, ReachabilityVia.NONE)
            ReachabilityVia.XRAY_CORE_OUTBOUND -> coreOnly(input)
            ReachabilityVia.VPN_BOUND_SOCKET -> bound(input)
        }
    }

    private fun allInconclusive(input: PathInput, reason: PathReason, via: ReachabilityVia) = PathVerdict(
        ReachabilityResult.INCONCLUSIVE, reason, via,
        TunnelPathResult.INCONCLUSIVE, reason, PathEvidence.NONE,
        EgressResult.INCONCLUSIVE, reason, input.session,
    )

    /**
     * The Xray core measures through its own outbound, not through the TUN: it
     * can show the far end is reachable from the VPS side of the session, and
     * says nothing about which path an app packet takes.
     */
    private fun coreOnly(input: PathInput): PathVerdict = PathVerdict(
        if (input.coreAnyOk == true) ReachabilityResult.REACHABLE else ReachabilityResult.INCONCLUSIVE,
        if (input.coreAnyOk == true) null else PathReason.REQUEST_FAILED,
        ReachabilityVia.XRAY_CORE_OUTBOUND,
        TunnelPathResult.INCONCLUSIVE, PathReason.CORE_MEASUREMENT_ONLY, PathEvidence.NONE,
        EgressResult.INCONCLUSIVE, PathReason.CORE_MEASUREMENT_ONLY, input.session,
    )

    private fun bound(input: PathInput): PathVerdict {
        val probe = input.probe
            ?: return allInconclusive(input, PathReason.NO_PROBE, ReachabilityVia.VPN_BOUND_SOCKET).copy(evidence = PathEvidence.SOCKET_BOUND_ONLY)
        val (reach, reachReason) = reachabilityOf(probe)
        fun withheld(reason: PathReason) = PathVerdict(
            reach, reachReason, ReachabilityVia.VPN_BOUND_SOCKET,
            TunnelPathResult.INCONCLUSIVE, reason, PathEvidence.SOCKET_BOUND_ONLY,
            EgressResult.INCONCLUSIVE, reason, input.session,
        )
        if (reach != ReachabilityResult.REACHABLE) return withheld(reachReason ?: PathReason.REQUEST_FAILED)

        val reference = input.reference ?: return withheld(PathReason.NO_REFERENCE)
        val age = input.nowEpochMillis - reference.measuredAtEpochMillis
        if (age < 0 || age > MAX_REFERENCE_AGE_MS) return withheld(PathReason.REFERENCE_STALE)
        val observed = input.observedExitIp ?: return withheld(PathReason.NO_OBSERVED_IP)

        // Canonicalize to validated binary content BEFORE comparing. The same
        // address can arrive as different text (compressed vs. full IPv6, mixed
        // case, an IPv4-mapped tail) and must never be reported as a difference;
        // conversely an ambiguous or invalid literal is never silently accepted.
        val referenceBytes = canonicalBytes(reference.ip) ?: return withheld(PathReason.REFERENCE_INVALID)
        val observedBytes = canonicalBytes(observed) ?: return withheld(PathReason.OBSERVED_INVALID)
        if (referenceBytes.size != observedBytes.size) return withheld(PathReason.FAMILY_MISMATCH)

        return if (referenceBytes.contentEquals(observedBytes)) {
            PathVerdict(
                reach, null, ReachabilityVia.VPN_BOUND_SOCKET,
                TunnelPathResult.VIOLATED, null, PathEvidence.EGRESS_SAME_AS_PHYSICAL,
                EgressResult.SAME_AS_PHYSICAL, null, input.session,
            )
        } else {
            PathVerdict(
                reach, null, ReachabilityVia.VPN_BOUND_SOCKET,
                TunnelPathResult.CONFIRMED, null, PathEvidence.SOCKET_BOUND_AND_EGRESS_DIFFERS,
                EgressResult.DIFFERS_FROM_PHYSICAL, null, input.session,
            )
        }
    }

    /**
     * REACHABLE needs an HTTP answer. UNREACHABLE needs positive evidence
     * (an OS "no route" errno). A timeout, a lookup failure and a TLS failure
     * each prove less than that and stay INCONCLUSIVE with their own reason.
     */
    internal fun reachabilityOf(probe: HttpProbeResult): Pair<ReachabilityResult, PathReason?> = when {
        probe.httpStatus != null -> ReachabilityResult.REACHABLE to null
        probe.failureKind == ProbeFailureKind.NO_ROUTE -> ReachabilityResult.UNREACHABLE to PathReason.NO_ROUTE
        probe.failureKind == ProbeFailureKind.TIMEOUT -> ReachabilityResult.INCONCLUSIVE to PathReason.TIMEOUT
        probe.failureKind == ProbeFailureKind.UNKNOWN_HOST -> ReachabilityResult.INCONCLUSIVE to PathReason.LOOKUP_FAILED
        probe.failureKind == ProbeFailureKind.TLS -> ReachabilityResult.INCONCLUSIVE to PathReason.TLS_FAILED
        else -> ReachabilityResult.INCONCLUSIVE to PathReason.REQUEST_FAILED
    }

    /**
     * Validated binary content of an IP literal, or null when the literal is
     * malformed, ambiguous, or in a reserved range. Text-only classification is
     * not enough: the same address can arrive as different text (compressed
     * vs. full IPv6, mixed case, an IPv4-mapped tail) and must never be
     * reported as a difference, while an ambiguous literal is never silently
     * accepted.
     *
     * No DNS lookup is performed: only IP literals are handled here.
     */
    private fun canonicalBytes(ip: String): ByteArray? {
        val v4 = IPV4.matchEntire(ip)
        if (v4 != null) {
            val o = v4.groupValues.drop(1).map { it.toInt() }
            if (!o.all { it in 0..255 }) return null
            if (isReservedV4(o)) return null
            return byteArrayOf(o[0].toByte(), o[1].toByte(), o[2].toByte(), o[3].toByte())
        }
        return canonicalV6(ip)
    }

    /** 16-byte canonical IPv6 content, or null when the literal is not a valid public IPv6 address. */
    private fun canonicalV6(ip: String): ByteArray? {
        val bytes = parseV6(ip) ?: return null
        if (isReservedV6(bytes)) return null
        return bytes
    }

    /**
     * Parses an IPv6 literal into 16 bytes, or returns null when it is malformed.
     * Handles the full form, the compressed form, and the embedded-IPv4 tail
     * (`::ffff:192.0.2.1`). Leading zeros in an IPv4 octet are rejected: they
     * are ambiguous in some contexts and are not a defined canonical form.
     */
    private fun parseV6(ip: String): ByteArray? {
        if (ip.count { it == ':' } < 2) return null
        if (ip.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' && it != ':' && it != '.' }) return null

        val lower = ip.lowercase()
        if (lower.count { it == ':' } > 7) return null
        if (lower.startsWith("::ffff:")) {
            val tail = lower.removePrefix("::ffff:")
            val v4 = IPV4.matchEntire(tail)
            if (v4 != null) {
                val o = v4.groupValues.drop(1).map { it.toInt() }
                if (!o.all { it in 0..255 }) return null
                // The embedded IPv4 is still subject to the same reserved-range
                // policy as a bare IPv4 literal: a private, loopback or
                // unspecified tail must not be accepted just because it was
                // written inside an IPv6 wrapper.
                if (isReservedV4(o)) return null
                // An IPv4-mapped address is 0:0:0:0:0:ffff:a.b.c.d - the two bytes
                // before the embedded IPv4 must be 0xff,0xff. Anything else is not
                // a mapped address and is rejected here rather than silently kept.
                return byteArrayOf(
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1,
                    o[0].toByte(), o[1].toByte(), o[2].toByte(), o[3].toByte(),
                )
            }
            return null
        }

        val parts = lower.split(':')
        if (parts.size > 8) return null
        val out = ByteArray(16)
        var idx = 0
        var seenEmpty = false
        for (part in parts) {
            if (part.isEmpty()) {
                if (seenEmpty) return null // more than one compression point
                seenEmpty = true
                continue
            }
            if (part.length > 4) return null
            val value = part.toIntOrNull(16) ?: return null
            if (value !in 0..0xFFFF) return null
            out[idx++] = (value shr 8).toByte()
            out[idx++] = (value and 0xFF).toByte()
        }
        if (idx > 16) return null
        if (!seenEmpty && idx != 16) return null
        return out
    }

    /** 16-byte canonical IPv6 content, or null when the literal is not a valid public IPv6 address. */
    private fun isReservedV6(bytes: ByteArray): Boolean = when (bytes[0].toInt() and 0xFF) {
        0x00 -> {
            // :: (unspecified) and ::1 (loopback): the leading 15 bytes are zero,
            // regardless of how the literal was written. The byte check works on
            // content, so the compressed form, the full form and any mix of the
            // two are all caught here.
            val leadingZeros = (0 until 15).all { bytes[it].toInt() and 0xFF == 0 }
            leadingZeros && (bytes[15].toInt() and 0xFF) <= 0x01
        }
        0xfe -> (bytes[1].toInt() and 0xC0) == 0x80 // fe80:: link-local
        0xfc, 0xfd -> true // unique local
        0xff -> true // multicast
        else -> false
    }

    private val IPV4 = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")

    /** Addresses a public echo service can never legitimately report. */
    private fun isReservedV4(o: List<Int>): Boolean = when {
        o[0] == 0 || o[0] == 10 || o[0] == 127 || o[0] >= 224 -> true
        o[0] == 100 && o[1] in 64..127 -> true
        o[0] == 169 && o[1] == 254 -> true
        o[0] == 172 && o[1] in 16..31 -> true
        o[0] == 192 && o[1] == 168 -> true
        else -> false
    }
}
