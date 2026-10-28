package net.pocvpn.client.diagnostics.fieldtest

/**
 * Which addresses the field-test stage/DNS probes may ever contact. Strict, hand-written IPv4 parsing
 * (no regex, no hostname lookup): a probe target is rejected here BEFORE any socket is opened.
 *
 * - [isPublicGateway]: where a stage probe may connect - an IP literal from the signed manifest that
 *   is publicly routable (never loopback / private / CGNAT / link-local / documentation / multicast).
 * - [isAcceptableResolver]: where a DNS probe may send - the physical network's resolver. A private
 *   resolver (a home router) is legitimate; loopback, 0.0.0.0, multicast and reserved space are not.
 */
internal object ProbeTargets {

    /** Four decimal octets 0..255 without signs, spaces or leading zeros ("01" is rejected); null otherwise. */
    fun parseIpv4(text: String): IntArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val out = IntArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v
        }
        return out
    }

    fun isPublicGateway(text: String): Boolean = parseIpv4(text)?.let(::isPublic) ?: false

    fun isAcceptableResolver(text: String): Boolean = parseIpv4(text)?.let(::isUsableResolver) ?: false

    private fun isUsableResolver(o: IntArray): Boolean = when {
        o[0] == 0 -> false // 0.0.0.0/8 (any-local)
        o[0] == 127 -> false // loopback
        o[0] >= 224 -> false // multicast, reserved, broadcast
        else -> true
    }

    private fun isPublic(o: IntArray): Boolean {
        val a = o[0]
        val b = o[1]
        val c = o[2]
        return when {
            a == 0 -> false // 0.0.0.0/8
            a == 10 -> false // private
            a == 100 && b in 64..127 -> false // CGNAT 100.64/10
            a == 127 -> false // loopback
            a == 169 && b == 254 -> false // link-local
            a == 172 && b in 16..31 -> false // private
            a == 192 && b == 0 && c == 0 -> false // IETF protocol assignments
            a == 192 && b == 0 && c == 2 -> false // documentation
            a == 192 && b == 168 -> false // private
            a == 198 && b in 18..19 -> false // benchmarking
            a == 198 && b == 51 && c == 100 -> false // documentation
            a == 203 && b == 0 && c == 113 -> false // documentation
            a >= 224 -> false // multicast, reserved, broadcast
            else -> true
        }
    }

    /** Dotted-quad text of [o]; used so a rejected/accepted address is always reported in one canonical form. */
    fun format(o: IntArray): String = o.joinToString(".")
}
