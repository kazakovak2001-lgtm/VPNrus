package net.pocvpn.client.vpn.hysteria

/**
 * B46-4A - the narrow, typed, fail-closed ABI/binary eligibility gate that
 * decides whether HYSTERIA2 may EVER become AVAILABLE in TransportRegistry,
 * independent of credential/signed-binding state (see
 * Hysteria2CredentialRepository for the separate credential gate and
 * [net.pocvpn.client.reachability.SignedTransportProfile.Hysteria2] for the
 * separate signed-binding gate). Mirrors
 * [net.pocvpn.client.vpn.shadowsocks.ShadowsocksAdapterEligibility]'s own
 * shape exactly.
 *
 * Physical evidence (B46-3B/B46-3C, OPPO CPH2173) is arm64-v8a only - this
 * set is deliberately narrower than "whatever ABI a binary resolver happens
 * to find a file for": a device reporting only unproven ABIs
 * (armeabi-v7a, x86_64, ...) must never be told HYSTERIA2 is usable even if
 * some stray file happened to exist at the expected path.
 *
 * Both native children (tun2socks-child AND hysteria-child) must be present
 * and executable - HYSTERIA2's three-process architecture cannot run with
 * only one of them.
 */
internal val SUPPORTED_HYSTERIA2_ABIS = setOf("arm64-v8a")

/** Typed, fail-closed outcome - never a bare Boolean that would lose the reason. */
sealed interface Hysteria2BinaryEligibility {
    data object Eligible : Hysteria2BinaryEligibility
    data class UnsupportedAbi(val deviceAbis: List<String>) : Hysteria2BinaryEligibility
    data class BinaryUnavailable(val reason: String) : Hysteria2BinaryEligibility

    val isEligible: Boolean get() = this is Eligible
}

/**
 * B46-4A - pure/injectable (no Android Context dependency of its own, same
 * "stays testable on the JVM" discipline
 * [net.pocvpn.client.vpn.shadowsocks.ShadowsocksAdapterEligibilityChecker]
 * already follows). ABI is checked FIRST and short-circuits; then BOTH
 * required child binaries must resolve, in a fixed order (tun2socks-child
 * first) so the reported reason is deterministic.
 */
internal object Hysteria2AdapterEligibilityChecker {
    fun check(deviceAbis: List<String>, nativeLibraryDir: String?): Hysteria2BinaryEligibility {
        if (deviceAbis.none { it in SUPPORTED_HYSTERIA2_ABIS }) {
            return Hysteria2BinaryEligibility.UnsupportedAbi(deviceAbis)
        }
        val tun2socks = Hysteria2Tun2SocksChildBinaryResolver.resolve(nativeLibraryDir)
        if (tun2socks is Hysteria2Tun2SocksChildBinaryResolver.Result.Missing) {
            return Hysteria2BinaryEligibility.BinaryUnavailable("tun2socks-child: ${tun2socks.reason}")
        }
        val hysteria = Hysteria2ChildBinaryResolver.resolve(nativeLibraryDir)
        if (hysteria is Hysteria2ChildBinaryResolver.Result.Missing) {
            return Hysteria2BinaryEligibility.BinaryUnavailable("hysteria-child: ${hysteria.reason}")
        }
        return Hysteria2BinaryEligibility.Eligible
    }
}
