package net.pocvpn.client.vpn.shadowsocks

/**
 * B45B-4 - the narrow, typed, fail-closed ABI/binary eligibility gate that
 * decides whether SHADOWSOCKS_2022 may EVER become AVAILABLE in
 * TransportRegistry, independent of credential state (see
 * Shadowsocks2022CredentialRepository for the separate credential gate).
 *
 * Current sslocal physical proof (B45A/B45B-3P) is arm64-v8a only - this set
 * is deliberately narrower than "whatever ABI the binary resolver happens to
 * find a file for": a device reporting only unproven ABIs (armeabi-v7a,
 * x86_64, ...) must never be told SHADOWSOCKS_2022 is usable even if some
 * stray file happened to exist at the expected path.
 */
internal val SUPPORTED_SHADOWSOCKS_ABIS = setOf("arm64-v8a")

/** Typed, fail-closed outcome - never a bare Boolean that would lose the reason. */
sealed interface ShadowsocksBinaryEligibility {
    data object Eligible : ShadowsocksBinaryEligibility
    data class UnsupportedAbi(val deviceAbis: List<String>) : ShadowsocksBinaryEligibility
    data class BinaryUnavailable(val reason: String) : ShadowsocksBinaryEligibility

    val isEligible: Boolean get() = this is Eligible
}

/**
 * B45B-4 - pure/injectable (no Android Context dependency of its own, same
 * "stays testable on the JVM" discipline [ShadowsocksNativeBinaryResolver]
 * already follows) - combines the ABI check with the existing binary
 * resolver. ABI is checked FIRST and short-circuits: a device on an
 * unsupported ABI is reported as [ShadowsocksBinaryEligibility.UnsupportedAbi]
 * even when a same-named file happens to exist at the expected path (should
 * never happen given real per-ABI native-library packaging, but this keeps
 * the eligibility claim honest about WHY, not just THAT, a device is
 * ineligible).
 */
internal object ShadowsocksAdapterEligibilityChecker {
    fun check(deviceAbis: List<String>, nativeLibraryDir: String?): ShadowsocksBinaryEligibility {
        if (deviceAbis.none { it in SUPPORTED_SHADOWSOCKS_ABIS }) {
            return ShadowsocksBinaryEligibility.UnsupportedAbi(deviceAbis)
        }
        return when (val resolution = ShadowsocksNativeBinaryResolver.resolve(nativeLibraryDir)) {
            is ShadowsocksNativeBinaryResolver.Result.Found -> ShadowsocksBinaryEligibility.Eligible
            is ShadowsocksNativeBinaryResolver.Result.Missing -> ShadowsocksBinaryEligibility.BinaryUnavailable(resolution.reason)
        }
    }
}
