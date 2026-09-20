package net.pocvpn.b46harness

/**
 * B46-2P - resolves the temporary Hysteria2 test server target from this
 * module's own `BuildConfig.B46_HYSTERIA_*` fields, sourced from a
 * gitignored local `b46harness/b46-hysteria-dataplane.properties` file -
 * see `b46harness/build.gradle.kts`. Unlike B45A's own resolver, this
 * deliberately has NO mechanics-only fallback target: B46-2P's whole point
 * is a real end-to-end QUIC proof against a real temporary server, so a
 * missing/blank server host fails closed with a typed error rather than
 * silently substituting a fake loopback target that would never prove
 * anything.
 *
 * Never logs, stores, or exposes [B46HysteriaChildConfig.auth] anywhere
 * beyond the in-memory value handed directly to
 * [writeChildConfigFile]/[B46HysteriaRuntime.startChild].
 */
internal object B46HysteriaDataPlaneConfig {

    sealed interface Result {
        data class Valid(val config: B46HysteriaChildConfig) : Result
        data class Invalid(val reason: String) : Result
    }

    fun resolve(): Result {
        val host = BuildConfig.B46_HYSTERIA_SERVER_HOST
        val port = BuildConfig.B46_HYSTERIA_SERVER_PORT
        if (host.isBlank() || port.isBlank()) {
            return Result.Invalid(
                "B46_HYSTERIA_SERVER_HOST/PORT are blank - create b46harness/b46-hysteria-dataplane.properties " +
                    "with serverHost/serverPort/auth/sni/insecure (see docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md)",
            )
        }
        val portInt = port.toIntOrNull()
        if (portInt == null || portInt <= 0 || portInt > 65535) {
            return Result.Invalid("B46_HYSTERIA_SERVER_PORT is not a valid port: $port")
        }

        return Result.Valid(
            B46HysteriaChildConfig(
                server = "$host:$port",
                auth = BuildConfig.B46_HYSTERIA_AUTH,
                sni = BuildConfig.B46_HYSTERIA_SNI,
                insecure = BuildConfig.B46_HYSTERIA_INSECURE.toBooleanStrictOrNull() ?: true,
                obfsSalamander = "",
                socksListen = B46HysteriaTunNetworkConfig.localSocksAddr,
                protectPath = "", // filled in by B46HysteriaRuntime.startChild once the protect socket path is known
            ),
        )
    }

    /** Empty until set via the properties file - used only for the acceptance doc's exit-IP check, never for routing decisions. */
    val expectedExitIp: String get() = BuildConfig.B46_HYSTERIA_EXPECTED_EXIT_IP
}
