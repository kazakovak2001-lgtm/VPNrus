package net.pocvpn.b46harness

import java.io.File

/**
 * B46-2P - resolves the temporary Hysteria2 test server target. PUBLIC/
 * non-secret values (host, port, SNI, insecure flag, expected exit IP)
 * come from this module's own `BuildConfig.B46_HYSTERIA_*` fields, sourced
 * from a gitignored local `b46harness/b46-hysteria-dataplane.properties`
 * file - see `b46harness/build.gradle.kts`. The SECRET value (`auth`, and
 * any future obfuscation secret) is deliberately NOT among them - see
 * [B46HysteriaRuntimeCredential]'s own doc for the pre-merge hardening
 * correction that moved it to a runtime-provisioned, app-private file
 * instead of a compiled-in `BuildConfig` field.
 *
 * Unlike B45A's own resolver, this deliberately has NO mechanics-only
 * fallback target: B46-2P's whole point is a real end-to-end QUIC proof
 * against a real temporary server, so a missing/blank server host, or a
 * missing/malformed runtime credential, fails closed with a typed error
 * rather than silently substituting a fake target that would never prove
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

    /** [filesDir] is the caller's own `Context.getFilesDir()` - used only to locate the runtime credential file, never persisted here. */
    fun resolve(filesDir: File): Result = resolve(
        filesDir = filesDir,
        host = BuildConfig.B46_HYSTERIA_SERVER_HOST,
        port = BuildConfig.B46_HYSTERIA_SERVER_PORT,
        sni = BuildConfig.B46_HYSTERIA_SNI,
        insecureStr = BuildConfig.B46_HYSTERIA_INSECURE,
    )

    /**
     * Narrow, environment-independent seam: the public [resolve] above
     * always reads real `BuildConfig` fields, which come from a gitignored
     * local properties file and are therefore blank on any checkout that
     * hasn't created one - not something a portable unit test should
     * depend on. This overload takes the public/non-secret values
     * explicitly so tests can exercise the credential-consumption logic
     * (the part that actually matters here) with deterministic inputs,
     * without needing Robolectric or a real `BuildConfig`.
     */
    internal fun resolve(filesDir: File, host: String, port: String, sni: String, insecureStr: String): Result {
        if (host.isBlank() || port.isBlank()) {
            return Result.Invalid(
                "B46_HYSTERIA_SERVER_HOST/PORT are blank - create b46harness/b46-hysteria-dataplane.properties " +
                    "with serverHost/serverPort/sni/insecure (see docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md)",
            )
        }
        val portInt = port.toIntOrNull()
        if (portInt == null || portInt <= 0 || portInt > 65535) {
            return Result.Invalid("B46_HYSTERIA_SERVER_PORT is not a valid port: $port")
        }

        val credential = when (val resolution = B46HysteriaRuntimeCredential.resolve(filesDir)) {
            is B46HysteriaRuntimeCredential.Result.Valid -> resolution
            // Fails closed WITHOUT deleting the file - a malformed/missing
            // file is provisioning INPUT the operator still needs to fix
            // and re-provision; only a SUCCESSFUL parse consumes it (see
            // below). The caller's own failure path
            // (B46HysteriaVpnService.failStartup) separately deletes it on
            // this Invalid outcome too, for defense in depth.
            is B46HysteriaRuntimeCredential.Result.Invalid -> return Result.Invalid(resolution.reason)
        }

        val config = B46HysteriaChildConfig(
            server = "$host:$port",
            auth = credential.auth,
            sni = sni,
            insecure = insecureStr.toBooleanStrictOrNull() ?: true,
            obfsSalamander = credential.obfsSalamander,
            socksListen = B46HysteriaTunNetworkConfig.localSocksAddr,
            protectPath = "", // filled in by B46HysteriaRuntime.startChild once the protect socket path is known
        )

        // PRE-MERGE HARDENING CORRECTION (2026-09-20): one-shot consumption.
        // The runtime credential file is provisioning INPUT, not session
        // state - once its secret values have been successfully copied into
        // `config` (in memory, above), the file itself must not remain at
        // rest for the rest of the session. Deleted HERE, immediately,
        // BEFORE the caller does anything with `config` (TUN/bridge/child
        // startup all happen strictly after `resolve()` returns) - never
        // deferred to `stop()`/failure cleanup, which would leave it on
        // disk for the whole session even on the success path. Idempotent;
        // a later `stop()`/`failStartup()` calling `delete()` again is a
        // safe no-op.
        B46HysteriaRuntimeCredential.delete(filesDir)

        return Result.Valid(config)
    }

    /** Empty until set via the properties file - used only for the acceptance doc's exit-IP check, never for routing decisions. Not secret. */
    val expectedExitIp: String get() = BuildConfig.B46_HYSTERIA_EXPECTED_EXIT_IP
}
