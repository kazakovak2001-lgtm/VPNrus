package net.pocvpn.client.debug.b45a

import java.util.Base64
import net.pocvpn.client.BuildConfig

/** The mechanics-only fake loopback target used by rounds 1-5 (no real server, never actually reachable). */
internal const val SPIKE_FALLBACK_SERVER = "127.0.0.1:8388"
internal const val SPIKE_FALLBACK_METHOD = "2022-blake3-aes-256-gcm"

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Resolves the real (disposable, test-only) Frankfurt data-plane server
 * target from `BuildConfig.B45A_TEST_SERVER_*` - fields that exist ONLY in
 * the `debug` buildType (see `android/app/build.gradle.kts`'s own
 * `debug {}` block), sourced from a gitignored, uncommitted local
 * `android/app/b45a-dataplane.properties` file (see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 30's own "client secret
 * delivery" section). When that file is absent (every other developer's
 * checkout, CI), every `BuildConfig.B45A_TEST_SERVER_*` field is an empty
 * string and [resolve] falls back to the same mechanics-only fake loopback
 * target rounds 1-5 already used - zero behavior change for anyone without
 * this file.
 *
 * Never logs, stores, or exposes the resolved key anywhere beyond the
 * in-memory `String` handed directly to [B45ARuntime]'s own CLI-args
 * construction (itself never surfaced in the debug UI - see
 * [B45ASpikeActivity]'s own class docs on this).
 */
internal object B45ADataPlaneConfig {

    /** Validated result of resolving the active (real-or-fallback) server target. */
    sealed interface Result {
        data class Valid(val serverAddr: String, val method: String, val key: String) : Result
        data class Invalid(val reason: String) : Result
    }

    /**
     * Resolves the active target and validates the key BEFORE it is ever
     * handed to `sslocal` (Phase 1's own explicit requirement): base64
     * decodes, and the decoded length must be exactly 32 bytes for
     * `2022-blake3-aes-256-gcm` (see [SPIKE_FAKE_PSK]'s own doc comment for
     * the source citation this exact requirement was verified against).
     */
    fun resolve(): Result {
        val host = BuildConfig.B45A_TEST_SERVER_HOST
        val port = BuildConfig.B45A_TEST_SERVER_PORT
        val method = BuildConfig.B45A_TEST_SERVER_METHOD.ifBlank { SPIKE_FALLBACK_METHOD }
        val key = BuildConfig.B45A_TEST_SERVER_KEY.ifBlank { SPIKE_FAKE_PSK }

        val serverAddr = if (host.isNotBlank() && port.isNotBlank()) "$host:$port" else SPIKE_FALLBACK_SERVER

        val decoded = try {
            Base64.getDecoder().decode(key)
        } catch (e: IllegalArgumentException) {
            return Result.Invalid("key is not valid base64: ${e.message}")
        }
        if (decoded.size != 32) {
            return Result.Invalid("key decodes to ${decoded.size} bytes, expected exactly 32 for $method")
        }

        return Result.Valid(serverAddr, method, key)
    }
}
