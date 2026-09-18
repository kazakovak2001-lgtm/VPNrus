package net.pocvpn.client.vpn.shadowsocks

import java.io.File

/** Filename the production sslocal binary is expected under in applicationInfo.nativeLibraryDir - deliberately distinct from the debug-only spike's libsslocal_spike.so (see B45ANativeBinaryResolver). No production packaging is added in this slice - see this class's own [resolve] docs. */
internal const val SHADOWSOCKS_BINARY_FILENAME = "libsslocal.so"

/**
 * B45B-3 - production binary-resolution authority, adapted from
 * (never sharing state with) the debug-only B45ANativeBinaryResolver. Pure/
 * injectable (a plain nullable String, no ApplicationInfo dependency) so it
 * is unit-testable on the JVM. No production sslocal binary is packaged in
 * this slice - a real device/CI checkout resolves [Missing] until a later
 * slice adds it, which is the correct, truthful, fail-closed behavior for an
 * adapter that must stay unreachable from real selection anyway.
 */
internal object ShadowsocksNativeBinaryResolver {
    sealed interface Result {
        data class Found(val file: File) : Result
        data class Missing(val reason: String) : Result
    }

    fun resolve(nativeLibraryDir: String?): Result {
        if (nativeLibraryDir.isNullOrBlank()) {
            return Result.Missing("applicationInfo.nativeLibraryDir is null or blank")
        }
        val file = File(nativeLibraryDir, SHADOWSOCKS_BINARY_FILENAME)
        return when {
            !file.exists() -> Result.Missing("not found at ${file.absolutePath}")
            !file.isFile -> Result.Missing("not a regular file: ${file.absolutePath}")
            !file.canRead() -> Result.Missing("not readable: ${file.absolutePath}")
            !file.canExecute() -> Result.Missing("not executable: ${file.absolutePath}")
            else -> Result.Found(file)
        }
    }
}
