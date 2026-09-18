package net.pocvpn.client.debug.b45a

import java.io.File

/** Filename the pinned `sslocal` ELF is packaged under in `src/debug/jniLibs/arm64-v8a/` (see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 26). */
internal const val SPIKE_BINARY_FILENAME = "libsslocal_spike.so"

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * The SINGLE binary-resolution authority for this spike (Section 26.7's own
 * "no duplicate path logic" requirement) - both [B45ASpikeVpnService]'s real
 * start flow and [B45ASpikeActivity]'s standalone exec probe call this same
 * function, so there is exactly one answer to "where is the binary" and
 * exactly one set of checks applied to it.
 *
 * **Supersedes the earlier debug-asset + `filesDir` extraction design**
 * (Section 23.2): that design was physically rejected on the real OPPO
 * device (Section 24.2 - real app-process `ProcessBuilder.exec()` of a file
 * the app itself wrote to `filesDir` was denied with `error=13, Permission
 * denied`, corroborated by an OEM kernel-security-module log). The
 * packaging-route decision pass (Section 26) found a debug-only-safe AGP
 * Variant-API fix (`packaging.jniLibs.useLegacyPackaging` set only for the
 * `debug` variant) that makes the Android package manager itself extract
 * this binary to `applicationInfo.nativeLibraryDir` at install time, with a
 * different, OS-trusted SELinux label (`apk_data_file`) than an
 * app-written `filesDir` entry - and a real on-device probe confirmed the
 * real app process can now `exec()` it. This resolver deliberately never
 * copies, chmods, or relabels the file - the package manager already owns
 * its permissions and label; this function only validates what is already
 * there and reports a typed reason when it is not usable.
 */
object B45ANativeBinaryResolver {

    /** Result of resolving the spike binary against a real (or fake, in tests) `nativeLibraryDir`. */
    sealed interface Result {
        data class Found(val file: File) : Result
        data class Missing(val reason: String) : Result
    }

    /**
     * [nativeLibraryDir] is expected to be `applicationInfo.nativeLibraryDir`
     * from the real caller - this function takes it as a plain nullable
     * `String` (rather than reading `ApplicationInfo` itself) specifically so
     * it has zero Android-framework dependency and is exercisable by a plain
     * JVM unit test.
     */
    fun resolve(nativeLibraryDir: String?): Result {
        if (nativeLibraryDir.isNullOrBlank()) {
            return Result.Missing("applicationInfo.nativeLibraryDir is null or blank")
        }
        val file = File(nativeLibraryDir, SPIKE_BINARY_FILENAME)
        return when {
            !file.exists() -> Result.Missing("not found at ${file.absolutePath} - was it packaged into src/debug/jniLibs/arm64-v8a/ with debug's useLegacyPackaging fix applied?")
            !file.isFile -> Result.Missing("not a regular file: ${file.absolutePath}")
            !file.canRead() -> Result.Missing("not readable: ${file.absolutePath}")
            !file.canExecute() -> Result.Missing("not executable: ${file.absolutePath}")
            else -> Result.Found(file)
        }
    }
}
