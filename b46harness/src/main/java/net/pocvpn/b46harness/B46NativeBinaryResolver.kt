package net.pocvpn.b46harness

import java.io.File

/** Filename the pinned minimal Hysteria2 child ELF is packaged under in `src/debug/jniLibs/arm64-v8a/`. */
internal const val B46_HYSTERIA_BINARY_FILENAME = "libnovahysteria.so"

/**
 * B46-2P - the single binary-resolution authority, mirroring
 * [net.pocvpn.client.debug.b45a.B45ANativeBinaryResolver]'s already-proven
 * approach: the AGP Variant API's `packaging.jniLibs.useLegacyPackaging`
 * (set for the `debug` variant in `android/app/build.gradle.kts`) makes the
 * package manager extract this binary to a real filesystem path under
 * `applicationInfo.nativeLibraryDir` at install time, with an OS-trusted
 * SELinux label - this resolver never copies, chmods, or relabels the
 * file, it only validates what is already there.
 */
object B46NativeBinaryResolver {

    sealed interface Result {
        data class Found(val file: File) : Result
        data class Missing(val reason: String) : Result
    }

    fun resolve(nativeLibraryDir: String?): Result {
        if (nativeLibraryDir.isNullOrBlank()) {
            return Result.Missing("applicationInfo.nativeLibraryDir is null or blank")
        }
        val file = File(nativeLibraryDir, B46_HYSTERIA_BINARY_FILENAME)
        return when {
            !file.exists() -> Result.Missing(
                "not found at ${file.absolutePath} - build research/b46-2p-android-physical/hysteria-minimal-client " +
                    "and copy the android/arm64 binary to src/debug/jniLibs/arm64-v8a/$B46_HYSTERIA_BINARY_FILENAME",
            )
            !file.isFile -> Result.Missing("not a regular file: ${file.absolutePath}")
            !file.canRead() -> Result.Missing("not readable: ${file.absolutePath}")
            !file.canExecute() -> Result.Missing("not executable: ${file.absolutePath}")
            else -> Result.Found(file)
        }
    }
}
