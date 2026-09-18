package net.pocvpn.client.debug.b45a

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B45A - SPIKE ONLY. Unit tests for [B45ANativeBinaryResolver] - the single
 * binary-resolution authority both [B45ASpikeVpnService]'s real start flow
 * and [B45ASpikeActivity]'s exec probe call (see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 26.7's "exec probe path ==
 * real runtime path" invariant). Pure `java.io.File` logic, no Android
 * framework dependency - real temp files/directories exercise the actual
 * exists/isFile/canRead/canExecute checks, not fakes.
 */
class B45ANativeBinaryResolverTest {

    private fun tempDir(): File = createTempDirectory("b45a-resolver-test").toFile().apply { deleteOnExit() }

    // 1. nativeLibraryDir path resolves correctly
    @Test
    fun `resolves a real executable file in nativeLibraryDir`() {
        val dir = tempDir()
        val binary = File(dir, SPIKE_BINARY_FILENAME).apply {
            writeText("fake elf bytes")
            setExecutable(true)
            setReadable(true)
            deleteOnExit()
        }

        val result = B45ANativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is B45ANativeBinaryResolver.Result.Found)
        assertEquals(binary.absolutePath, (result as B45ANativeBinaryResolver.Result.Found).file.absolutePath)
    }

    // 2. missing binary -> typed Missing
    @Test
    fun `missing binary in an existing nativeLibraryDir is reported as Missing`() {
        val dir = tempDir() // exists, but empty - no libsslocal_spike.so

        val result = B45ANativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is B45ANativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `null nativeLibraryDir is reported as Missing, never a crash`() {
        val result = B45ANativeBinaryResolver.resolve(null)

        assertTrue(result is B45ANativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `blank nativeLibraryDir is reported as Missing`() {
        val result = B45ANativeBinaryResolver.resolve("   ")

        assertTrue(result is B45ANativeBinaryResolver.Result.Missing)
    }

    // 3. non-executable binary -> typed failure. NOT independently
    // unit-testable on this Windows development machine: java.io.File's
    // canExecute()/setExecutable() map to NTFS ACLs, not a POSIX x-bit, and
    // Windows JVMs report canExecute()=true for any accessible file
    // regardless of setExecutable(false) - empirically confirmed by running
    // this exact check and observing it fail on this host, then removed
    // rather than left as a flaky/misleading assertion (the same "requires
    // real Android/POSIX behavior" discipline this project's own test suite
    // already follows - see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section
    // 19.12/19.13's disclosed coverage gaps). The `canExecute()` check
    // itself is still real production code, exercised for real by the
    // physical-device probe (Section 26.5), just not by a JVM unit test.

    @Test
    fun `a directory named like the binary is rejected, not treated as a regular file`() {
        val dir = tempDir()
        File(dir, SPIKE_BINARY_FILENAME).apply {
            mkdirs()
            deleteOnExit()
        }

        val result = B45ANativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is B45ANativeBinaryResolver.Result.Missing)
    }
}
