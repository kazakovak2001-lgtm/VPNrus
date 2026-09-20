package net.pocvpn.b46harness

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-2P - mirrors [net.pocvpn.client.debug.b45a.B45ANativeBinaryResolverTest]'s
 * own coverage for the analogous B46 resolver.
 */
class B46NativeBinaryResolverTest {

    private fun tempDir(): File = createTempDirectory("b46-resolver-test").toFile().apply { deleteOnExit() }

    @Test
    fun `resolves a real executable file in nativeLibraryDir`() {
        val dir = tempDir()
        val binary = File(dir, B46_HYSTERIA_BINARY_FILENAME).apply {
            writeText("fake elf bytes")
            setExecutable(true)
            setReadable(true)
            deleteOnExit()
        }

        val result = B46NativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is B46NativeBinaryResolver.Result.Found)
        assertEquals(binary.absolutePath, (result as B46NativeBinaryResolver.Result.Found).file.absolutePath)
    }

    @Test
    fun `missing binary in an existing nativeLibraryDir is reported as Missing`() {
        val dir = tempDir()

        val result = B46NativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is B46NativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `null nativeLibraryDir is reported as Missing, never a crash`() {
        val result = B46NativeBinaryResolver.resolve(null)

        assertTrue(result is B46NativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `blank nativeLibraryDir is reported as Missing`() {
        val result = B46NativeBinaryResolver.resolve("   ")

        assertTrue(result is B46NativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `a directory named like the binary is rejected, not treated as a regular file`() {
        val dir = tempDir()
        File(dir, B46_HYSTERIA_BINARY_FILENAME).apply {
            mkdirs()
            deleteOnExit()
        }

        val result = B46NativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is B46NativeBinaryResolver.Result.Missing)
    }
}
