package net.pocvpn.client.vpn.shadowsocks

import org.junit.Assert.assertTrue
import org.junit.Test

class ShadowsocksNativeBinaryResolverTest {

    @Test
    fun `blank nativeLibraryDir resolves Missing`() {
        val result = ShadowsocksNativeBinaryResolver.resolve(null)
        assertTrue(result is ShadowsocksNativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `absent binary file resolves Missing`() {
        val dir = kotlin.io.path.createTempDirectory("shadowsocks-binary-test").toFile().apply { deleteOnExit() }
        val result = ShadowsocksNativeBinaryResolver.resolve(dir.absolutePath)
        assertTrue(result is ShadowsocksNativeBinaryResolver.Result.Missing)
    }

    @Test
    fun `present readable executable binary resolves Found`() {
        val dir = kotlin.io.path.createTempDirectory("shadowsocks-binary-test").toFile().apply { deleteOnExit() }
        val binary = java.io.File(dir, SHADOWSOCKS_BINARY_FILENAME)
        binary.writeText("fake")
        binary.setExecutable(true)

        val result = ShadowsocksNativeBinaryResolver.resolve(dir.absolutePath)

        assertTrue(result is ShadowsocksNativeBinaryResolver.Result.Found)
    }

    // Not exercised here: File.setExecutable(false)/canExecute() do not
    // reliably round-trip on every host filesystem (notably NTFS on this
    // Windows dev machine, which has no Unix executable bit) - the
    // executable-bit branch itself is a single `!file.canExecute()` check,
    // exercised for real only against a real Android/Linux filesystem.
}
