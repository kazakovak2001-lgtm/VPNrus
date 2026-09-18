package net.pocvpn.client.vpn.shadowsocks

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B45B-4 (Phase 7, items 1/4) - proves the narrow ABI eligibility rule: only
 * arm64-v8a is a proven, selectable ABI, and a device reporting no supported
 * ABI is ineligible even when a same-named file happens to exist.
 */
class ShadowsocksAdapterEligibilityTest {

    @Test
    fun `unsupported device ABI is ineligible even when the binary file exists`() {
        val dir = kotlin.io.path.createTempDirectory("shadowsocks-eligibility-test").toFile().apply { deleteOnExit() }
        java.io.File(dir, SHADOWSOCKS_BINARY_FILENAME).apply {
            writeText("fake")
            setExecutable(true)
        }

        val result = ShadowsocksAdapterEligibilityChecker.check(
            deviceAbis = listOf("armeabi-v7a", "x86_64"),
            nativeLibraryDir = dir.absolutePath,
        )

        assertEquals(ShadowsocksBinaryEligibility.UnsupportedAbi(listOf("armeabi-v7a", "x86_64")), result)
        assertTrue(!result.isEligible)
    }

    @Test
    fun `arm64-v8a with no packaged binary is ineligible - typed BinaryUnavailable, never a crash`() {
        val dir = kotlin.io.path.createTempDirectory("shadowsocks-eligibility-test").toFile().apply { deleteOnExit() }

        val result = ShadowsocksAdapterEligibilityChecker.check(
            deviceAbis = listOf("arm64-v8a"),
            nativeLibraryDir = dir.absolutePath,
        )

        assertTrue(result is ShadowsocksBinaryEligibility.BinaryUnavailable)
        assertTrue(!result.isEligible)
    }

    @Test
    fun `arm64-v8a with a real resolvable binary is Eligible`() {
        val dir = kotlin.io.path.createTempDirectory("shadowsocks-eligibility-test").toFile().apply { deleteOnExit() }
        java.io.File(dir, SHADOWSOCKS_BINARY_FILENAME).apply {
            writeText("fake")
            setExecutable(true)
        }

        val result = ShadowsocksAdapterEligibilityChecker.check(
            deviceAbis = listOf("arm64-v8a"),
            nativeLibraryDir = dir.absolutePath,
        )

        assertEquals(ShadowsocksBinaryEligibility.Eligible, result)
        assertTrue(result.isEligible)
    }

    @Test
    fun `a device listing arm64-v8a alongside other ABIs is still eligible - any match is sufficient`() {
        val dir = kotlin.io.path.createTempDirectory("shadowsocks-eligibility-test").toFile().apply { deleteOnExit() }
        java.io.File(dir, SHADOWSOCKS_BINARY_FILENAME).apply {
            writeText("fake")
            setExecutable(true)
        }

        val result = ShadowsocksAdapterEligibilityChecker.check(
            deviceAbis = listOf("arm64-v8a", "armeabi-v7a"),
            nativeLibraryDir = dir.absolutePath,
        )

        assertEquals(ShadowsocksBinaryEligibility.Eligible, result)
    }
}
