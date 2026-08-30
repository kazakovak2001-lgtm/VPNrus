package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.XrayProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * B8K4C - proves XrayRuntimeResolver's load -> fail-closed -> map -> validate
 * -> render chain in isolation, with no Android framework dependency.
 */
class XrayRuntimeResolverTest {

    private val validProfile = XrayProfile(
        server = "152.70.43.1",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "a1b2c3d4",
    )

    private fun newRepository(dir: File = Files.createTempDirectory("xray-resolver-test").toFile()): SecureXrayProfileRepository =
        SecureXrayProfileRepository(FileXrayProfileStore(dir), FakeAesGcmKeyEncryptor())

    @Test
    fun `a valid stored profile resolves to Ready with the exact mapped and rendered config`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)

        val resolution = XrayRuntimeResolver.resolve(repository)

        assertTrue(resolution is XrayRuntimeResolution.Ready)
        val ready = resolution as XrayRuntimeResolution.Ready
        assertEquals(validProfile.toXrayVlessRealityConfig(), ready.config)
        assertEquals(XrayConfigRenderer.render(ready.config), ready.renderedConfig)
    }

    @Test
    fun `no stored profile fails closed`() = runBlocking {
        val resolution = XrayRuntimeResolver.resolve(newRepository())

        assertTrue(resolution is XrayRuntimeResolution.Rejected)
        assertEquals("no Xray profile configured", (resolution as XrayRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `a corrupted stored profile fails closed`() = runBlocking {
        val dir = Files.createTempDirectory("xray-resolver-corrupt-test").toFile()
        dir.mkdirs()
        File(dir, "xray_profile.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
        val repository = newRepository(dir)

        val resolution = XrayRuntimeResolver.resolve(repository)

        assertTrue(resolution is XrayRuntimeResolution.Rejected)
        assertEquals("failed to load Xray profile: XrayProfileCorruptedException", (resolution as XrayRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `an invalid mapped config is rejected and never rendered`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile.copy(uuid = "not-a-uuid"))

        val resolution = XrayRuntimeResolver.resolve(repository)

        assertTrue(resolution is XrayRuntimeResolution.Rejected)
        assertEquals("stored Xray profile failed validation: 1 error(s)", (resolution as XrayRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `no rejection reason ever contains the profile's actual secret field values`() = runBlocking {
        val repository = newRepository()
        val saved = validProfile.copy(uuid = "not-a-uuid") // invalid, but still real-looking key/shortId material
        repository.saveProfile(saved)

        val resolution = XrayRuntimeResolver.resolve(repository) as XrayRuntimeResolution.Rejected

        assertFalse(resolution.reason.contains(saved.uuid))
        assertFalse(resolution.reason.contains(saved.realityPublicKey))
        assertFalse(resolution.reason.contains(saved.shortId))
    }
}
