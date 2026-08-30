package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.FileXrayTlsProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.SecureXrayTlsProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
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

/** B8O2 - the TLS/TCP counterpart of [XrayRuntimeResolverTest], same load -> fail-closed -> map -> validate -> render chain. */
class XrayTlsRuntimeResolverTest {

    private val validTlsProfile = XrayTlsProfile(
        server = "152.70.43.1",
        serverPort = 2053,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "203.0.113.1",
        fingerprint = "chrome",
    )

    private fun newTlsRepository(dir: File = Files.createTempDirectory("xray-tls-resolver-test").toFile()): SecureXrayTlsProfileRepository =
        SecureXrayTlsProfileRepository(FileXrayTlsProfileStore(dir), FakeAesGcmKeyEncryptor())

    @Test
    fun `a valid stored TLS profile resolves to Ready with the exact mapped and rendered config`() = runBlocking {
        val repository = newTlsRepository()
        repository.saveProfile(validTlsProfile)

        val resolution = XrayRuntimeResolver.resolveTls(repository)

        assertTrue(resolution is XrayTlsRuntimeResolution.Ready)
        val ready = resolution as XrayTlsRuntimeResolution.Ready
        assertEquals(validTlsProfile.toXrayVlessTlsConfig(), ready.config)
        assertEquals(XrayConfigRenderer.render(ready.config), ready.renderedConfig)
    }

    @Test
    fun `no stored TLS profile fails closed`() = runBlocking {
        val resolution = XrayRuntimeResolver.resolveTls(newTlsRepository())

        assertTrue(resolution is XrayTlsRuntimeResolution.Rejected)
        assertEquals("no Xray TLS profile configured", (resolution as XrayTlsRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `a corrupted stored TLS profile fails closed`() = runBlocking {
        val dir = Files.createTempDirectory("xray-tls-resolver-corrupt-test").toFile()
        dir.mkdirs()
        File(dir, "xray_tls_profile.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
        val repository = newTlsRepository(dir)

        val resolution = XrayRuntimeResolver.resolveTls(repository)

        assertTrue(resolution is XrayTlsRuntimeResolution.Rejected)
        assertEquals("failed to load Xray TLS profile: XrayTlsProfileCorruptedException", (resolution as XrayTlsRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `an invalid mapped TLS config is rejected and never rendered`() = runBlocking {
        val repository = newTlsRepository()
        repository.saveProfile(validTlsProfile.copy(uuid = "not-a-uuid"))

        val resolution = XrayRuntimeResolver.resolveTls(repository)

        assertTrue(resolution is XrayTlsRuntimeResolution.Rejected)
        assertEquals("stored Xray TLS profile failed validation: 1 error(s)", (resolution as XrayTlsRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `no rejection reason ever contains the TLS profile's actual uuid`() = runBlocking {
        val repository = newTlsRepository()
        val saved = validTlsProfile.copy(uuid = "not-a-uuid")
        repository.saveProfile(saved)

        val resolution = XrayRuntimeResolver.resolveTls(repository) as XrayTlsRuntimeResolution.Rejected

        assertFalse(resolution.reason.contains(saved.uuid))
    }
}
