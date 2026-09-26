package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.FileXrayTlsProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.SecureXrayTlsProfileRepository
import net.pocvpn.client.identity.FileXrayXhttpProfileStore
import net.pocvpn.client.identity.SecureXrayXhttpProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.identity.XrayXhttpProfile
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
        // B13 (audit fix) - the real endpoint-scoped file name, computed the same way production does.
        File(dir, "xray_profile_${net.pocvpn.client.identity.sanitizeForFileName(net.pocvpn.client.reachability.EndpointId("frankfurt"))}.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
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
        // B13 (audit fix) - the real endpoint-scoped file name, computed the same way production does.
        File(dir, "xray_tls_profile_${net.pocvpn.client.identity.sanitizeForFileName(net.pocvpn.client.reachability.EndpointId("frankfurt"))}.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
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

/**
 * B61/B61.4 - the EXIT-role (Frankfurt, B60) XHTTP counterpart of
 * [XrayRuntimeResolverTest]/[XrayTlsRuntimeResolverTest]. Proves the real
 * load -> map -> validate -> render machinery reaches Ready using the
 * evidence-backed EXIT constants established in B61.3/B61.4 (never the
 * Stockholm ingress profile's own values), and that padding is genuinely
 * omitted from the rendered config rather than a synthesized HEADER/QUERY
 * guess.
 */
class XrayXhttpRuntimeResolverTest {

    private val validXhttpProfile = XrayXhttpProfile(
        server = "edge.aknova.pp.ua",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        xhttpHost = "edge.aknova.pp.ua",
        xhttpPath = "/nova-xhttp/",
        mode = "packet-up",
        uplinkHttpMethod = "POST",
        fingerprint = "chrome",
    )

    private fun newXhttpRepository(dir: File = Files.createTempDirectory("xray-xhttp-resolver-test").toFile()): SecureXrayXhttpProfileRepository =
        SecureXrayXhttpProfileRepository(FileXrayXhttpProfileStore(dir), FakeAesGcmKeyEncryptor())

    @Test
    fun `a valid stored XHTTP profile resolves to Ready using the evidence-backed EXIT constants`() = runBlocking {
        val repository = newXhttpRepository()
        repository.saveProfile(validXhttpProfile)

        val resolution = XrayRuntimeResolver.resolveXhttp(repository)

        assertTrue(resolution is XrayXhttpRuntimeResolution.Ready)
        val ready = resolution as XrayXhttpRuntimeResolution.Ready
        assertEquals("edge.aknova.pp.ua", ready.config.server)
        assertEquals(443, ready.config.serverPort)
        assertEquals("edge.aknova.pp.ua", ready.config.tlsServerName)
        assertEquals("edge.aknova.pp.ua", ready.config.xhttpHost)
        assertEquals("/nova-xhttp/", ready.config.xhttpPath)
        assertEquals(XrayXhttpMode.PACKET_UP, ready.config.mode)
        assertEquals(XrayXhttpUplinkHttpMethod.POST, ready.config.uplinkHttpMethod)
        assertEquals("chrome", ready.config.fingerprint)
        // B61.3/B61.4 evidence-backed EXIT constants (see XrayProfileMapper's own docs).
        assertEquals(XrayXhttpMinimumTlsVersion.TLS_1_3, ready.config.minimumTlsVersion)
        assertEquals("h2", ready.config.alpn)
        assertEquals(1_000_000, ready.config.maxEachPostBytes)
        // Padding is genuinely omitted, never a synthesized placement.
        assertEquals(null, ready.config.paddingPlacement)
        assertEquals(null, ready.config.paddingMinBytes)
        assertEquals(null, ready.config.paddingMaxBytes)
        assertEquals(XrayConfigRenderer.render(ready.config), ready.renderedConfig)
    }

    @Test
    fun `rendered config never contains an explicit padding placement`() = runBlocking {
        val repository = newXhttpRepository()
        repository.saveProfile(validXhttpProfile)

        val resolution = XrayRuntimeResolver.resolveXhttp(repository) as XrayXhttpRuntimeResolution.Ready

        assertFalse(resolution.renderedConfig.contains("xPaddingPlacement"))
        assertFalse(resolution.renderedConfig.contains("xPaddingBytes"))
        assertFalse(resolution.renderedConfig.contains("xPaddingObfsMode"))
        // Never a synthesized HEADER/QUERY wire value standing in for Xray's
        // own real (unrepresentable) PlacementQueryInHeader default.
        assertFalse(resolution.renderedConfig.contains("\"header\""))
        assertFalse(resolution.renderedConfig.contains("\"query\""))
    }

    @Test
    fun `no stored XHTTP profile fails closed`() = runBlocking {
        val resolution = XrayRuntimeResolver.resolveXhttp(newXhttpRepository())

        assertTrue(resolution is XrayXhttpRuntimeResolution.Rejected)
        assertEquals("no Xray XHTTP profile configured", (resolution as XrayXhttpRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `a corrupted stored XHTTP profile fails closed`() = runBlocking {
        val dir = Files.createTempDirectory("xray-xhttp-resolver-corrupt-test").toFile()
        dir.mkdirs()
        File(dir, "xray_xhttp_profile_${net.pocvpn.client.identity.sanitizeForFileName(net.pocvpn.client.reachability.EndpointId("frankfurt"))}.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
        val repository = newXhttpRepository(dir)

        val resolution = XrayRuntimeResolver.resolveXhttp(repository)

        assertTrue(resolution is XrayXhttpRuntimeResolution.Rejected)
        assertEquals("failed to load Xray XHTTP profile: XrayXhttpProfileCorruptedException", (resolution as XrayXhttpRuntimeResolution.Rejected).reason)
    }

    @Test
    fun `an unrecognized wire mode value fails closed`() = runBlocking {
        val repository = newXhttpRepository()
        repository.saveProfile(validXhttpProfile.copy(mode = "stream-up"))

        val resolution = XrayRuntimeResolver.resolveXhttp(repository)

        assertTrue(resolution is XrayXhttpRuntimeResolution.Rejected)
    }

    @Test
    fun `resolved config never carries the loopback backend address or port`() = runBlocking {
        val repository = newXhttpRepository()
        repository.saveProfile(validXhttpProfile)

        val resolution = XrayRuntimeResolver.resolveXhttp(repository) as XrayXhttpRuntimeResolution.Ready

        assertFalse(resolution.config.server.contains("127.0.0.1"))
        assertFalse(resolution.renderedConfig.contains("127.0.0.1"))
        assertFalse(resolution.renderedConfig.contains("2099"))
    }

    @Test
    fun `no rejection reason ever contains the XHTTP profile's actual uuid`() = runBlocking {
        val repository = newXhttpRepository()
        val saved = validXhttpProfile.copy(mode = "not-a-mode")
        repository.saveProfile(saved)

        val resolution = XrayRuntimeResolver.resolveXhttp(repository) as XrayXhttpRuntimeResolution.Rejected

        assertFalse(resolution.reason.contains(saved.uuid))
    }
}
