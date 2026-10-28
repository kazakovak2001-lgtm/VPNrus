package net.pocvpn.client.debug.f2

import android.content.Intent
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.UnderlyingNetworkRecovery
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.XrayConfigRenderer

class F2XhttpHarnessTest {

    private fun ok(
        dial: String = "10.0.2.2",
        sni: String = "f2-test.example.invalid",
        host: String? = null,
        alpn: String? = null,
        mode: String? = null,
        port: Int = 8443,
        maxSeconds: Int? = null,
    ): F2XhttpTestProfile.BuildResult.Ok = F2XhttpTestProfile.build(
        dialHost = dial, port = port, sni = sni, httpHost = host, alpn = alpn, mode = mode, maxSeconds = maxSeconds,
    ) as F2XhttpTestProfile.BuildResult.Ok

    private fun reason(
        dial: String? = "10.0.2.2",
        sni: String? = "f2-test.example.invalid",
        host: String? = null,
        alpn: String? = null,
        mode: String? = null,
        port: Int? = 8443,
    ) = (F2XhttpTestProfile.build(dial, port, sni, host, null, alpn, mode, null)
        as F2XhttpTestProfile.BuildResult.Rejected).reason

    // --- configuration separation -------------------------------------------------------

    @Test
    fun `dial address SNI and HTTP Host stay independent in the config and the rendered Xray JSON`() {
        val built = ok(dial = "10.0.2.2", sni = "sni.f2.invalid", host = "host.f2.invalid")
        val c = built.transportConfig.config
        assertEquals("10.0.2.2", c.server)
        assertEquals("sni.f2.invalid", c.tlsServerName)
        assertEquals("host.f2.invalid", c.xhttpHost)

        val outbound = JSONObject(XrayConfigRenderer.render(c)).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("10.0.2.2", outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"))
        val stream = outbound.getJSONObject("streamSettings")
        assertEquals("xhttp", stream.getString("network"))
        assertEquals("sni.f2.invalid", stream.getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("host.f2.invalid", stream.getJSONObject("xhttpSettings").getString("host"))
    }

    @Test
    fun `TLS verification is never relaxed and the profile is a Direct isolated-endpoint session`() {
        val built = ok()
        val stream = JSONObject(XrayConfigRenderer.render(built.transportConfig.config))
            .getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        assertFalse(stream.getJSONObject("tlsSettings").getBoolean("allowInsecure"))
        assertFalse(built.transportConfig.isRelayed)
        assertEquals(F2XhttpTestProfile.ENDPOINT_ID, built.transportConfig.endpointId.value)
    }

    @Test
    fun `an NXDOMAIN-style reserved hostname is accepted as the dial target and an IP is accepted with a separate SNI`() {
        assertEquals("nxdomain.test.invalid", ok(dial = "nxdomain.test.invalid").transportConfig.config.server)
        assertEquals("f2-test.example.invalid", ok(dial = "192.168.1.5").transportConfig.config.tlsServerName)
    }

    @Test
    fun `host defaults to SNI and maxSeconds is clamped`() {
        assertEquals("f2-test.example.invalid", ok().transportConfig.config.xhttpHost)
        assertEquals(20_000L, ok().maxMillis)
        assertEquals(5_000L, ok(maxSeconds = 1).maxMillis)
        assertEquals(60_000L, ok(maxSeconds = 9_999).maxMillis)
    }

    @Test
    fun `production and public targets are refused`() {
        for (prod in listOf("152.70.43.1", "16.170.208.231", "8.8.8.8", "172.32.0.1", "cdn.example.com", "localhost")) {
            assertEquals(prod, F2XhttpTestProfile.Reason.DIAL_HOST_NOT_TEST_ONLY, reason(dial = prod))
        }
        assertEquals(F2XhttpTestProfile.Reason.SNI_NOT_TEST_ONLY, reason(sni = "www.google.com"))
        assertEquals(F2XhttpTestProfile.Reason.HTTP_HOST_NOT_TEST_ONLY, reason(host = "www.google.com"))
        assertEquals(F2XhttpTestProfile.Reason.DIAL_HOST_NOT_TEST_ONLY, reason(dial = null))
    }

    @Test
    fun `h3 an unknown mode and a bad port are refused`() {
        assertEquals(F2XhttpTestProfile.Reason.UNSUPPORTED_ALPN, reason(alpn = "h3"))
        assertEquals(F2XhttpTestProfile.Reason.INVALID_MODE, reason(mode = "bogus"))
        assertEquals(F2XhttpTestProfile.Reason.INVALID_PORT, reason(port = 0))
        assertEquals(F2XhttpTestProfile.Reason.INVALID_PORT, reason(port = null))
    }

    // --- bounded run, timeout, cancellation ---------------------------------------------

    private class FakeTransport(private val script: suspend (MutableStateFlow<TransportState>) -> Unit = {}) : VpnTransport {
        val state = MutableStateFlow<TransportState>(TransportState.Disconnected)
        var connects = 0
        var disconnects = 0
        override val name = "fake-xhttp"
        override val kind = TransportKind.XRAY_XHTTP
        override val capabilities = TransportCapabilities.xrayXhttpAdapterShell()
        override val underlyingNetworkRecovery = UnderlyingNetworkRecovery.RESTART_SESSION
        override fun preparePermissionIntent(): Intent? = null
        override suspend fun connect(config: TransportConfig) {
            connects++
            state.value = TransportState.Connecting
            script(state)
        }
        override suspend fun disconnect() { disconnects++ }
        override fun observeState(): Flow<TransportState> = state.asStateFlow()
    }

    private val config get() = ok().transportConfig

    @Test
    fun `a stalled attempt times out after one connect and is disconnected exactly once`() = runBlocking {
        val t = FakeTransport()
        val outcome = F2XhttpRunner(t).run(config, 80)
        assertTrue(outcome is F2XhttpRunner.Outcome.TimedOut)
        assertEquals(1, t.connects)
        assertEquals(1, t.disconnects)
    }

    @Test
    fun `an Error state ends the run as Failed with the failure kind and still disconnects`() = runBlocking {
        val t = FakeTransport { it.value = TransportState.Error("x", failureKind = net.pocvpn.client.vpn.TransportFailureKind.REMOTE_UNCONFIRMED) }
        val events = mutableListOf<F2XhttpRunner.Event>()
        val outcome = F2XhttpRunner(t).run(config, 5_000) { events += it }
        val failed = outcome as F2XhttpRunner.Outcome.Failed
        assertEquals("REMOTE_UNCONFIRMED", failed.failureKind)
        assertEquals(1, t.connects)
        assertEquals(1, t.disconnects)
        // StateFlow conflates: the synchronous Connecting -> Error pair may surface as Error alone.
        assertTrue(events.any { it.state == "Error(kind=REMOTE_UNCONFIRMED)" })
    }

    @Test
    fun `cancelling a run disconnects its transport`() = runBlocking {
        val t = FakeTransport()
        val job = launch(Dispatchers.Default) { F2XhttpRunner(t).run(config, 60_000) }
        while (t.connects == 0) delay(5)
        job.cancel()
        job.join()
        assertEquals(1, t.disconnects)
    }

    // --- release isolation ---------------------------------------------------------------

    @Test
    fun `the harness is declared only in the debug manifest behind the shell-only permission`() {
        val debug = file("src/debug/AndroidManifest.xml").readText()
        val start = debug.indexOf("net.pocvpn.client.debug.f2.F2XhttpHarnessActivity")
        check(start >= 0) { "harness activity not declared in the debug manifest" }
        val declaration = debug.substring(start, debug.indexOf("/>", start))
        assertTrue(declaration.contains("android:permission=\"android.permission.DUMP\""))

        assertFalse(file("src/main/AndroidManifest.xml").readText().contains("F2Xhttp"))
    }

    @Test
    fun `no production source references the harness`() {
        val offenders = File("src/main").walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "java" || it.extension == "xml") }
            .filter { f -> f.readText().let { "debug.f2" in it || "F2Xhttp" in it } }
            .map { it.path }.toList()
        assertTrue("production sources reference the F2 harness: $offenders", offenders.isEmpty())
        assertTrue(File("src/debug/java/net/pocvpn/client/debug/f2/F2XhttpHarnessActivity.kt").isFile)
        assertFalse(File("src/main/java/net/pocvpn/client/debug").exists())
    }

    private fun file(relativePath: String): File = File(relativePath).also {
        check(it.isFile) { "Expected app-module file at ${it.absolutePath}" }
    }
}
