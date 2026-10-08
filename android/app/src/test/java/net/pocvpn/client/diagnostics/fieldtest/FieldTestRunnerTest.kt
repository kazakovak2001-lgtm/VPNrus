package net.pocvpn.client.diagnostics.fieldtest

import android.net.Network
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class FieldTestRunnerTest {

    private fun manifest() = EndpointManifest(
        manifestVersion = 6,
        issuedAtEpochMillis = 1,
        expiresAtEpochMillis = 2,
        signingKeyId = "test-key",
        endpoints = listOf(
            EndpointDescriptor(
                id = EndpointId("frankfurt"), roles = setOf(EndpointRole.GATEWAY), region = "DE", provider = "test",
                transports = listOf(
                    EndpointTransportBinding(TransportKind.AMNEZIA_WG, "152.70.43.1", 51820),
                    EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 2053),
                    EndpointTransportBinding(TransportKind.TLS_TCP, "152.70.43.1", 2083),
                ),
            ),
            EndpointDescriptor(
                id = EndpointId("stockholm"), roles = setOf(EndpointRole.GATEWAY), region = "SE", provider = "test",
                transports = listOf(
                    EndpointTransportBinding(TransportKind.AMNEZIA_WG, "16.170.208.231", 51820),
                    EndpointTransportBinding(TransportKind.XRAY_REALITY, "16.170.208.231", 2053),
                    EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443),
                    EndpointTransportBinding(TransportKind.HYSTERIA2, "16.170.208.231", 443),
                ),
            ),
        ),
    )

    /**
     * Fake app: connect() lands in Connected for REALITY/AUTO, Error for AWG,
     * and stays Disconnected (refused, lastError set) for XHTTP.
     */
    private inner class FakeHost(
        private val provisioned: Set<ProductionGatewayId> = setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
        private val permission: Boolean = true,
        // Like the real controller: disconnect() of an idle transport leaves Error in place.
        private val stickyError: Boolean = false,
        private val signedManifest: EndpointManifest = manifest(),
        private val ingressActivation: String = "unknown",
    ) : FieldTestHost {
        override val transportState = MutableStateFlow<TransportState>(TransportState.Disconnected)
        override val sessionHealth = MutableStateFlow<VpnSessionHealth>(VpnSessionHealth.Idle)
        override val currentTransportKind = MutableStateFlow<TransportKind?>(null)
        var applied: FieldAttemptTarget? = null
        val connects = mutableListOf<String>()
        var restored: Any? = null
        var lastError: String? = null

        override fun vpnPermissionGranted() = permission
        override fun provisionedGateways() = provisioned
        override fun trustedManifest() = signedManifest
        override fun endpointIdFor(gateway: ProductionGatewayId) =
            if (gateway == ProductionGatewayId.GERMANY) "frankfurt" else "stockholm"
        override fun saveSelection(): Any = "saved"
        override fun restoreSelection(saved: Any) { restored = saved }
        override fun applyTarget(target: FieldAttemptTarget): String? { applied = target; return null }
        override fun connect() {
            val t = applied!!
            connects += t.label
            when (t.transport) {
                TransportKind.TLS_TCP -> transportState.value = TransportState.Error("handshake timeout")
                TransportKind.XRAY_XHTTP -> lastError = "NoCandidateAvailable"
                else -> {
                    transportState.value = TransportState.Connected
                    sessionHealth.value = VpnSessionHealth.DirectProtected
                    currentTransportKind.value = t.transport ?: TransportKind.XRAY_REALITY
                }
            }
        }
        override fun disconnect() {
            if (stickyError && transportState.value is TransportState.Error) return
            transportState.value = TransportState.Disconnected
            sessionHealth.value = VpnSessionHealth.Idle
            currentTransportKind.value = null
        }
        override fun transportScores() = mapOf(TransportKind.XRAY_REALITY to 10)
        override fun lastErrorText() = lastError
        override fun lastForcedRelayKeys(): List<String>? = null
        override suspend fun relayIngressActivation(ingressId: String) = ingressActivation
        override fun latestDiagnosticSession(): JSONObject? = JSONObject().put("selectedPathKind", "DIRECT")
        override fun appState() = JSONObject().put("state", "x")
        override fun supportBundle(): JSONObject? = JSONObject().put("schemaVersion", 1)
        override fun networkContext() = JSONObject().put("summary", "WIFI, operator Test (25001, ru)")
        override fun vpnNetwork(): Network? = null
        override fun appInfo() = JSONObject().put("gitCommit", "abc")
        override fun deviceInfo() = JSONObject().put("model", "test")
        override suspend fun refreshManifestOutcome(): String? = "Refreshed(v6)"
        override fun exitReasons() = org.json.JSONArray().put(JSONObject().put("reason", "EXIT_SELF").put("status", 2))
        override fun crashes() = org.json.JSONArray()
        override suspend fun logs() = listOf("I/Nova: line")
        var network = "WIFI validated=true net=100"
        override fun activeNetworkSummary() = network
        var coreAnswers = true
        override suspend fun measureViaXrayCore(urls: List<String>) =
            if (coreAnswers) urls.map { net.pocvpn.client.vpn.xray.XrayProcessBridge.CoreMeasurement(it, 42, null) } else null
    }

    private fun okProbe(label: String, url: String, maxBytes: Long, trace: Map<String, String> = emptyMap()) =
        HttpProbeResult(label, url, true, 200, 10, 5, maxBytes, null, true, null, trace)

    /** In-tunnel vs direct is decided by the fake host's connection state (its vpnNetwork() is null). */
    private fun fakeProbes(host: FakeHost, stallBulk: Boolean = false) = FieldProbeSet(
        dns = { h, _ -> DnsProbeResult(h, true, listOf("1.2.3.4"), 1, null) },
        tcp = { l, h, p, _ -> TcpProbeResult(l, h, p, true, 5, null) },
        censorship = { _ -> CensorshipReport(emptyList(), mapOf("8.8.8.8:53" to false), mapOf("cloudflare" to true), listOf("UDP53_TO_FOREIGN_RESOLVERS_BLOCKED")) },
        api = { origins -> org.json.JSONArray().apply { origins.forEach { put(JSONObject().put("origin", it).put("path", "/v1/activate").put("verdict", "API_REACHABLE").put("httpStatus", 400)) } } },
        leaks = { _, direct -> JSONObject().put("verdict", if (direct.isEmpty()) "NO_LEAK_OBSERVED" else "NO_LEAK_OBSERVED") },
        https = { label, url, _, maxBytes, parseTrace ->
            val inTunnel = host.transportState.value is TransportState.Connected
            when {
                inTunnel && host.currentTransportKind.value == TransportKind.HYSTERIA2 ->
                    HttpProbeResult(label, url, false, null, 1, null, 0, null, false, "SocketException: Binding socket to network 196 failed: EPERM (Operation not permitted)")
                parseTrace -> okProbe(label, url, 200, mapOf("ip" to if (inTunnel) "152.70.43.1" else "198.51.100.7", "loc" to "RU", "colo" to "ARN"))
                stallBulk && url == FieldTestTargets.BULK_TUNNEL ->
                    HttpProbeResult(label, url, false, 200, 9000, 100, 16_384, 16_384, false, "stalled after 16384 bytes")
                else -> okProbe(label, url, maxBytes)
            }
        },
    )

    private val fastTimings = FieldTestTimings(
        connectTimeoutMs = 5_000, healthGraceMs = 1_000, settleMs = 10, stabilityHoldMs = 10,
        disconnectTimeoutMs = 1_000, betweenRunsMs = 10, notStartedGraceMs = 1_000,
    )

    private fun TestScope.runner(host: FakeHost, probes: FieldProbeSet = fakeProbes(host)) =
        FieldTestRunner(host, probes, fastTimings, clock = { testScheduler.currentTime })

    @Test
    fun `full run covers every gateway x transport plus smart connect and classifies each`() = runTest {
        val host = FakeHost()
        val report = runner(host).run { }
        val byLabel = report.runs.associateBy { it.target.label }

        assertEquals(ProductionGatewayId.entries.size * FIELD_TEST_TRANSPORTS.size + 1, report.runs.size)
        // AWG: the app is inside the tunnel -> app-level probes.
        assertEquals(FieldRunOutcome.DATA_PLANE_OK, byLabel.getValue("GERMANY / AMNEZIA_WG").outcome)
        assertEquals("152.70.43.1", byLabel.getValue("GERMANY / AMNEZIA_WG").exitIp)
        // Stockholm AWG exits through 152.70.43.1 in the fake -> not a Stockholm address.
        assertEquals(FieldRunOutcome.EXIT_MISMATCH, byLabel.getValue("STOCKHOLM / AMNEZIA_WG").outcome)
        assertEquals(FieldRunOutcome.CONNECT_FAILED, byLabel.getValue("GERMANY / TLS_TCP").outcome)
        // Xray family: the app is excluded from the tunnel -> measured by the Xray core.
        val reality = byLabel.getValue("GERMANY / XRAY_REALITY")
        assertEquals(FieldRunOutcome.DATA_PLANE_CORE_CONFIRMED, reality.outcome)
        assertNull(reality.exitIp)
        assertTrue(reality.coreMeasurements!!.any { it.url == "https://152.70.43.1/v1/tunnel-probe" })
        assertEquals(FieldRunOutcome.UNAVAILABLE, byLabel.getValue("STOCKHOLM / XRAY_XHTTP").outcome)
        assertEquals(FieldRunOutcome.SKIPPED, byLabel.getValue("GERMANY / XRAY_XHTTP").outcome)
        assertEquals("not offered by the signed manifest for this gateway", byLabel.getValue("GERMANY / XRAY_XHTTP").skipReason)
        assertEquals(FieldRunOutcome.DATA_PLANE_CORE_CONFIRMED, byLabel.getValue("AUTO / SMART_CONNECT").outcome)
        assertEquals("saved", host.restored)
        assertTrue(host.transportState.value is TransportState.Disconnected)
        assertFalse(report.cancelled)
        assertNull(report.abortReason)
    }

    @Test
    fun `direct probes never keep the device's own public IP`() = runTest {
        val report = runner(FakeHost()).run { }
        val trace = report.direct!!.http.first { it.label == "Cloudflare trace" }
        assertFalse(trace.trace.containsKey("ip"))
        assertEquals("RU", trace.trace["loc"])
        assertFalse(report.toJson().toString().contains("198.51.100.7"))
    }

    @Test
    fun `direct phase probes every signed TCP binding and the CDN edge but not UDP bindings`() = runTest {
        val report = runner(FakeHost()).run { }
        val tcpLabels = report.direct!!.tcp.map { it.label }
        assertTrue(tcpLabels.contains("frankfurt XRAY_REALITY tcp/2053"))
        assertFalse(tcpLabels.any { it.contains("AMNEZIA_WG") })
        assertTrue(report.direct!!.http.any { it.url == "https://edge.example/" })
        assertTrue(report.direct!!.http.any { it.url == "https://152.70.43.1/v1/tunnel-probe" })
    }

    @Test
    fun `a freeze after 16 KB is reported as the suspected throttling pattern`() = runTest {
        val report = FakeHost().let { h -> runner(h, fakeProbes(h, stallBulk = true)) }.run { }
        val run = report.runs.first { it.target.label == "GERMANY / AMNEZIA_WG" }
        assertEquals(FieldRunOutcome.DATA_PLANE_STALL_SUSPECTED, run.outcome)
        assertTrue(report.summaryLines().any { it.contains("STALL at 16384") })
    }

    @Test
    fun `gateways not activated on this device are skipped, not attempted`() = runTest {
        val host = FakeHost(provisioned = setOf(ProductionGatewayId.GERMANY))
        val report = runner(host).run { }
        assertTrue(report.runs.filter { it.target.gateway == ProductionGatewayId.STOCKHOLM }.all { it.outcome == FieldRunOutcome.SKIPPED })
        assertFalse(host.connects.any { it.startsWith("STOCKHOLM") })
    }

    @Test
    fun `missing VPN permission aborts before any connect and still yields a report`() = runTest {
        val host = FakeHost(permission = false)
        val report = runner(host).run { }
        assertTrue(report.abortReason!!.contains("VPN permission"))
        assertTrue(host.connects.isEmpty())
        assertEquals("saved", host.restored)
    }

    @Test
    fun `cancel keeps finished runs, disconnects and restores the selection`() = runTest {
        val host = FakeHost()
        var report: FieldTestReport? = null
        // Cancel while the test is in the middle of the VPN runs (step 4 = third attempt).
        val job = launch { report = runner(host).run { p -> if (p.running && p.step >= 4) throw kotlinx.coroutines.CancellationException("user") } }
        advanceUntilIdle()
        job.join()
        val r = report!!
        assertTrue(r.cancelled)
        assertTrue(r.runs.size < ProductionGatewayId.entries.size * FIELD_TEST_TRANSPORTS.size + 1)
        assertTrue(host.transportState.value is TransportState.Disconnected)
        assertEquals("saved", host.restored)
    }

    private fun manifestWith(extraFrankfurt: List<EndpointTransportBinding> = emptyList(), ingress: EndpointDescriptor? = null): EndpointManifest {
        val base = manifest()
        val endpoints = base.endpoints.map { e ->
            if (e.id.value == "frankfurt") e.copy(transports = e.transports + extraFrankfurt) else e
        } + listOfNotNull(ingress)
        return base.copy(endpoints = endpoints)
    }

    @Test
    fun `a previous run's Error is not reported as the next attempt's result`() = runTest {
        // GERMANY / TLS_TCP ends in Error, which disconnect() does not clear; the
        // next attempt (GERMANY / XRAY_XHTTP) is refused without any state change.
        val host = FakeHost(
            stickyError = true,
            signedManifest = manifestWith(listOf(EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443))),
        )
        val report = runner(host).run { }
        val xhttp = report.runs.first { it.target.label == "GERMANY / XRAY_XHTTP" }

        assertEquals(FieldRunOutcome.UNAVAILABLE, xhttp.outcome)
        assertEquals("NoCandidateAvailable", xhttp.errorMessage)
        assertEquals("NotStarted", xhttp.terminalState)
        // The attempt waited for its own result instead of returning on the first poll.
        assertTrue(xhttp.errorMessage != "handshake timeout")
    }

    @Test
    fun `a leftover Error that never changes is reported as not observed`() = runTest {
        val host = FakeHost(stickyError = true)
        host.transportState.value = TransportState.Error("handshake timeout")
        // Every connect is refused silently (no state change, no new error).
        val silent = object : FieldTestHost by host {
            override fun connect() { host.applied?.let { host.connects += it.label } }
        }
        val report = FieldTestRunner(silent, fakeProbes(host), fastTimings, clock = { testScheduler.currentTime }).run { }
        val reality = report.runs.first { it.target.label == "GERMANY / XRAY_REALITY" }

        assertEquals("NotStarted", reality.terminalState)
        assertTrue(reality.errorMessage!!.startsWith("attempt not observed"))
        assertTrue(reality.outcome != FieldRunOutcome.DATA_PLANE_CORE_CONFIRMED)
    }

    @Test
    fun `relay runs record whether the ingress is activated on this device`() = runTest {
        val ingress = EndpointDescriptor(
            id = EndpointId("stockholm-ingress-1"), roles = setOf(EndpointRole.INGRESS), region = "SE", provider = "test",
            transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "16.170.208.231", 2093)),
            relayTo = EndpointId("frankfurt"),
        )
        val host = FakeHost(signedManifest = manifestWith(ingress = ingress), ingressActivation = "NOT_ACTIVATED")
        val report = runner(host).run { }
        val relay = report.runs.first { it.target.relayIngress == "stockholm-ingress-1" }

        assertTrue(relay.notes.contains("relay ingress stockholm-ingress-1 on this device: NOT_ACTIVATED"))
    }

    @Test
    fun `report JSON carries schema, summary, app state and every run`() = runTest {
        val report = runner(FakeHost()).run { }
        val json = report.toJson()
        assertEquals(FieldTestReport.SCHEMA, json.getString("schema"))
        assertEquals(report.runs.size, json.getJSONArray("runs").length())
        assertEquals("abc", json.getJSONObject("app").getString("gitCommit"))
        assertTrue(json.getJSONArray("summary").getString(0).startsWith("Nova field test"))
        assertEquals("DIRECT", json.getJSONArray("runs").getJSONObject(1).getJSONObject("diagnosticSession").getString("selectedPathKind"))
    }

    @Test
    fun `full run also carries censorship, API, manifest refresh, exit reasons, logs and leak verdicts`() = runTest {
        val report = runner(FakeHost()).run { }
        assertEquals(listOf("UDP53_TO_FOREIGN_RESOLVERS_BLOCKED"), report.censorship!!.networkVerdicts)
        assertEquals("Refreshed(v6)", report.manifestRefresh)
        assertTrue(report.apiChecks!!.length() >= 3) // 152.70.43.1, 16.170.208.231, control.aknova.pp.ua
        assertEquals("EXIT_SELF", report.exitReasons!!.getJSONObject(0).getString("reason"))
        assertEquals(listOf("I/Nova: line"), report.logs)
        assertEquals("NO_LEAK_OBSERVED", report.runs.first { it.target.label == "GERMANY / AMNEZIA_WG" }.leaks!!.getString("verdict"))
        assertNull(report.runs.first { it.target.label == "GERMANY / XRAY_REALITY" }.leaks)
        val json = report.toJson()
        assertEquals("FULL", json.getString("mode"))
        assertTrue(json.getJSONArray("summary").toString().contains("UDP53_TO_FOREIGN_RESOLVERS_BLOCKED"))
    }

    @Test
    fun `quick mode never connects, works without VPN permission and reconnects a session it paused`() = runTest {
        val host = FakeHost(permission = false)
        host.applyTarget(FieldAttemptTarget(null, null))
        host.connect() // the user was connected before the check
        host.connects.clear()
        val report = runner(host).run(FieldTestMode.QUICK, 0) { }
        assertTrue(report.runs.isEmpty())
        assertNull(report.abortReason)
        assertTrue(report.censorship != null && report.direct != null)
        assertEquals(1, host.connects.size) // only the final reconnect
    }

    @Test
    fun `monitor mode samples the user's own connection and records events`() = runTest {
        val host = FakeHost()
        host.applyTarget(FieldAttemptTarget(null, null))
        val report = runner(host).run(FieldTestMode.MONITOR, 5 * 60_000L) { }
        val m = report.monitor!!
        assertEquals(10, m.getJSONArray("samples").length())
        assertTrue(m.getString("probeSuccess").startsWith("10/"))
        assertTrue(m.getJSONArray("events").toString().contains("state Connected"))
        assertTrue(host.transportState.value is TransportState.Disconnected)
    }

    @Test
    fun `relay ingresses in the manifest each get a forced relay run`() {
        val withIngress = manifest().let { m ->
            m.copy(
                endpoints = m.endpoints + EndpointDescriptor(
                    id = EndpointId("stockholm-xhttp-ingress-1"), roles = setOf(EndpointRole.INGRESS), region = "SE", provider = "test",
                    transports = listOf(EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443)),
                    relayTo = EndpointId("frankfurt"),
                ),
            )
        }
        assertEquals(listOf("stockholm-xhttp-ingress-1"), relayIngressIds(withIngress))
        val plan = planAttempts(ProductionGatewayId.entries.toList(), relayIngressIds(withIngress))
        assertTrue(plan.contains(FieldAttemptTarget(null, null, relayIngress = "stockholm-xhttp-ingress-1")))
        assertEquals(FieldAttemptTarget(null, null), plan.last())
        assertEquals(setOf("152.70.43.1"), expectedExitIps(withIngress, "frankfurt"))
    }

    @Test
    fun `an Xray run whose core does not answer is CONNECTED_NO_DATA with an explanation`() = runTest {
        val host = FakeHost().apply { coreAnswers = false }
        val run = runner(host).run { }.runs.first { it.target.label == "GERMANY / XRAY_REALITY" }
        assertEquals(FieldRunOutcome.CONNECTED_NO_DATA, run.outcome)
        assertTrue(run.notes.any { "did not answer" in it })
    }

    @Test
    fun `a VPN that excludes the app is CONNECTED_APP_EXCLUDED, never a false leak or no-data verdict`() = runTest {
        val run = runner(FakeHost()).run { }.runs.first { it.target.label == "STOCKHOLM / HYSTERIA2" }
        assertEquals(FieldRunOutcome.CONNECTED_APP_EXCLUDED, run.outcome)
        assertNull(run.leaks)
        assertNull(run.throughput)
        assertTrue(run.notes.any { "EPERM" in it })
    }
}
