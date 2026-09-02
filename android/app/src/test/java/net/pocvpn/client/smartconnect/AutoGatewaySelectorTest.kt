package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.PathHistoryEntry
import net.pocvpn.client.reachability.withIngressKind
import net.pocvpn.client.reachability.ReachabilityEvidenceSummary
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B16/B17 - real, focused proof that AutoGatewaySelector genuinely reuses
 * PathScorer/ReachabilityEngine rather than inventing a parallel scoring
 * path, and enforces every "Candidate identity"/bounded-failover invariant
 * PROJECT_ARCHITECTURE.md documents - AND (B17) that DISCOVERY is gated by
 * the caller-supplied manifest endpoint list, never `ProductionGatewayCatalog`
 * enumerated directly.
 */
class AutoGatewaySelectorTest {

    private val germanyId = ProductionGatewayCatalog.GERMANY.endpointId
    private val stockholmId = ProductionGatewayCatalog.STOCKHOLM.endpointId

    private fun manifestEndpointFor(gateway: ProductionGatewayDescriptor): EndpointDescriptor = EndpointDescriptor(
        id = gateway.endpointId,
        roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
        region = "${gateway.displayCountry} / ${gateway.displayCity}",
        provider = gateway.provider,
        transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, gateway.awg.endpointHost, gateway.awg.endpointPort)),
    )

    private val bothManifestEndpoints = listOf(
        manifestEndpointFor(ProductionGatewayCatalog.GERMANY),
        manifestEndpointFor(ProductionGatewayCatalog.STOCKHOLM),
    )

    private val catalogById = ProductionGatewayCatalog.all.associateBy { it.endpointId }

    private fun healthyRegistry(kind: TransportKind = TransportKind.AMNEZIA_WG): TransportRegistry = TransportRegistry.build(
        listOf(
            TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }),
        ),
    )

    /** B24 - a registry with EVERY kind AVAILABLE, for combined-attempt tests that need both AMNEZIA_WG (Direct/exit) and TLS_TCP (ingress) resolvable at once. */
    private fun multiTransportRegistry(vararg kinds: TransportKind): TransportRegistry = TransportRegistry.build(
        kinds.map { kind -> TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }) },
    )

    private fun reachable(endpointId: EndpointId, kind: TransportKind) = EndpointReachability(
        endpointId = endpointId,
        transportKind = kind,
        state = ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(
            transportHealthState = TransportHealthState.HEALTHY,
            transportHealthAgeMillis = 0,
            endpointSpecificReachable = true,
            networkUsable = true,
            restrictionClass = RestrictionClass.UNKNOWN,
        ),
    )

    private fun healthy() = TransportHealth(state = TransportHealthState.HEALTHY, consecutiveFailures = 0, latencyMillis = null, lastProbeEpochMillis = null)

    private fun buildDefault(
        manifestEndpoints: List<EndpointDescriptor> = bothManifestEndpoints,
        provisioned: Set<ProductionGatewayId> = setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
        preference: UserTransportPreference = UserTransportPreference.Auto,
        historyFor: (String, TransportKind) -> PathHistoryEntry? = { _, _ -> null },
    ) = AutoGatewaySelector.buildCandidates(
        manifestEndpoints = manifestEndpoints,
        gatewayFactsFor = { catalogById[it] },
        provisioned = { it in provisioned },
        clientTunnelIp = { if (it in provisioned) "10.77.0.5" else null },
        registryFor = { healthyRegistry() },
        xrayAvailableFor = { false },
        xrayTlsAvailableFor = { false },
        reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
        transportHealthFor = { healthy() },
        historyFor = historyFor,
        preference = preference,
    )

    @Test
    fun `both provisioned gateways produce candidates when both are also named in the manifest`() {
        val candidates = buildDefault()
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), candidates.map { it.gatewayId }.toSet())
    }

    @Test
    fun `unprovisioned gateway is excluded entirely`() {
        val candidates = buildDefault(provisioned = setOf(ProductionGatewayId.GERMANY))
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    /** B17 - the core runtime-authority proof: catalog membership alone is never enough. */
    @Test
    fun `endpoint absent from the trusted manifest is never a candidate even though it exists in ProductionGatewayCatalog`() {
        val candidates = buildDefault(manifestEndpoints = listOf(manifestEndpointFor(ProductionGatewayCatalog.GERMANY)))
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    /** B17 - an empty (untrusted) manifest yields zero candidates, never a fallback to the catalog. */
    @Test
    fun `no trusted manifest endpoints yields no candidates at all - fail closed, never a catalog fallback`() {
        assertTrue(buildDefault(manifestEndpoints = emptyList()).isEmpty())
    }

    @Test
    fun `gateway with no client tunnel identity is excluded even if marked provisioned`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = bothManifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { id -> if (id == ProductionGatewayId.GERMANY) "10.77.0.5" else null },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    @Test
    fun `neither gateway provisioned yields no candidates - no random selection`() {
        assertTrue(buildDefault(provisioned = emptySet()).isEmpty())
    }

    @Test
    fun `every candidate carries an exact GatewayConfigSnapshot resolved from the catalog compatibility lookup`() {
        val candidates = buildDefault()
        val germany = candidates.first { it.gatewayId == ProductionGatewayId.GERMANY }
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointHost, germany.configSnapshot.endpointHost)
        assertEquals("10.77.0.5", germany.configSnapshot.clientTunnelIp)
    }

    /**
     * B17-2 - the runtime-authority fix's core proof: the manifest's OWN
     * transport binding host/port is what ends up in the pinned
     * GatewayConfigSnapshot, even when the catalog compatibility lookup
     * would return a DIFFERENT host for the same endpoint id - a signed
     * manifest advertising a rotated host/port must actually change what
     * gets executed, never be silently overridden by
     * ProductionGatewayCatalog.
     */
    @Test
    fun `configSnapshot host and port come from the manifest binding, not the catalog, even when they differ`() {
        val manifestHost = "203.0.113.50"
        val manifestPort = 44444
        val manifestEndpoints = listOf(
            EndpointDescriptor(
                id = germanyId,
                roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                region = "Germany / Frankfurt",
                provider = "Oracle Cloud",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, manifestHost, manifestPort)),
            ),
        )
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { catalogById[it] }, // the catalog's OWN host/port differ from manifestHost/manifestPort above
            provisioned = { it == ProductionGatewayId.GERMANY },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        val germany = candidates.single { it.gatewayId == ProductionGatewayId.GERMANY }
        assertEquals(manifestHost, germany.configSnapshot.endpointHost)
        assertEquals(manifestPort.toString(), germany.configSnapshot.endpointPort)
        // Sanity: this only proves something if the two actually differ.
        assertTrue(manifestHost != ProductionGatewayCatalog.GERMANY.awg.endpointHost)
        assertTrue(manifestPort != ProductionGatewayCatalog.GERMANY.awg.endpointPort)
    }

    @Test
    fun `pinned manual transport preference restricts every gateway to that one transport kind`() {
        val candidates = buildDefault(preference = UserTransportPreference.Manual(TransportKind.AMNEZIA_WG))
        assertTrue(candidates.all { it.transport == TransportKind.AMNEZIA_WG })
    }

    @Test
    fun `richer PathHistory success ratio ranks a candidate higher - real PathScorer reuse, not a parallel scorer`() {
        val richHistory = PathHistoryEntry(successCount = 10, failureCount = 0, lastOutcomeEpochMillis = 1L, lastOutcomeSuccess = true)
        val candidates = buildDefault(
            historyFor = { pathId, _ -> if (pathId == stockholmId.value) richHistory else null },
        )
        assertEquals(ProductionGatewayId.STOCKHOLM, candidates.first().gatewayId)
    }

    @Test
    fun `unreachable-ineligible transport is never a candidate - PathScorer eligibility is honored`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = bothManifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            // Registry reports NOT AVAILABLE for AWG - PathScorer.isEligible must reject it.
            registryFor = {
                TransportRegistry.build(
                    listOf(TransportDescriptor(kind = TransportKind.AMNEZIA_WG, status = TransportStatus.NOT_IMPLEMENTED, capabilities = TransportCapabilities.notImplemented(), factory = null)),
                )
            },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertTrue(candidates.isEmpty())
    }

    // --- nextCandidate: bounded, no-repeat failover ordering ---

    @Test
    fun `nextCandidate returns the top-ranked candidate first`() {
        val candidates = buildDefault()
        val first = AutoGatewaySelector.nextCandidate(candidates, attempted = emptySet())
        assertEquals(candidates.first(), first)
    }

    @Test
    fun `nextCandidate skips already-attempted gateway plus transport pairs`() {
        val candidates = buildDefault()
        val first = candidates[0]
        val second = AutoGatewaySelector.nextCandidate(candidates, attempted = setOf(first.gatewayId to first.transport))
        assertEquals(candidates[1], second)
    }

    @Test
    fun `nextCandidate never returns the same gateway plus transport pair twice`() {
        val candidates = buildDefault()
        var attempted = emptySet<Pair<ProductionGatewayId, TransportKind>>()
        val seen = mutableListOf<Pair<ProductionGatewayId, TransportKind>>()
        while (true) {
            val next = AutoGatewaySelector.nextCandidate(candidates, attempted) ?: break
            val key = next.gatewayId to next.transport
            assertTrue("candidate $key retried", key !in seen)
            seen += key
            attempted = attempted + key
        }
        assertEquals(candidates.size, seen.size)
    }

    @Test
    fun `nextCandidate fails closed once the bounded candidate set is exhausted`() {
        val candidates = buildDefault()
        val exhausted = candidates.map { it.gatewayId to it.transport }.toSet()
        assertNull(AutoGatewaySelector.nextCandidate(candidates, exhausted))
    }

    @Test
    fun `nextCandidate stops at MAX_ATTEMPTS even if more distinct candidates exist`() {
        val pairs = listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM).flatMap { g -> TransportKind.entries.map { g to it } }
        val snapshot = buildDefault().first().configSnapshot
        val many = pairs.mapIndexed { i, (gatewayId, kind) ->
            GatewayAttemptCandidate(
                gatewayId = gatewayId,
                endpointId = germanyId,
                transport = kind,
                region = "x",
                configSnapshot = snapshot,
                score = (pairs.size - i).toLong(),
                reasons = emptyList(),
            )
        }
        assertTrue(many.size > AutoGatewaySelector.MAX_ATTEMPTS)
        val attempted = many.take(AutoGatewaySelector.MAX_ATTEMPTS).map { it.gatewayId to it.transport }.toSet()
        assertNull(AutoGatewaySelector.nextCandidate(many, attempted))
    }

    // --- B19: health/reachability become genuinely decision-driving for Auto ranking ---

    /** The task's own headline scenario, verified at the real production caller. */
    @Test
    fun `fresh AWG UNREACHABLE plus REALITY REACHABLE ranks REALITY first for the same gateway`() {
        val bothTransports = EndpointDescriptor(
            id = ProductionGatewayCatalog.GERMANY.endpointId,
            roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
            region = "Germany / Frankfurt",
            provider = ProductionGatewayCatalog.GERMANY.provider,
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.9", 443),
            ),
        )
        val dualRegistry = TransportRegistry.build(
            listOf(
                TransportDescriptor(kind = TransportKind.AMNEZIA_WG, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }),
                TransportDescriptor(kind = TransportKind.XRAY_REALITY, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.xrayRealityAdapterShell(), factory = { throw UnsupportedOperationException() }),
            ),
        )
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = listOf(bothTransports),
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { dualRegistry },
            xrayAvailableFor = { true },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind ->
                val state = if (kind == TransportKind.AMNEZIA_WG) ReachabilityState.UNREACHABLE else ReachabilityState.REACHABLE
                EndpointReachability(
                    endpointId, kind, state,
                    evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, state == ReachabilityState.REACHABLE, true, RestrictionClass.UNKNOWN),
                )
            },
            transportHealthFor = { kind -> TransportHealth(state = if (kind == TransportKind.AMNEZIA_WG) TransportHealthState.UNREACHABLE else TransportHealthState.HEALTHY) },
            historyFor = { _, _ -> null },
        )

        // B19-3 - fresh UNREACHABLE now makes AWG genuinely INELIGIBLE, not
        // merely low-ranked: it must be entirely ABSENT from the executable
        // plan, and therefore never attempted at all - never consuming a
        // MAX_ATTEMPTS slot or appearing from nextCandidate.
        assertEquals(listOf(TransportKind.XRAY_REALITY), candidates.map { it.transport })
        var attempted = emptySet<Pair<ProductionGatewayId, TransportKind>>()
        var next = AutoGatewaySelector.nextCandidate(candidates, attempted)
        while (next != null) {
            assertTrue("AWG must never be attempted from a plan where it was ineligible", next.transport != TransportKind.AMNEZIA_WG)
            attempted = attempted + (next.gatewayId to next.transport)
            next = AutoGatewaySelector.nextCandidate(candidates, attempted)
        }
    }

    @Test
    fun `AWG DEGRADED plus REALITY HEALTHY - dynamic evidence reorders past the static AMNEZIA_WG preference`() {
        val bothTransports = EndpointDescriptor(
            id = ProductionGatewayCatalog.GERMANY.endpointId,
            roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
            region = "Germany / Frankfurt",
            provider = ProductionGatewayCatalog.GERMANY.provider,
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.9", 443),
            ),
        )
        val dualRegistry = TransportRegistry.build(
            listOf(
                TransportDescriptor(kind = TransportKind.AMNEZIA_WG, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }),
                TransportDescriptor(kind = TransportKind.XRAY_REALITY, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.xrayRealityAdapterShell(), factory = { throw UnsupportedOperationException() }),
            ),
        )
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = listOf(bothTransports),
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { dualRegistry },
            xrayAvailableFor = { true },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind ->
                val state = if (kind == TransportKind.AMNEZIA_WG) ReachabilityState.DEGRADED else ReachabilityState.REACHABLE
                EndpointReachability(endpointId, kind, state, evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN))
            },
            transportHealthFor = { kind -> TransportHealth(state = if (kind == TransportKind.AMNEZIA_WG) TransportHealthState.DEGRADED else TransportHealthState.HEALTHY) },
            historyFor = { _, _ -> null },
        )

        assertEquals(TransportKind.XRAY_REALITY, candidates.first().transport)
    }

    @Test
    fun `when all dynamic evidence is UNKNOWN, static transport preference (AMNEZIA_WG first) determines order`() {
        val bothTransports = EndpointDescriptor(
            id = ProductionGatewayCatalog.GERMANY.endpointId,
            roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
            region = "Germany / Frankfurt",
            provider = ProductionGatewayCatalog.GERMANY.provider,
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.9", 443),
            ),
        )
        val dualRegistry = TransportRegistry.build(
            listOf(
                TransportDescriptor(kind = TransportKind.AMNEZIA_WG, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }),
                TransportDescriptor(kind = TransportKind.XRAY_REALITY, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.xrayRealityAdapterShell(), factory = { throw UnsupportedOperationException() }),
            ),
        )
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = listOf(bothTransports),
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { dualRegistry },
            xrayAvailableFor = { true },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind ->
                EndpointReachability(endpointId, kind, ReachabilityState.UNKNOWN, evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN))
            },
            transportHealthFor = { TransportHealth(state = TransportHealthState.UNKNOWN) },
            historyFor = { _, _ -> null },
        )

        assertEquals(TransportKind.AMNEZIA_WG, candidates.first().transport)
    }

    // --- B19: diversity bonus is a real per-candidate signal, never an identical batch-wide bonus ---

    @Test
    fun `a candidate on a clean provider gets the diversity bonus only when a troubled provider exists in the batch`() {
        // GERMANY (Oracle Cloud) is made UNREACHABLE/DEGRADED - a genuinely troubled provider;
        // STOCKHOLM (AWS eu-north-1) is clean and should pick up the bonus.
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = bothManifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind ->
                val degraded = endpointId == germanyId
                val state = if (degraded) ReachabilityState.DEGRADED else ReachabilityState.REACHABLE
                EndpointReachability(endpointId, kind, state, evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN))
            },
            transportHealthFor = { TransportHealth(state = TransportHealthState.HEALTHY) },
            historyFor = { _, _ -> null },
        )
        val stockholm = candidates.first { it.gatewayId == ProductionGatewayId.STOCKHOLM }
        assertTrue("expected a diversity-bonus reason for the clean provider: ${stockholm.reasons}", stockholm.reasons.any { it.startsWith("diversityBonus") })
    }

    @Test
    fun `no diversity bonus anywhere when nothing in the batch is troubled`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = bothManifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertTrue(candidates.none { c -> c.reasons.any { it.startsWith("diversityBonus") } })
    }

    @Test
    fun `a troubled provider never grants itself the diversity bonus`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = bothManifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind ->
                val degraded = endpointId == germanyId
                val state = if (degraded) ReachabilityState.DEGRADED else ReachabilityState.REACHABLE
                EndpointReachability(endpointId, kind, state, evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN))
            },
            transportHealthFor = { TransportHealth(state = TransportHealthState.HEALTHY) },
            historyFor = { _, _ -> null },
        )
        val germany = candidates.first { it.gatewayId == ProductionGatewayId.GERMANY }
        assertTrue(germany.reasons.none { it.startsWith("diversityBonus") })
    }

    // --- B19: stale UNREACHABLE evidence decays back to eligible/UNKNOWN, never a permanent exclusion ---

    @Test
    fun `stale endpoint-specific unreachable evidence decays to UNKNOWN and the candidate remains eligible`() {
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = listOf(manifestEndpointFor(ProductionGatewayCatalog.GERMANY)),
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { endpointId, kind ->
                // A stale (old) UNKNOWN-health, no-endpoint-evidence read - exactly what
                // ReachabilityEngine.assess produces once earlier bad evidence has expired.
                EndpointReachability(endpointId, kind, ReachabilityState.UNKNOWN, evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN))
            },
            transportHealthFor = { TransportHealth(state = TransportHealthState.UNKNOWN) },
            historyFor = { _, _ -> null },
        )
        assertEquals(1, candidates.size)
    }

    // --- B23: buildRelayedCandidates - real, evidence-driven relay ranking ---

    private val ingressEndpoint = EndpointDescriptor(
        id = EndpointId("ru-ingress-1"),
        roles = setOf(EndpointRole.INGRESS),
        region = "ru",
        provider = "operator-a",
        transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.50", 443).withIngressKind(IngressKind.CDN_FRONTED)),
        relayTo = germanyId,
    )

    private val exitEndpoint = manifestEndpointFor(ProductionGatewayCatalog.GERMANY)

    private fun relayReachable(id: EndpointId, kind: TransportKind) = EndpointReachability(
        id, kind, ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, 0, true, true, RestrictionClass.POSSIBLE_HARD_WHITELIST, endpointSpecificReachableAgeMillis = 0),
    )

    private fun relayUnknown(id: EndpointId, kind: TransportKind) = EndpointReachability(
        id, kind, ReachabilityState.UNKNOWN,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN),
    )

    private fun relayFreshlyUnreachable(id: EndpointId, kind: TransportKind) = EndpointReachability(
        id, kind, ReachabilityState.UNREACHABLE,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, 0, false, true, RestrictionClass.POSSIBLE_HARD_WHITELIST, endpointSpecificReachableAgeMillis = 0),
    )

    private fun buildRelayedDefault(
        manifestEndpoints: List<EndpointDescriptor> = listOf(ingressEndpoint, exitEndpoint),
        reachabilityFor: (EndpointId, TransportKind) -> EndpointReachability = { id, kind -> relayReachable(id, kind) },
        transportHealthFor: (TransportKind) -> TransportHealth = { healthy() },
    ) = AutoGatewaySelector.buildRelayedCandidates(
        manifestEndpoints = manifestEndpoints,
        registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
        reachabilityFor = reachabilityFor,
        transportHealthFor = transportHealthFor,
        historyFor = { _, _ -> null },
    )

    @Test
    fun `a manifest naming an INGRESS with relayTo an EXIT produces a real Relayed candidate`() {
        val candidates = buildRelayedDefault()
        assertEquals(1, candidates.size)
        assertEquals(ingressEndpoint.id, candidates.first().ingressEndpointId)
        assertEquals(exitEndpoint.id, candidates.first().exitEndpointId)
        assertEquals(TransportKind.TLS_TCP, candidates.first().ingressTransport)
        assertEquals(TransportKind.AMNEZIA_WG, candidates.first().exitTransport)
        // B27 - the candidate's own ingressKind is copied straight off the
        // manifest binding's own withIngressKind(CDN_FRONTED) metadata.
        assertEquals(IngressKind.CDN_FRONTED, candidates.first().ingressKind)
    }

    // --- B27: DIRECT_IP and CDN_FRONTED ingress candidates coexist ---

    private val directIpIngressEndpoint = EndpointDescriptor(
        id = EndpointId("direct-ip-ingress-1"),
        roles = setOf(EndpointRole.INGRESS),
        region = "ru",
        provider = "operator-b",
        // No withIngressKind() call at all - every pre-B27 manifest's own
        // shape - must default to DIRECT_IP, never inferred as CDN_FRONTED.
        transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.51", 443)),
        relayTo = germanyId,
    )

    @Test
    fun `a binding with no declared ingress kind defaults to DIRECT_IP, never inferred as CDN_FRONTED`() {
        val candidates = buildRelayedDefault(manifestEndpoints = listOf(directIpIngressEndpoint, exitEndpoint))
        assertEquals(1, candidates.size)
        assertEquals(IngressKind.DIRECT_IP, candidates.first().ingressKind)
    }

    @Test
    fun `DIRECT_IP and CDN_FRONTED ingress candidates coexist in one ranked list, each keeping its own pinned kind`() {
        val candidates = buildRelayedDefault(manifestEndpoints = listOf(directIpIngressEndpoint, ingressEndpoint, exitEndpoint))

        assertEquals(2, candidates.size)
        val byIngressId = candidates.associateBy { it.ingressEndpointId }
        assertEquals(IngressKind.DIRECT_IP, byIngressId.getValue(directIpIngressEndpoint.id).ingressKind)
        assertEquals(IngressKind.CDN_FRONTED, byIngressId.getValue(ingressEndpoint.id).ingressKind)
        // Neither candidate's own historyPathId/exit facts are affected by
        // the other candidate's presence or kind - two fully independent
        // relay identities, exactly like two Direct gateways coexisting.
        assertEquals(exitEndpoint.id, byIngressId.getValue(directIpIngressEndpoint.id).exitEndpointId)
        assertEquals(exitEndpoint.id, byIngressId.getValue(ingressEndpoint.id).exitEndpointId)
        // B27 review fix - the two candidates' own historyPathId strings
        // must be genuinely distinct too, not merely their in-memory
        // ingressKind field - this is what actually determines which
        // PathHistoryStore slot each one's evidence is recorded/read under.
        assertTrue(
            byIngressId.getValue(directIpIngressEndpoint.id).historyPathId !=
                byIngressId.getValue(ingressEndpoint.id).historyPathId,
        )
    }

    @Test
    fun `B27 review fix - the SAME ingress endpoint+transport reclassified from DIRECT_IP to CDN_FRONTED produces a different historyPathId`() {
        val directCandidate = buildRelayedDefault(manifestEndpoints = listOf(directIpIngressEndpoint, exitEndpoint)).single()
        val reclassified = directIpIngressEndpoint.copy(
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.51", 443).withIngressKind(IngressKind.CDN_FRONTED)),
        )
        val cdnCandidate = buildRelayedDefault(manifestEndpoints = listOf(reclassified, exitEndpoint)).single()

        assertEquals(directCandidate.ingressEndpointId, cdnCandidate.ingressEndpointId)
        assertEquals(directCandidate.ingressTransport, cdnCandidate.ingressTransport)
        assertTrue(
            "the SAME endpoint+transport reclassified to a different IngressKind must produce a DIFFERENT historyPathId",
            directCandidate.historyPathId != cdnCandidate.historyPathId,
        )
    }

    @Test
    fun `B27 review fix - stale history recorded under one ingress kind's historyPathId never influences scoring for the same endpoint+transport under a different kind`() {
        // A caller's own recorded evidence store, keyed by the EXACT
        // historyPathId string a real PathHistoryStore would use - only
        // the DIRECT_IP-shaped key has any evidence at all.
        val directHistoryPathId = "${directIpIngressEndpoint.id.value}:${IngressKind.DIRECT_IP}:TLS_TCP->${exitEndpoint.id.value}:AMNEZIA_WG"
        val richPositiveHistory = PathHistoryEntry(successCount = 20, failureCount = 0, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = true)
        val historyFor: (String, TransportKind) -> PathHistoryEntry? = { pathId, _ -> if (pathId == directHistoryPathId) richPositiveHistory else null }

        val reclassifiedToCdn = directIpIngressEndpoint.copy(
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.51", 443).withIngressKind(IngressKind.CDN_FRONTED)),
        )

        val directCandidates = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(directIpIngressEndpoint, exitEndpoint),
            registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = historyFor,
        )
        val cdnCandidates = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(reclassifiedToCdn, exitEndpoint),
            registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = historyFor,
        )

        // The DIRECT_IP candidate's own historyPathId genuinely matches the
        // seeded key, so its score reflects the rich positive history.
        // The CDN_FRONTED candidate, despite the SAME endpoint id and
        // transport, has a DIFFERENT historyPathId - the stale DIRECT_IP
        // evidence must never be read back for it (and vice versa: a
        // CDN_FRONTED-keyed history entry, symmetric by construction, could
        // never leak into a DIRECT_IP lookup either, since historyFor is
        // looked up by the exact string either way).
        assertTrue(
            "a candidate whose historyPathId has real evidence must score higher than an otherwise-identical candidate with none",
            directCandidates.single().score > cdnCandidates.single().score,
        )
    }

    @Test
    fun `an ingress absent a relayTo target never produces a candidate`() {
        val orphanIngress = ingressEndpoint.copy(relayTo = null)
        assertTrue(buildRelayedDefault(manifestEndpoints = listOf(orphanIngress, exitEndpoint)).isEmpty())
    }

    @Test
    fun `an endpoint with no INGRESS role is never treated as a relay entrypoint`() {
        assertTrue(buildRelayedDefault(manifestEndpoints = listOf(exitEndpoint)).isEmpty())
    }

    @Test
    fun `UNKNOWN ingress reachability does not outrank a healthy Direct candidate by default`() {
        val direct = buildDefault(manifestEndpoints = listOf(exitEndpoint))
        val relayed = buildRelayedDefault(reachabilityFor = { id, kind -> relayUnknown(id, kind) })

        assertTrue(direct.isNotEmpty())
        assertTrue(relayed.isNotEmpty())
        assertTrue("a healthy Direct candidate must outscore an UNKNOWN relay", direct.first().score > relayed.first().score)
    }

    @Test
    fun `a fresh, proven-reachable ingress under hard-whitelist evidence is eligible even when Direct has no path`() {
        // Direct's own exit reachability is fresh UNREACHABLE - the exact
        // shape a real hard-whitelist network produces for the foreign exit.
        val direct = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = listOf(exitEndpoint),
            gatewayFactsFor = { catalogById[it] },
            provisioned = { true },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry() },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            reachabilityFor = { id, kind -> relayFreshlyUnreachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        val relayed = buildRelayedDefault()

        assertTrue("no eligible Direct path under hard whitelist", direct.isEmpty())
        assertEquals(1, relayed.size)
    }

    @Test
    fun `a fresh ingress failure excludes the relay - never merely low-scored`() {
        val relayed = buildRelayedDefault(reachabilityFor = { id, kind -> relayFreshlyUnreachable(id, kind) })
        assertTrue(relayed.isEmpty())
    }

    @Test
    fun `a stale ingress failure decays back to UNKNOWN and no longer excludes the relay`() {
        // Same shape as relayFreshlyUnreachable but with NO age (null) -
        // ReachabilityEngine.assess's own freshness gate never trusts an
        // undated outcome, so this is exactly what a once-fresh failure
        // looks like once it has expired - reused verbatim, not a second
        // staleness rule invented here.
        val staleFailure = { id: EndpointId, kind: TransportKind ->
            EndpointReachability(
                id, kind, ReachabilityState.UNKNOWN,
                evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, false, true, RestrictionClass.UNKNOWN),
            )
        }
        val relayed = buildRelayedDefault(reachabilityFor = staleFailure)
        assertEquals(1, relayed.size)
    }

    @Test
    fun `pinning a MANUAL transport preference filters relay candidates the same way it filters Direct ones`() {
        val relayed = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ingressEndpoint, exitEndpoint),
            registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
            preference = UserTransportPreference.Manual(TransportKind.AMNEZIA_WG),
        )
        assertTrue(relayed.isEmpty())
    }

    @Test
    fun `no ingress endpoints in the manifest yields no relay candidates - fail closed, never a fabricated one`() {
        assertTrue(buildRelayedDefault(manifestEndpoints = listOf(exitEndpoint)).isEmpty())
    }

    // --- B23 (PR #37 review fix): ingress and exit transports are pinned independently ---

    @Test
    fun `an ingress with two transports and an exit with two transports scores every pair independently, never assuming a shared transport`() {
        val ingressTwoTransports = ingressEndpoint.copy(
            transports = listOf(
                EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.50", 443),
                EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 8443),
            ),
        )
        val exitTwoTransports = exitEndpoint.copy(
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                EndpointTransportBinding(TransportKind.TLS_TCP, ProductionGatewayCatalog.GERMANY.awg.endpointHost, 443),
            ),
        )
        val relayed = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ingressTwoTransports, exitTwoTransports),
            registryFor = { TransportRegistry.build(listOf(TransportKind.TLS_TCP, TransportKind.XRAY_REALITY).map { kind -> TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() }) }) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        // 2 ingress transports x 2 exit transports = 4 independently-scored pairs.
        assertEquals(4, relayed.size)
        val pairs = relayed.map { it.ingressTransport to it.exitTransport }.toSet()
        assertEquals(4, pairs.size)
        assertTrue((TransportKind.TLS_TCP to TransportKind.AMNEZIA_WG) in pairs)
        assertTrue((TransportKind.XRAY_REALITY to TransportKind.TLS_TCP) in pairs)
    }

    @Test
    fun `a MANUAL preference pins only the client-facing ingress transport, never the exit-upstream transport`() {
        val exitTwoTransports = exitEndpoint.copy(
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                EndpointTransportBinding(TransportKind.TLS_TCP, ProductionGatewayCatalog.GERMANY.awg.endpointHost, 443),
            ),
        )
        val relayed = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ingressEndpoint, exitTwoTransports),
            registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
            preference = UserTransportPreference.Manual(TransportKind.TLS_TCP),
        )
        // The single ingress transport (TLS_TCP) matches the pin, so both of
        // the exit's own transports remain viable - the pin never touches exitTransport.
        assertEquals(2, relayed.size)
        assertTrue(relayed.all { it.ingressTransport == TransportKind.TLS_TCP })
        assertEquals(setOf(TransportKind.AMNEZIA_WG, TransportKind.TLS_TCP), relayed.map { it.exitTransport }.toSet())
    }

    // --- B23 (PR #37 review fix, round 2): RelayAttemptCandidate pins the exact per-hop bindings ---

    @Test
    fun `RelayAttemptCandidate exposes the exact ingress binding selected at candidate-build time`() {
        val candidate = buildRelayedDefault().single()
        assertEquals(ingressEndpoint.transports.single(), candidate.ingressBinding)
        assertEquals("203.0.113.50", candidate.ingressBinding.host)
        assertEquals(443, candidate.ingressBinding.port)
        assertEquals(TransportKind.TLS_TCP, candidate.ingressBinding.kind)
    }

    @Test
    fun `RelayAttemptCandidate exposes the exact exit binding selected at candidate-build time`() {
        val candidate = buildRelayedDefault().single()
        assertEquals(exitEndpoint.transports.single(), candidate.exitBinding)
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointHost, candidate.exitBinding.host)
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointPort, candidate.exitBinding.port)
        assertEquals(TransportKind.AMNEZIA_WG, candidate.exitBinding.kind)
    }

    /**
     * B23 (PR #37 review fix, round 2) - the B16/B23 attempt-pinning
     * invariant: an ALREADY-BUILT RelayAttemptCandidate's own binding facts
     * must never be re-resolvable from a manifest that later rotates for the
     * SAME endpoint ids - a caller holding the earlier candidate must keep
     * seeing the ORIGINAL host/port, exactly the guarantee
     * GatewayAttemptCandidate.configSnapshot already provides for Direct.
     */
    @Test
    fun `mutating or replacing endpoint descriptors used elsewhere after candidate creation cannot change the pinned candidate bindings`() {
        val original = buildRelayedDefault().single()
        val originalIngressBinding = original.ingressBinding
        val originalExitBinding = original.exitBinding

        // A caller resolves an entirely FRESH descriptor set for the SAME
        // endpoint ids, with different host/port on both hops - simulating a
        // manifest refresh mid-attempt. This must never be able to reach
        // back into `original` and change what it reports.
        val rotatedIngress = ingressEndpoint.copy(
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "198.51.100.9", 9443).withIngressKind(IngressKind.DIRECT_IP)),
        )
        val rotatedExit = exitEndpoint.copy(
            transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "198.51.100.10", 51821)),
        )
        val rebuilt = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(rotatedIngress, rotatedExit),
            registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        ).single()

        // The original candidate's own fields are unchanged (data class vals
        // - structurally impossible to mutate - but assert the actual values
        // to prove the fix, not merely that the type is immutable).
        assertEquals(originalIngressBinding, original.ingressBinding)
        assertEquals(originalExitBinding, original.exitBinding)
        assertEquals("203.0.113.50", original.ingressBinding.host)
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointHost, original.exitBinding.host)

        // The REBUILT candidate correctly reflects the rotated facts - proving
        // the rotation itself was real and the original genuinely didn't see it.
        assertEquals("198.51.100.9", rebuilt.ingressBinding.host)
        assertEquals("198.51.100.10", rebuilt.exitBinding.host)
        assertTrue(original.ingressBinding != rebuilt.ingressBinding)
        assertTrue(original.exitBinding != rebuilt.exitBinding)
    }

    @Test
    fun `ingress and exit bindings remain independently pinned when their transports differ`() {
        val exitTwoTransports = exitEndpoint.copy(
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.77", 443),
            ),
        )
        val relayed = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ingressEndpoint, exitTwoTransports),
            registryFor = { healthyRegistry(TransportKind.TLS_TCP) },
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertEquals(2, relayed.size)

        val viaAwgExit = relayed.single { it.exitTransport == TransportKind.AMNEZIA_WG }
        val viaTlsExit = relayed.single { it.exitTransport == TransportKind.TLS_TCP }

        // Both share the SAME ingress binding (the ingress transport never changed)...
        assertEquals(viaAwgExit.ingressBinding, viaTlsExit.ingressBinding)
        assertEquals(TransportKind.TLS_TCP, viaAwgExit.ingressBinding.kind)
        // ...but each pins its OWN distinct exit binding, independent of the ingress hop.
        assertTrue(viaAwgExit.exitBinding != viaTlsExit.exitBinding)
        assertEquals(TransportKind.AMNEZIA_WG, viaAwgExit.exitBinding.kind)
        assertEquals(TransportKind.TLS_TCP, viaTlsExit.exitBinding.kind)
        assertEquals("203.0.113.77", viaTlsExit.exitBinding.host)
    }

    // --- B24: buildCombinedAttempts - ONE combined executable attempt plan ---

    private fun buildCombinedDefault(
        manifestEndpoints: List<EndpointDescriptor>,
        reachabilityFor: (EndpointId, TransportKind) -> EndpointReachability,
        transportHealthFor: (TransportKind) -> TransportHealth = { healthy() },
        provisioned: Set<ProductionGatewayId> = setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
    ) = AutoGatewaySelector.buildCombinedAttempts(
        manifestEndpoints = manifestEndpoints,
        gatewayFactsFor = { catalogById[it] },
        provisioned = { it in provisioned },
        clientTunnelIp = { if (it in provisioned) "10.77.0.5" else null },
        registryFor = { multiTransportRegistry(TransportKind.AMNEZIA_WG, TransportKind.TLS_TCP) },
        xrayAvailableFor = { false },
        xrayTlsAvailableFor = { false },
        reachabilityFor = reachabilityFor,
        transportHealthFor = transportHealthFor,
        historyFor = { _, _ -> null },
    )

    /** Task requirement A - combined ranking returns ONE immutable executable attempt type covering both shapes. */
    @Test
    fun `combined attempts contain both DirectAttempt and RelayedAttempt when both exist`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(exitEndpoint, ingressEndpoint),
            reachabilityFor = { id, kind -> reachable(id, kind) },
        )
        assertTrue(attempts.any { it is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt })
        assertTrue(attempts.any { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt })
    }

    /** Task requirement B - exact pinned ingress/exit bindings survive ranking -> execution unchanged. */
    @Test
    fun `the RelayedAttempt winner carries the exact same pinned bindings buildRelayedCandidates produced`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(ingressEndpoint, exitEndpoint),
            reachabilityFor = { id, kind -> relayReachable(id, kind) },
        )
        val relayedWinner = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>().first().candidate
        val relayedOnly = buildRelayedDefault(manifestEndpoints = listOf(ingressEndpoint, exitEndpoint)).single()
        assertEquals(relayedOnly.ingressBinding, relayedWinner.ingressBinding)
        assertEquals(relayedOnly.exitBinding, relayedWinner.exitBinding)
        assertEquals(relayedOnly.historyPathId, relayedWinner.historyPathId)
    }

    /** Task requirement C - Direct path behavior is unchanged when no ingress exists. */
    @Test
    fun `combined attempts equal the Direct-only list, wrapped, when no ingress endpoint exists`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = bothManifestEndpoints,
            reachabilityFor = { id, kind -> reachable(id, kind) },
        )
        assertTrue(attempts.all { it is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt })
        val direct = buildDefault(manifestEndpoints = bothManifestEndpoints)
        assertEquals(direct.map { it.gatewayId }.toSet(), attempts.map { (it as AutoGatewaySelector.AutoConnectAttempt.DirectAttempt).candidate.gatewayId }.toSet())
    }

    /** Task requirement D - under normal network evidence, healthy Direct wins over UNKNOWN relay. */
    @Test
    fun `a healthy Direct attempt outranks an UNKNOWN relay attempt under normal evidence`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(exitEndpoint, ingressEndpoint),
            reachabilityFor = { id, kind -> if (id == ingressEndpoint.id) relayUnknown(id, kind) else reachable(id, kind) },
        )
        assertTrue(attempts.first() is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt)
    }

    /** Task requirement E - under hard-whitelist evidence, a proven relay can win over a failed Direct. */
    @Test
    fun `a proven relay attempt outranks a fresh-unreachable Direct attempt under hard-whitelist evidence`() {
        // The exit gets a SECOND transport (TLS_TCP) so its own AMNEZIA_WG
        // dial (what Direct uses) can genuinely differ from its TLS_TCP
        // dial (what the relay's exit hop uses) - the real architecture
        // keys reachability by (endpointId, transportKind), so a hard
        // whitelist that blocks ONE transport to the exit but not another
        // is exactly what makes a relay meaningfully different from Direct
        // here, never a fabricated distinction.
        val exitTwoTransports = exitEndpoint.copy(
            transports = exitEndpoint.transports + EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.77", 443),
        )
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(exitTwoTransports, ingressEndpoint),
            reachabilityFor = { id, kind ->
                if (id == exitTwoTransports.id && kind == TransportKind.AMNEZIA_WG) relayFreshlyUnreachable(id, kind) else relayReachable(id, kind)
            },
        )
        assertTrue(attempts.first() is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt)
    }

    /** Task requirement F - no eligible path (Direct or relay) fails closed: an empty combined list. */
    @Test
    fun `no eligible Direct or relay path yields an empty combined attempt list - fail closed`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(exitEndpoint, ingressEndpoint),
            reachabilityFor = { id, kind -> relayFreshlyUnreachable(id, kind) },
        )
        assertTrue(attempts.isEmpty())
    }

    /** Task requirement K (selector level) - the shared MAX_ATTEMPTS budget bounds combined retries across BOTH types. */
    @Test
    fun `nextCombinedAttempt is bounded by the shared MAX_ATTEMPTS budget across Direct and Relayed together`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(exitEndpoint, ingressEndpoint),
            reachabilityFor = { id, kind -> reachable(id, kind) },
        )
        var attemptedKeys = emptySet<String>()
        var iterations = 0
        while (true) {
            val next = AutoGatewaySelector.nextCombinedAttempt(attempts, attemptedKeys) ?: break
            attemptedKeys = attemptedKeys + next.attemptKey
            iterations++
        }
        assertTrue(iterations <= AutoGatewaySelector.MAX_ATTEMPTS)
    }

    @Test
    fun `nextCombinedAttempt never returns the same attemptKey twice`() {
        val attempts = buildCombinedDefault(
            manifestEndpoints = listOf(exitEndpoint, ingressEndpoint),
            reachabilityFor = { id, kind -> reachable(id, kind) },
        )
        val first = AutoGatewaySelector.nextCombinedAttempt(attempts, emptySet())!!
        val second = AutoGatewaySelector.nextCombinedAttempt(attempts, setOf(first.attemptKey))
        assertTrue(second == null || second.attemptKey != first.attemptKey)
    }
}
