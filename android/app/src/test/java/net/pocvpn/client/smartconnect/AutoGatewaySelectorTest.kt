package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.PathHistoryEntry
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
        historyFor: (EndpointId, TransportKind) -> PathHistoryEntry? = { _, _ -> null },
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

    /** B21 - QUIC appears as a generic candidate ONLY when the manifest declares it AND local availability says yes - no QUIC-specific branch in the ranking itself. */
    @Test
    fun `QUIC candidate appears when the manifest declares it and this device has a usable profile`() {
        val manifestEndpoints = listOf(
            manifestEndpointFor(ProductionGatewayCatalog.GERMANY).copy(
                transports = listOf(
                    EndpointTransportBinding(TransportKind.AMNEZIA_WG, ProductionGatewayCatalog.GERMANY.awg.endpointHost, ProductionGatewayCatalog.GERMANY.awg.endpointPort),
                    EndpointTransportBinding(TransportKind.QUIC, "203.0.113.9", 443),
                ),
            ),
        )
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { it == ProductionGatewayId.GERMANY },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry(TransportKind.QUIC) },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            xrayQuicAvailableFor = { true },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertTrue(candidates.any { it.transport == TransportKind.QUIC })
    }

    /** B21 - a manifest declaring QUIC does NOT imply this device is provisioned for it - same "manifest facts vs local provisioning" rule REALITY/TLS_TCP already enforce. */
    @Test
    fun `QUIC binding in the manifest is ignored when this device has no usable QUIC profile`() {
        val manifestEndpoints = listOf(
            manifestEndpointFor(ProductionGatewayCatalog.GERMANY).copy(
                transports = listOf(EndpointTransportBinding(TransportKind.QUIC, "203.0.113.9", 443)),
            ),
        )
        val candidates = AutoGatewaySelector.buildCandidates(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { catalogById[it] },
            provisioned = { it == ProductionGatewayId.GERMANY },
            clientTunnelIp = { "10.77.0.5" },
            registryFor = { healthyRegistry(TransportKind.QUIC) },
            xrayAvailableFor = { false },
            xrayTlsAvailableFor = { false },
            xrayQuicAvailableFor = { false },
            reachabilityFor = { endpointId, kind -> reachable(endpointId, kind) },
            transportHealthFor = { healthy() },
            historyFor = { _, _ -> null },
        )
        assertTrue(candidates.isEmpty())
    }

    /** B21 - callers that never wire QUIC availability at all (every pre-B21 call site) see byte-for-byte the same behavior as before this parameter existed. */
    @Test
    fun `omitting xrayQuicAvailableFor entirely defaults to QUIC always unavailable`() {
        val candidates = buildDefault(
            manifestEndpoints = listOf(
                manifestEndpointFor(ProductionGatewayCatalog.GERMANY).copy(
                    transports = listOf(EndpointTransportBinding(TransportKind.QUIC, "203.0.113.9", 443)),
                ),
            ),
            provisioned = setOf(ProductionGatewayId.GERMANY),
        )
        assertTrue(candidates.isEmpty())
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
            historyFor = { endpointId, _ -> if (endpointId == stockholmId) richHistory else null },
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
}
