package net.pocvpn.client.controlplane

import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B67.2 - Multi-Path Activation Discovery.
 *
 * Uses only deterministic fake [ControlPlaneOrigin]/[ActivationPathCandidate]
 * objects and typed [ProvisioningResult] outcomes - no sleeps, no timing
 * races, no concurrency, no live network. Fake origins are distinguished by
 * host string so a test can assert exactly which trusted origin was actually
 * dialed, without relying on call count alone (task requirement 6).
 *
 * These tests prove the DIRECT/CHAIN_DIRECT/CHAIN_CDN composition/fallback
 * MECHANISM - they do NOT prove real production CHAIN_DIRECT/CHAIN_CDN
 * reachability, since [TrustedChainControlPlaneOriginCatalog] deploys neither
 * today (see that object's own docs). Synthetic multi-path origins here come
 * ONLY from [ActivationPathCandidateBuilder.forGatewayFromOrigins], an
 * `internal` (module-visible-only) test seam this test class is the sole
 * caller of - the production entry point, [ActivationPathCandidateBuilder
 * .forGateway], takes no origin/host parameter at all.
 */
class ActivationPathCandidateTest {

    private val gateway = ProductionGatewayId.GERMANY
    private val direct = ControlPlaneOrigin(gateway, "direct-origin")
    private val chainDirect = ControlPlaneOrigin(gateway, "chain-direct-origin")
    private val chainCdn = ControlPlaneOrigin(gateway, "chain-cdn-origin")

    private fun success(host: String) = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.5",
        gatewayPublicKey = "pk",
        gatewayTunnelIp = "10.77.0.1",
        endpointHost = host,
        endpointPort = 51820,
    )

    // --- ActivationPathCandidateBuilder: composition & deterministic ordering ---

    @Test
    fun `candidate builder composes DIRECT, CHAIN_DIRECT, CHAIN_CDN in that fixed order when all are trusted`() {
        val candidates = ActivationPathCandidateBuilder.forGatewayFromOrigins(
            gateway,
            directOrigins = listOf(direct),
            chainDirectOrigins = listOf(chainDirect),
            chainCdnOrigins = listOf(chainCdn),
        )
        assertEquals(
            listOf(ActivationPathKind.DIRECT, ActivationPathKind.CHAIN_DIRECT, ActivationPathKind.CHAIN_CDN),
            candidates.map { it.kind },
        )
    }

    @Test
    fun `an ineligible untrusted path shape contributes no candidate - never an empty-origin placeholder`() {
        val candidates = ActivationPathCandidateBuilder.forGatewayFromOrigins(
            gateway,
            directOrigins = listOf(direct),
            chainDirectOrigins = emptyList(),
            chainCdnOrigins = emptyList(),
        )
        assertEquals(listOf(ActivationPathKind.DIRECT), candidates.map { it.kind })
    }

    @Test
    fun `today's real production catalog yields DIRECT only - existing single-path behavior is unchanged`() {
        val candidates = ActivationPathCandidateBuilder.forGateway(gateway)
        assertEquals(listOf(ActivationPathKind.DIRECT), candidates.map { it.kind })
        assertEquals(ControlPlaneOriginSetBuilder.forGateway(gateway), candidates.single().origins)
    }

    @Test
    fun `flattened origin set matches ControlPlaneOriginSetBuilder alone when no chain path is trusted`() {
        assertEquals(
            ControlPlaneOriginSetBuilder.forGateway(gateway),
            ActivationPathOriginSetBuilder.forGateway(gateway),
        )
    }

    @Test
    fun `the production entry point takes no origin-host parameter - only the internal test seam does`() {
        // ActivationPathCandidateBuilder.forGateway(gatewayId) is the ONLY
        // function MainViewModel (via ActivationPathOriginSetBuilder) ever
        // calls, and its sole parameter is a closed ProductionGatewayId enum
        // - there is no origin/host/URL argument to pass through it at all.
        // The overload that DOES accept origin lists (forGatewayFromOrigins)
        // is `internal` - a compile-time/Kotlin-visibility mechanism, not a
        // runtime security boundary; invisible from outside this Gradle
        // module. forGateway() itself calls it, but only ever with origins
        // forGateway() already resolved from the trusted production
        // catalogs (ControlPlaneOriginSetBuilder/
        // TrustedChainControlPlaneOriginCatalog) - this test class calls it
        // directly only with synthetic test origins, to exercise the
        // composition mechanism deterministically. No production caller
        // supplies a raw external/user/network-supplied host to it. This
        // test proves the production call shape, not an unprovable
        // universal absence of any injection seam.
        val candidates = ActivationPathCandidateBuilder.forGateway(gateway)
        candidates.flatMap { it.origins }.forEach { assertEquals(gateway, it.gatewayId) }
    }

    @Test
    fun `today's real production catalog is DIRECT-only - CHAIN_DIRECT and CHAIN_CDN are not yet deployed`() {
        // TrustedChainControlPlaneOriginCatalog.chainDirect/chainCdn both
        // return emptyList() today (no trusted relay/CDN control-plane
        // origin has been deployed or audited yet) - so real production
        // activation traffic is DIRECT-only, not a genuine three-path
        // system, regardless of the composition mechanism proven below.
        assertTrue(TrustedChainControlPlaneOriginCatalog.chainDirect(gateway).isEmpty())
        assertTrue(TrustedChainControlPlaneOriginCatalog.chainCdn(gateway).isEmpty())
        assertEquals(listOf(ActivationPathKind.DIRECT), ActivationPathCandidateBuilder.forGateway(gateway).map { it.kind })
    }

    // --- End-to-end through the existing, unmodified ActivationResilienceCoordinator ---
    // (synthetic trusted origins via the internal forGatewayFromOrigins test seam -
    // proves the composition/fallback MECHANISM, not production reachability)

    private fun flattenedOrigins() = ActivationPathCandidateBuilder.forGatewayFromOrigins(
        gateway,
        directOrigins = listOf(direct),
        chainDirectOrigins = listOf(chainDirect),
        chainCdnOrigins = listOf(chainCdn),
    ).flatMap { it.origins }

    @Test
    fun `DIRECT succeeds - later paths are not attempted`() {
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ -> attempted += origin.host; success(origin.host) },
            origins = flattenedOrigins(),
        )
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Success)
        assertEquals(listOf("direct-origin"), attempted)
        assertEquals("direct-origin", (outcome as ActivationResilienceCoordinator.Outcome.Success).result.endpointHost)
    }

    @Test
    fun `DIRECT network failure falls through to CHAIN_DIRECT which succeeds - exact path order proven`() {
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                attempted += origin.host
                if (origin.host == "direct-origin") ProvisioningResult.NetworkError("SocketTimeoutException: t") else success(origin.host)
            },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf("direct-origin", "chain-direct-origin"), attempted)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Success)
        assertEquals("chain-direct-origin", (outcome as ActivationResilienceCoordinator.Outcome.Success).result.endpointHost)
    }

    @Test
    fun `DIRECT and CHAIN_DIRECT fail, CHAIN_CDN succeeds - exact bounded fallback proven`() {
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                attempted += origin.host
                if (origin.host == "chain-cdn-origin") success(origin.host) else ProvisioningResult.ServiceUnavailable
            },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf("direct-origin", "chain-direct-origin", "chain-cdn-origin"), attempted)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Success)
    }

    @Test
    fun `authorization rejection on DIRECT is terminal - CHAIN_DIRECT and CHAIN_CDN are never attempted`() {
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "wrong-cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ -> attempted += origin.host; ProvisioningResult.Revoked },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf("direct-origin"), attempted)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Rejected)
        assertEquals(ProvisioningResult.Revoked, (outcome as ActivationResilienceCoordinator.Outcome.Rejected).result)
    }

    @Test
    fun `authorization rejection on a later path is still terminal - no further paths attempted`() {
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "wrong-cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                attempted += origin.host
                if (origin.host == "direct-origin") ProvisioningResult.ServiceUnavailable else ProvisioningResult.Revoked
            },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf("direct-origin", "chain-direct-origin"), attempted)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Rejected)
    }

    @Test
    fun `all eligible paths fail - one bounded final outcome, no infinite retry, no credential leakage`() {
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "super-secret-credential",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ -> attempted += origin.host; ProvisioningResult.ServiceUnavailable },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf("direct-origin", "chain-direct-origin", "chain-cdn-origin"), attempted)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.AllOriginsExhausted)
        val exhausted = outcome as ActivationResilienceCoordinator.Outcome.AllOriginsExhausted
        assertEquals(3, exhausted.failures.size)
        exhausted.failures.forEach { failure ->
            assertFalse(failure.toString().contains("super-secret-credential"))
        }
    }

    @Test
    fun `exact origin routing - the selected trusted origin is genuinely dialed, not merely counted`() {
        val dialedOrigins = mutableListOf<ControlPlaneOrigin>()
        ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                dialedOrigins += origin
                if (origin.host == "direct-origin") ProvisioningResult.NetworkError("SocketTimeoutException: t") else success(origin.host)
            },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf(direct, chainDirect), dialedOrigins)
        // Never the same host dialed twice, never a hardcoded host substituted for the selected one.
        assertEquals(dialedOrigins.distinct(), dialedOrigins)
    }

    @Test
    fun `nested boundedness - a multi-origin CHAIN_DIRECT path never multiplies into unbounded retries`() {
        val chainDirectSecondary = ControlPlaneOrigin(gateway, "chain-direct-origin-2")
        val origins = ActivationPathCandidateBuilder.forGatewayFromOrigins(
            gateway,
            directOrigins = listOf(direct),
            chainDirectOrigins = listOf(chainDirect, chainDirectSecondary),
            chainCdnOrigins = listOf(chainCdn),
        ).flatMap { it.origins }

        var attempts = 0
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                attempts++
                if (origin.host == "chain-direct-origin-2") success(origin.host) else ProvisioningResult.ServiceUnavailable
            },
            origins = origins,
        )
        // direct-origin, chain-direct-origin, chain-direct-origin-2 = exactly 3 attempts, never more.
        assertEquals(3, attempts)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Success)
    }

    @Test
    fun `B56-5 compatibility - an activation-package-redeemed credential still flows through the same multi-path activation`() {
        // The B56-5 NovaActivationPackage flow decodes into the same
        // (publicKey, activationCredential) shape MainViewModel.activateDevice()
        // already accepts - it never bypasses ActivationResilienceCoordinator,
        // so it automatically benefits from the same DIRECT -> CHAIN_DIRECT ->
        // CHAIN_CDN discovery proven above, with no separate code path.
        val attempted = mutableListOf<String>()
        val outcome = ActivationResilienceCoordinator().activate(
            gatewayId = gateway,
            publicKey = "device-key-from-package",
            activationCredential = "credential-from-nova-activation-package",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                attempted += origin.host
                if (origin.host == "direct-origin") ProvisioningResult.NetworkError("SocketTimeoutException: t") else success(origin.host)
            },
            origins = flattenedOrigins(),
        )
        assertEquals(listOf("direct-origin", "chain-direct-origin"), attempted)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Success)
    }
}
