package net.pocvpn.client.relay

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * B32 (PR #53 follow-up) - the real production [RelayIngressResolver]
 * ([RelayCompositionFactoryTest] already proves this is what
 * [net.pocvpn.client.MainViewModel.Factory.create] actually wires, never
 * [NotProvisionedRelayIngressResolver]) has no dedicated unit test of its
 * own before this - a real, pre-existing gap. This file closes it for
 * every early-return branch that never touches AndroidKeyStore
 * ([PROFILE_NOT_PROVISIONED]/[PROFILE_MISMATCH]/[PROFILE_EXPIRED] - see
 * [RelayIngressResolverImpl.resolve]'s own source: each of these returns
 * BEFORE the `when (plan.ingressTransport)` block that writes through
 * `XrayProfileRepositoryFactory`). The success/`Resolved` branch is NOT
 * exercised here: it additionally performs a real
 * AndroidKeyStore-backed encrypted write, a documented, pre-existing
 * incompatibility between this project's Robolectric version and
 * AndroidKeyStore (see [RelayCompositionFactoryTest]'s own docs for the
 * exact `KeyStoreException`/`NoSuchAlgorithmException` this hits) - not
 * something this task introduces or can safely force through.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RelayIngressResolverImplTest {

    private val ingressId = EndpointId("stockholm-ingress-1")
    private val pinnedBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "16.170.208.231", 2093)
    private val exitBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 443)

    private fun plan(binding: EndpointTransportBinding = pinnedBinding, transport: TransportKind = TransportKind.XRAY_REALITY, ingressKind: IngressKind = IngressKind.DIRECT_IP) =
        RelayedExecutionPlan.from(
            AutoGatewaySelector.RelayAttemptCandidate(
                ingressEndpointId = ingressId,
                exitEndpointId = EndpointId("frankfurt"),
                ingressTransport = transport,
                exitTransport = TransportKind.XRAY_REALITY,
                ingressBinding = binding,
                exitBinding = exitBinding,
                ingressKind = ingressKind,
                ingressRegion = "Stockholm",
                exitRegion = "Frankfurt",
                score = 1_000L,
                reasons = listOf("test"),
                historyPathId = "${ingressId.value}:$ingressKind:$transport->frankfurt:XRAY_REALITY",
            ),
        )

    private fun realityProfile(server: String, port: Int) = XrayProfile(
        server = server, serverPort = port, uuid = "11111111-1111-1111-1111-111111111111",
        flow = "", serverName = "www.bing.com", fingerprint = "chrome", realityPublicKey = "A".repeat(43), shortId = "ab",
    )

    private fun newResolver(store: IngressProfileStore, nowProvider: () -> Long = System::currentTimeMillis) =
        RelayIngressResolverImpl(ApplicationProvider.getApplicationContext<Context>(), store, nowProvider)

    @Test
    fun `XHTTP resolves to real transport using exact ingress profile without TLS repository write`() = runTest {
        val binding = EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.aknova.pp.ua", 443)
        val profile = IngressClientProfile(
            ingressEndpointId = ingressId, ingressBinding = binding,
            transport = TransportKind.XRAY_XHTTP, ingressKind = IngressKind.CDN_FRONTED,
            tlsProfile = XrayTlsProfile(
                server = binding.host, serverPort = binding.port,
                uuid = "11111111-1111-1111-1111-111111111111",
                serverName = binding.host, fingerprint = "chrome",
            ),
            profileVersion = 1, issuedAtEpochMillis = 1,
        )
        val store = InMemoryIngressProfileStore()
        store.saveProfile(profile)

        val resolution = newResolver(store).resolve(
            plan(binding, TransportKind.XRAY_XHTTP, IngressKind.CDN_FRONTED),
        )

        assertTrue(resolution is RelayIngressResolution.Resolved)
        val resolved = resolution as RelayIngressResolution.Resolved
        assertEquals(TransportKind.XRAY_XHTTP, resolved.kind)
        assertTrue(resolved.transport is net.pocvpn.client.vpn.VlessXhttpTransport)
        assertEquals(profile, resolved.profile)
    }

    @Test
    fun `no stored profile resolves to NotProvisioned PROFILE_NOT_PROVISIONED`() = runTest {
        val resolver = newResolver(InMemoryIngressProfileStore())

        val resolution = resolver.resolve(plan())

        assertTrue(resolution is RelayIngressResolution.NotProvisioned)
        assertEquals(RelayFailureCategory.PROFILE_NOT_PROVISIONED, (resolution as RelayIngressResolution.NotProvisioned).category)
    }

    @Test
    fun `a stored profile pinned to a DIFFERENT binding resolves to NotProvisioned PROFILE_MISMATCH - never silently reused`() = runTest {
        val store = InMemoryIngressProfileStore()
        store.saveProfile(
            IngressClientProfile(
                ingressEndpointId = ingressId,
                // A stale/foreign binding (e.g. left over from a prior deployment) - NOT the plan's own pinned fact.
                ingressBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "198.51.100.1", 9999),
                transport = TransportKind.XRAY_REALITY,
                realityProfile = realityProfile("198.51.100.1", 9999),
                profileVersion = 1,
                issuedAtEpochMillis = 1_000L,
            ),
        )
        val resolver = newResolver(store)

        val resolution = resolver.resolve(plan())

        assertTrue(resolution is RelayIngressResolution.NotProvisioned)
        assertEquals(RelayFailureCategory.PROFILE_MISMATCH, (resolution as RelayIngressResolution.NotProvisioned).category)
    }

    @Test
    fun `a stored profile for a DIFFERENT ingress kind resolves to PROFILE_MISMATCH even with an identical binding`() = runTest {
        val store = InMemoryIngressProfileStore()
        store.saveProfile(
            IngressClientProfile(
                ingressEndpointId = ingressId,
                ingressBinding = pinnedBinding,
                transport = TransportKind.XRAY_REALITY,
                ingressKind = IngressKind.CDN_FRONTED,
                realityProfile = realityProfile(pinnedBinding.host, pinnedBinding.port),
                profileVersion = 1,
                issuedAtEpochMillis = 1_000L,
            ),
        )
        val resolver = newResolver(store)

        // plan()'s own ingressKind is DIRECT_IP - the stored profile is CDN_FRONTED.
        val resolution = resolver.resolve(plan())

        assertTrue(resolution is RelayIngressResolution.NotProvisioned)
        assertEquals(RelayFailureCategory.PROFILE_MISMATCH, (resolution as RelayIngressResolution.NotProvisioned).category)
    }

    @Test
    fun `an expired stored profile resolves to NotProvisioned PROFILE_EXPIRED - never reused past its own validity window`() = runTest {
        val store = InMemoryIngressProfileStore()
        store.saveProfile(
            IngressClientProfile(
                ingressEndpointId = ingressId,
                ingressBinding = pinnedBinding,
                transport = TransportKind.XRAY_REALITY,
                realityProfile = realityProfile(pinnedBinding.host, pinnedBinding.port),
                profileVersion = 1,
                issuedAtEpochMillis = 1_000L,
                expiresAtEpochMillis = 2_000L,
            ),
        )
        val resolver = newResolver(store, nowProvider = { 5_000L })

        val resolution = resolver.resolve(plan())

        assertTrue(resolution is RelayIngressResolution.NotProvisioned)
        assertEquals(RelayFailureCategory.PROFILE_EXPIRED, (resolution as RelayIngressResolution.NotProvisioned).category)
    }

    @Test
    fun `a profile stored for a DIFFERENT ingress endpoint id never satisfies THIS plan - endpoint-scoped, never cross-endpoint reuse`() = runTest {
        val store = InMemoryIngressProfileStore()
        store.saveProfile(
            IngressClientProfile(
                ingressEndpointId = EndpointId("some-other-ingress"),
                ingressBinding = pinnedBinding,
                transport = TransportKind.XRAY_REALITY,
                realityProfile = realityProfile(pinnedBinding.host, pinnedBinding.port),
                profileVersion = 1,
                issuedAtEpochMillis = 1_000L,
            ),
        )
        val resolver = newResolver(store)

        val resolution = resolver.resolve(plan())

        assertTrue(resolution is RelayIngressResolution.NotProvisioned)
        assertEquals(RelayFailureCategory.PROFILE_NOT_PROVISIONED, (resolution as RelayIngressResolution.NotProvisioned).category)
    }
}
