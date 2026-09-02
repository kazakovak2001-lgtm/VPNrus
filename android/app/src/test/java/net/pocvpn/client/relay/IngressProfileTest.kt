package net.pocvpn.client.relay

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

private fun realityPlan(ingressId: String = "ru-ingress-1") = RelayedExecutionPlan(
    ingressEndpointId = EndpointId(ingressId),
    ingressBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 443),
    ingressTransport = TransportKind.XRAY_REALITY,
    exitEndpointId = EndpointId("germany"),
    exitBinding = EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.60", 51820),
    exitTransport = TransportKind.AMNEZIA_WG,
    historyPathId = "$ingressId:XRAY_REALITY->germany:AMNEZIA_WG",
)

/** B25 (task E/M#7/M#9/M#10) - [IngressClientProfile]'s own matching/expiry/serialization contract. */
class IngressClientProfileTest {

    @Test
    fun `matches is true only for the exact same ingress endpoint, binding, and transport`() {
        val plan = realityPlan()
        val profile = fakeIngressClientProfile(plan)
        assertTrue(profile.matches(plan))

        val differentEndpoint = plan.copy(ingressEndpointId = EndpointId("different-ingress"))
        assertFalse(profile.matches(differentEndpoint))

        val differentBinding = plan.copy(ingressBinding = plan.ingressBinding.copy(port = 8443))
        assertFalse(profile.matches(differentBinding))

        val differentTransport = plan.copy(ingressTransport = TransportKind.TLS_TCP)
        assertFalse(profile.matches(differentTransport))
    }

    @Test
    fun `isExpired is false with no expiry and true only once now has reached expiresAtEpochMillis`() {
        val plan = realityPlan()
        val noExpiry = fakeIngressClientProfile(plan, expiresAtEpochMillis = null)
        assertFalse(noExpiry.isExpired(Long.MAX_VALUE))

        val expiring = fakeIngressClientProfile(plan, expiresAtEpochMillis = 1_000L)
        assertFalse(expiring.isExpired(999L))
        assertTrue(expiring.isExpired(1_000L))
        assertTrue(expiring.isExpired(1_001L))
    }

    @Test
    fun `toJson-fromJson round-trips every field exactly, including the binding and probe coordinates`() {
        val plan = realityPlan()
        val profile = fakeIngressClientProfile(
            plan,
            profileVersion = 3,
            issuedAtEpochMillis = 111L,
            expiresAtEpochMillis = 222L,
            endToEndProbeUrl = "https://exit.example/v1/relay-health",
            endToEndProbeToken = "secret-token",
        )
        val restored = IngressClientProfile.fromJson(profile.toJson())
        assertEquals(profile, restored)
    }

    @Test
    fun `toJson-fromJson round-trips a TLS profile with no realityProfile`() {
        val plan = realityPlan().copy(
            ingressBinding = EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.50", 443),
            ingressTransport = TransportKind.TLS_TCP,
        )
        val profile = fakeIngressClientProfile(plan)
        assertNull(profile.realityProfile)
        val restored = IngressClientProfile.fromJson(profile.toJson())
        assertEquals(profile, restored)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `toJson refuses a structurally inconsistent profile (transport without a matching credential)`() {
        val plan = realityPlan()
        IngressClientProfile(
            ingressEndpointId = plan.ingressEndpointId,
            ingressBinding = plan.ingressBinding,
            transport = TransportKind.XRAY_REALITY,
            realityProfile = null,
            tlsProfile = null,
            profileVersion = 1,
            issuedAtEpochMillis = 0L,
        ).toJson()
    }
}

/** B25 (task E) - [FileIngressProfileStore]'s encrypted-at-rest, per-endpoint-scoped persistence. */
class FileIngressProfileStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun `a saved profile round-trips exactly for its own endpoint and is absent for a different one`() = runTest {
        val store = FileIngressProfileStore(tmp.newFolder(), FakeAesGcmKeyEncryptor())
        val planA = realityPlan("ingress-a")
        val planB = realityPlan("ingress-b")
        val profileA = fakeIngressClientProfile(planA)

        assertNull(store.getProfileOrNull(planA.ingressEndpointId))
        store.saveProfile(profileA)
        assertEquals(profileA, store.getProfileOrNull(planA.ingressEndpointId))
        assertNull("a profile saved for one ingress endpoint must never be visible under a different one", store.getProfileOrNull(planB.ingressEndpointId))
    }

    @Test
    fun `clearProfile removes exactly the targeted endpoint's profile`() = runTest {
        val store = FileIngressProfileStore(tmp.newFolder(), FakeAesGcmKeyEncryptor())
        val plan = realityPlan()
        store.saveProfile(fakeIngressClientProfile(plan))
        store.clearProfile(plan.ingressEndpointId)
        assertNull(store.getProfileOrNull(plan.ingressEndpointId))
    }
}
