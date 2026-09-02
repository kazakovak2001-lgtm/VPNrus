package net.pocvpn.client.relay

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.provisioning.IngressProfileResult
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B26 (task D/E) / review fix (blocker 1) - IngressProfileProvisioner's own
 * unit-level contract: cross-checks the server response against the
 * caller's pinned endpoint/binding/transport (never uses a mismatched
 * response), and [IngressProfileProvisioner.ensureFreshProfile]'s bounded
 * refresh policy (reuse a still-valid profile, otherwise exactly one
 * network attempt).
 */
class IngressProfileProvisionerTest {

    private val endpointId = EndpointId("ru-ingress-1")
    private val binding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 8443)

    private fun successResult(
        ingressEndpointId: String = endpointId.value,
        ingressKind: IngressKind = IngressKind.DIRECT_IP,
        serverAddress: String = binding.host,
        serverPort: Int = binding.port,
        isRealityShaped: Boolean = true,
        expiresAtEpochSeconds: Long? = null,
    ) = IngressProfileResult.Success(
        ingressEndpointId = ingressEndpointId,
        ingressKind = ingressKind,
        serverAddress = serverAddress,
        serverPort = serverPort,
        uuid = "11111111-1111-1111-1111-111111111111",
        serverName = "example.com",
        fingerprint = "chrome",
        flow = if (isRealityShaped) "" else null,
        realityPublicKey = if (isRealityShaped) "A".repeat(43) else null,
        shortId = if (isRealityShaped) "ab" else null,
        isRealityShaped = isRealityShaped,
        profileVersion = 1,
        issuedAtEpochSeconds = 1_000L,
        expiresAtEpochSeconds = expiresAtEpochSeconds,
        probeUrl = "https://exit.example/v1/relay-health",
        probeToken = "test-token",
    )

    @Test
    fun `a valid matching response is persisted with the CALLER's pinned binding, never a response-derived one`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult() })

        val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        val saved = store.getProfileOrNull(endpointId)
        assertEquals(binding, saved?.ingressBinding)
    }

    @Test
    fun `a response naming a different endpoint id is rejected as Mismatched and never persisted`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(ingressEndpointId = "some-other-ingress") })

        val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Mismatched)
        assertNull(store.getProfileOrNull(endpointId))
    }

    @Test
    fun `a response naming a different server host or port is rejected as Mismatched and never persisted`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(serverAddress = "198.51.100.1") })

        val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Mismatched)
        assertNull(store.getProfileOrNull(endpointId))
    }

    @Test
    fun `a TLS-shaped response requested for REALITY is rejected as Mismatched`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(isRealityShaped = false) })

        val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Mismatched)
        assertNull(store.getProfileOrNull(endpointId))
    }

    @Test
    fun `unauthorized, revoked, and expired all fail closed without persisting anything`() = runBlocking {
        for (result in listOf(IngressProfileResult.Unauthorized, IngressProfileResult.Revoked, IngressProfileResult.Expired, IngressProfileResult.DeviceNotBound)) {
            val store = InMemoryIngressProfileStore()
            val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> result })

            val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

            assertTrue("expected AuthorizationFailed for $result", outcome is IngressActivationOutcome.AuthorizationFailed)
            assertNull(store.getProfileOrNull(endpointId))
        }
    }

    @Test
    fun `AMNEZIA_WG ingress transport is rejected as unsupported - never a fabricated profile for a transport this provisioner cannot fetch`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        var called = false
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> called = true; successResult() })

        val outcome = provisioner.provision(endpointId, binding, TransportKind.AMNEZIA_WG, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.UnsupportedTransport)
        assertTrue("must fail before ever making a network call", !called)
    }

    // --- ensureFreshProfile: the bounded refresh policy (task E) ---

    @Test
    fun `ensureFreshProfile reuses a still-valid stored profile without any network call`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(
            store, fetchIngressProfile = { _, _, _, _ -> fetchCount++; successResult(expiresAtEpochSeconds = 10_000L) },
            nowProvider = { 5_000_000L }, // 5_000s, well before the 10_000s expiry above
        )
        // Prime the store with an already-valid profile via one real provision() call.
        provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")
        assertEquals(1, fetchCount)

        val outcome = provisioner.ensureFreshProfile(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        assertEquals("a still-valid profile must never trigger a second network call", 1, fetchCount)
    }

    @Test
    fun `ensureFreshProfile makes exactly ONE network attempt when nothing valid is stored`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> fetchCount++; successResult() })

        val outcome = provisioner.ensureFreshProfile(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        assertEquals(1, fetchCount)
    }

    @Test
    fun `ensureFreshProfile refreshes exactly once when the stored profile has expired`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        var nowMillis = 1_000L
        val provisioner = IngressProfileProvisioner(
            store, fetchIngressProfile = { _, _, _, _ -> fetchCount++; successResult(expiresAtEpochSeconds = 2L) }, // expires at 2000ms
            nowProvider = { nowMillis },
        )
        provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")
        assertEquals(1, fetchCount)

        nowMillis = 3_000L // now past the 2000ms expiry
        val outcome = provisioner.ensureFreshProfile(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        assertEquals("an expired profile must trigger exactly one refresh, never zero and never more than one", 2, fetchCount)
    }

    // --- B27: ingress-kind cross-check (frontend/origin/backend confusion must fail closed) ---

    @Test
    fun `a response declaring a different ingress kind than pinned is rejected as Mismatched and never persisted`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(ingressKind = IngressKind.CDN_FRONTED) })

        // The CALLER pins DIRECT_IP (e.g. from a manifest-derived candidate)
        // but the server claims CDN_FRONTED - exactly the frontend/origin/
        // backend confusion that must fail closed, never silently accepted
        // just because host/port/endpoint id all still match.
        val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Mismatched)
        assertNull(store.getProfileOrNull(endpointId))
    }

    @Test
    fun `a genuinely CDN_FRONTED pinned candidate is saved when the server agrees`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(ingressKind = IngressKind.CDN_FRONTED) })

        val outcome = provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.CDN_FRONTED, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        assertEquals(IngressKind.CDN_FRONTED, store.getProfileOrNull(endpointId)?.ingressKind)
    }

    @Test
    fun `ensureFreshProfile refreshes when only the pinned ingress kind changed - a stale DIRECT_IP profile is never reused for a CDN_FRONTED pin`() = runBlocking {
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(
            store,
            fetchIngressProfile = { _, _, _, _ ->
                fetchCount++
                // Always answers with whatever kind was actually requested -
                // a real server would too, since the pinned host/port IS
                // that specific ingress deployment's own configured kind.
                successResult(ingressKind = if (fetchCount == 1) IngressKind.DIRECT_IP else IngressKind.CDN_FRONTED)
            },
        )
        provisioner.provision(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.DIRECT_IP, "pubkey", "cred")
        assertEquals(1, fetchCount)

        val outcome = provisioner.ensureFreshProfile(endpointId, binding, TransportKind.XRAY_REALITY, IngressKind.CDN_FRONTED, "pubkey", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        assertEquals("a kind change must trigger a fresh fetch, never reuse the stale DIRECT_IP profile", 2, fetchCount)
    }
}
