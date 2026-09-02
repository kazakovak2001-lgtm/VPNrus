@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.IngressProfileResult
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.IngressProfileProvisioner
import net.pocvpn.client.relay.InMemoryIngressProfileStore
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressResolution
import net.pocvpn.client.relay.RelayIngressResolver
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayAutoModeStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val USABLE_WIFI = net.pocvpn.client.network.NetworkProfile(
    type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
    roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
    vpnActive = false, generation = 1,
)

private class RelayActivationAlwaysAutoModeStore : GatewayAutoModeStore {
    override fun read(): Boolean = true
    override fun write(auto: Boolean) {}
}

/** A resolver stub keyed by ingress endpoint id, so a two-candidate test can give each its own scripted resolution. */
private class RelayActivationStubResolver(private val resolutionFor: (RelayedExecutionPlan) -> RelayIngressResolution) : RelayIngressResolver {
    val resolvedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        resolvedPlans += plan
        return resolutionFor(plan)
    }
}

/**
 * B26 review fix (round 2, blocker) - proves the real PAUSE/RESUME/RETRY
 * design: a relayed Auto attempt that hits an activation-fixable
 * [RelayFailureCategory] PAUSES the combined sequence (never advances via
 * [MainViewModel] internal `attemptCombined` while a prompt is pending -
 * task requirement G), storing the FULL resume context so a successful
 * activation retries the BYTE-FOR-BYTE IDENTICAL candidate exactly once
 * (task requirement B/C/D), and any other outcome (failure, or the user
 * dismissing) resumes the ORIGINAL combined attempt list/budget exactly
 * once, never a freshly re-ranked one (task requirement E/F/H).
 *
 * Uses [MainViewModel.attemptRelayedAttempt] directly (now `internal`, not
 * `private` - see its own docs) with a hand-built
 * [AutoGatewaySelector.RelayAttemptCandidate] rather than going through
 * the full [MainViewModel.combinedAutoAttempts]/`connect()` ranking
 * pipeline: a genuinely ELIGIBLE XRAY_REALITY/TLS_TCP relayed candidate
 * cannot be produced through that pipeline in this test harness
 * (`isXrayAvailableFor` is hardcoded to the Germany/Stockholm production
 * endpoints only - see `buildTransportRegistry`'s own init-time wiring),
 * and [net.pocvpn.client.relay.IngressProfileProvisioner] only ever
 * supports XRAY_REALITY/TLS_TCP - this is the real, meaningful transport
 * combination task D/E's own tests need, not a stand-in.
 */
class MainViewModelRelayActivationTest {

    private val testDispatcher = StandardTestDispatcher()
    private val ingressIdA = EndpointId("ru-ingress-a")
    private val ingressIdB = EndpointId("ru-ingress-b")
    private val exitId = EndpointId("frankfurt")
    private val bindingA = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 8443)
    private val bindingB = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.60", 8443)
    private val exitBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 8443)

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun candidate(
        ingressId: EndpointId = ingressIdA,
        ingressBinding: EndpointTransportBinding = bindingA,
        ingressKind: IngressKind = IngressKind.DIRECT_IP,
    ) = AutoGatewaySelector.RelayAttemptCandidate(
        ingressEndpointId = ingressId,
        exitEndpointId = exitId,
        ingressTransport = TransportKind.XRAY_REALITY,
        exitTransport = TransportKind.XRAY_REALITY,
        ingressBinding = ingressBinding,
        exitBinding = exitBinding,
        ingressKind = ingressKind,
        ingressRegion = "ru",
        exitRegion = "de",
        score = 1_000L,
        reasons = listOf("test"),
        // B27 review fix - kind-aware, matching PathCandidate.Relayed
        // .historyPathId's own real format exactly (never a stand-in that
        // could hide a kind-conflation bug in these tests).
        historyPathId = "${ingressId.value}:$ingressKind:XRAY_REALITY->frankfurt:XRAY_REALITY",
    )

    private fun asAttempt(c: AutoGatewaySelector.RelayAttemptCandidate) = AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt(c)

    private fun newViewModel(
        transport: VpnTransport = FakeVpnTransport(),
        relayIngressResolver: RelayIngressResolver,
        ingressProfileProvisioner: IngressProfileProvisioner? = null,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        gatewayAutoModeStore = RelayActivationAlwaysAutoModeStore(),
        initialNetworkProfile = USABLE_WIFI,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        relayIngressResolver = relayIngressResolver,
        ingressProfileProvisioner = ingressProfileProvisioner,
        ioDispatcher = testDispatcher,
    )

    private fun successResult(
        serverAddress: String = bindingA.host,
        serverPort: Int = bindingA.port,
        ingressEndpointId: String = ingressIdA.value,
        ingressKind: IngressKind = IngressKind.DIRECT_IP,
    ) = IngressProfileResult.Success(
        ingressEndpointId = ingressEndpointId,
        ingressKind = ingressKind,
        serverAddress = serverAddress,
        serverPort = serverPort,
        uuid = "11111111-1111-1111-1111-111111111111",
        serverName = "example.com",
        fingerprint = "chrome",
        flow = "",
        realityPublicKey = "A".repeat(43),
        shortId = "ab",
        isRealityShaped = true,
        profileVersion = 1,
        issuedAtEpochSeconds = 1_000L,
        expiresAtEpochSeconds = null,
        probeUrl = "https://exit.example/v1/relay-health",
        probeToken = "test-token",
    )

    // --- A/G: first encounter with a fixable category PAUSES - no auto-advance ---

    @Test
    fun `PROFILE_NOT_PROVISIONED pauses and surfaces a prompt carrying byte-for-byte the pinned facts - no other candidate starts`() = runTest {
        val candA = candidate()
        val candB = candidate(ingressIdB, bindingB)
        val resolver = RelayActivationStubResolver { plan ->
            if (plan.ingressEndpointId == ingressIdA) RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED)
            else RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val viewModel = newViewModel(relayIngressResolver = resolver)
        val attempts = listOf(asAttempt(candA), asAttempt(candB))

        viewModel.attemptRelayedAttempt(candA, attempts, setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()

        val request = viewModel.relayActivationNeeded.value
        assertNotNull(request)
        assertEquals(ingressIdA, request!!.ingressEndpointId)
        assertEquals(bindingA, request.ingressBinding)
        assertEquals(TransportKind.XRAY_REALITY, request.ingressTransport)
        // G: candidate B (still in `attempts`, not yet attempted) is never
        // touched while the prompt is pending - attemptCombined never ran.
        assertEquals(1, resolver.resolvedPlans.size)
    }

    @Test
    fun `PROFILE_EXPIRED and PROFILE_MISMATCH also pause`() = runTest {
        for (category in listOf(RelayFailureCategory.PROFILE_EXPIRED, RelayFailureCategory.PROFILE_MISMATCH)) {
            val candA = candidate()
            val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(category) }
            val viewModel = newViewModel(relayIngressResolver = resolver)
            viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
            testDispatcher.scheduler.runCurrent()
            assertNotNull("category $category must pause with a prompt", viewModel.relayActivationNeeded.value)
        }
    }

    @Test
    fun `a category no activation can fix never pauses - the combined sequence advances immediately`() = runTest {
        for (category in listOf(
            RelayFailureCategory.INGRESS_UNREACHABLE,
            RelayFailureCategory.RELAY_AUTH_FAILED,
            RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
        )) {
            val candA = candidate()
            val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(category) }
            val viewModel = newViewModel(relayIngressResolver = resolver)
            viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
            testDispatcher.scheduler.runCurrent()
            assertNull("category $category must never pause/prompt", viewModel.relayActivationNeeded.value)
            // attemptCombined ran immediately (exhausted, only one candidate, already attempted).
            assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
        }
    }

    // --- B/C/D: successful activation retries the SAME candidate exactly once, no re-ranking ---

    @Test
    fun `successful activation retries the byte-for-byte identical candidate exactly once`() = runTest {
        val candA = candidate()
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> fetchCount++; successResult() })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)

        viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertEquals(1, resolver.resolvedPlans.size)

        viewModel.activateIngress("real-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Saved)
        assertNotNull("the profile must be persisted", store.getProfileOrNull(ingressIdA))
        assertEquals(1, fetchCount)
        // D: exactly ONE additional resolve() call - the bounded retry.
        assertEquals(2, resolver.resolvedPlans.size)
        // B/C: the retry resolved the EXACT SAME plan (same historyPathId,
        // same bindings/transport) - never rebuilt/re-ranked.
        assertEquals(resolver.resolvedPlans[0], resolver.resolvedPlans[1])
    }

    @Test
    fun `activation retry preserves the exact pinned CDN_FRONTED candidate - never silently downgraded to DIRECT_IP or re-ranked`() = runTest {
        val candA = candidate(ingressKind = IngressKind.CDN_FRONTED)
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(ingressKind = IngressKind.CDN_FRONTED) })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)

        viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        val request = viewModel.relayActivationNeeded.value
        assertNotNull(request)
        assertEquals(IngressKind.CDN_FRONTED, request!!.ingressKind)

        viewModel.activateIngress("real-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Saved)
        val saved = store.getProfileOrNull(ingressIdA)
        assertEquals("the persisted profile must keep the pinned CDN_FRONTED kind", IngressKind.CDN_FRONTED, saved?.ingressKind)
        assertEquals(2, resolver.resolvedPlans.size)
        assertEquals(IngressKind.CDN_FRONTED, resolver.resolvedPlans[0].ingressKind)
        // Requirement 4: the retry keeps the IDENTICAL kind-aware
        // historyPathId - never re-ranked into a different (endpoint,
        // kind, transport) identity.
        assertEquals(candA.historyPathId, resolver.resolvedPlans[0].historyPathId)
        assertEquals(candA.historyPathId, resolver.resolvedPlans[1].historyPathId)
        assertTrue(candA.historyPathId.contains(":CDN_FRONTED:"))
        assertEquals(IngressKind.CDN_FRONTED, resolver.resolvedPlans[1].ingressKind)
    }

    @Test
    fun `if the bounded retry itself still fails, it never pauses again - the combined sequence just resumes`() = runTest {
        val candA = candidate()
        val candB = candidate(ingressIdB, bindingB)
        // A resolves NotProvisioned every time (even after "activation");
        // the retry must not re-pause despite this still being a fixable category.
        val resolver = RelayActivationStubResolver { plan ->
            if (plan.ingressEndpointId == ingressIdA) RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED)
            else RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult() })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        val attempts = listOf(asAttempt(candA), asAttempt(candB))

        viewModel.attemptRelayedAttempt(candA, attempts, setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)

        viewModel.activateIngress("real-credential")
        testDispatcher.scheduler.runCurrent()

        // The retry (2nd resolvedPlans entry) failed again, but did not
        // re-pause: it resumed the ORIGINAL combined list/budget, which
        // then attempted candidate B (3rd entry) - never a THIRD attempt
        // at A.
        assertNull("must not pause a second time for the same candidate", viewModel.relayActivationNeeded.value)
        assertEquals(3, resolver.resolvedPlans.size)
        assertEquals(ingressIdA, resolver.resolvedPlans[0].ingressEndpointId)
        assertEquals(ingressIdA, resolver.resolvedPlans[1].ingressEndpointId)
        assertEquals(ingressIdB, resolver.resolvedPlans[2].ingressEndpointId)
    }

    // --- E/F: dismiss resumes the ORIGINAL combined list/budget, never a fresh ranking ---

    @Test
    fun `dismissing the prompt never retries the paused candidate and resumes the original list to the next candidate exactly once`() = runTest {
        val candA = candidate()
        val candB = candidate(ingressIdB, bindingB)
        val resolver = RelayActivationStubResolver { plan ->
            if (plan.ingressEndpointId == ingressIdA) RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED)
            else RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val viewModel = newViewModel(relayIngressResolver = resolver)
        val attempts = listOf(asAttempt(candA), asAttempt(candB))

        viewModel.attemptRelayedAttempt(candA, attempts, setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertEquals(1, resolver.resolvedPlans.size)

        viewModel.dismissRelayActivationPrompt()
        testDispatcher.scheduler.runCurrent()

        assertNull(viewModel.relayActivationNeeded.value)
        // A was never retried; the ORIGINAL list/budget resumed straight to
        // B (the only other, still-unattempted candidate in `attempts`) -
        // never a freshly rebuilt/re-ranked list, and never a second A.
        assertEquals(2, resolver.resolvedPlans.size)
        assertEquals(ingressIdA, resolver.resolvedPlans[0].ingressEndpointId)
        assertEquals(ingressIdB, resolver.resolvedPlans[1].ingressEndpointId)
    }

    // --- H: unauthorized/revoked activation fails closed and resumes exactly once ---

    @Test
    fun `unauthorized activation credential fails closed, never persists, never retries A, and resumes to B exactly once`() = runTest {
        val candA = candidate()
        val candB = candidate(ingressIdB, bindingB)
        val resolver = RelayActivationStubResolver { plan ->
            if (plan.ingressEndpointId == ingressIdA) RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED)
            else RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> IngressProfileResult.Unauthorized })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        val attempts = listOf(asAttempt(candA), asAttempt(candB))

        viewModel.attemptRelayedAttempt(candA, attempts, setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)

        viewModel.activateIngress("bad-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(IngressActivationOutcome.AuthorizationFailed, viewModel.ingressActivationState.value)
        assertNull("fails closed: the prompt must be cleared, not left standing", viewModel.relayActivationNeeded.value)
        assertNull(store.getProfileOrNull(ingressIdA))
        // A was never retried (no usable profile) - the original list/budget
        // resumed straight to B exactly once.
        assertEquals(2, resolver.resolvedPlans.size)
        assertEquals(ingressIdA, resolver.resolvedPlans[0].ingressEndpointId)
        assertEquals(ingressIdB, resolver.resolvedPlans[1].ingressEndpointId)
    }

    @Test
    fun `activateIngress with nothing pending is a safe no-op`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val viewModel = newViewModel(relayIngressResolver = resolver)

        viewModel.activateIngress("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(IngressActivationOutcome.Unavailable, viewModel.ingressActivationState.value)
        assertEquals(0, resolver.resolvedPlans.size)
    }

    // --- Mismatch is never persisted, and still resumes closed like any other non-Saved outcome ---

    @Test
    fun `a response naming a different server address is rejected as Mismatched, never persisted, and still resumes`() = runTest {
        val candA = candidate()
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult(serverAddress = "198.51.100.99") })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)

        viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()

        viewModel.activateIngress("real-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Mismatched)
        assertNull("a mismatched response must never be persisted", store.getProfileOrNull(ingressIdA))
        assertNull(viewModel.relayActivationNeeded.value)
    }

    // --- B26 review fix (round 3, blocker) - atomic single-owner claim of PendingRelayActivation ---

    @Test
    fun `two activateIngress calls before the first provisioning completes - only the first claims, provisions, and retries`() = runTest {
        val candA = candidate()
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> fetchCount++; successResult() })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)

        viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertEquals(1, resolver.resolvedPlans.size)

        // Two calls back to back, BEFORE the first call's provisioning
        // coroutine has run at all (StandardTestDispatcher queues work,
        // it does not execute inline) - the synchronous claim inside
        // activateIngress() means the second call observes the pending
        // context already gone, strictly before either coroutine body runs.
        viewModel.activateIngress("real-credential")
        viewModel.activateIngress("real-credential")
        // The prompt is already gone the instant the FIRST call claimed it -
        // synchronously, before any suspension - never left standing for a
        // second caller to also observe as "pending".
        assertNull(viewModel.relayActivationNeeded.value)

        testDispatcher.scheduler.runCurrent()

        // Exactly ONE provisioning request (the second call's own early
        // "nothing pending" branch never calls the provisioner at all) and
        // exactly ONE retry of A (never two).
        assertEquals(1, fetchCount)
        assertEquals(2, resolver.resolvedPlans.size)
        assertEquals(candA.historyPathId, resolver.resolvedPlans[0].historyPathId)
        assertEquals(candA.historyPathId, resolver.resolvedPlans[1].historyPathId)
        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Saved)
    }

    @Test
    fun `dismiss while an activation is already in flight is a no-op - the in-flight activation is the sole resumer`() = runTest {
        val candA = candidate()
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult() })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)

        viewModel.attemptRelayedAttempt(candA, listOf(asAttempt(candA)), setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, resolver.resolvedPlans.size)

        // Claims the pending context and queues its provisioning coroutine -
        // NOT yet run.
        viewModel.activateIngress("real-credential")
        // Races in before the queued coroutine runs - must observe nothing
        // left to claim, and must NOT independently resume anything.
        viewModel.dismissRelayActivationPrompt()
        assertNull(viewModel.relayActivationNeeded.value)

        testDispatcher.scheduler.runCurrent()

        // The in-flight activation is the ONLY thing that ever resumes this
        // candidate - exactly one retry, never a second (dismiss-triggered)
        // resume racing it.
        assertEquals(2, resolver.resolvedPlans.size)
        assertEquals(candA.historyPathId, resolver.resolvedPlans[1].historyPathId)
        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Saved)
    }

    @Test
    fun `activateIngress then immediate dismiss then a real connect retry never resumes the same candidate twice - even with a second, later candidate available`() = runTest {
        val candA = candidate()
        val candB = candidate(ingressIdB, bindingB)
        val resolver = RelayActivationStubResolver { plan ->
            if (plan.ingressEndpointId == ingressIdA) RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED)
            else RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> successResult() })
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        val attempts = listOf(asAttempt(candA), asAttempt(candB))

        viewModel.attemptRelayedAttempt(candA, attempts, setOf(candA.historyPathId))
        testDispatcher.scheduler.runCurrent()

        viewModel.activateIngress("real-credential")
        viewModel.dismissRelayActivationPrompt() // no-op: already claimed by the activation above
        testDispatcher.scheduler.runCurrent()

        // A was resolved exactly twice (initial + the one bounded retry,
        // both from the SAME activation call) - dismiss contributed no
        // resume of its own, so B is reached exactly once, as the natural
        // next candidate in the ORIGINAL combined list after A's retry
        // consumed its budget - never a duplicate/concurrent progression.
        val aResolves = resolver.resolvedPlans.count { it.ingressEndpointId == ingressIdA }
        val bResolves = resolver.resolvedPlans.count { it.ingressEndpointId == ingressIdB }
        assertEquals(2, aResolves)
        assertEquals(1, bResolves)
        assertEquals(3, resolver.resolvedPlans.size)
    }
}
