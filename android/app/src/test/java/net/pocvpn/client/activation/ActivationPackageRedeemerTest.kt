package net.pocvpn.client.activation

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * B56-5 - package -> EXISTING activation flow. [activate] stands in for
 * MainViewModel.activateDevice; these tests prove what reaches it (and
 * what never does), network-down behaviour, and replay marking.
 */
class ActivationPackageRedeemerTest {
    @get:Rule val tmp = TemporaryFolder()
    private lateinit var f: ActivationPackageFixtures
    private lateinit var guardDir: File
    private var now = 0L
    private val activated = mutableListOf<String>()
    private val states = mutableListOf<ActivationPackageUiState>()

    @Before fun setUp() {
        f = ActivationPackageFixtures(tmp.newFolder())
        now = f.now
        guardDir = tmp.newFolder()
    }

    private fun redeemer() = ActivationPackageRedeemer(f.importer(FileActivationReplayGuard(guardDir)), { now }, Dispatchers.Unconfined)

    /** Every fixture envelope carries no hints (EntitlementScope.Unscoped) - always eligible for the caller's own explicit target. */
    private val alwaysEligible: (EntitlementScope) -> GatewayEligibilityResult = {
        GatewayEligibilityResult.Eligible(listOf(ProductionGatewayId.GERMANY))
    }

    private fun activateWith(outcome: ActivationAttemptOutcome): suspend (String, List<ProductionGatewayId>) -> ActivationAttemptOutcome = { credential, _ ->
        activated += credential
        outcome
    }

    private fun redeem(r: ActivationPackageRedeemer, text: String, outcome: ActivationAttemptOutcome) =
        runBlocking { r.redeem(ActivationPackageInput.Text(text), { states += it }, alwaysEligible, activateWith(outcome)) }

    @Test fun `valid package reaches the existing activation flow with exactly the envelope credential`() {
        redeem(redeemer(), f.packageText(), ActivationAttemptOutcome.SUCCEEDED)
        assertEquals(listOf(f.credential), activated)
        assertEquals(
            listOf(
                ActivationPackageUiState.Verifying,
                ActivationPackageUiState.Activating(BootstrapStagingStatus.NOT_INCLUDED),
                ActivationPackageUiState.Succeeded(BootstrapStagingStatus.NOT_INCLUDED),
            ),
            states,
        )
    }

    @Test fun `invalid, expired, unknown-issuer and malformed packages never reach activation`() {
        val r = redeemer()
        val cases = mapOf(
            f.packageText(key = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(java.security.SecureRandom())) to ActivationPackageRejectionKind.SIGNATURE_INVALID,
            f.packageText(f.envelope(notBefore = now - 10_000L, expiresAt = now)) to ActivationPackageRejectionKind.EXPIRED,
            f.packageText(f.envelope(keyId = ActivationIssuerKeyId("nope"))) to ActivationPackageRejectionKind.ISSUER_UNKNOWN,
            "nova-activation:1:AAAA" to ActivationPackageRejectionKind.PACKAGE_MALFORMED,
        )
        for ((text, kind) in cases) {
            states.clear()
            redeem(r, text, ActivationAttemptOutcome.SUCCEEDED)
            assertEquals(ActivationPackageUiState.Rejected(kind), states.last())
        }
        assertTrue(activated.isEmpty())
        assertFalse(r.hasPending)
    }

    @Test fun `replayed package is rejected after a successful redemption, across restarts`() {
        redeem(redeemer(), f.packageText(), ActivationAttemptOutcome.SUCCEEDED)
        activated.clear()
        redeem(redeemer(), f.packageText(), ActivationAttemptOutcome.SUCCEEDED) // fresh instance, same guard dir
        assertEquals(ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.ALREADY_REDEEMED), states.last())
        assertTrue(activated.isEmpty())
    }

    @Test fun `failed or network-failed activation does not mark the envelope redeemed`() {
        redeem(redeemer(), f.packageText(), ActivationAttemptOutcome.FAILED)
        assertEquals(ActivationPackageUiState.ActivationFailed, states.last())
        redeem(redeemer(), f.packageText(), ActivationAttemptOutcome.NETWORK_UNAVAILABLE)
        assertEquals(ActivationPackageUiState.NetworkRequired(BootstrapStagingStatus.NOT_INCLUDED), states.last())
        assertEquals(2, activated.size)
    }

    @Test fun `network down with a bundled bootstrap - bundle staged offline, activation completes on retry`() {
        val bundle = f.bundleBytes(2)
        val text = f.packageText(f.envelope(bundleRef = f.refFor(bundle, 2)), bundle)
        val r = redeemer()
        redeem(r, text, ActivationAttemptOutcome.NETWORK_UNAVAILABLE)
        assertEquals(ActivationPackageUiState.NetworkRequired(BootstrapStagingStatus.STAGED), states.last())
        assertEquals(2, f.repository.trusted()!!.manifestVersion) // staged with no network at all
        assertTrue(r.hasPending)

        val retried = runBlocking { r.retry({ states += it }, alwaysEligible, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
        assertTrue(retried)
        assertEquals(ActivationPackageUiState.Succeeded(BootstrapStagingStatus.STAGED), states.last())
        assertFalse(r.hasPending)
        assertEquals(listOf(f.credential, f.credential), activated)
    }

    @Test fun `network down without bootstrap data reports NetworkRequired with NOT_INCLUDED, never a fake offline success`() {
        redeem(redeemer(), f.packageText(), ActivationAttemptOutcome.NETWORK_UNAVAILABLE)
        assertEquals(ActivationPackageUiState.NetworkRequired(BootstrapStagingStatus.NOT_INCLUDED), states.last())
    }

    @Test fun `pending package that expires while waiting for network is rejected on retry without activating`() {
        val r = redeemer()
        redeem(r, f.packageText(f.envelope(expiresAt = now + 60_000L)), ActivationAttemptOutcome.NETWORK_UNAVAILABLE)
        activated.clear()
        now += 60_000L
        runBlocking { r.retry({ states += it }, alwaysEligible, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
        assertEquals(ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.EXPIRED), states.last())
        assertTrue(activated.isEmpty())
        assertFalse(r.hasPending)
    }

    @Test fun `retry with nothing pending does nothing`() {
        assertFalse(runBlocking { redeemer().retry({ states += it }, alwaysEligible, activateWith(ActivationAttemptOutcome.SUCCEEDED)) })
        assertTrue(activated.isEmpty() && states.isEmpty())
    }

    @Test fun `offline parse and verification need no network at all`() {
        // Nothing in import touches the network: the only dependency is the local manifest repository.
        val result = f.importer().import(ActivationPackageInput.Text(f.packageText()), now)
        assertTrue(result is ActivationPackageImportResult.Verified)
    }

    // --- B67.6: entitlement-aware gateway eligibility, checked before activate() ---

    @Test fun `a gateway-ineligible envelope is rejected before ever reaching activate`() {
        val denied: (EntitlementScope) -> GatewayEligibilityResult = {
            GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_HINTED_ENDPOINT_TRUSTED)
        }
        val text = f.packageText(f.envelope(hints = listOf(net.pocvpn.client.reachability.EndpointId("stockholm"))))
        runBlocking { redeemer().redeem(ActivationPackageInput.Text(text), { states += it }, denied, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
        assertEquals(ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.GATEWAY_NOT_ELIGIBLE), states.last())
        assertTrue(activated.isEmpty())
        assertFalse(redeemer().hasPending)
    }

    @Test fun `resolveEligibility receives Unscoped for an envelope with no hints, and Hinted for one with hints`() {
        val observedScopes = mutableListOf<EntitlementScope>()
        val capture: (EntitlementScope) -> GatewayEligibilityResult = {
            observedScopes += it
            GatewayEligibilityResult.Eligible(listOf(ProductionGatewayId.GERMANY))
        }
        // Independent, freshly-scoped replay guards - two DIFFERENT envelopes
        // redeemed once each, never a replay of the same activationId.
        val unscopedRedeemer = ActivationPackageRedeemer(f.importer(InMemoryActivationReplayGuard()), { now }, Dispatchers.Unconfined)
        runBlocking {
            unscopedRedeemer.redeem(ActivationPackageInput.Text(f.packageText()), { }, capture, activateWith(ActivationAttemptOutcome.SUCCEEDED))
        }
        assertEquals(listOf(EntitlementScope.Unscoped), observedScopes)

        observedScopes.clear()
        val hinted = listOf(net.pocvpn.client.reachability.EndpointId("frankfurt"))
        val hintedRedeemer = ActivationPackageRedeemer(f.importer(InMemoryActivationReplayGuard()), { now }, Dispatchers.Unconfined)
        runBlocking {
            hintedRedeemer.redeem(
                ActivationPackageInput.Text(f.packageText(f.envelope(hints = hinted))),
                { },
                capture,
                activateWith(ActivationAttemptOutcome.SUCCEEDED),
            )
        }
        assertEquals(listOf(EntitlementScope.Hinted(hinted)), observedScopes)
    }

    @Test fun `an eligibility denial never marks the envelope redeemed - the same package can still be re-attempted`() {
        val denied: (EntitlementScope) -> GatewayEligibilityResult = {
            GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_TRUSTED_MANIFEST)
        }
        val r = redeemer()
        val text = f.packageText(f.envelope(hints = listOf(net.pocvpn.client.reachability.EndpointId("stockholm"))))
        runBlocking { r.redeem(ActivationPackageInput.Text(text), { states += it }, denied, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
        assertEquals(ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.GATEWAY_NOT_ELIGIBLE), states.last())

        states.clear()
        runBlocking { r.redeem(ActivationPackageInput.Text(text), { states += it }, alwaysEligible, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
        assertEquals(ActivationPackageUiState.Succeeded(BootstrapStagingStatus.NOT_INCLUDED), states.last())
    }
}
