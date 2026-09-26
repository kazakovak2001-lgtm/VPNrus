package net.pocvpn.client.activation

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
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

    private fun activateWith(outcome: ActivationAttemptOutcome): suspend (String) -> ActivationAttemptOutcome = { credential ->
        activated += credential
        outcome
    }

    private fun redeem(r: ActivationPackageRedeemer, text: String, outcome: ActivationAttemptOutcome) =
        runBlocking { r.redeem(ActivationPackageInput.Text(text), { states += it }, activateWith(outcome)) }

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

        val retried = runBlocking { r.retry({ states += it }, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
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
        runBlocking { r.retry({ states += it }, activateWith(ActivationAttemptOutcome.SUCCEEDED)) }
        assertEquals(ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.EXPIRED), states.last())
        assertTrue(activated.isEmpty())
        assertFalse(r.hasPending)
    }

    @Test fun `retry with nothing pending does nothing`() {
        assertFalse(runBlocking { redeemer().retry({ states += it }, activateWith(ActivationAttemptOutcome.SUCCEEDED)) })
        assertTrue(activated.isEmpty() && states.isEmpty())
    }

    /**
     * Regression for the `retry()` race where `pending` was read BEFORE
     * `busy.tryLock()`: a `retry()` that captured a stale `pending` snapshot
     * while `busy` was held by a concurrent `redeem()` could, once that
     * `redeem()` released the lock, go on to activate the now-superseded
     * package instead of the current one.
     *
     * Deterministic by construction, no sleeps/thread races: each
     * `redeem()`'s [activate] lambda signals a `readyX` [CompletableDeferred]
     * IMMEDIATELY BEFORE it suspends on its own `outcomeX` deferred, and the
     * test coroutine `await()`s that signal - a real suspension point, not a
     * scheduling assumption - before attempting a concurrent `retry()`. That
     * guarantees `redeem()` is suspended inside [activate] - i.e. still
     * holding `busy` (unlocked only in `redeem()`'s `finally`, which runs
     * after [activate] returns) - at the moment `retry()` is attempted.
     */
    @Test fun `retry never activates a package captured before it acquired the lock`() {
        val credB = "Zbc_def-123GHIjklMNOpqrSTUvwxYZ0123456789ab"
        val r = redeemer()
        val readyA = CompletableDeferred<Unit>()
        val outcomeA = CompletableDeferred<ActivationAttemptOutcome>()
        val readyB = CompletableDeferred<Unit>()
        val outcomeB = CompletableDeferred<ActivationAttemptOutcome>()

        runBlocking {
            // --- Package A becomes pending, then redeem() suspends mid-
            // activation - busy is still held (activatePending() runs
            // before the finally-block unlock). ---
            val jobA = launch {
                r.redeem(
                    ActivationPackageInput.Text(f.packageText(f.envelope(nonceSeed = 1))),
                    { states += it },
                ) { credential -> activated += credential; readyA.complete(Unit); outcomeA.await() }
            }
            readyA.await()
            // A concurrent retry() here must refuse outright (busy held) -
            // it must never read `pending` before establishing that busy is
            // free, which is exactly the bug: reading `pending` first would
            // have captured A regardless of what happens next.
            assertFalse(r.retry({ states += it }, activateWith(ActivationAttemptOutcome.SUCCEEDED)))
            outcomeA.complete(ActivationAttemptOutcome.NETWORK_UNAVAILABLE)
            jobA.join()
            assertTrue(r.hasPending) // A is now the pending package (NetworkRequired)

            // --- Package B replaces A as `pending`, again suspending
            // redeem() mid-activation while busy is held. ---
            val jobB = launch {
                r.redeem(
                    ActivationPackageInput.Text(f.packageText(f.envelope(nonceSeed = 2, credential = credB))),
                    { states += it },
                ) { credential -> activated += credential; readyB.complete(Unit); outcomeB.await() }
            }
            readyB.await()
            // Same refusal, now with a DIFFERENT package superseding the
            // first: the buggy implementation would have captured `pending`
            // as A again before even checking the lock.
            assertFalse(r.retry({ states += it }, activateWith(ActivationAttemptOutcome.SUCCEEDED)))
            outcomeB.complete(ActivationAttemptOutcome.NETWORK_UNAVAILABLE)
            jobB.join()
            assertTrue(r.hasPending) // B has replaced A as the pending package

            activated.clear()
            // busy is free now: retry() must act on the CURRENT pending
            // package (B) - never a stale snapshot of A captured earlier.
            assertTrue(r.retry({ states += it }, activateWith(ActivationAttemptOutcome.SUCCEEDED)))
            assertEquals(listOf(credB), activated)
            assertEquals(ActivationPackageUiState.Succeeded(BootstrapStagingStatus.NOT_INCLUDED), states.last())
            assertFalse(r.hasPending)
        }
    }

    @Test fun `offline parse and verification need no network at all`() {
        // Nothing in import touches the network: the only dependency is the local manifest repository.
        val result = f.importer().import(ActivationPackageInput.Text(f.packageText()), now)
        assertTrue(result is ActivationPackageImportResult.Verified)
    }
}
