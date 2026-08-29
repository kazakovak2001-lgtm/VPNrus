@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.smartconnect

import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8J - narrow tests for the bounded HTTPS reachability probe: this
 * feature's own required cases 8, 9, 10, 11. No real network I/O anywhere
 * here - performAttempt is always a fake (see HttpsGatewayReachabilityProbe's
 * own "additive test seam" docs).
 */
class GatewayReachabilityProbeTest {

    @Test
    fun `an HTTP 4xx response counts as reachable - TCP TLS and HTTP all succeeded`() {
        assertTrue(interpretProbeAttempt(ProbeAttemptOutcome.HttpResponse(404)))
        assertTrue(interpretProbeAttempt(ProbeAttemptOutcome.HttpResponse(403)))
    }

    @Test
    fun `any successful HTTP status counts as reachable, not just 2xx`() {
        assertTrue(interpretProbeAttempt(ProbeAttemptOutcome.HttpResponse(200)))
        assertTrue(interpretProbeAttempt(ProbeAttemptOutcome.HttpResponse(500)))
    }

    @Test
    fun `a TLS or connect failure does NOT count as reachable`() {
        assertFalse(interpretProbeAttempt(ProbeAttemptOutcome.TlsOrConnectFailure))
    }

    @Test
    fun `a timed-out attempt does NOT count as reachable`() {
        assertFalse(interpretProbeAttempt(ProbeAttemptOutcome.TimedOut))
    }

    @Test
    fun `the probe is bounded by its timeout - a slow attempt still resolves promptly as unreachable`() = runTest {
        val probe = HttpsGatewayReachabilityProbe(
            timeoutMs = 1_000L,
            performAttempt = {
                delay(60_000L) // would hang forever without the bound
                ProbeAttemptOutcome.HttpResponse(200)
            },
        )

        val result = probe.isReachable()

        // withTimeoutOrNull cut the slow attempt off at 1s (virtual time) -
        // the probe still produced a definitive, bounded answer.
        assertFalse(result)
    }

    @Test
    fun `a fast attempt within the timeout is not affected by the bound`() = runTest {
        val probe = HttpsGatewayReachabilityProbe(
            timeoutMs = 5_000L,
            performAttempt = { ProbeAttemptOutcome.HttpResponse(204) },
        )

        assertTrue(probe.isReachable())
    }

    @Test
    fun `cancelling the calling coroutine cancels an in-flight probe instead of it hanging`() = runTest {
        val probe = HttpsGatewayReachabilityProbe(
            timeoutMs = 60_000L,
            performAttempt = { awaitCancellation() }, // never completes on its own
        )

        val job = launch { probe.isReachable() }
        runCurrent()
        assertTrue("probe should still be running until cancelled", job.isActive)

        job.cancel()
        runCurrent()

        assertTrue("cancelling the caller must actually cancel the in-flight probe, not leave it hanging", job.isCancelled)
    }
}
