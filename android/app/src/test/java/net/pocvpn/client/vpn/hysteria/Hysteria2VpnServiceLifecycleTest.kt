package net.pocvpn.client.vpn.hysteria

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * B46-4A review fix (Finding 6) - direct, deterministic tests of the
 * lifecycle-ownership state machine that replaced the previous
 * `sessionActive: Boolean` guard. These call [Hysteria2VpnService.tryBeginStarting]/
 * [Hysteria2VpnService.tryMarkRunning]/[Hysteria2VpnService.tryClaimTerminal]
 * directly (made `internal` specifically for this) rather than racing real
 * coroutines against a background dispatcher - the state machine's
 * correctness does not depend on timing, so the test shouldn't either.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Hysteria2VpnServiceLifecycleTest {

    private fun newService() = Robolectric.buildService(Hysteria2VpnService::class.java).create().get()

    @Test
    fun `a second START during STARTING is rejected deterministically`() {
        val service = newService()

        assertTrue(service.tryBeginStarting(1L))
        // Second start for a DIFFERENT session while the first is still STARTING.
        assertFalse(service.tryBeginStarting(2L))
        assertEquals(Hysteria2ServiceLifecycle.Starting(1L), service.lifecycle)
    }

    @Test
    fun `a second START while RUNNING is rejected deterministically`() {
        val service = newService()
        service.tryBeginStarting(1L)
        assertTrue(service.tryMarkRunning(1L))

        assertFalse(service.tryBeginStarting(2L))
        assertEquals(Hysteria2ServiceLifecycle.Running(1L), service.lifecycle)
    }

    @Test
    fun `tryMarkRunning fails for a session that is no longer the one STARTING`() {
        val service = newService()
        service.tryBeginStarting(1L)
        // A STOP (or a superseding event) already claimed the terminal transition.
        service.tryClaimTerminal()

        assertFalse("a superseded session must never transition to Running", service.tryMarkRunning(1L))
    }

    @Test
    fun `tryClaimTerminal during STARTING returns the session id and moves to Stopping`() {
        val service = newService()
        service.tryBeginStarting(7L)

        val claimed = service.tryClaimTerminal()

        assertEquals(7L, claimed)
        assertEquals(Hysteria2ServiceLifecycle.Stopping(7L), service.lifecycle)
    }

    @Test
    fun `tryClaimTerminal during RUNNING returns the session id and moves to Stopping`() {
        val service = newService()
        service.tryBeginStarting(9L)
        service.tryMarkRunning(9L)

        val claimed = service.tryClaimTerminal()

        assertEquals(9L, claimed)
        assertEquals(Hysteria2ServiceLifecycle.Stopping(9L), service.lifecycle)
    }

    @Test
    fun `a duplicate STOP (already Stopping) is a safe no-op, never double-claims`() {
        val service = newService()
        service.tryBeginStarting(1L)
        val firstClaim = service.tryClaimTerminal()
        val secondClaim = service.tryClaimTerminal()

        assertEquals(1L, firstClaim)
        assertNull("a second claim on an already-Stopping session must be a no-op", secondClaim)
    }

    @Test
    fun `STOP on an idle (never-started) service is a safe no-op`() {
        val service = newService()

        assertNull(service.tryClaimTerminal())
        assertEquals(Hysteria2ServiceLifecycle.Idle, service.lifecycle)
    }

    @Test
    fun `unexpected death or start failure returns ownership to Idle - a later fresh session can start`() {
        val service = newService()
        service.tryBeginStarting(1L)
        service.tryClaimTerminal()
        // Simulate what failStartup/handleUnexpectedExit do after claiming the terminal transition.
        service.lifecycle = Hysteria2ServiceLifecycle.Idle

        // A later, fresh session must be able to start cleanly.
        assertTrue(service.tryBeginStarting(2L))
        assertEquals(Hysteria2ServiceLifecycle.Starting(2L), service.lifecycle)
    }

    @Test
    fun `a stale terminal claim for an old session cannot affect a newer already-started session`() {
        val service = newService()
        service.tryBeginStarting(1L)
        service.tryClaimTerminal()
        service.lifecycle = Hysteria2ServiceLifecycle.Idle
        // A fresh, newer session starts and reaches RUNNING.
        service.tryBeginStarting(2L)
        service.tryMarkRunning(2L)

        // A stale event for session 1 (expectedSessionId=1) must not be able
        // to claim/tear down session 2's now-current lifecycle.
        val staleClaim = service.tryClaimTerminal(expectedSessionId = 1L)

        assertNull("a stale session-1 claim must not affect session 2", staleClaim)
        assertEquals(Hysteria2ServiceLifecycle.Running(2L), service.lifecycle)
    }

    @Test
    fun `missing endpoint id fails closed synchronously - never touches credential repository, TUN, or children`() {
        val service = newService()
        var factoryCalls = 0
        service.credentialRepositoryFactory = { _, _ -> factoryCalls++; throw AssertionError("must never be called") }

        val intent = android.content.Intent(Hysteria2VpnService.ACTION_START)
            .putExtra(Hysteria2VpnService.EXTRA_SESSION_ID, 1L)
            .putExtra(Hysteria2VpnService.EXTRA_HOST, "host.example")
            .putExtra(Hysteria2VpnService.EXTRA_PORT, 443)
            .putExtra(Hysteria2VpnService.EXTRA_SNI, "sni.example.com")
        // Deliberately no EXTRA_ENDPOINT_ID.

        service.onStartCommand(intent, 0, 1)

        assertEquals(0, factoryCalls)
        assertEquals(Hysteria2ServiceLifecycle.Idle, service.lifecycle)
        val status = Hysteria2VpnService.status.value
        assertEquals(Hysteria2RuntimePhase.FAILED, status?.phase)
        assertEquals(Hysteria2RuntimeError.MissingEndpointId, status?.error)
    }

    @Test
    fun `blank endpoint id also fails closed - not just null`() {
        val service = newService()
        var factoryCalls = 0
        service.credentialRepositoryFactory = { _, _ -> factoryCalls++; throw AssertionError("must never be called") }

        val intent = android.content.Intent(Hysteria2VpnService.ACTION_START)
            .putExtra(Hysteria2VpnService.EXTRA_SESSION_ID, 1L)
            .putExtra(Hysteria2VpnService.EXTRA_ENDPOINT_ID, "   ")
            .putExtra(Hysteria2VpnService.EXTRA_HOST, "host.example")
            .putExtra(Hysteria2VpnService.EXTRA_PORT, 443)
            .putExtra(Hysteria2VpnService.EXTRA_SNI, "sni.example.com")

        service.onStartCommand(intent, 0, 1)

        assertEquals(0, factoryCalls)
        assertEquals(Hysteria2RuntimeError.MissingEndpointId, Hysteria2VpnService.status.value?.error)
    }
}
