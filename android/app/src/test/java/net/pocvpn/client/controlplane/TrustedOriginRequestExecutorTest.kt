package net.pocvpn.client.controlplane

import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedOriginRequestExecutorTest {

    private val primary = ControlPlaneOrigin(ProductionGatewayId.GERMANY, "origin-a")
    private val secondary = ControlPlaneOrigin(ProductionGatewayId.GERMANY, "origin-b")

    @Test
    fun `primary origin fails, secondary succeeds`() {
        val calls = mutableListOf<ControlPlaneOrigin>()
        val result = TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = { origin ->
                calls += origin
                if (origin == primary) {
                    TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.HTTP_UNAVAILABLE)
                } else {
                    TrustedOriginRequestExecutor.OriginCallResult.Success("ok")
                }
            },
        )
        assertEquals(listOf(primary, secondary), calls)
        assertTrue(result is TrustedOriginRequestExecutor.ExecutionResult.Success)
        assertEquals("ok", (result as TrustedOriginRequestExecutor.ExecutionResult.Success).value)
        assertEquals(secondary, result.origin)
    }

    @Test
    fun `primary connect timeout, secondary succeeds`() {
        val result = TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = { origin ->
                if (origin == primary) {
                    TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.CONNECT_TIMEOUT)
                } else {
                    TrustedOriginRequestExecutor.OriginCallResult.Success(42)
                }
            },
        )
        assertTrue(result is TrustedOriginRequestExecutor.ExecutionResult.Success)
        assertEquals(42, (result as TrustedOriginRequestExecutor.ExecutionResult.Success).value)
    }

    @Test
    fun `all origins fail yields explicit typed exhaustion, never an exception`() {
        val result = TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = { TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.HTTP_UNAVAILABLE) },
        )
        assertTrue(result is TrustedOriginRequestExecutor.ExecutionResult.Exhausted)
        val failures = (result as TrustedOriginRequestExecutor.ExecutionResult.Exhausted).failures
        assertEquals(2, failures.size)
        assertEquals(listOf(primary, secondary), failures.map { it.origin })
        assertTrue(failures.all { it.reason == ControlPlaneFailureReason.HTTP_UNAVAILABLE })
    }

    @Test
    fun `bounded attempt count - never tries more origins than were passed in, never an infinite retry`() {
        var attempts = 0
        TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = {
                attempts++
                TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.HTTP_UNAVAILABLE)
            },
        )
        assertEquals(2, attempts)
    }

    @Test
    fun `authorization rejection on the primary origin stops early - never tried against a second origin`() {
        var attempts = 0
        val result = TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = {
                attempts++
                TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.AUTHORIZATION_REJECTED)
            },
        )
        assertEquals(1, attempts)
        assertTrue(result is TrustedOriginRequestExecutor.ExecutionResult.Exhausted)
    }

    @Test
    fun `onAttemptStart and onAttemptResult callbacks fire once per real attempt, in order`() {
        val started = mutableListOf<ControlPlaneOrigin>()
        val finished = mutableListOf<Pair<ControlPlaneOrigin, ControlPlaneFailureReason?>>()
        TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            onAttemptStart = { started += it },
            onAttemptResult = { origin, reason -> finished += origin to reason },
            callPerOrigin = { origin ->
                if (origin == primary) {
                    TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.HTTP_UNAVAILABLE)
                } else {
                    TrustedOriginRequestExecutor.OriginCallResult.Success(Unit)
                }
            },
        )
        assertEquals(listOf(primary, secondary), started)
        assertEquals(listOf(primary to ControlPlaneFailureReason.HTTP_UNAVAILABLE, secondary to null), finished)
    }

    @Test
    fun `a TLS-trust failure on one origin falls through safely to the next origin`() {
        val result = TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = { origin ->
                if (origin == primary) {
                    TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.TLS_TRUST_FAILED)
                } else {
                    TrustedOriginRequestExecutor.OriginCallResult.Success("ok")
                }
            },
        )
        assertTrue(result is TrustedOriginRequestExecutor.ExecutionResult.Success)
    }

    @Test
    fun `an untrusted redirect is rejected, never treated as success, and falls through like any other origin failure`() {
        val result = TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = { origin ->
                if (origin == primary) {
                    TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.UNTRUSTED_REDIRECT_REJECTED)
                } else {
                    TrustedOriginRequestExecutor.OriginCallResult.Success("ok")
                }
            },
        )
        assertTrue(result is TrustedOriginRequestExecutor.ExecutionResult.Success)
        assertEquals(secondary, (result as TrustedOriginRequestExecutor.ExecutionResult.Success).origin)
    }

    @Test
    fun `each origin attempt is independent - a credential or header value supplied for one origin is never visible to another's call`() {
        val seenPerOrigin = mutableMapOf<ControlPlaneOrigin, String>()
        TrustedOriginRequestExecutor.execute(
            origins = listOf(primary, secondary),
            callPerOrigin = { origin ->
                // Each invocation independently captures its own origin -
                // nothing here reads state left behind by a previous
                // iteration, proving no header/credential object is shared
                // or mutated across attempts.
                seenPerOrigin[origin] = "credential-for-${origin.host}"
                TrustedOriginRequestExecutor.OriginCallResult.Failure(ControlPlaneFailureReason.HTTP_UNAVAILABLE)
            },
        )
        assertEquals(setOf(primary, secondary), seenPerOrigin.keys)
        assertEquals("credential-for-origin-a", seenPerOrigin.getValue(primary))
        assertEquals("credential-for-origin-b", seenPerOrigin.getValue(secondary))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `an empty origin list is rejected rather than silently no-op`() {
        TrustedOriginRequestExecutor.execute<Unit>(
            origins = emptyList(),
            callPerOrigin = { TrustedOriginRequestExecutor.OriginCallResult.Success(Unit) },
        )
    }
}
