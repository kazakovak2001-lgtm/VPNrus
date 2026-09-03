package net.pocvpn.client.controlplane

/**
 * B30 (task 4) - the ONE generic trusted-origin retry loop, reusable for
 * activation, xray-profile, and ingress-profile alike (task requirement
 * "do not create transport-specific copies of control-plane retry logic").
 * Pure and synchronous - no networking, no coroutines, no I/O of its own:
 * the caller supplies [callPerOrigin], the actual per-origin network call,
 * already reduced to a typed [OriginCallResult]. This is what makes the
 * bounded-attempt/no-infinite-retry/typed-failure discipline unit-testable
 * with fake origins and fake results, never a live HTTPS connection.
 *
 * Bounded by construction: tries at most `origins.size` origins, each
 * exactly once, in order - never a retry loop, never unbounded. Stops
 * early (does not try remaining origins) on any reason in [stopOnReasons] -
 * default [ControlPlaneFailureReason.AUTHORIZATION_REJECTED]: a rejected
 * credential is evidence about the CREDENTIAL, not about which origin was
 * reachable, so trying the same rejected credential against a different
 * origin is never useful and would look like credential-probing across
 * hosts - task requirement 2's "never forward credentials/auth headers to
 * another host automatically" extends to this: [callPerOrigin] is invoked
 * fresh per origin from whatever closure the caller built, so there is no
 * shared connection/header state this executor could carry across origins
 * even if it wanted to.
 */
object TrustedOriginRequestExecutor {

    sealed class OriginCallResult<out T> {
        data class Success<T>(val value: T) : OriginCallResult<T>()
        data class Failure(val reason: ControlPlaneFailureReason) : OriginCallResult<Nothing>()
    }

    sealed class ExecutionResult<out T> {
        data class Success<T>(val value: T, val origin: ControlPlaneOrigin) : ExecutionResult<T>()
        data class Exhausted(val failures: List<OriginFailure>) : ExecutionResult<Nothing>()
    }

    data class OriginFailure(val origin: ControlPlaneOrigin, val reason: ControlPlaneFailureReason)

    fun <T> execute(
        origins: List<ControlPlaneOrigin>,
        stopOnReasons: Set<ControlPlaneFailureReason> = setOf(ControlPlaneFailureReason.AUTHORIZATION_REJECTED),
        onAttemptStart: (ControlPlaneOrigin) -> Unit = {},
        onAttemptResult: (ControlPlaneOrigin, ControlPlaneFailureReason?) -> Unit = { _, _ -> },
        callPerOrigin: (ControlPlaneOrigin) -> OriginCallResult<T>,
    ): ExecutionResult<T> {
        require(origins.isNotEmpty()) { "TrustedOriginRequestExecutor requires at least one trusted origin" }
        val failures = mutableListOf<OriginFailure>()
        for (origin in origins) {
            onAttemptStart(origin)
            when (val result = callPerOrigin(origin)) {
                is OriginCallResult.Success -> {
                    onAttemptResult(origin, null)
                    return ExecutionResult.Success(result.value, origin)
                }
                is OriginCallResult.Failure -> {
                    onAttemptResult(origin, result.reason)
                    failures += OriginFailure(origin, result.reason)
                    if (result.reason in stopOnReasons) {
                        return ExecutionResult.Exhausted(failures)
                    }
                }
            }
        }
        return ExecutionResult.Exhausted(failures)
    }
}
