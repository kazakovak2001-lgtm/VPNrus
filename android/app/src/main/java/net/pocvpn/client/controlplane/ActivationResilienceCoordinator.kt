package net.pocvpn.client.controlplane

import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.classifyProvisioningResultFailure
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B30 - the resilient activation path: wraps the SAME per-gateway
 * activation network call this codebase already has (see
 * [net.pocvpn.client.provisioning.ProvisioningClient.activate]'s 3-arg,
 * endpointHost-aware overload) with [TrustedOriginRequestExecutor]'s
 * bounded/typed-failure discipline, plus the two resilience rules task
 * requirement 3/5 need:
 *
 *  1. Requirement 3 - "if activation is already valid locally, do not
 *     unnecessarily re-activate": [hasValidLocalActivation] (an additive
 *     seam, the caller's own pure freshness check over its persisted
 *     stores - this class never reads any store itself) is consulted FIRST;
 *     a true short-circuits to [Outcome.AlreadyValidLocally] with zero
 *     network calls and zero diagnostics origin-attempt events (only
 *     [SupportDiagnosticsRecorder.recordOfflineStateReused]).
 *  2. Idempotency (requirement 11) - this class never generates or rotates
 *     any identity itself; [publicKey] is the caller's own already
 *     get-or-created device key (see [net.pocvpn.client.identity.ClientKeyRepository]),
 *     passed in unchanged, so a Retry that reaches the network again always
 *     presents the SAME public key + the SAME activationCredential the
 *     first attempt did - exactly what the server's own idempotent
 *     activation (locked by credential digest, see gateway/api/activations.py)
 *     needs to treat a retried request as the SAME logical activation, never
 *     a new device identity.
 *
 * Deliberately returns the raw [ProvisioningResult.Success] on success
 * (never applies/persists anything itself) - applying a validated success
 * (gatewayConfigOverride/profileStore/clientTunnelIdentityStore writes,
 * matchGatewayId cross-check) stays the caller's job, exactly the same
 * "only after full validation, never partial" ordering
 * [net.pocvpn.client.MainViewModel.activateDevice] already enforces - this
 * class adds resilience AROUND that call, it does not re-implement what
 * happens after a validated success (requirement 12 - "no half-written
 * activation credentials": nothing here writes to any store at all).
 */
class ActivationResilienceCoordinator(
    private val diagnosticsRecorder: SupportDiagnosticsRecorder? = null,
) {
    sealed class Outcome {
        /** No network call was made - a valid local activation already exists (requirement 3/5). */
        object AlreadyValidLocally : Outcome()
        data class Success(val result: ProvisioningResult.Success, val originIndex: Int) : Outcome()
        /** A terminal, non-retryable rejection (Unauthorized/Revoked/Expired/DeviceLimitReached/BadRequest) - never tried against another origin, see [TrustedOriginRequestExecutor]'s own stopOnReasons docs. */
        data class Rejected(val result: ProvisioningResult) : Outcome()
        data class AllOriginsExhausted(val failures: List<TrustedOriginRequestExecutor.OriginFailure>) : Outcome()
    }

    fun activate(
        gatewayId: ProductionGatewayId,
        publicKey: String,
        activationCredential: String,
        hasValidLocalActivation: () -> Boolean,
        callActivate: (origin: ControlPlaneOrigin, publicKey: String, activationCredential: String) -> ProvisioningResult,
        origins: List<ControlPlaneOrigin> = ControlPlaneOriginSetBuilder.forGateway(gatewayId),
    ): Outcome {
        if (hasValidLocalActivation()) {
            diagnosticsRecorder?.recordOfflineStateReused()
            return Outcome.AlreadyValidLocally
        }

        diagnosticsRecorder?.recordActivationStarted(gatewayId)

        // A terminal rejection short-circuits the whole executor loop (never
        // tried against another origin - see class docs) but must still be
        // returned to the caller as its OWN result, not merely a failure
        // reason - captured here since ExecutionResult.Exhausted only
        // carries the closed ControlPlaneFailureReason taxonomy, not the
        // richer ProvisioningResult a caller needs to show e.g. "revoked"
        // vs "expired" distinctly.
        var terminalRejection: ProvisioningResult? = null

        val originIndexOf = origins.withIndex().associate { (i, o) -> o to i }
        val executed = TrustedOriginRequestExecutor.execute(
            origins = origins,
            onAttemptStart = { origin -> diagnosticsRecorder?.recordControlOriginAttempt(gatewayId, originIndexOf.getValue(origin)) },
            onAttemptResult = { origin, reason ->
                if (reason == null) {
                    diagnosticsRecorder?.recordControlOriginSucceeded(gatewayId, originIndexOf.getValue(origin))
                } else {
                    diagnosticsRecorder?.recordControlOriginFailed(gatewayId, originIndexOf.getValue(origin), reason)
                }
            },
            callPerOrigin = { origin ->
                val result = callActivate(origin, publicKey, activationCredential)
                val reason = classifyProvisioningResultFailure(result)
                if (reason == null) {
                    TrustedOriginRequestExecutor.OriginCallResult.Success(result as ProvisioningResult.Success)
                } else {
                    if (reason == ControlPlaneFailureReason.AUTHORIZATION_REJECTED) {
                        terminalRejection = result
                    }
                    TrustedOriginRequestExecutor.OriginCallResult.Failure(reason)
                }
            },
        )

        return when (executed) {
            is TrustedOriginRequestExecutor.ExecutionResult.Success -> {
                diagnosticsRecorder?.recordActivationSucceeded(gatewayId)
                Outcome.Success(executed.value, originIndexOf.getValue(executed.origin))
            }
            is TrustedOriginRequestExecutor.ExecutionResult.Exhausted -> {
                val rejection = terminalRejection
                if (rejection != null) {
                    diagnosticsRecorder?.recordActivationFailed(ControlPlaneFailureReason.AUTHORIZATION_REJECTED)
                    Outcome.Rejected(rejection)
                } else {
                    diagnosticsRecorder?.recordActivationFailed(ControlPlaneFailureReason.ALL_ORIGINS_EXHAUSTED)
                    Outcome.AllOriginsExhausted(executed.failures)
                }
            }
        }
    }
}

/**
 * B30 - [net.pocvpn.client.provisioning.ProvisioningClient]'s own
 * `executeGeneric` collapses every IOException into
 * `ProvisioningResult.NetworkError("${e.javaClass.simpleName}: ...")`
 * (see that file) rather than exposing the exception itself. Safe to
 * pattern-match here on the exception SIMPLE CLASS NAME specifically
 * (never the rest of the message, which is never inspected) - this is OUR
 * OWN deterministic prefix, not untrusted server text, the same
 * distinction [DiagnosticSanitizer] draws elsewhere between a closed/known
 * format and arbitrary free text. `internal` so this is unit-testable
 * without a live connection.
 */
internal fun classifyNetworkErrorMessage(message: String): ControlPlaneFailureReason = when {
    message.startsWith("UnknownHostException") -> ControlPlaneFailureReason.DNS_RESOLUTION_FAILED
    message.startsWith("SocketTimeoutException") -> ControlPlaneFailureReason.CONNECT_TIMEOUT
    message.startsWith("SSLException") || message.startsWith("SSLHandshakeException") || message.startsWith("SSLPeerUnverifiedException") ->
        ControlPlaneFailureReason.TLS_TRUST_FAILED
    else -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
}
