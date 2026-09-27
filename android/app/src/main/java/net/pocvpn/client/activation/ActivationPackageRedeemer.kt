package net.pocvpn.client.activation

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B56-5 - package -> EXISTING activation flow orchestration, kept out of
 * MainViewModel so its guarantees are unit-testable on the JVM:
 *
 * - [activate] (production: MainViewModel.activateDevice, the SAME
 *   `/v1/activate` + device binding + AWG/Xray/Shadowsocks/Hysteria2
 *   provisioning path a typed credential uses - no second provisioning
 *   system) is invoked ONLY for an [ActivationPackageImportResult.Verified]
 *   envelope, and only with that envelope's credential.
 * - Network unavailable: the verified envelope stays pending IN MEMORY so
 *   [retry] can finish activation once connectivity returns; the bundle (if
 *   any) was already staged locally during verification. Pending state is
 *   never persisted, so the credential is never written anywhere new.
 * - The envelope is marked redeemed (local replay guard) only after
 *   [activate] reports success.
 * - One redemption at a time: a call while another is in flight is ignored
 *   (returns false) rather than racing two activations.
 *
 * B67.6 - entitlement-aware gateway eligibility, checked BEFORE [activate]
 * is ever called (never after, and never merged with server-side
 * rejection): [resolveEligibility] is handed the envelope's own signed
 * [ActivationEnvelope.bootstrapEndpointHints] (via [EntitlementScope],
 * derived here from data this class already legitimately owns - no second
 * envelope verification), and decides whether ANY currently-eligible
 * gateway exists for it. A [GatewayEligibilityResult.Denied] fails closed
 * with [ActivationPackageRejectionKind.GATEWAY_NOT_ELIGIBLE] - clears
 * [pending] and never reaches [activate] at all, so an envelope this device
 * cannot currently satisfy never even attempts a network call. Mapping
 * [EntitlementScope] to a concrete gateway set needs the trusted manifest
 * and the product gateway catalog, neither of which this pure-JVM class
 * depends on directly - [resolveEligibility] is the caller's own decision
 * (production: MainViewModel, via [EntitlementGatewayEligibility]), keeping
 * this class unit-testable exactly as before with a plain fake function.
 */
class ActivationPackageRedeemer(
    private val importer: ActivationPackageImporter,
    private val nowEpochMillis: () -> Long,
    private val ioDispatcher: CoroutineDispatcher,
) {
    private val busy = Mutex()

    @Volatile
    private var pending: ActivationPackageImportResult.Verified? = null

    val hasPending: Boolean get() = pending != null

    suspend fun redeem(
        input: ActivationPackageInput,
        onState: (ActivationPackageUiState) -> Unit,
        resolveEligibility: (EntitlementScope) -> GatewayEligibilityResult,
        activate: suspend (credential: String, eligibleGatewayIds: List<ProductionGatewayId>) -> ActivationAttemptOutcome,
    ): Boolean {
        if (!busy.tryLock()) return false
        try {
            onState(ActivationPackageUiState.Verifying)
            val result = withContext(ioDispatcher) { importer.import(input, nowEpochMillis()) }
            when (result) {
                is ActivationPackageImportResult.Rejected -> {
                    pending = null
                    onState(ActivationPackageUiState.Rejected(result.kind))
                }
                is ActivationPackageImportResult.Verified -> {
                    pending = result
                    onState(activatePending(result, onState, resolveEligibility, activate))
                }
            }
            return true
        } finally {
            busy.unlock()
        }
    }

    suspend fun retry(
        onState: (ActivationPackageUiState) -> Unit,
        resolveEligibility: (EntitlementScope) -> GatewayEligibilityResult,
        activate: suspend (credential: String, eligibleGatewayIds: List<ProductionGatewayId>) -> ActivationAttemptOutcome,
    ): Boolean {
        val current = pending ?: return false
        if (!busy.tryLock()) return false
        try {
            onState(activatePending(current, onState, resolveEligibility, activate))
            return true
        } finally {
            busy.unlock()
        }
    }

    private suspend fun activatePending(
        verified: ActivationPackageImportResult.Verified,
        onState: (ActivationPackageUiState) -> Unit,
        resolveEligibility: (EntitlementScope) -> GatewayEligibilityResult,
        activate: suspend (credential: String, eligibleGatewayIds: List<ProductionGatewayId>) -> ActivationAttemptOutcome,
    ): ActivationPackageUiState {
        // A package verified earlier can expire while waiting for network.
        if (nowEpochMillis() >= verified.envelope.expiresAtEpochMillis) {
            pending = null
            return ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.EXPIRED)
        }
        val scope = EntitlementScope.fromEnvelopeHints(verified.envelope.bootstrapEndpointHints)
        val eligibility = resolveEligibility(scope)
        val eligibleGatewayIds = when (eligibility) {
            is GatewayEligibilityResult.Denied -> {
                pending = null
                return ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.GATEWAY_NOT_ELIGIBLE)
            }
            is GatewayEligibilityResult.Eligible -> eligibility.gatewayIds
        }
        onState(ActivationPackageUiState.Activating(verified.bootstrap))
        return when (activate(verified.envelope.credential.value, eligibleGatewayIds)) {
            ActivationAttemptOutcome.SUCCEEDED -> {
                pending = null
                // Activation already succeeded server-side; failing to record
                // the LOCAL dedupe entry must not turn that into a failure
                // (the server binding remains the authoritative replay bound).
                try {
                    withContext(ioDispatcher) { importer.markRedeemed(verified.envelope, nowEpochMillis()) }
                } catch (e: java.io.IOException) {
                    // intentionally non-fatal - see above
                }
                ActivationPackageUiState.Succeeded(verified.bootstrap)
            }
            ActivationAttemptOutcome.NETWORK_UNAVAILABLE -> ActivationPackageUiState.NetworkRequired(verified.bootstrap)
            ActivationAttemptOutcome.FAILED -> {
                pending = null
                ActivationPackageUiState.ActivationFailed
            }
        }
    }
}
