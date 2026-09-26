package net.pocvpn.client.activation

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext

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
        activate: suspend (credential: String) -> ActivationAttemptOutcome,
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
                    onState(activatePending(result, onState, activate))
                }
            }
            return true
        } finally {
            busy.unlock()
        }
    }

    suspend fun retry(
        onState: (ActivationPackageUiState) -> Unit,
        activate: suspend (credential: String) -> ActivationAttemptOutcome,
    ): Boolean {
        if (!busy.tryLock()) return false
        try {
            // `pending` is read only after `busy` is held - reading it
            // before the lock (the previous implementation) could capture a
            // package that a concurrent redeem()/retry() then replaces or
            // clears while this call was still waiting for the mutex,
            // activating a stale package. See ActivationPackageRedeemerTest
            // `retry never activates a package captured before it acquired
            // the lock`.
            val current = pending ?: return false
            onState(activatePending(current, onState, activate))
            return true
        } finally {
            busy.unlock()
        }
    }

    private suspend fun activatePending(
        verified: ActivationPackageImportResult.Verified,
        onState: (ActivationPackageUiState) -> Unit,
        activate: suspend (credential: String) -> ActivationAttemptOutcome,
    ): ActivationPackageUiState {
        // A package verified earlier can expire while waiting for network.
        if (nowEpochMillis() >= verified.envelope.expiresAtEpochMillis) {
            pending = null
            return ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.EXPIRED)
        }
        onState(ActivationPackageUiState.Activating(verified.bootstrap))
        return when (activate(verified.envelope.credential.value)) {
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
