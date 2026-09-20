package net.pocvpn.client.vpn.shadowsocks

/**
 * B45B-3 - internal runtime phases for the production Shadowsocks 2022
 * adapter. Never exposed outside this package; [ShadowsocksTransport] maps
 * these into net.pocvpn.client.vpn.TransportState, the one public lifecycle
 * authority (see that class's own docs).
 */
internal enum class ShadowsocksRuntimePhase {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    FAILED,
}

/** Typed, non-secret internal failure - never a raw exception message crossing into TransportState.Error's own message field without going through here first. */
internal sealed interface ShadowsocksRuntimeError {
    data class CredentialAbsent(val endpointId: String) : ShadowsocksRuntimeError
    data class CredentialCorrupted(val reason: String) : ShadowsocksRuntimeError
    /** B45B-4P (correction) - the trusted manifest's signed method and the endpoint-scoped secret credential's own method disagree; both values are PUBLIC method identifiers only, never key material. */
    data class ProfileMethodMismatch(val signedMethod: String, val credentialMethod: String) : ShadowsocksRuntimeError
    data class BinaryMissing(val reason: String) : ShadowsocksRuntimeError
    /** B45B-3P - a previous abnormal process death (SIGABRT/SIGKILL) left ephemeral runtime files this start attempt could not clear before writing a new plaintext config - see ShadowsocksRuntime's own sweepStaleEphemeralState docs. */
    data class StaleStateCleanupFailed(val reason: String) : ShadowsocksRuntimeError
    data class RuntimeConfigWriteFailed(val reason: String) : ShadowsocksRuntimeError
    data class ProtectListenerFailed(val reason: String) : ShadowsocksRuntimeError
    data class SpawnFailed(val reason: String) : ShadowsocksRuntimeError
    data class TunEstablishFailed(val reason: String) : ShadowsocksRuntimeError
    data class TunFdHandoffFailed(val reason: String) : ShadowsocksRuntimeError
    data class TunFdHandoffTimedOut(val waitedMillis: Long) : ShadowsocksRuntimeError
    data class ProcessExitedUnexpectedly(val exitCode: Int) : ShadowsocksRuntimeError
}

internal data class ShadowsocksRuntimeStatus(
    val phase: ShadowsocksRuntimePhase,
    val lastError: ShadowsocksRuntimeError? = null,
) {
    companion object {
        val IDLE = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.STOPPED)
    }
}
