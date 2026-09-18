package net.pocvpn.client.debug.b45a

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Pure Kotlin state model for the debug-only independent shadowsocks-rust
 * runtime feasibility spike (see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md). Has
 * no Android framework dependency so it is testable with plain JVM unit
 * tests - the actual Android glue (LocalSocket, VpnService, ProcessBuilder)
 * lives in separate classes that hold an instance of this state machine
 * rather than embedding transition logic themselves.
 *
 * This is not, and must never become, a second production transport/
 * reconnect/diagnostics authority - see architecture principle 11 in
 * PROJECT_ARCHITECTURE.md. It exists only to prove Android-side mechanics
 * for B45A's own acceptance matrix.
 */
enum class B45ARuntimePhase {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    FAILED,
}

/** Typed states for the TUN-fd handoff bridge (Android is the CLIENT in this protocol - see B45ATunFdBridge). */
enum class B45ATunFdBridgeState {
    WAITING,
    CONNECTED,
    FD_SENT,
    FAILED,
    CLOSED,
}

/** Typed states for the VPN-protect bridge (Android is the SERVER/listener in this protocol - see B45AVpnProtectBridge). */
enum class B45AProtectBridgeState {
    WAITING,
    CONNECTED,
    ACKNOWLEDGED,
    FAILED,
    CLOSED,
}

/**
 * A single typed spike error - never a raw exception message surfaced as if
 * it were a production B29 diagnostics category (architecture principle 9).
 * This vocabulary is intentionally separate from, and never fed into,
 * DiagnosticFailureMapping/SupportDiagnosticsRecorder.
 */
sealed interface B45ASpikeError {
    data class BinaryMissing(val expectedPath: String) : B45ASpikeError
    data class SpawnFailed(val reason: String) : B45ASpikeError
    data class AlreadyRunning(val existingPid: Int?) : B45ASpikeError
    data class TunFdHandoffFailed(val reason: String) : B45ASpikeError
    data class TunFdHandoffTimedOut(val waitedMillis: Long) : B45ASpikeError
    data class ProtectListenerFailed(val reason: String) : B45ASpikeError
    data class ProcessExitedUnexpectedly(val exitCode: Int) : B45ASpikeError
    data class StopTimedOut(val waitedMillis: Long) : B45ASpikeError
    /** Round 6 - the active data-plane target's key failed base64/length validation before ever reaching sslocal. */
    data class InvalidTestCredential(val reason: String) : B45ASpikeError
}

/** Immutable snapshot of everything the debug UI needs to show - see Phase 11's requested status lines. */
data class B45ASpikeStatus(
    val phase: B45ARuntimePhase,
    val pid: Int? = null,
    val tunFdBridgeState: B45ATunFdBridgeState? = null,
    val protectBridgeState: B45AProtectBridgeState? = null,
    val protectRequestCount: Int = 0,
    val protectFailureCount: Int = 0,
    val exitCode: Int? = null,
    val lastError: B45ASpikeError? = null,
) {
    companion object {
        val IDLE = B45ASpikeStatus(phase = B45ARuntimePhase.STOPPED)
    }
}

/**
 * The runtime's own transition rules, kept separate from any I/O so they can
 * be unit tested exhaustively. A caller (B45ARuntime) is the only thing that
 * actually performs I/O (spawning the process, running the bridges) and
 * feeds its real outcomes back through these pure functions.
 */
object B45ASpikeTransitions {

    /** Only STOPPED or FAILED may transition to STARTING - never a double-start (Phase 8/13.B requirement). */
    fun canStart(current: B45ASpikeStatus): Boolean =
        current.phase == B45ARuntimePhase.STOPPED || current.phase == B45ARuntimePhase.FAILED

    fun starting(): B45ASpikeStatus = B45ASpikeStatus(phase = B45ARuntimePhase.STARTING)

    /**
     * Transitions to RUNNING, changing only the fields THIS transition owns
     * (`phase`, `pid`) - `.copy()`, not a fresh [B45ASpikeStatus], so fields
     * an earlier step in the same `start()` call already set (notably
     * `protectBridgeState`, bound before `sslocal` is ever spawned - see
     * [B45ARuntime.start]) survive. **Round 4/5 fix**: the previous version
     * of this function constructed a brand-new [B45ASpikeStatus], silently
     * discarding `protectBridgeState` back to `null` the moment RUNNING was
     * reached - a real, physically-observed status-reporting bug (round 4's
     * UI showed "protect bridge: n/a" despite the bridge almost certainly
     * already being `WAITING`), not a protocol/mechanism defect. See
     * [withProtectBridgeState]'s own regression test.
     */
    fun running(current: B45ASpikeStatus, pid: Int): B45ASpikeStatus =
        current.copy(phase = B45ARuntimePhase.RUNNING, pid = pid)

    fun withTunFdBridgeState(current: B45ASpikeStatus, state: B45ATunFdBridgeState): B45ASpikeStatus =
        current.copy(tunFdBridgeState = state)

    fun withProtectBridgeState(current: B45ASpikeStatus, state: B45AProtectBridgeState): B45ASpikeStatus =
        current.copy(protectBridgeState = state)

    fun onProtectRequestHandled(current: B45ASpikeStatus, succeeded: Boolean): B45ASpikeStatus = current.copy(
        protectRequestCount = current.protectRequestCount + 1,
        protectFailureCount = if (succeeded) current.protectFailureCount else current.protectFailureCount + 1,
    )

    /** Stop is idempotent - stopping an already-STOPPED runtime is a no-op, never an error (Phase 13.C requirement). */
    fun canStop(current: B45ASpikeStatus): Boolean = current.phase != B45ARuntimePhase.STOPPED

    fun stopping(current: B45ASpikeStatus): B45ASpikeStatus = current.copy(phase = B45ARuntimePhase.STOPPING)

    fun stopped(): B45ASpikeStatus = B45ASpikeStatus.IDLE

    fun failed(current: B45ASpikeStatus, error: B45ASpikeError): B45ASpikeStatus =
        current.copy(phase = B45ARuntimePhase.FAILED, lastError = error)

    /** A process that exits on its own (never requested by us) always clears ownership - never left dangling as "RUNNING". Preserves prior counters (protect request/failure counts) for the status UI rather than resetting them. */
    fun processExitedUnexpectedly(current: B45ASpikeStatus, exitCode: Int): B45ASpikeStatus = current.copy(
        phase = B45ARuntimePhase.FAILED,
        exitCode = exitCode,
        lastError = B45ASpikeError.ProcessExitedUnexpectedly(exitCode),
    )
}
