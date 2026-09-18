package net.pocvpn.client.debug.b46hysteria

/**
 * B46-2A/B46-2B - PREPARATION ONLY, NOT A PRODUCTION TRANSPORT.
 *
 * Pure Kotlin state model for a future, still-unbuilt debug-only Hysteria2
 * Android feasibility spike (see
 * docs/B46_2A_HYSTERIA2_ANDROID_FEASIBILITY.md, Phase 5, and
 * docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md). No Android framework
 * dependency, so it is unit-testable on a plain JVM. There is deliberately
 * no `B46HysteriaSpikeActivity`/`B46HysteriaVpnService`/`B46HysteriaRuntime`
 * yet in this slice - per the task's own instruction, "if the correct
 * integration design is still unclear after Phase 1-4, STOP at
 * documentation/build-proof rather than writing speculative Android code."
 * B46-2B's design doc answers the remaining design questions (TUN-to-
 * sing-tun-relay shape) and adds a host-side synthetic proof, but no
 * physical device evidence exists yet to justify wiring a real
 * VpnService/process/FD-Control bridge - that is B46-2P's job. This type
 * exists only so B46-2P has an already-reviewed, already-tested state
 * shape to build the real harness against, exactly the role
 * B45ASpikeState.kt played before B45A's own real VpnService/Runtime
 * classes were written.
 *
 * **B46-2B addition: `TUN_BRIDGE_READY`.** B46-2A's TUN-ownership finding
 * (Nova must own the TUN; Hysteria2 cannot receive an external fd directly)
 * means there are now genuinely TWO independently-verifiable milestones
 * between "the TUN device exists" and "the Hysteria2 process is running":
 * (1) the TUN fd exists ([TUN_ESTABLISHED]), and (2) a separate bridge
 * component (the sing-tun-driven relay, Option A) is actually demuxing
 * TCP/UDP flows off that fd and forwarding them toward the not-yet-started
 * Hysteria2 process's local listener ([TUN_BRIDGE_READY]). Collapsing these
 * would let a caller believe the relay is live merely because the TUN
 * exists, which B46-2B's own synthetic proof shows are NOT the same
 * event (the relay must be constructed and started against the fd before
 * it demuxes anything) - so this is a real, independently observable
 * boundary, not an arbitrary subdivision.
 *
 * This is not, and must never become, a second production transport/
 * reconnect/diagnostics authority - see architecture principle 11 in
 * PROJECT_ARCHITECTURE.md. It must stay unreachable from
 * TransportRegistry/SmartConnectDecisionEngine/AutoGatewaySelector/
 * TransportOrchestrator/VpnController/production connection UI, exactly
 * like B45A's own debug-only harness.
 */
enum class B46HysteriaSpikePhase {
    IDLE,
    STARTING,
    TUN_ESTABLISHED,
    TUN_BRIDGE_READY,
    RUNTIME_STARTED,
    FD_CONTROL_READY,
    DATA_PLANE_READY,
    STOPPING,
    STOPPED,
    ERROR,
}

/**
 * A single typed spike error - never a raw exception message surfaced as if
 * it were a production B29 diagnostics category (architecture principle 9).
 * Intentionally separate from, and never fed into, DiagnosticFailureMapping/
 * SupportDiagnosticsRecorder - see B45ASpikeState.kt's own precedent.
 */
sealed interface B46HysteriaSpikeError {
    data class TunEstablishFailed(val reason: String) : B46HysteriaSpikeError

    /** The sing-tun-driven relay (Option A, B46-2B) failed to construct/start against the TUN fd. */
    data class BridgeStartFailed(val reason: String) : B46HysteriaSpikeError

    /** The bridge process/component exited on its own - distinct from a Hysteria2 runtime exit. */
    data class BridgeExited(val reason: String) : B46HysteriaSpikeError

    /** The bridge received bytes off the TUN fd it could not parse as a valid IPv4/TCP/UDP flow. */
    data class BridgeFlowParseFailed(val reason: String) : B46HysteriaSpikeError
    data class BinaryMissing(val expectedPath: String) : B46HysteriaSpikeError
    data class RuntimeSpawnFailed(val reason: String) : B46HysteriaSpikeError
    data class RuntimeExitedUnexpectedly(val exitCode: Int) : B46HysteriaSpikeError
    data class FdControlHandoffFailed(val reason: String) : B46HysteriaSpikeError
    data class FdControlHandoffTimedOut(val waitedMillis: Long) : B46HysteriaSpikeError
    data class AuthFailed(val reason: String) : B46HysteriaSpikeError
    data class TlsFailed(val reason: String) : B46HysteriaSpikeError
    data class QuicUnreachable(val reason: String) : B46HysteriaSpikeError

    /**
     * "process started" is explicitly NOT sufficient evidence per Phase 6 -
     * these are the typed failures when the future readiness probes (real
     * proxied TCP/UDP round trips, real DNS resolution through the
     * intended path) do not complete, distinct from FdControlHandoffFailed
     * (FD Control succeeding only proves the QUIC socket was protected,
     * not that traffic flows end to end).
     */
    data class TcpProbeFailed(val reason: String) : B46HysteriaSpikeError
    data class UdpProbeFailed(val reason: String) : B46HysteriaSpikeError
    data class DnsProbeFailed(val reason: String) : B46HysteriaSpikeError
    data class StopTimedOut(val waitedMillis: Long) : B46HysteriaSpikeError
}

/**
 * Immutable snapshot of everything a future debug UI would show.
 *
 * [runtimePid] means "the pid this status currently claims ownership of" -
 * it is ALWAYS cleared (set to `null`) the moment the runtime process is
 * known to no longer be live (normal `stopped()`, or an unexpected exit
 * via [B46HysteriaSpikeTransitions.runtimeExitedUnexpectedly]), so a
 * caller can never read a stale pid and mistake it for a still-owned,
 * still-live process. [exitCode] is separate, purely diagnostic evidence
 * of how the LAST run ended and is allowed to persist independently.
 */
data class B46HysteriaSpikeStatus(
    val phase: B46HysteriaSpikePhase,
    val runtimePid: Int? = null,
    val fdControlRequestCount: Int = 0,
    val fdControlFailureCount: Int = 0,
    val exitCode: Int? = null,
    val lastError: B46HysteriaSpikeError? = null,
) {
    companion object {
        val IDLE = B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.IDLE)

        /** The terminal state a normal, completed stop reaches - see [B46HysteriaSpikeTransitions.stopped]. */
        val STOPPED = B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.STOPPED)
    }
}

/**
 * The state machine's own transition rules, kept separate from any I/O so
 * they can be unit tested exhaustively without a real process, TUN, or
 * Unix-domain socket. Mirrors B45ASpikeTransitions's separation of pure
 * transition logic from the (not-yet-written) I/O-performing runtime class.
 *
 * Ordering encodes Phase 5/6's design: TUN_ESTABLISHED (Nova owns/creates
 * the TUN, per the doc's TUN-ownership decision) must happen before
 * RUNTIME_STARTED (the Hysteria2 process/runtime is launched), which must
 * happen before FD_CONTROL_READY (the FD Control Unix-domain-socket
 * handshake completed and the QUIC outbound socket was protect()'d), which
 * must happen before DATA_PLANE_READY (a real proxied traffic probe
 * succeeded - never inferred from process-alive alone, per Phase 6).
 */
object B46HysteriaSpikeTransitions {

    /**
     * Only IDLE or STOPPED may transition to STARTING - never a double-start,
     * and, deliberately, **never directly from ERROR**. `failed()`/
     * [runtimeExitedUnexpectedly] can be entered while a runtime/process/
     * resource is still live or not yet confirmed torn down (ERROR only
     * records that something went wrong, not that cleanup finished) - so
     * ERROR is NOT treated as "safe to restart from" here. The required
     * recovery path is explicit: `ERROR -> STOPPING -> STOPPED -> STARTING`
     * (i.e. the SAME stop/cleanup path a normal session takes, `canStop`
     * already allows it from ERROR too), never a shortcut straight back to
     * STARTING.
     */
    fun canStart(current: B46HysteriaSpikeStatus): Boolean = current.phase == B46HysteriaSpikePhase.IDLE ||
        current.phase == B46HysteriaSpikePhase.STOPPED

    fun starting(): B46HysteriaSpikeStatus = B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.STARTING)

    fun tunEstablished(current: B46HysteriaSpikeStatus): B46HysteriaSpikeStatus =
        requireStartingOrLater(current).copy(phase = B46HysteriaSpikePhase.TUN_ESTABLISHED)

    /**
     * B46-2B: the sing-tun-driven relay (Option A) has been constructed
     * against the already-established TUN fd and started - a genuinely
     * separate, independently-verifiable milestone from [tunEstablished]
     * (see the phase enum's own doc). Only reachable from
     * [B46HysteriaSpikePhase.TUN_ESTABLISHED] - the bridge cannot start
     * before the fd it drives exists.
     */
    fun tunBridgeReady(current: B46HysteriaSpikeStatus): B46HysteriaSpikeStatus =
        requirePhase(current, B46HysteriaSpikePhase.TUN_ESTABLISHED)
            .copy(phase = B46HysteriaSpikePhase.TUN_BRIDGE_READY)

    /** Now gated on the bridge, not merely the TUN fd - the Hysteria2 process has nothing to talk to before the bridge is live. */
    fun runtimeStarted(current: B46HysteriaSpikeStatus, pid: Int): B46HysteriaSpikeStatus =
        requirePhase(current, B46HysteriaSpikePhase.TUN_BRIDGE_READY)
            .copy(phase = B46HysteriaSpikePhase.RUNTIME_STARTED, runtimePid = pid)

    /**
     * The bridge component exits/crashes on its own (never requested) -
     * mirrors [runtimeExitedUnexpectedly]'s "known terminated, never claim
     * ownership" discipline, applied to the bridge rather than the
     * Hysteria2 runtime process (they are separate failure domains, see
     * the architecture doc's failure taxonomy).
     */
    fun bridgeExitedUnexpectedly(current: B46HysteriaSpikeStatus, reason: String): B46HysteriaSpikeStatus = current.copy(
        phase = B46HysteriaSpikePhase.ERROR,
        runtimePid = null,
        lastError = B46HysteriaSpikeError.BridgeExited(reason),
    )

    fun fdControlReady(current: B46HysteriaSpikeStatus): B46HysteriaSpikeStatus =
        requirePhase(current, B46HysteriaSpikePhase.RUNTIME_STARTED)
            .copy(phase = B46HysteriaSpikePhase.FD_CONTROL_READY)

    fun onFdControlRequestHandled(current: B46HysteriaSpikeStatus, succeeded: Boolean): B46HysteriaSpikeStatus = current.copy(
        fdControlRequestCount = current.fdControlRequestCount + 1,
        fdControlFailureCount = if (succeeded) current.fdControlFailureCount else current.fdControlFailureCount + 1,
    )

    /** Only reachable after a real proxied-traffic probe succeeds (Phase 6) - never after mere process/FD-Control success. */
    fun dataPlaneReady(current: B46HysteriaSpikeStatus): B46HysteriaSpikeStatus =
        requirePhase(current, B46HysteriaSpikePhase.FD_CONTROL_READY)
            .copy(phase = B46HysteriaSpikePhase.DATA_PLANE_READY)

    /** Stop is idempotent from any non-IDLE/STOPPED phase - never an error to call stop twice. */
    fun canStop(current: B46HysteriaSpikeStatus): Boolean =
        current.phase != B46HysteriaSpikePhase.IDLE && current.phase != B46HysteriaSpikePhase.STOPPED

    fun stopping(current: B46HysteriaSpikeStatus): B46HysteriaSpikeStatus = current.copy(phase = B46HysteriaSpikePhase.STOPPING)

    /**
     * A completed stop reaches `STOPPED`, never silently collapsed back to
     * `IDLE` - they are distinct phases in [B46HysteriaSpikePhase] on
     * purpose (IDLE = never started; STOPPED = a session ran and was
     * cleanly torn down), and collapsing them would make `STOPPED`
     * unreachable via the normal stop path.
     */
    fun stopped(): B46HysteriaSpikeStatus = B46HysteriaSpikeStatus.STOPPED

    fun failed(current: B46HysteriaSpikeStatus, error: B46HysteriaSpikeError): B46HysteriaSpikeStatus =
        current.copy(phase = B46HysteriaSpikePhase.ERROR, lastError = error)

    /**
     * A runtime process that exits on its own (never requested) always
     * clears [B46HysteriaSpikeStatus.runtimePid] - the process is KNOWN
     * terminated, so the resulting `ERROR` status must never claim
     * ownership of a pid that no longer refers to a live process.
     * [exitCode] is kept as separate diagnostic evidence of how that run
     * ended; it is not an ownership claim.
     */
    fun runtimeExitedUnexpectedly(current: B46HysteriaSpikeStatus, exitCode: Int): B46HysteriaSpikeStatus = current.copy(
        phase = B46HysteriaSpikePhase.ERROR,
        runtimePid = null,
        exitCode = exitCode,
        lastError = B46HysteriaSpikeError.RuntimeExitedUnexpectedly(exitCode),
    )

    private fun requirePhase(current: B46HysteriaSpikeStatus, expected: B46HysteriaSpikePhase): B46HysteriaSpikeStatus {
        check(current.phase == expected) { "expected phase $expected, was ${current.phase}" }
        return current
    }

    private fun requireStartingOrLater(current: B46HysteriaSpikeStatus): B46HysteriaSpikeStatus {
        check(current.phase == B46HysteriaSpikePhase.STARTING) { "expected phase STARTING, was ${current.phase}" }
        return current
    }
}
