package net.pocvpn.client.vpn

import net.pocvpn.client.smartconnect.TrafficProgressMonitor
import net.pocvpn.client.smartconnect.TrafficProgressPolicy
import net.pocvpn.client.smartconnect.TrafficProgressSample
import net.pocvpn.client.smartconnect.TrafficProgressVerdict
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats

/**
 * H2-GATE Gap A - the Hysteria2 data-plane state machine. Pure: no clock, no
 * coroutines, no I/O. [VpnController] feeds it one stats sample per poll and
 * the results of the S1 probes it asked for, and executes the returned
 * [Action]s under its own ownership checks.
 *
 * Evidence (all scoped to the current [epoch]):
 * - E-RX / E-TX: a `Counters` sample whose rx / tx is strictly greater than
 *   the previous `Counters` sample of the same epoch. The first `Counters`
 *   sample of an epoch is only the baseline.
 * - E-LIVE: the newest sample is `Counters` (the stats producer is alive) -
 *   never forwarding evidence.
 * - E-HIST: [TrafficProgressMonitor.evaluate] returns VERIFIED over this
 *   epoch's samples only (a new epoch starts with an empty list).
 * - S1: a session-scoped probe through the Hysteria2 child's local SOCKS to
 *   the gateway. It proves that path only, never TUN/tun2socks forwarding,
 *   so it never promotes.
 *
 * Promotion (initial and from [State.REVOKED]) is E-HIST and E-RX, nothing
 * else. No probe runs before the first promotion, so S1 can never end an
 * unverified session. While Protected: an rx advance keeps it; tx without rx
 * for the verification window revokes at once (an S1 success can never undo
 * that); a quiet period of [T_QUIET_MILLIS] starts one IDLE probe whose
 * success keeps Protected only with E-LIVE. A revoke starts a new epoch and a
 * recovery episode of at most [MAX_RECOVERY_PROBES] serialized probes; two
 * consecutive failures tear the session down, successes never restore.
 *
 * Telemetry: `Unavailable` (no fresh line) is transient - it never tears down
 * (decision D4 is open) but revokes Protected at once. `Unsupported` is
 * permanent for the session - the monitor stops in [State.UNVERIFIABLE]
 * without teardown (decision D5 is open); the session stays non-Protected
 * until it ends.
 */
internal class Hysteria2DataPlaneMonitor(
    private val policy: TrafficProgressPolicy = TrafficProgressPolicy.forTransport(TransportKind.HYSTERIA2),
) {
    enum class State { VERIFYING, CONFIRMING, PROTECTED, SUSPECT, REVOKED, UNVERIFIABLE, TORN_DOWN }

    enum class ProbeKind { IDLE, RECOVERY }

    sealed interface Action {
        data object Promote : Action
        data object Revoke : Action
        data class Teardown(val reason: String) : Action
        data class StartProbe(val requestId: Long, val epoch: Long, val kind: ProbeKind) : Action
        data object CancelProbe : Action
        data object Stop : Action
    }

    private data class Outstanding(val requestId: Long, val epoch: Long, val kind: ProbeKind)

    var state: State = State.VERIFYING
        private set
    var epoch: Long = 0L
        private set
    var lastVerdict: TrafficProgressVerdict = TrafficProgressVerdict.VERIFYING
        private set
    val epochSamples: List<TrafficProgressSample> get() = samples.toList()

    private val samples = mutableListOf<TrafficProgressSample>()
    private var previous: TransportStats.Counters? = null
    private var latestIsCounters = false
    private var txSinceRx = false
    private var lastRxAt: Long? = null
    private var lastProbeOkAt: Long? = null
    private var nextIdleProbeAt = Long.MAX_VALUE
    private var outstanding: Outstanding? = null
    private var nextRequestId = 0L
    private var episodeStart = 0L
    private var episodeProbes = 0
    private var consecutiveFailures = 0
    private var lastProbeFailed = false
    private var nextRecoveryProbeAt = 0L
    private var hold = false

    val finished: Boolean get() = state == State.UNVERIFIABLE || state == State.TORN_DOWN

    fun onSample(stats: TransportStats, nowMillis: Long): List<Action> {
        if (finished) return emptyList()
        val actions = mutableListOf<Action>()
        when (stats) {
            is TransportStats.Counters -> onCounters(stats, nowMillis, actions)
            TransportStats.Unavailable -> {
                latestIsCounters = false
                if (state == State.PROTECTED || state == State.SUSPECT) revoke(nowMillis, actions, failedIdleProbe = null)
            }
            else -> {
                // Unsupported / NotImplemented: permanent for this session.
                latestIsCounters = false
                if (state == State.PROTECTED || state == State.SUSPECT) actions += Action.Revoke
                if (outstanding != null) actions += Action.CancelProbe
                outstanding = null
                state = State.UNVERIFIABLE
                actions += Action.Stop
                return actions
            }
        }
        if (!finished) schedule(nowMillis, actions)
        return actions
    }

    fun onProbeResult(requestId: Long, probeEpoch: Long, success: Boolean, nowMillis: Long): List<Action> {
        val current = outstanding ?: return emptyList()
        if (finished || current.requestId != requestId || current.epoch != probeEpoch || probeEpoch != epoch) return emptyList()
        outstanding = null
        val actions = mutableListOf<Action>()
        when {
            state == State.SUSPECT && current.kind == ProbeKind.IDLE ->
                if (success && latestIsCounters) {
                    state = State.PROTECTED
                    lastProbeOkAt = nowMillis
                    consecutiveFailures = 0
                    nextIdleProbeAt = nowMillis + T_QUIET_MILLIS
                } else {
                    revoke(nowMillis, actions, failedIdleProbe = !success)
                }
            state == State.REVOKED && current.kind == ProbeKind.RECOVERY ->
                if (success) {
                    lastProbeFailed = false
                    nextRecoveryProbeAt = nowMillis + T_QUIET_MILLIS
                } else {
                    consecutiveFailures++
                    lastProbeFailed = true
                    nextRecoveryProbeAt = nowMillis
                    if (consecutiveFailures >= TEARDOWN_CONSECUTIVE_FAILURES) {
                        state = State.TORN_DOWN
                        actions += Action.Teardown("S1 probe failed $consecutiveFailures times in a row after Protected was revoked")
                        return actions
                    }
                }
        }
        if (!finished) schedule(nowMillis, actions)
        return actions
    }

    private fun onCounters(stats: TransportStats.Counters, nowMillis: Long, actions: MutableList<Action>) {
        latestIsCounters = true
        val prev = previous
        val rxAdvance = prev != null && stats.bytesReceived > prev.bytesReceived
        val txAdvance = prev != null && stats.bytesSent > prev.bytesSent
        previous = stats
        samples += TrafficProgressSample(nowMillis, stats.bytesReceived, stats.bytesSent)
        val horizon = nowMillis - (policy.verificationWindowMillis + policy.stallWindowMillis)
        while (samples.size > 1 && samples.first().elapsedMillis < horizon) samples.removeAt(0)
        if (rxAdvance) {
            lastRxAt = nowMillis
            txSinceRx = false
            consecutiveFailures = 0
            if (outstanding != null) {
                outstanding = null
                actions += Action.CancelProbe
            }
        } else if (txAdvance) {
            txSinceRx = true
        }
        val verdict = TrafficProgressMonitor.evaluate(samples, policy)
        lastVerdict = verdict
        when (state) {
            State.VERIFYING, State.CONFIRMING, State.REVOKED -> when {
                verdict == TrafficProgressVerdict.NO_PAYLOAD || verdict == TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD -> {
                    state = State.TORN_DOWN
                    if (outstanding != null) actions += Action.CancelProbe
                    outstanding = null
                    actions += Action.Teardown(verdict.name)
                }
                verdict == TrafficProgressVerdict.VERIFIED && rxAdvance -> promote(nowMillis, actions)
                state != State.REVOKED -> state = if (verdict == TrafficProgressVerdict.VERIFIED) State.CONFIRMING else State.VERIFYING
            }
            State.PROTECTED, State.SUSPECT -> when {
                rxAdvance -> {
                    state = State.PROTECTED
                    nextIdleProbeAt = nowMillis + T_QUIET_MILLIS
                }
                txSinceRx && nowMillis - maxOf(lastRxAt ?: Long.MIN_VALUE, lastProbeOkAt ?: Long.MIN_VALUE) >= policy.verificationWindowMillis ->
                    revoke(nowMillis, actions, failedIdleProbe = null)
            }
            else -> Unit
        }
    }

    private fun promote(nowMillis: Long, actions: MutableList<Action>) {
        state = State.PROTECTED
        hold = false
        consecutiveFailures = 0
        nextIdleProbeAt = nowMillis + T_QUIET_MILLIS
        actions += Action.Promote
    }

    /** [failedIdleProbe]: null = revoked by S2 / telemetry; true/false = the IDLE probe that started this episode failed / succeeded. */
    private fun revoke(nowMillis: Long, actions: MutableList<Action>, failedIdleProbe: Boolean?) {
        state = State.REVOKED
        epoch++
        samples.clear()
        previous = null
        txSinceRx = false
        if (outstanding != null) actions += Action.CancelProbe
        outstanding = null
        episodeStart = nowMillis
        hold = false
        when (failedIdleProbe) {
            null -> {
                episodeProbes = 0
                consecutiveFailures = 0
                lastProbeFailed = false
                nextRecoveryProbeAt = nowMillis
            }
            true -> {
                episodeProbes = 1
                consecutiveFailures = 1
                lastProbeFailed = true
                nextRecoveryProbeAt = nowMillis
            }
            false -> {
                episodeProbes = 1
                consecutiveFailures = 0
                lastProbeFailed = false
                nextRecoveryProbeAt = nowMillis + T_QUIET_MILLIS
            }
        }
        actions += Action.Revoke
    }

    private fun schedule(nowMillis: Long, actions: MutableList<Action>) {
        when (state) {
            State.PROTECTED -> if (outstanding == null && nowMillis >= nextIdleProbeAt) {
                state = State.SUSPECT
                actions += startProbe(ProbeKind.IDLE)
            }
            State.REVOKED -> {
                if (hold || outstanding != null) return
                if (nowMillis - episodeStart >= RECOVERY_EPISODE_MILLIS || episodeProbes >= MAX_RECOVERY_PROBES) {
                    // Deadline or probe budget reached with no probe in flight: decide once.
                    if (lastProbeFailed) {
                        state = State.TORN_DOWN
                        actions += Action.Teardown("recovery episode ended with a failed S1 probe and no fresh S2 evidence")
                    } else {
                        hold = true
                    }
                    return
                }
                if (nowMillis >= nextRecoveryProbeAt) {
                    episodeProbes++
                    actions += startProbe(ProbeKind.RECOVERY)
                }
            }
            else -> Unit
        }
    }

    private fun startProbe(kind: ProbeKind): Action.StartProbe {
        val request = Outstanding(++nextRequestId, epoch, kind)
        outstanding = request
        return Action.StartProbe(request.requestId, request.epoch, kind)
    }

    companion object {
        /** Decided (provisional until device-tested): one IDLE probe after this long without an rx advance or S1 success. */
        const val T_QUIET_MILLIS = 60_000L
        const val TEARDOWN_CONSECUTIVE_FAILURES = 2
        /** Provisional design/test parameters - not a production-approved lifecycle bound. */
        const val MAX_RECOVERY_PROBES = 3
        const val RECOVERY_EPISODE_MILLIS = 120_000L
    }
}
