package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportKind
import org.json.JSONArray
import org.json.JSONObject

/** Lifecycle of one bounded B-WL7 check as the field report sees it. */
enum class DataPlaneCheckStatus {
    /** Still sampling when the report was taken. */
    RUNNING,
    /** The loop ended normally; [DataPlaneCheckRecord.end] says why. */
    COMPLETED,
    /** Cancelled before it ended (disconnect, new connect, reconnect). No verdict was acted on. */
    CANCELLED,
    /** Ended by an unexpected exception. No verdict was acted on. */
    ABORTED,
}

/**
 * B-WL7 M1 - what the one independent-egress probe of a check returned, as
 * far as the caller can tell. NOT_REACHED also covers every failure the
 * `:xray` side or the IPC bridge already folded into NOT_REACHED (TLS or
 * HTTP-status failure, its own 6 s / 8 s bounds, a changed session) - those
 * are not distinguishable here. CALLER_TIMEOUT and EXCEPTION are only the
 * controller's own 10 s bound and an exception thrown back to it.
 */
enum class EgressProbeOutcome { REACHED, NOT_REACHED, UNAVAILABLE, CALLER_TIMEOUT, EXCEPTION }

/**
 * One probe per check at most. [verdictBefore] is the unhealthy verdict that
 * triggered it. [rebaselined] is true only when REACHED was followed by a
 * fresh counter read, i.e. when the check really restarted from it.
 * [durationMs] is measured wall-clock time of the call.
 */
data class EgressProbeRecord(
    val outcome: EgressProbeOutcome,
    val durationMs: Long,
    val verdictBefore: TrafficProgressVerdict,
    val rebaselined: Boolean,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("outcome", outcome.name)
        .put("durationMs", durationMs)
        .put("verdictBefore", verdictBefore.name)
        .put("rebaselined", rebaselined)
}

/** What the controller did with a COMPLETED check's verdict. */
enum class DataPlaneCheckAction {
    /** Not a dead-data-plane verdict: the session was left as it was. */
    PRESERVED,
    /** NO_PAYLOAD/STALLED: the session was ended with DataPlaneNoTraffic. */
    TORN_DOWN,
    /** NO_PAYLOAD/STALLED, but the session was no longer this check's (newer attempt, disconnect, state change): nothing was touched. */
    STALE_IGNORED,
}

/**
 * B-WL7 - one data-plane check, kept in memory so the field report carries it
 * independently of logcat (whose buffer can rotate it away before export).
 * [checkId] is unique per process and increases with every check, so a record
 * always names exactly one session's check - a later session gets its own id
 * and never inherits an earlier verdict. [silentForMs] is NOMINAL (poll index
 * x poll interval), not measured device time. Non-secret: counts and windows
 * only, never payload, keys or config.
 */
data class DataPlaneCheckRecord(
    val checkId: Long,
    val transport: TransportKind,
    val status: DataPlaneCheckStatus,
    val verdict: TrafficProgressVerdict,
    val stallWindowMs: Long,
    val verificationWindowMs: Long,
    val silentForMs: Long?,
    val samples: Int,
    val polls: Int,
    val maxPolls: Int,
    /** Null unless [status] is COMPLETED. */
    val end: TrafficProgressCheckEnd?,
    val startedAtEpochMillis: Long,
    /** Null while RUNNING. */
    val finishedAtEpochMillis: Long?,
    /** VpnController's reconnect generation that owned this check; null when not supplied. */
    val generation: Long? = null,
    /** Null when no probe was asked (the check never saw an unhealthy verdict, or the transport has none). */
    val egressProbe: EgressProbeRecord? = null,
    /** Null until a COMPLETED check's verdict was acted on; stays null for CANCELLED/ABORTED. */
    val action: DataPlaneCheckAction? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("checkId", checkId)
        .put("transport", transport.name)
        .put("status", status.name)
        .put("verdict", verdict.name)
        .put("stallWindowMs", stallWindowMs)
        .put("verificationWindowMs", verificationWindowMs)
        .put("silentForMs", silentForMs ?: JSONObject.NULL)
        .put("samples", samples)
        .put("polls", polls)
        .put("maxPolls", maxPolls)
        .put("end", end?.name ?: JSONObject.NULL)
        .put("startedAtEpochMillis", startedAtEpochMillis)
        .put("finishedAtEpochMillis", finishedAtEpochMillis ?: JSONObject.NULL)
        .put("generation", generation ?: JSONObject.NULL)
        .put("egressProbe", egressProbe?.toJson() ?: JSONObject.NULL)
        .put("action", action?.name ?: JSONObject.NULL)
}

/**
 * Bounded, thread-safe in-memory log of the most recent B-WL7 checks. Written
 * only by VpnController's progress observation; read only by the field report.
 * Reading never changes it, so a failed or repeated export cannot alter or
 * consume a record.
 */
class DataPlaneCheckLog(
    private val capacity: Int = DEFAULT_CAPACITY,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    private val lock = Any()
    private val records = ArrayDeque<DataPlaneCheckRecord>()
    private var nextId = 1L

    /** Opens a RUNNING record and returns its id. */
    fun start(transport: TransportKind, policy: TrafficProgressPolicy, maxPolls: Int, generation: Long? = null): Long = synchronized(lock) {
        val id = nextId++
        add(
            DataPlaneCheckRecord(
                checkId = id, transport = transport, status = DataPlaneCheckStatus.RUNNING,
                verdict = TrafficProgressVerdict.VERIFYING,
                stallWindowMs = policy.stallWindowMillis, verificationWindowMs = policy.verificationWindowMillis,
                silentForMs = null, samples = 0, polls = 0, maxPolls = maxPolls, end = null,
                startedAtEpochMillis = clock(), finishedAtEpochMillis = null, generation = generation,
            ),
        )
        id
    }

    /** [maxPolls] replaces the opening value when a REACHED probe extended the window. */
    fun complete(
        checkId: Long,
        verdict: TrafficProgressVerdict,
        samples: List<TrafficProgressSample>,
        polls: Int,
        end: TrafficProgressCheckEnd,
        maxPolls: Int? = null,
    ) = finish(checkId, DataPlaneCheckStatus.COMPLETED, verdict, samples, polls, end, maxPolls)

    /** Attaches the check's one probe while it is still RUNNING; a second call or a finished record is ignored. */
    fun recordEgressProbe(checkId: Long, probe: EgressProbeRecord) = synchronized(lock) {
        val index = records.indexOfFirst { it.checkId == checkId }
        if (index < 0 || records[index].status != DataPlaneCheckStatus.RUNNING || records[index].egressProbe != null) return@synchronized
        records[index] = records[index].copy(egressProbe = probe)
    }

    /** Sets the action once, only on a COMPLETED record. */
    fun recordAction(checkId: Long, action: DataPlaneCheckAction) = synchronized(lock) {
        val index = records.indexOfFirst { it.checkId == checkId }
        if (index < 0 || records[index].status != DataPlaneCheckStatus.COMPLETED || records[index].action != null) return@synchronized
        records[index] = records[index].copy(action = action)
    }

    /** Ends a still-RUNNING record as CANCELLED or ABORTED with whatever it had sampled. */
    fun interrupt(checkId: Long, cancelled: Boolean, verdict: TrafficProgressVerdict, samples: List<TrafficProgressSample>, polls: Int) =
        finish(checkId, if (cancelled) DataPlaneCheckStatus.CANCELLED else DataPlaneCheckStatus.ABORTED, verdict, samples, polls, null)

    fun snapshot(): List<DataPlaneCheckRecord> = synchronized(lock) { records.toList() }

    private fun finish(
        checkId: Long,
        status: DataPlaneCheckStatus,
        verdict: TrafficProgressVerdict,
        samples: List<TrafficProgressSample>,
        polls: Int,
        end: TrafficProgressCheckEnd?,
        maxPolls: Int? = null,
    ) = synchronized(lock) {
        val index = records.indexOfFirst { it.checkId == checkId }
        // Already evicted, or already finished: never overwrite a final record.
        if (index < 0 || records[index].status != DataPlaneCheckStatus.RUNNING) return@synchronized
        records[index] = records[index].copy(
            status = status, verdict = verdict,
            silentForMs = TrafficProgressMonitor.silentForMillis(samples),
            samples = samples.size, polls = polls, end = end,
            maxPolls = maxPolls ?: records[index].maxPolls,
            finishedAtEpochMillis = clock(),
        )
    }

    private fun add(record: DataPlaneCheckRecord) {
        records.addLast(record)
        while (records.size > capacity) records.removeFirst()
    }

    companion object {
        const val DEFAULT_CAPACITY = 10
        const val TIME_BASIS = "silentForMs is NOMINAL (poll index x poll interval), not measured device time"

        /**
         * The report section: status NOT_RUN when no check has been recorded
         * in this process, RECORDED otherwise. Items are oldest first; match
         * them to a run by checkId and timestamps, never by position.
         */
        fun reportJson(records: List<DataPlaneCheckRecord>): JSONObject = JSONObject()
            .put("status", if (records.isEmpty()) "NOT_RUN" else "RECORDED")
            .put("timeBasis", TIME_BASIS)
            .put("items", JSONArray().apply { records.forEach { put(it.toJson()) } })
    }
}
