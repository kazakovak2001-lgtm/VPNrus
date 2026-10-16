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
    fun start(transport: TransportKind, policy: TrafficProgressPolicy, maxPolls: Int): Long = synchronized(lock) {
        val id = nextId++
        add(
            DataPlaneCheckRecord(
                checkId = id, transport = transport, status = DataPlaneCheckStatus.RUNNING,
                verdict = TrafficProgressVerdict.VERIFYING,
                stallWindowMs = policy.stallWindowMillis, verificationWindowMs = policy.verificationWindowMillis,
                silentForMs = null, samples = 0, polls = 0, maxPolls = maxPolls, end = null,
                startedAtEpochMillis = clock(), finishedAtEpochMillis = null,
            ),
        )
        id
    }

    fun complete(checkId: Long, verdict: TrafficProgressVerdict, samples: List<TrafficProgressSample>, polls: Int, end: TrafficProgressCheckEnd) =
        finish(checkId, DataPlaneCheckStatus.COMPLETED, verdict, samples, polls, end)

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
    ) = synchronized(lock) {
        val index = records.indexOfFirst { it.checkId == checkId }
        // Already evicted, or already finished: never overwrite a final record.
        if (index < 0 || records[index].status != DataPlaneCheckStatus.RUNNING) return@synchronized
        records[index] = records[index].copy(
            status = status, verdict = verdict,
            silentForMs = TrafficProgressMonitor.silentForMillis(samples),
            samples = samples.size, polls = polls, end = end,
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
