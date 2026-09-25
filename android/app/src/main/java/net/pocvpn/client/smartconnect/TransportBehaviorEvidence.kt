package net.pocvpn.client.smartconnect

/**
 * B-WL1 - per-attempt transport BEHAVIOR evidence: what actually happened on
 * the wire during one connection attempt (connect -> handshake -> first
 * payload -> sustained progress), as opposed to the reachability PROBES
 * [RestrictionEvidence] already carries. This is the dimension a
 * whitelist/default-deny or early-drop network shows up in: a small HTTPS
 * probe can succeed while every sustained flow to the same place stalls.
 *
 * Closed, non-secret shape (same "the format itself cannot represent it"
 * discipline as ConnectionOutcome/PathHistoryStore): [destinationKey] must be
 * an OPAQUE caller-supplied identity (e.g. PathCandidate.historyPathId or an
 * HMAC of it) - never a host, IP, URL, UUID or key - and there is no field
 * for payload contents, headers, credentials or raw addresses.
 */
data class TransportAttemptObservation(
    val destinationKey: String,
    val protocol: TransportAttemptProtocol,
    /** TCP connect / UDP socket-and-first-send outcome. */
    val connect: AttemptStageOutcome,
    /** TLS/REALITY/AWG (or other transport) handshake outcome. */
    val handshake: AttemptStageOutcome,
    val bytesSent: Long,
    val bytesReceived: Long,
    val progress: TrafficProgressOutcome,
    val termination: AttemptTermination,
    val observedAtEpochMillis: Long,
)

enum class TransportAttemptProtocol { TCP, UDP }

enum class AttemptStageOutcome { SUCCEEDED, FAILED, NOT_OBSERVED }

/**
 * How traffic progressed after the handshake, as decided by
 * [TrafficProgressMonitor] (B-WL7) over a bounded health window - never by a
 * fixed byte count. [STALLED_AFTER_INITIAL_PAYLOAD] means "some payload
 * arrived, then no further progress for the whole stall window", whatever the
 * byte total was.
 */
enum class TrafficProgressOutcome { SUSTAINED, STALLED_AFTER_INITIAL_PAYLOAD, NO_PAYLOAD, NOT_OBSERVED }

enum class AttemptTermination { NONE_OBSERVED, RST, FIN, TIMEOUT }

/** B-WL1 - the closed behavioral patterns [TransportBehaviorAnalyzer] can report. */
enum class TransportBehaviorPattern {
    /** Sustained end-to-end progress observed - positive evidence the network carries real traffic. */
    SUSTAINED_PROGRESS,
    /** UDP attempts got no response while TCP handshakes/progress succeeded. */
    UDP_NO_RESPONSE_TCP_OK,
    /** One TCP flow: connect + handshake + initial payload, then stall without RST. */
    EARLY_DROP,
    /** The same early-drop pattern reproduced on repeated attempts to ONE destination. */
    REPEATED_EARLY_DROP,
    /** The early-drop pattern reproduced across at least two DISTINCT destinations. */
    REPEATED_EARLY_DROP_MULTI_DESTINATION,
    /** Every attempt, across at least two distinct destinations, failed before any payload. */
    ALL_CONNECT_FAILED,
    /** Too little, stale, or contradictory evidence - never a guess. */
    INSUFFICIENT,
}

enum class TransportBehaviorSignal {
    TCP_CONNECT, TCP_CONNECT_FAILED, TLS_HANDSHAKE, INITIAL_PAYLOAD, BYTES_RECEIVED,
    STREAM_PROGRESS, STALL, RST, FIN, TIMEOUT, UDP_RESPONSE, UDP_NO_RESPONSE,
    REPEATED_FAILURE, MULTIPLE_DESTINATIONS, CONTRADICTORY,
}

/**
 * Pattern + qualitative confidence + the evidence it rests on. [quality]
 * deliberately reuses B40's [RestrictionEvidenceQuality] - a closed
 * qualitative scale, not a probability - rather than inventing a second,
 * numeric confidence model next to the existing one.
 */
data class TransportBehaviorAssessment(
    val pattern: TransportBehaviorPattern,
    val quality: RestrictionEvidenceQuality,
    val signals: Set<TransportBehaviorSignal>,
    val observationCount: Int,
)

/**
 * B-WL1 - pure, deterministic analysis of recent [TransportAttemptObservation]s.
 * Detects patterns from BEHAVIOR (connect/handshake/payload/stall/termination
 * combinations), never from a specific byte count: there is no "16 KB" or any
 * other magic threshold anywhere in this object. A single observation never
 * yields more than LOW quality; reproduction raises it; mixed evidence
 * (early-drop on one path, sustained progress on another) is reported as
 * [TransportBehaviorPattern.INSUFFICIENT] rather than a network-wide claim.
 */
object TransportBehaviorAnalyzer {

    fun assess(
        observations: List<TransportAttemptObservation>,
        nowEpochMillis: Long = Long.MAX_VALUE,
        staleAfterMillis: Long = RestrictionClassifier.DEFAULT_STALE_AFTER_MILLIS,
    ): TransportBehaviorAssessment {
        val fresh = observations.filter { isFresh(it.observedAtEpochMillis, nowEpochMillis, staleAfterMillis) }
        val signals = linkedSetOf<TransportBehaviorSignal>()
        fresh.forEach { signals += signalsOf(it) }
        if (fresh.isEmpty()) return TransportBehaviorAssessment(TransportBehaviorPattern.INSUFFICIENT, RestrictionEvidenceQuality.INSUFFICIENT, emptySet(), 0)

        val tcp = fresh.filter { it.protocol == TransportAttemptProtocol.TCP }
        val udp = fresh.filter { it.protocol == TransportAttemptProtocol.UDP }
        val earlyDrops = tcp.filter(::isEarlyDrop)
        val sustainedTcp = tcp.filter { it.progress == TrafficProgressOutcome.SUSTAINED }
        val sustainedAny = fresh.filter { it.progress == TrafficProgressOutcome.SUSTAINED }
        val earlyDropDestinations = earlyDrops.map { it.destinationKey }.toSet()

        fun result(pattern: TransportBehaviorPattern, quality: RestrictionEvidenceQuality) =
            TransportBehaviorAssessment(pattern, quality, signals, fresh.size)

        if (earlyDrops.isNotEmpty()) {
            if (sustainedTcp.isNotEmpty()) {
                // Destination-specific stall while other TCP flows progress is
                // not a network-wide pattern - refuse to generalize it.
                signals += TransportBehaviorSignal.CONTRADICTORY
                return result(TransportBehaviorPattern.INSUFFICIENT, RestrictionEvidenceQuality.INSUFFICIENT)
            }
            if (earlyDrops.size >= 2) signals += TransportBehaviorSignal.REPEATED_FAILURE
            return when {
                earlyDropDestinations.size >= 2 -> {
                    signals += TransportBehaviorSignal.MULTIPLE_DESTINATIONS
                    result(TransportBehaviorPattern.REPEATED_EARLY_DROP_MULTI_DESTINATION, RestrictionEvidenceQuality.HIGH)
                }
                earlyDrops.size >= 2 -> result(TransportBehaviorPattern.REPEATED_EARLY_DROP, RestrictionEvidenceQuality.HIGH)
                else -> result(TransportBehaviorPattern.EARLY_DROP, RestrictionEvidenceQuality.LOW)
            }
        }

        val udpNoResponse = udp.filter(::isUdpNoResponse)
        val udpResponded = udp.any { it.bytesReceived > 0 || it.handshake == AttemptStageOutcome.SUCCEEDED }
        val tcpWorks = tcp.any { it.handshake == AttemptStageOutcome.SUCCEEDED || it.progress == TrafficProgressOutcome.SUSTAINED }
        if (udpNoResponse.isNotEmpty() && !udpResponded && tcpWorks) {
            if (udpNoResponse.size >= 2) signals += TransportBehaviorSignal.REPEATED_FAILURE
            val quality = if (udpNoResponse.size >= 2) RestrictionEvidenceQuality.MEDIUM else RestrictionEvidenceQuality.LOW
            return result(TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK, quality)
        }

        val allFailedBeforePayload = fresh.all(::failedBeforePayload)
        val destinations = fresh.map { it.destinationKey }.toSet()
        if (allFailedBeforePayload && fresh.size >= 2 && destinations.size >= 2) {
            signals += TransportBehaviorSignal.REPEATED_FAILURE
            signals += TransportBehaviorSignal.MULTIPLE_DESTINATIONS
            return result(TransportBehaviorPattern.ALL_CONNECT_FAILED, RestrictionEvidenceQuality.MEDIUM)
        }

        if (sustainedAny.isNotEmpty() && fresh.none(::failedBeforePayload)) {
            val quality = if (sustainedAny.size >= 2) RestrictionEvidenceQuality.HIGH else RestrictionEvidenceQuality.MEDIUM
            return result(TransportBehaviorPattern.SUSTAINED_PROGRESS, quality)
        }

        return result(TransportBehaviorPattern.INSUFFICIENT, RestrictionEvidenceQuality.INSUFFICIENT)
    }

    /** Connected + handshaken + some payload, then no progress, and NOT reset by the peer. */
    private fun isEarlyDrop(o: TransportAttemptObservation): Boolean =
        o.connect == AttemptStageOutcome.SUCCEEDED &&
            o.handshake == AttemptStageOutcome.SUCCEEDED &&
            o.bytesReceived > 0 &&
            o.progress == TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD &&
            o.termination != AttemptTermination.RST

    private fun isUdpNoResponse(o: TransportAttemptObservation): Boolean =
        o.protocol == TransportAttemptProtocol.UDP &&
            o.bytesReceived == 0L &&
            o.handshake != AttemptStageOutcome.SUCCEEDED &&
            (o.handshake == AttemptStageOutcome.FAILED || o.termination == AttemptTermination.TIMEOUT)

    private fun failedBeforePayload(o: TransportAttemptObservation): Boolean = when (o.protocol) {
        TransportAttemptProtocol.TCP -> o.connect == AttemptStageOutcome.FAILED && o.bytesReceived == 0L
        TransportAttemptProtocol.UDP -> isUdpNoResponse(o)
    }

    private fun signalsOf(o: TransportAttemptObservation): Set<TransportBehaviorSignal> {
        val s = linkedSetOf<TransportBehaviorSignal>()
        when (o.protocol) {
            TransportAttemptProtocol.TCP -> {
                if (o.connect == AttemptStageOutcome.SUCCEEDED) s += TransportBehaviorSignal.TCP_CONNECT
                if (o.connect == AttemptStageOutcome.FAILED) s += TransportBehaviorSignal.TCP_CONNECT_FAILED
                if (o.handshake == AttemptStageOutcome.SUCCEEDED) s += TransportBehaviorSignal.TLS_HANDSHAKE
            }
            TransportAttemptProtocol.UDP -> {
                if (o.bytesReceived > 0 || o.handshake == AttemptStageOutcome.SUCCEEDED) s += TransportBehaviorSignal.UDP_RESPONSE
                if (isUdpNoResponse(o)) s += TransportBehaviorSignal.UDP_NO_RESPONSE
            }
        }
        if (o.bytesReceived > 0) {
            s += TransportBehaviorSignal.INITIAL_PAYLOAD
            s += TransportBehaviorSignal.BYTES_RECEIVED
        }
        when (o.progress) {
            TrafficProgressOutcome.SUSTAINED -> s += TransportBehaviorSignal.STREAM_PROGRESS
            TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD -> s += TransportBehaviorSignal.STALL
            TrafficProgressOutcome.NO_PAYLOAD, TrafficProgressOutcome.NOT_OBSERVED -> Unit
        }
        when (o.termination) {
            AttemptTermination.RST -> s += TransportBehaviorSignal.RST
            AttemptTermination.FIN -> s += TransportBehaviorSignal.FIN
            AttemptTermination.TIMEOUT -> s += TransportBehaviorSignal.TIMEOUT
            AttemptTermination.NONE_OBSERVED -> Unit
        }
        return s
    }

    /** Same freshness rule as RestrictionClassifier's own probe staleness (non-negative age, bounded). */
    private fun isFresh(epochMillis: Long, nowEpochMillis: Long, staleAfterMillis: Long): Boolean {
        if (nowEpochMillis == Long.MAX_VALUE) return true
        val age = nowEpochMillis - epochMillis
        return age in 0..staleAfterMillis
    }
}
