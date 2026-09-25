package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportStats

/**
 * B-WL-R1 - the ONE place real attempt facts become a [TransportAttemptObservation].
 * Every factory records only what the caller actually observed: a stage the
 * runtime cannot see is [AttemptStageOutcome.NOT_OBSERVED], byte counts come
 * only from real [TransportStats.Counters] (0 when the transport exposes none),
 * and nothing is inferred from a byte count. [destinationKey] must be an
 * opaque path/endpoint identity (e.g. a manifest endpoint id), never a host,
 * IP, URL or credential.
 */
object TransportAttemptObservations {

    /**
     * A UDP handshake attempt (AmneziaWG): the backend accepted the tunnel
     * (socket up), then a fresh handshake either arrived or did not within
     * the bounded handshake window. A missing handshake is recorded as a
     * timeout; it counts as "no UDP response" only when the transport's own
     * counters show zero received bytes, or expose no counters at all.
     */
    fun udpHandshake(destinationKey: String, handshakeSucceeded: Boolean, stats: TransportStats, nowEpochMillis: Long): TransportAttemptObservation {
        val counters = stats as? TransportStats.Counters
        return TransportAttemptObservation(
            destinationKey = destinationKey,
            protocol = TransportAttemptProtocol.UDP,
            connect = AttemptStageOutcome.SUCCEEDED,
            handshake = if (handshakeSucceeded) AttemptStageOutcome.SUCCEEDED else AttemptStageOutcome.FAILED,
            bytesSent = counters?.bytesSent ?: 0L,
            bytesReceived = counters?.bytesReceived ?: 0L,
            progress = if (handshakeSucceeded || (counters?.bytesReceived ?: 0L) > 0L) TrafficProgressOutcome.NOT_OBSERVED else TrafficProgressOutcome.NO_PAYLOAD,
            termination = if (handshakeSucceeded) AttemptTermination.NONE_OBSERVED else AttemptTermination.TIMEOUT,
            observedAtEpochMillis = nowEpochMillis,
        )
    }

    /**
     * A TCP-based (Xray) attempt that passed B33 remote confirmation: a real
     * request/response round trip through the tunnel, so TCP connect and the
     * TLS/REALITY handshake demonstrably succeeded. Sustained progress is not
     * claimed here - that is [progress]'s job.
     */
    fun tcpConfirmed(destinationKey: String, stats: TransportStats, nowEpochMillis: Long): TransportAttemptObservation {
        val counters = stats as? TransportStats.Counters
        return TransportAttemptObservation(
            destinationKey = destinationKey,
            protocol = TransportAttemptProtocol.TCP,
            connect = AttemptStageOutcome.SUCCEEDED,
            handshake = AttemptStageOutcome.SUCCEEDED,
            bytesSent = counters?.bytesSent ?: 0L,
            bytesReceived = counters?.bytesReceived ?: 0L,
            progress = TrafficProgressOutcome.NOT_OBSERVED,
            termination = AttemptTermination.NONE_OBSERVED,
            observedAtEpochMillis = nowEpochMillis,
        )
    }

    /**
     * A TCP-based (Xray) attempt whose remote confirmation never succeeded.
     * The native core does not report WHICH stage failed (TCP connect vs.
     * TLS/REALITY handshake vs. first response), so both stages stay
     * NOT_OBSERVED: this observation is diagnostic only and, by construction,
     * can never on its own produce a UDP-filtering, early-drop or
     * full-shutdown classification.
     */
    fun tcpUnconfirmed(destinationKey: String, nowEpochMillis: Long): TransportAttemptObservation = TransportAttemptObservation(
        destinationKey = destinationKey,
        protocol = TransportAttemptProtocol.TCP,
        connect = AttemptStageOutcome.NOT_OBSERVED,
        handshake = AttemptStageOutcome.NOT_OBSERVED,
        bytesSent = 0L,
        bytesReceived = 0L,
        progress = TrafficProgressOutcome.NO_PAYLOAD,
        termination = AttemptTermination.TIMEOUT,
        observedAtEpochMillis = nowEpochMillis,
    )

    /**
     * A post-connect traffic-progress verdict on an already confirmed session
     * (connect + handshake succeeded by definition). Returns null for verdicts
     * that carry no progress claim (VERIFYING/IDLE/UNAVAILABLE) - nothing is
     * recorded for them.
     */
    fun progress(
        destinationKey: String,
        protocol: TransportAttemptProtocol,
        snapshot: TrafficProgressSnapshot,
        nowEpochMillis: Long,
    ): TransportAttemptObservation? {
        val verdict = snapshot.verdict
        val outcome = TrafficProgressMonitor.toProgressOutcome(verdict)
        if (outcome == TrafficProgressOutcome.NOT_OBSERVED) return null
        return TransportAttemptObservation(
            destinationKey = destinationKey,
            protocol = protocol,
            connect = AttemptStageOutcome.SUCCEEDED,
            handshake = AttemptStageOutcome.SUCCEEDED,
            bytesSent = snapshot.txBytes,
            bytesReceived = snapshot.rxBytes,
            progress = outcome,
            termination = if (TrafficProgressMonitor.isUnhealthy(verdict)) AttemptTermination.TIMEOUT else AttemptTermination.NONE_OBSERVED,
            observedAtEpochMillis = nowEpochMillis,
        )
    }
}
