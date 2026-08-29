package net.pocvpn.client.smartconnect

import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * B8J - ONE bounded HTTPS reachability probe against the existing gateway.
 * Answers exactly one question: did TCP+TLS+HTTP all succeed, REGARDLESS of
 * the HTTP status code returned (a 4xx still means the gateway answered -
 * see interpretProbeAttempt's own docs). No credentials, no VPN public/
 * private keys, no provisioning request - a bare HEAD with no body and no
 * auth header is the whole request.
 */
fun interface GatewayReachabilityProbe {
    suspend fun isReachable(): Boolean
}

/**
 * What one raw attempt observed - JVM-testable without real network I/O
 * (see interpretProbeAttempt). Public (not internal) ONLY because it
 * appears in HttpsGatewayReachabilityProbe's public `performAttempt` test
 * seam parameter - it carries nothing sensitive (a status code or a
 * failure/timeout marker), unlike e.g. ConnectionOutcome's own closed field
 * set, which is public for a materially different reason (it's a real
 * production model, not a test seam type).
 */
sealed class ProbeAttemptOutcome {
    data class HttpResponse(val statusCode: Int) : ProbeAttemptOutcome()
    object TlsOrConnectFailure : ProbeAttemptOutcome()
    object TimedOut : ProbeAttemptOutcome()
}

/**
 * ANY successfully-received HTTP response - including a 4xx - means
 * REACHABLE: the point of this probe is transport-layer reachability
 * (TCP/TLS/HTTP all completing), not application-layer correctness. Only a
 * TLS/connect failure or a bounded timeout means UNREACHABLE.
 */
internal fun interpretProbeAttempt(outcome: ProbeAttemptOutcome): Boolean = when (outcome) {
    is ProbeAttemptOutcome.HttpResponse -> true
    ProbeAttemptOutcome.TlsOrConnectFailure -> false
    ProbeAttemptOutcome.TimedOut -> false
}

/**
 * Real implementation: normal platform CA validation only (the default
 * HttpsURLConnection trust manager - never pinned/bypassed, never a
 * trust-all TrustManager). [performAttempt] is an additive test seam - real
 * network I/O is the production default; tests inject a fake attempt so
 * this class's TIMEOUT/CANCELLATION behavior is provable without touching
 * the network (see GatewayReachabilityProbeTest).
 */
class HttpsGatewayReachabilityProbe(
    private val urlString: String = DEFAULT_GATEWAY_HTTPS_URL,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    private val performAttempt: suspend () -> ProbeAttemptOutcome = { performRealAttempt(urlString, timeoutMs) },
) : GatewayReachabilityProbe {

    /** Bounded by [timeoutMs] AND cancellable - withTimeoutOrNull is a normal coroutine suspension point, not a non-cancellable blocking wait. */
    override suspend fun isReachable(): Boolean {
        val outcome = withTimeoutOrNull(timeoutMs) { performAttempt() } ?: ProbeAttemptOutcome.TimedOut
        return interpretProbeAttempt(outcome)
    }

    companion object {
        /** The existing pinned gateway (see B5/gateway/README.md) - no new endpoint, no provisioning request. */
        const val DEFAULT_GATEWAY_HTTPS_URL = "https://152.70.43.1"
        const val DEFAULT_TIMEOUT_MS = 4_000L

        private suspend fun performRealAttempt(urlString: String, timeoutMs: Long): ProbeAttemptOutcome =
            withContext(Dispatchers.IO) {
                try {
                    val connection = URL(urlString).openConnection() as HttpsURLConnection
                    connection.requestMethod = "HEAD" // no body, no credentials, no provisioning payload
                    connection.connectTimeout = timeoutMs.toInt()
                    connection.readTimeout = timeoutMs.toInt()
                    connection.instanceFollowRedirects = false
                    try {
                        val code = connection.responseCode
                        ProbeAttemptOutcome.HttpResponse(code)
                    } finally {
                        connection.disconnect()
                    }
                } catch (e: SSLException) {
                    ProbeAttemptOutcome.TlsOrConnectFailure
                } catch (e: IOException) {
                    ProbeAttemptOutcome.TlsOrConnectFailure
                }
            }
    }
}
