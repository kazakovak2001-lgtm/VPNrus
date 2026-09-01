package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.withTimeoutOrNull

/**
 * B21-fix - closes the architectural gap the QUIC physical test exposed:
 * `startLoop()` returning without throwing only means the Go runtime's
 * goroutines launched, never that a real proxied session succeeded (a
 * config-load or dial failure surfaces asynchronously, if at all - see
 * [XrayCoreDiagnostics] for why it was previously invisible). [XrayCoreController]
 * now requires one of these to be [Ready] before it will ever report
 * [XrayCoreStartOutcome.Started].
 */
sealed class XrayDataPlaneReadiness {
    data class Ready(val latencyMs: Long) : XrayDataPlaneReadiness()
    object Timeout : XrayDataPlaneReadiness()
    data class Failed(val reason: String) : XrayDataPlaneReadiness()
}

/**
 * B21-fix - transport-agnostic Xray data-plane readiness check. Reuses
 * [XrayCoreRuntime.measureDelay] (mirrors AndroidLibXrayLite's
 * `CoreController.measureDelay(url)`, verified present in the shipped AAR's
 * API via javap - the ONE genuine "does the currently running outbound pass
 * real traffic" signal this AAR exports) rather than inventing a new
 * mechanism or a second daemon. One implementation covers XRAY_REALITY,
 * TLS_TCP, and QUIC identically because each renders exactly one outbound
 * into the running core (see [XrayConfigRenderer]) - `measureDelay` dials
 * whichever outbound is currently loaded, with no transport-specific
 * branching required here.
 */
object XrayDataPlaneReadinessCheck {
    const val DEFAULT_TIMEOUT_MS = 8_000L

    /**
     * A generic, non-tunnel-specific 204 endpoint - only used to prove the
     * outbound can complete a real request, never anything server/gateway
     * specific (no coupling to Frankfurt/Stockholm or any manifest entry).
     */
    const val DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"

    suspend fun check(
        coreRuntime: XrayCoreRuntime,
        testUrl: String = DEFAULT_TEST_URL,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    ): XrayDataPlaneReadiness {
        return try {
            val latency = withTimeoutOrNull(timeoutMs) { coreRuntime.measureDelay(testUrl) }
                ?: return XrayDataPlaneReadiness.Timeout
            if (latency < 0) {
                XrayDataPlaneReadiness.Failed("negative latency")
            } else {
                XrayDataPlaneReadiness.Ready(latency)
            }
        } catch (t: Throwable) {
            XrayDataPlaneReadiness.Failed(t.javaClass.simpleName)
        }
    }
}
