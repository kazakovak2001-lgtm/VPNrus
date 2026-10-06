package net.pocvpn.client.smartconnect

/**
 * Debug-only path override for the NEXT Auto connect (B57 "Force Path:
 * RELAYED", extended for the field test to pin ONE relay ingress, e.g. the
 * CDN-fronted XHTTP ingress vs the DIRECT_IP REALITY ingress). The `release`
 * build type compiles a no-op counterpart with the same package and name
 * (`src/release/.../DebugPathOverride.kt`) - the same build-type-scoped
 * pattern as LocalDiagnosticsExporter - so no release class contains this
 * filter or a way to set it.
 *
 * It never ranks, scores, builds or dials anything itself: [applyAndConsume]
 * only drops entries from the list MainViewModel.connectAuto already built
 * through the unchanged production AutoGatewaySelector.buildCombinedAttempts,
 * so the kept Relayed attempts keep their production order, scores and
 * pinned bindings and go through the unchanged relayed execution path (and
 * its watchdog). Fail-closed: if nothing matches, the result is empty and
 * connectAuto reports NoCandidateAvailable - never a silent fallback to
 * Direct, which would make a forced-relay test pass on a Direct session.
 *
 * One-shot like the debug transport force: applying it resets it to AUTO.
 * Only connectAuto applies it - a MANUAL-mode connect leaves it pending.
 * Process-local, never persisted.
 */
object DebugPathOverride {

    private sealed class Mode {
        object Auto : Mode()
        /** Any Relayed attempt; or only those entering through [ingressEndpointId]. */
        data class Relayed(val ingressEndpointId: String?) : Mode()
    }

    @Volatile private var mode: Mode = Mode.Auto

    // historyPathId of the Relayed attempts the last forced connect kept -
    // shown in [statusLine] so the evidence names the exact relay path.
    @Volatile private var lastApplied: List<String>? = null

    fun forceRelayed() {
        mode = Mode.Relayed(null)
    }

    /** Field test: pin the next Auto connect to relays entering through [ingressEndpointId]. */
    fun forceRelayedVia(ingressEndpointId: String) {
        mode = Mode.Relayed(ingressEndpointId)
    }

    fun clear() {
        mode = Mode.Auto
    }

    fun lastAppliedAttemptKeys(): List<String>? = lastApplied

    fun applyAndConsume(
        attempts: List<AutoGatewaySelector.AutoConnectAttempt>,
    ): List<AutoGatewaySelector.AutoConnectAttempt> {
        val current = mode as? Mode.Relayed ?: return attempts
        mode = Mode.Auto
        val relayed = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>()
            .filter { current.ingressEndpointId == null || it.candidate.ingressEndpointId.value == current.ingressEndpointId }
        lastApplied = relayed.map { it.attemptKey }
        return relayed
    }

    fun statusLine(): String? {
        val pending = when (val m = mode) {
            Mode.Auto -> "AUTO"
            is Mode.Relayed -> "RELAYED${m.ingressEndpointId?.let { " via $it" } ?: ""} (applies to the next Auto-mode connect)"
        }
        val last = lastApplied?.let { if (it.isEmpty()) "none (fail-closed)" else it.joinToString(", ") } ?: "-"
        return "Path preference: $pending (debug only); last forced connect kept: $last"
    }

    fun actions(): List<Pair<String, () -> Unit>> = listOf(
        "Force Path RELAYED on next Auto connect" to ::forceRelayed,
        "Clear path force / AUTO" to ::clear,
    )
}
