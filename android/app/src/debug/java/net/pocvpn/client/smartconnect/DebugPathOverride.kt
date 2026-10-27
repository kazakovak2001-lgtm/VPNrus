package net.pocvpn.client.smartconnect

/**
 * B57 relayed-watchdog physical validation - debug-only "Force Path:
 * RELAYED" for the NEXT Auto connect. The `release` build type compiles a
 * no-op counterpart with the same package and name instead
 * (`src/release/.../DebugPathOverride.kt`) - the SAME build-type-scoped
 * pattern as [net.pocvpn.client.diagnostics.support.LocalDiagnosticsExporter] -
 * so no release class or dex contains this filter, its labels or a way to
 * set it.
 *
 * It never ranks, scores, builds or dials anything itself: [applyAndConsume]
 * only drops the [AutoGatewaySelector.AutoConnectAttempt.DirectAttempt]
 * entries from the list MainViewModel.connectAuto already built through
 * the unchanged production [AutoGatewaySelector.buildCombinedAttempts], so
 * the remaining Relayed attempts keep their production order, scores and
 * pinned bindings and go through the unchanged attemptCombined/
 * attemptRelayedAttempt execution path (and its watchdog). Fail-closed: if
 * that list has no Relayed attempt the result is empty and connectAuto
 * reports NoCandidateAvailable - never a silent fallback to Direct, which
 * would make a forced-relay test pass on a Direct session.
 *
 * One-shot, like the debug transport force: applying it resets it to AUTO.
 * Only connectAuto applies it - a MANUAL-mode connect leaves it pending,
 * which [statusLine] says explicitly. Process-local, never persisted: an
 * app restart always returns to AUTO.
 */
object DebugPathOverride {

    private enum class Mode { AUTO, RELAYED }

    @Volatile private var mode: Mode = Mode.AUTO

    // historyPathId of the Relayed attempts the last forced connect kept -
    // shown in [statusLine] so the evidence names the exact relay path.
    @Volatile private var lastApplied: List<String>? = null

    fun forceRelayed() {
        mode = Mode.RELAYED
    }

    fun clear() {
        mode = Mode.AUTO
    }

    fun applyAndConsume(
        attempts: List<AutoGatewaySelector.AutoConnectAttempt>,
    ): List<AutoGatewaySelector.AutoConnectAttempt> {
        if (mode != Mode.RELAYED) return attempts
        mode = Mode.AUTO
        val relayed = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>()
        lastApplied = relayed.map { it.attemptKey }
        return relayed
    }

    fun statusLine(): String? {
        val pending = when (mode) {
            Mode.AUTO -> "AUTO"
            Mode.RELAYED -> "RELAYED (applies to the next Auto-mode connect)"
        }
        val last = lastApplied?.let { if (it.isEmpty()) "none (fail-closed)" else it.joinToString(", ") } ?: "-"
        return "Path preference: $pending (debug only); last forced connect kept: $last"
    }

    fun actions(): List<Pair<String, () -> Unit>> = listOf(
        "Force Path RELAYED on next Auto connect" to ::forceRelayed,
        "Clear path force / AUTO" to ::clear,
    )
}
