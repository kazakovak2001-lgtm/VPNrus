package net.pocvpn.client.smartconnect

/**
 * Release counterpart of the debug-only path override (see the `debug`
 * source set's DebugPathOverride - same package, same name). AGP compiles
 * exactly one of the two, so a release build only has this body:
 * [applyAndConsume] returns the production attempt list unchanged (same
 * instance), there is no status line, no action, and nothing can switch it on.
 */
object DebugPathOverride {
    /** False here: [forceRelayedVia] does nothing, so a caller must not label a run as relay-forced. */
    const val isAvailable: Boolean = false

    fun applyAndConsume(
        attempts: List<AutoGatewaySelector.AutoConnectAttempt>,
    ): List<AutoGatewaySelector.AutoConnectAttempt> = attempts

    fun forceRelayedVia(ingressEndpointId: String) {}

    fun clear() {}

    fun lastAppliedAttemptKeys(): List<String>? = null

    fun statusLine(): String? = null

    fun actions(): List<Pair<String, () -> Unit>> = emptyList()
}
