package net.pocvpn.client.smartconnect

/**
 * Release counterpart of the debug-only path override (see the `debug`
 * source set's DebugPathOverride - same package, same name). AGP compiles
 * exactly one of the two, so a release build only has this body:
 * [applyAndConsume] returns the production attempt list unchanged (same
 * instance), there is no status line, no action, and nothing can switch it on.
 */
object DebugPathOverride {
    fun applyAndConsume(
        attempts: List<AutoGatewaySelector.AutoConnectAttempt>,
    ): List<AutoGatewaySelector.AutoConnectAttempt> = attempts

    fun forceRelayedVia(ingressEndpointId: String) {}

    fun clear() {}

    fun lastAppliedAttemptKeys(): List<String>? = null

    fun statusLine(): String? = null

    fun actions(): List<Pair<String, () -> Unit>> = emptyList()
}
