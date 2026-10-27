package net.pocvpn.client.smartconnect

/**
 * B57 - the `release` build type's own counterpart to the debug-only path
 * override (see the `debug` source set's [DebugPathOverride] - same
 * package, same name - for the real implementation's docs). AGP compiles
 * exactly one of the two into a build, so a release build contains only
 * this body: [applyAndConsume] returns the production attempt list
 * unchanged (the same instance), there is no status line and no action,
 * and nothing can switch it on.
 */
object DebugPathOverride {
    fun applyAndConsume(
        attempts: List<AutoGatewaySelector.AutoConnectAttempt>,
    ): List<AutoGatewaySelector.AutoConnectAttempt> = attempts

    fun statusLine(): String? = null

    fun actions(): List<Pair<String, () -> Unit>> = emptyList()
}
