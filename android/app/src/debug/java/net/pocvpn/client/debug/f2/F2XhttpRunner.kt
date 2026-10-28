package net.pocvpn.client.debug.f2

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.TransportConfig

/**
 * F2A - drives ONE bounded attempt through a [VpnTransport] (production: VlessXhttpTransport),
 * records every state transition with its elapsed time, and ALWAYS disconnects afterwards -
 * on success, failure, timeout and cancellation. It never retries: one connect() per run, so
 * the harness itself cannot create connection bursts (the core's own retries are bounded by
 * the [maxMillis] window and the final disconnect).
 */
class F2XhttpRunner(
    private val transport: VpnTransport,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    data class Event(val elapsedMs: Long, val state: String)

    sealed interface Outcome {
        data class Connected(val elapsedMs: Long) : Outcome
        data class Failed(val elapsedMs: Long, val state: String, val failureKind: String?) : Outcome
        data class TimedOut(val maxMillis: Long) : Outcome
    }

    suspend fun run(
        config: TransportConfig.XrayXhttp,
        maxMillis: Long,
        onEvent: (Event) -> Unit = {},
    ): Outcome {
        val startedAt = clockMillis()
        val terminal = CompletableDeferred<Outcome>()
        try {
            return coroutineScope {
                // Subscribed before connect() so no transition can be missed.
                val observer = launch(start = CoroutineStart.UNDISPATCHED) {
                    transport.observeState().collect { state ->
                        val elapsed = clockMillis() - startedAt
                        onEvent(Event(elapsed, describe(state)))
                        when (state) {
                            is TransportState.Connected -> terminal.complete(Outcome.Connected(elapsed))
                            is TransportState.Error ->
                                terminal.complete(Outcome.Failed(elapsed, "Error", state.failureKind?.name))
                            is TransportState.HandshakeFailed ->
                                terminal.complete(Outcome.Failed(elapsed, "HandshakeFailed", null))
                            else -> Unit
                        }
                    }
                }
                try {
                    transport.connect(config)
                    withTimeoutOrNull(maxMillis) { terminal.await() } ?: Outcome.TimedOut(maxMillis)
                } finally {
                    observer.cancel()
                }
            }
        } finally {
            // Only the session this run started: a disconnect on its own transport instance.
            withContext(NonCancellable) { runCatching { transport.disconnect() } }
        }
    }

    // State names only - never the exception message/cause, which could echo configuration.
    private fun describe(state: TransportState): String = when (state) {
        is TransportState.Error -> "Error(kind=${state.failureKind?.name ?: "none"})"
        is TransportState.Reconnecting -> "Reconnecting(${state.attempt})"
        else -> state.javaClass.simpleName
    }
}
