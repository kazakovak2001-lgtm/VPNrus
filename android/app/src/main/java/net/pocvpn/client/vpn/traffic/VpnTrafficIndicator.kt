package net.pocvpn.client.vpn.traffic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState

/** Where the live speed goes (the VPN notification in production, a fake in tests). */
interface VpnTrafficIndicatorSink {
    fun show(rate: TrafficRate)

    /** [sessionEnded] true = the Connected period is over; false = only paused (screen off). */
    fun hide(sessionEnded: Boolean)

    /** Called once, by [VpnTrafficIndicator.stop]. */
    fun release() {}
}

/**
 * Live speed indicator - the ONE sampling loop. Observation only: it reads
 * the controller's state and [counters] and never connects, disconnects,
 * reconnects or reroutes anything.
 *
 * Samples every [intervalMillis] only while [state] is Connected AND
 * [interactive] is true (screen on), with a fresh [TrafficRateMeter] per such
 * period, so a reconnect, transport switch or screen-on never mixes counters
 * of two sessions. `collectLatest` cancels the running loop before the next
 * one starts, so there is never more than one loop; [start] is idempotent.
 */
class VpnTrafficIndicator(
    private val state: Flow<TransportState>,
    private val counters: suspend () -> TransportStats,
    private val sink: VpnTrafficIndicatorSink,
    private val elapsedRealtimeMillis: () -> Long,
    private val interactive: Flow<Boolean> = flowOf(true),
    private val intervalMillis: Long = 1_000,
) {
    private var job: Job? = null

    fun start(scope: CoroutineScope) {
        if (job?.isActive == true) return
        job = scope.launch {
            combine(state, interactive) { s, on -> (s is TransportState.Connected) to on }
                .distinctUntilChanged()
                .collectLatest { (connected, on) ->
                    when {
                        !connected -> sink.hide(sessionEnded = true)
                        !on -> sink.hide(sessionEnded = false)
                        else -> sampleWhileConnected()
                    }
                }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        sink.hide(sessionEnded = true)
        sink.release()
    }

    private suspend fun sampleWhileConnected() {
        val meter = TrafficRateMeter()
        while (true) {
            val stats = counters()
            sink.show(meter.update(elapsedRealtimeMillis(), stats))
            delay(intervalMillis)
        }
    }
}
