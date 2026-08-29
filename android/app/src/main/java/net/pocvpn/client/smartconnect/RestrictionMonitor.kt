package net.pocvpn.client.smartconnect

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.vpn.TransportState

/**
 * B8J - decides WHETHER a transport-state transition alone justifies a
 * probe. Deliberately conservative: an ordinary Connecting->Connected (or
 * any other non-failure) transition NEVER triggers one - see
 * RestrictionMonitor's own "do NOT continuously poll while Protected"
 * requirement. Pure/JVM-testable, no coroutine/network involved.
 */
internal fun isMeaningfulProbeTrigger(previous: TransportState, current: TransportState): Boolean = when {
    // Initial handshake failure - a genuinely new failure, not a repeat.
    current is TransportState.HandshakeFailed && previous !is TransportState.HandshakeFailed -> true
    // Reconnect exhaustion: the loop settles on Error only by falling out of Reconnecting.
    current is TransportState.Error && previous is TransportState.Reconnecting -> true
    else -> false
}

/**
 * A network TYPE change (WIFI<->CELLULAR<->NONE etc, not a metered/roaming
 * flag flicker) counts as meaningful ONLY while NOT Connected - exactly the
 * "healthy network callbacks don't cause aggressive probes" requirement:
 * while Protected, network churn is not itself evidence of anything.
 */
internal fun isMeaningfulNetworkChange(previousType: NetworkType?, currentType: NetworkType, transportState: TransportState): Boolean =
    previousType != null && previousType != currentType && transportState !is TransportState.Connected

/**
 * B8J - owns WHEN to run the bounded GatewayReachabilityProbe. Never
 * connects/disconnects a VpnTransport (has no reference to one at all -
 * see class docs), never rebuilds the VpnService interface, and never
 * polls on a timer - every probe is triggered by a real transport-state or
 * network-type transition via [isMeaningfulProbeTrigger]/
 * [isMeaningfulNetworkChange] above. Single-flight: a new trigger cancels
 * whatever probe was still in flight rather than piling up concurrent ones.
 */
class RestrictionMonitor(
    private val probe: GatewayReachabilityProbe,
    private val scope: CoroutineScope,
) {
    private val _lastProbeResult = MutableStateFlow<Boolean?>(null)
    val lastProbeResult: StateFlow<Boolean?> = _lastProbeResult.asStateFlow()

    private var observeJob: Job? = null
    private var probeJob: Job? = null

    fun start(transportState: Flow<TransportState>, networkProfile: Flow<NetworkProfile>) {
        stop()
        observeJob = scope.launch {
            var previousTransportState: TransportState = TransportState.Disconnected
            var previousNetworkType: NetworkType? = null
            combine(transportState, networkProfile) { t, n -> t to n }.collect { (t, n) ->
                val meaningful = isMeaningfulProbeTrigger(previousTransportState, t) ||
                    isMeaningfulNetworkChange(previousNetworkType, n.type, t)
                if (meaningful) triggerProbe()
                previousTransportState = t
                previousNetworkType = n.type
            }
        }
    }

    fun stop() {
        observeJob?.cancel()
        observeJob = null
        probeJob?.cancel()
        probeJob = null
    }

    private fun triggerProbe() {
        probeJob?.cancel()
        probeJob = scope.launch {
            _lastProbeResult.value = probe.isReachable()
        }
    }
}
