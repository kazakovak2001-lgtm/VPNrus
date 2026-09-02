package net.pocvpn.client.smartconnect

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
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
    // B8M - additive, defaults to empty so every existing call site (real
    // or test) is byte-for-byte unaffected: with no diverse probes,
    // lastDiverseReachabilityResult simply never leaves null (DiverseReachabilityEvaluator's
    // own "no probe ran yet -> null" case), the same fail-safe-to-unknown
    // shape RestrictionClassifier already requires. Probed on the SAME
    // trigger as [probe] (never a second polling mechanism) - see
    // triggerProbe's own docs.
    private val diverseProbes: List<GatewayReachabilityProbe> = emptyList(),
    // B28 - additive, defaults to the real wall clock so every existing
    // call site is unaffected in production; tests override it for
    // deterministic staleness assertions. Used ONLY to timestamp
    // [lastProbeEpochMillis]/[lastDiverseReachabilityEpochMillis] below -
    // this class still triggers a probe purely from real transport-state/
    // network-type transitions (see [start]'s own docs), never a timer.
    private val nowProvider: () -> Long = System::currentTimeMillis,
) {
    private val _lastProbeResult = MutableStateFlow<Boolean?>(null)
    val lastProbeResult: StateFlow<Boolean?> = _lastProbeResult.asStateFlow()

    private val _lastDiverseReachabilityResult = MutableStateFlow<Boolean?>(null)
    val lastDiverseReachabilityResult: StateFlow<Boolean?> = _lastDiverseReachabilityResult.asStateFlow()

    // B28 - the REAL wall-clock timestamp of the probe that produced the
    // CURRENT [lastProbeResult]/[lastDiverseReachabilityResult] value -
    // null until the first probe ever completes. This is what lets
    // [RestrictionClassifier.classify] decay a POSSIBLE_HARD_WHITELIST/
    // POSSIBLE_UDP_OR_AWG_FILTERING classification back to UNKNOWN once the
    // evidence behind it is no longer fresh (see that function's own
    // staleness docs) - mirroring the SAME "an undated/expired signal is
    // never trusted forever" discipline ReachabilityEngine.assess already
    // applies to endpoint-specific reachability, rather than inventing a
    // second staleness model.
    private val _lastProbeEpochMillis = MutableStateFlow<Long?>(null)
    val lastProbeEpochMillis: StateFlow<Long?> = _lastProbeEpochMillis.asStateFlow()

    private val _lastDiverseReachabilityEpochMillis = MutableStateFlow<Long?>(null)
    val lastDiverseReachabilityEpochMillis: StateFlow<Long?> = _lastDiverseReachabilityEpochMillis.asStateFlow()

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
            // Concurrent, not sequential - a slow/timed-out diverse probe
            // must never delay the gateway probe's own result (or vice
            // versa); each is independently bounded by its own probe's
            // timeout (see GatewayReachabilityProbe implementations).
            val gatewayResult = async { probe.isReachable() }
            val diverseResults = diverseProbes.map { async { it.isReachable() } }
            _lastProbeResult.value = gatewayResult.await()
            _lastProbeEpochMillis.value = nowProvider()
            _lastDiverseReachabilityResult.value = DiverseReachabilityEvaluator.evaluate(diverseResults.awaitAll())
            _lastDiverseReachabilityEpochMillis.value = nowProvider()
        }
    }
}
