package net.pocvpn.client.bootstrap

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.isFreshHandshake

/**
 * B36 - the ONE owner of the bootstrap tunnel's lifecycle (task requirement
 * 8): starting a candidate's transport, knowing which candidate is
 * currently active, tearing it down, and the deterministic
 * Frankfurt -> Stockholm -> Unavailable fallback (task requirement 2/9).
 * Never loops past [candidates] - each candidate is attempted at most once
 * per [connect] call.
 *
 * [transportFactory] is invoked ONCE PER ATTEMPT (never reused across
 * candidates) so a failed candidate's transport instance is always
 * discarded, never silently retried under a different peer/config -
 * production supplies a fresh [net.pocvpn.client.vpn.AmneziaWgTransport]
 * each time; tests supply a fake [VpnTransport] whose behavior can differ
 * per invocation.
 *
 * "Usable" (task requirement 1's BOOTSTRAP_CONNECTED) means a genuine fresh
 * handshake was observed, not merely [net.pocvpn.client.vpn.TransportState
 * .Connected] (interface up) - the SAME distinction and the SAME bounded
 * poll shape [net.pocvpn.client.vpn.VpnController.awaitFreshHandshake]
 * already uses for the normal connect path (reusing its own
 * [isFreshHandshake] predicate directly, never a second copy).
 */
class BootstrapTunnelController(
    private val transportFactory: (ProductionGatewayId) -> VpnTransport,
    private val candidates: List<ProductionGatewayId> = BootstrapCatalog.candidatesInOrder,
    private val diagnostics: BootstrapDiagnosticsRecorder? = null,
    private val nowProvider: () -> Long = System::currentTimeMillis,
    private val delayMs: suspend (Long) -> Unit = { delay(it) },
) {
    private val _state = MutableStateFlow<BootstrapState>(BootstrapState.Idle)
    val state: StateFlow<BootstrapState> = _state.asStateFlow()

    private var activeTransport: VpnTransport? = null

    /**
     * Tries [candidates] in order, returns the terminal
     * [BootstrapState.Connected]/[BootstrapState.Unavailable] reached. A
     * call while not [BootstrapState.Idle] is refused (returns the current
     * state unchanged, starts nothing new) - never a second concurrent
     * bootstrap sequence, and never overlaps with an already-active one
     * (task requirement 8's "no simultaneous bootstrap + normal Nova
     * tunnel" - this guard is the bootstrap-internal half of that; the
     * caller is separately responsible for never invoking this while a
     * normal VpnController session is active - see
     * [BootstrapActivationOrchestrator]'s own docs).
     */
    suspend fun connect(): BootstrapState {
        if (_state.value !is BootstrapState.Idle) return _state.value

        val attempted = mutableListOf<ProductionGatewayId>()
        for (candidate in candidates) {
            attempted += candidate
            _state.value = BootstrapState.Connecting(candidate)
            val gateway = ProductionGatewayCatalog.byId(candidate)
            diagnostics?.recordAttemptStarted(candidate, TransportKind.AMNEZIA_WG)

            val transport = transportFactory(candidate)
            val usable = try {
                if (transport.preparePermissionIntent() != null) {
                    // VPN permission not yet granted - the same precondition
                    // net.pocvpn.client.vpn.VpnController.connect() already
                    // requires of its own caller. Bootstrap never requests
                    // permission itself (no new UI surface, task requirement
                    // 5) - it fails this candidate closed rather than
                    // silently proceeding without a real tun interface.
                    false
                } else {
                    transport.connect(TransportConfig.Awg(buildBootstrapAwgConfig(gateway)))
                    awaitUsableHandshake(transport)
                }
            } catch (t: Throwable) {
                false
            }

            diagnostics?.recordConnectResult(candidate, usable)

            if (usable) {
                activeTransport = transport
                _state.value = BootstrapState.Connected(candidate)
                diagnostics?.recordBecameUsable(candidate)
                return _state.value
            }

            // Not usable - discard this attempt's transport before trying
            // the next candidate (or giving up). Best-effort: a transport
            // that never got past preparePermissionIntent()/connect() may
            // have nothing to tear down at all.
            runCatching { transport.disconnect() }
        }

        _state.value = BootstrapState.Unavailable(attempted.toList())
        diagnostics?.recordUnavailable(attempted.toList())
        return _state.value
    }

    /**
     * Tears down whatever candidate is currently active/connecting and
     * returns to [BootstrapState.Idle]. Safe to call from any state,
     * including [BootstrapState.Idle]/[BootstrapState.Unavailable] (no-op
     * beyond resetting to Idle) - the caller (task requirement 9's "bootstrap
     * teardown must complete before normal connection transition") is
     * expected to `await` this before exposing PROVISIONED.
     */
    suspend fun teardown() {
        val candidate = when (val current = _state.value) {
            is BootstrapState.Connecting -> current.candidate
            is BootstrapState.Connected -> current.candidate
            is BootstrapState.TearingDown -> current.candidate
            is BootstrapState.Idle, is BootstrapState.Unavailable -> null
        }
        val transport = activeTransport
        if (candidate != null) {
            _state.value = BootstrapState.TearingDown(candidate)
        }
        if (transport != null) {
            runCatching { transport.disconnect() }
            activeTransport = null
        }
        _state.value = BootstrapState.Idle
        if (candidate != null) {
            diagnostics?.recordTeardown(candidate)
        }
    }

    private suspend fun awaitUsableHandshake(transport: VpnTransport): Boolean {
        val attemptStart = nowProvider()
        val maxPolls = (HANDSHAKE_TIMEOUT_MS / HANDSHAKE_POLL_INTERVAL_MS).toInt()
        for (pollIndex in 0..maxPolls) {
            when (val stats = transport.stats()) {
                is TransportStats.Counters -> {
                    if (isFreshHandshake(stats.lastHandshakeEpochMillis, attemptStart)) return true
                }
                TransportStats.Unsupported, TransportStats.NotImplemented -> return true
                TransportStats.Unavailable -> Unit
            }
            if (pollIndex < maxPolls) delayMs(HANDSHAKE_POLL_INTERVAL_MS)
        }
        return false
    }

    companion object {
        const val HANDSHAKE_TIMEOUT_MS = 8_000L
        const val HANDSHAKE_POLL_INTERVAL_MS = 500L
    }
}
