package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.coroutineContext
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgPeer
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.TransportConfig

sealed class ControllerEvent {
    data class RequestVpnPermission(val intent: Intent) : ControllerEvent()
}

/**
 * Connection orchestrator sitting between the UI (ViewModel) and VpnTransport.
 * Owns: VPN permission flow, gateway-config precondition checks, connect/
 * disconnect serialization (no overlapping backend operations), and the
 * client-side reconnect state machine. Holds no UI references and survives
 * independently of any Activity.
 *
 * B8G1 - "Break-before-make" and why reconnectLoop() never re-calls connect():
 * decompiling the pinned AmneziaWG AAR's org.amnezia.awg.backend.GoBackend
 * .setState(tunnel, UP, config) shows that whenever a tunnel is ALREADY up,
 * bringing up ANY config (even an unchanged one) first tears the existing
 * one down (setStateInternal(oldTunnel, null, DOWN)) before establishing the
 * new one - a real, brief window where the OS-level VpnService interface
 * and its 0.0.0.0/0+::/0 routes could be gone, before the replacement comes
 * up (GoBackend attempts to roll back to the previous tunnel only if the
 * NEW one throws - it does not avoid the teardown itself). This is internal
 * to that pinned, unmodified dependency - not something this class can
 * avoid by "not calling disconnect" alone.
 *
 * The fix: reconnectLoop() below NEVER calls transport.connect() to retry
 * an unchanged config. Once a tunnel is established, the AmneziaWG/
 * WireGuard protocol itself keeps attempting handshakes on its own - no
 * app-level "nudge" is needed or even available (the pinned AAR's native
 * JNI bridge, org.amnezia.awg.GoBackend, exposes only awgTurnOn / awgTurnOff
 * / awgGetConfig / awgGetSocketV4 / awgGetSocketV6 / awgVersion - no
 * incremental "retry"/"rekey" native call exists to call instead). This is
 * standard, documented
 * WireGuard behavior ("you don't need to worry about asking it to
 * reconnect... everything else is handled for you automatically"),
 * reinforced here by AwgPeer's own default persistentKeepaliveSeconds=25,
 * which keeps the underlying engine periodically retrying even with no
 * real outbound traffic queued. So reconnectLoop() only WAITS (polling the
 * exact same awaitFreshHandshake() the initial connect already uses) for
 * that automatic recovery, leaving the established interface/routes
 * completely untouched throughout - no setState call, no teardown window,
 * for as long as the session is merely recovering rather than being
 * explicitly reconfigured. A real rebuild (a new setState(UP, ...) call)
 * only ever happens for a genuine INITIAL connect() or an explicit
 * reactivation - never as an automatic retry.
 *
 * This closes the automatic-failure leak window Level A (this class) can
 * control. It does NOT make this a strict, OS-enforced kill switch: if the
 * VpnService process itself is killed by the OS (not merely a lost
 * handshake), only Android's own Always-on VPN + "Block connections
 * without VPN" system setting (Level B, entirely outside this app's
 * control - see AlwaysOnVpnState's own docs) can guarantee no leak in that
 * case. Never claim otherwise in the UI.
 */
class VpnController(
    private val transport: VpnTransport,
    private val clientKeyRepository: ClientKeyRepository,
    private val gatewayConfigurationRepository: GatewayConfigurationRepository,
    private val reconnectManager: ReconnectManager,
    private val diagnostics: DiagnosticsStore,
    private val scope: CoroutineScope,
) {
    private companion object {
        // B8B3D - "small bounded startup window" per the task's own wording.
        const val HANDSHAKE_TIMEOUT_MS = 8_000L
        const val HANDSHAKE_POLL_INTERVAL_MS = 500L
    }

    private val connectMutex = Mutex()

    private val _state = MutableStateFlow<TransportState>(TransportState.Disconnected)
    val state: StateFlow<TransportState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<ControllerEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<ControllerEvent> = _events

    @Volatile private var userInitiatedDisconnect = true
    private var reconnectJob: Job? = null

    // Guards against a startup race: observeState() is a hot/replaying flow, so
    // whenever our collector coroutine actually gets scheduled to start, its
    // first emission is just a replay of the transport's CURRENT (possibly
    // stale) state - not a new transition. If a permission/gateway-config
    // check set an error state directly (without ever touching the transport)
    // before that replay is collected, we must not let it clobber that error.
    // Once we've actually invoked the transport at least once, every further
    // emission is a genuine transition and is always forwarded.
    @Volatile private var hasTouchedTransport = false

    init {
        scope.launch {
            transport.observeState().collect { transportState ->
                if (!hasTouchedTransport) return@collect
                // While a reconnect cycle owns the visible state (Reconnecting/backoff),
                // don't let a transient Disconnected from an internal retry attempt
                // flicker the UI back to plain Disconnected.
                if (reconnectJob?.isActive != true) {
                    _state.value = transportState
                }
                diagnostics.updateTransportState(_state.value)
            }
        }
        reconnectManager.start(
            onNetworkLost = { handleNetworkLost() },
            onNetworkAvailable = { /* reconnect loop polls isNetworkAvailable() on its own cadence */ },
        )
    }

    fun gatewayStatus(): GatewayConfiguration = gatewayConfigurationRepository.get()

    /** Call once, early, from the UI layer to know whether a permission prompt will be needed. */
    fun permissionIntentIfNeeded(): Intent? = transport.preparePermissionIntent()

    suspend fun connect() {
        if (!connectMutex.tryLock()) {
            diagnostics.recordError(VpnError.AlreadyInProgress)
            return
        }
        try {
            if (_state.value is TransportState.Connecting || _state.value is TransportState.Connected) {
                return
            }
            userInitiatedDisconnect = false
            cancelReconnectLocked()

            val permissionIntent = transport.preparePermissionIntent()
            if (permissionIntent != null) {
                _events.tryEmit(ControllerEvent.RequestVpnPermission(permissionIntent))
                return
            }
            diagnostics.updatePermission(true)
            doConnectAttempt()
        } finally {
            connectMutex.unlock()
        }
    }

    /** Call from the Activity's permission-result callback. */
    suspend fun onVpnPermissionResult(granted: Boolean) {
        diagnostics.updatePermission(granted)
        if (!granted) {
            diagnostics.recordError(VpnError.PermissionDenied)
            _state.value = TransportState.Error("VPN permission denied")
            return
        }
        connectMutex.withLock { doConnectAttempt() }
    }

    suspend fun disconnect() {
        connectMutex.withLock {
            if (_state.value is TransportState.Disconnected || _state.value is TransportState.Disconnecting) {
                return@withLock
            }
            userInitiatedDisconnect = true
            cancelReconnectLocked()
            hasTouchedTransport = true
            transport.disconnect()
        }
    }

    /**
     * Caller must already hold connectMutex. Returns true only if
     * transport.connect() completed without throwing. The reconnect loop
     * relies on this return value - NOT on re-reading `_state`, which is
     * only updated asynchronously by the background collector and would
     * race against this same call.
     */
    private suspend fun doConnectAttempt(): Boolean {
        when (val config = gatewayConfigurationRepository.get()) {
            is GatewayConfiguration.Missing -> {
                diagnostics.recordError(VpnError.GatewayConfigurationMissing)
                diagnostics.updateGateway(configured = false, endpointDisplay = "NOT CONFIGURED")
                _state.value = TransportState.Error("Gateway configuration is not configured. Real VPS required.")
                return false
            }
            is GatewayConfiguration.Invalid -> {
                diagnostics.recordError(VpnError.InvalidGatewayConfiguration(config.reason))
                _state.value = TransportState.Error("Invalid gateway configuration: ${config.reason}")
                return false
            }
            is GatewayConfiguration.Configured -> {
                diagnostics.updateGateway(
                    configured = true,
                    endpointDisplay = "${config.endpointHost}:${config.endpointPort}",
                )
                val transportConfig = try {
                    buildTransportConfig(config)
                } catch (e: Exception) {
                    diagnostics.recordError(VpnError.ConfigurationMappingFailure(e.javaClass.simpleName))
                    _state.value = TransportState.Error("Failed to build tunnel configuration")
                    return false
                }
                return try {
                    hasTouchedTransport = true
                    // B8B3D: the attempt's own start time - a handshake is only
                    // trusted as proof of THIS attempt's success if it is at or
                    // after this timestamp, never a stale one from a prior
                    // session (see class docs' session-semantics note).
                    val attemptStartEpochMillis = System.currentTimeMillis()
                    transport.connect(transportConfig)
                    // Interface-up/TX>0 alone is deliberately NOT treated as
                    // success here - see awaitFreshHandshake's own docs. Set
                    // directly (not left to the background collector) for the
                    // same reason the prior direct-set comment explained: we
                    // know unambiguously, right here, whether THIS attempt
                    // produced a real handshake.
                    if (awaitFreshHandshake(attemptStartEpochMillis)) {
                        recordCurrentStats()
                        _state.value = TransportState.Connected
                        true
                    } else {
                        diagnostics.recordError(VpnError.HandshakeTimeout)
                        // Deliberately does NOT call transport.disconnect() -
                        // failover/kill-switch policy is out of scope for this
                        // slice (see class docs). The interface may still be
                        // up; only the user-visible state reflects the truth.
                        _state.value = TransportState.HandshakeFailed
                        false
                    }
                } catch (e: Exception) {
                    diagnostics.recordError(VpnError.BackendStartFailure(e.javaClass.simpleName))
                    _state.value = TransportState.Error("Backend failed to start")
                    false
                }
            }
        }
    }

    private suspend fun buildTransportConfig(config: GatewayConfiguration.Configured): TransportConfig {
        val privateKey = clientKeyRepository.getPrivateKeyForTunnel()
        val awgConfig = AwgConfig(
            privateKeyBase64 = privateKey,
            localAddresses = listOf("${config.clientTunnelIp}/32"),
            dnsServers = config.dnsServers,
            profile = config.profile,
            peer = AwgPeer(
                publicKeyBase64 = config.serverPublicKeyBase64,
                endpointHost = config.endpointHost,
                endpointPort = config.endpointPort,
                allowedIps = config.allowedIps,
                persistentKeepaliveSeconds = config.persistentKeepaliveSeconds,
            ),
        )
        return TransportConfig.Awg(awgConfig)
    }

    /**
     * B8B3D - the authoritative startup-success signal: a REAL AWG handshake
     * for THIS connection attempt, observed via the existing
     * VpnTransport.stats() boundary (AmneziaWgTransport.stats(), backed by
     * Backend.getLastHandshake/getStatistics - no second polling system, no
     * new state-machine framework). Polls at a fixed virtual-time interval,
     * bounded by HANDSHAKE_TIMEOUT_MS total - purely delay()-driven (no
     * wall-clock deadline check), so it is exactly as fast-forwardable under
     * kotlinx-coroutines-test's virtual time as the existing reconnect
     * backoff loop already is.
     *
     * A handshake only counts if its timestamp is >= attemptStartEpochMillis -
     * a stale handshake left over from a previous session can never satisfy
     * a NEW attempt. This is also exactly why an established CONNECTED
     * session is never re-evaluated later: this function runs ONCE per
     * connect() attempt and is never invoked again while already connected -
     * ordinary handshake-age growth during an idle period never reaches this
     * check at all.
     *
     * A transport that cannot report stats at all (Unsupported/NotImplemented -
     * i.e. there is nothing to observe) is trusted on its own connect()
     * success, exactly like pre-B8B3D behavior - this check can only make a
     * transport's reported success LESS trusted when it has real evidence to
     * evaluate, never penalize a transport that offers none.
     */
    private suspend fun awaitFreshHandshake(attemptStartEpochMillis: Long): Boolean {
        val maxPolls = (HANDSHAKE_TIMEOUT_MS / HANDSHAKE_POLL_INTERVAL_MS).toInt()
        for (pollIndex in 0..maxPolls) {
            when (val stats = transport.stats()) {
                is TransportStats.Counters -> {
                    if (isFreshHandshake(stats.lastHandshakeEpochMillis, attemptStartEpochMillis)) {
                        return true
                    }
                }
                TransportStats.Unsupported, TransportStats.NotImplemented -> return true
                TransportStats.Unavailable -> Unit
            }
            if (pollIndex < maxPolls) delay(HANDSHAKE_POLL_INTERVAL_MS)
        }
        return false
    }

    private suspend fun recordCurrentStats() {
        val stats = transport.stats()
        if (stats is TransportStats.Counters) {
            diagnostics.updateStats(stats.lastHandshakeEpochMillis, stats.bytesReceived, stats.bytesSent)
        }
    }

    private fun handleNetworkLost() {
        if (userInitiatedDisconnect) return
        if (_state.value !is TransportState.Connected) return
        diagnostics.updateNetworkType("unavailable")
        reconnectJob = scope.launch { reconnectLoop() }
    }

    /**
     * B8G1 - kill-switch fix: this loop NEVER calls transport.connect() (=
     * backend.setState(UP, config)) to "retry" - see the class doc's own
     * "Break-before-make" section for exactly why that would be
     * counterproductive. It only WAITS for the SAME already-established
     * tunnel to recover a fresh handshake on its own, polling via the exact
     * same awaitFreshHandshake() helper doConnectAttempt() uses for the
     * initial connect - reused verbatim, not reimplemented.
     *
     * reconnectionThresholdEpochMillis is captured ONCE, at the moment this
     * reconnect session begins - not recomputed per attempt - because the
     * underlying AmneziaWG tunnel keeps retrying handshakes entirely on its
     * own timeline (protocol-level retry backed by PersistentKeepalive, see
     * class docs), asynchronously to this loop's own polling cadence. A
     * per-attempt "now" threshold could miss a handshake that already
     * landed moments before this loop happened to check.
     */
    private suspend fun reconnectLoop() {
        var attempt = 0
        val reconnectionThresholdEpochMillis = System.currentTimeMillis()
        while (coroutineContext.isActive && !userInitiatedDisconnect) {
            attempt++
            diagnostics.updateReconnectAttempts(attempt)
            _state.value = TransportState.Reconnecting(attempt)

            if (attempt > ReconnectBackoff.MAX_ATTEMPTS) {
                diagnostics.recordError(VpnError.ReconnectExhausted)
                _state.value = TransportState.Error("Reconnect attempts exhausted")
                return
            }

            delay(ReconnectBackoff.delayForAttempt(attempt))
            if (!coroutineContext.isActive || userInitiatedDisconnect) return

            if (!reconnectManager.isNetworkAvailable()) {
                continue // keep backing off until a network reappears
            }

            val recovered = connectMutex.withLock { awaitFreshHandshake(reconnectionThresholdEpochMillis) }
            if (recovered) {
                recordCurrentStats()
                _state.value = TransportState.Connected
                diagnostics.updateReconnectAttempts(0)
                return
            }
        }
    }

    /** Caller must already hold connectMutex. */
    private fun cancelReconnectLocked() {
        reconnectJob?.cancel()
        reconnectJob = null
    }

    fun shutdown() {
        reconnectManager.stop()
    }
}

/**
 * B8B3D - pure, file-scope (not a VpnController member) specifically so it
 * is directly unit-testable with concrete millisecond values, independent
 * of FakeVpnTransport/any transport double - the exact thing the seconds-
 * vs-milliseconds unit bug needed proving against (a value that is only
 * "fresh" if compared as milliseconds, not seconds).
 *
 * `handshakeEpochMillis` must already be real epoch MILLISECONDS - see
 * AmneziaWgTransport.stats()'s own docs for why it sources this from
 * Statistics.PeerStats.latestHandshakeEpochMillis(), never from the
 * seconds-valued Backend.getLastHandshake(). A null input (no handshake
 * observed, including a normalized 0/sentinel) is never fresh.
 */
internal fun isFreshHandshake(handshakeEpochMillis: Long?, attemptStartEpochMillis: Long): Boolean =
    handshakeEpochMillis != null && handshakeEpochMillis >= attemptStartEpochMillis
