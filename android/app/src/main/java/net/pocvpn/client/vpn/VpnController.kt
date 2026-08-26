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
 */
class VpnController(
    private val transport: VpnTransport,
    private val clientKeyRepository: ClientKeyRepository,
    private val gatewayConfigurationRepository: GatewayConfigurationRepository,
    private val reconnectManager: ReconnectManager,
    private val diagnostics: DiagnosticsStore,
    private val scope: CoroutineScope,
) {
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
                    transport.connect(transportConfig)
                    // Set directly rather than relying solely on the background collector:
                    // observeState() is a StateFlow, which only guarantees delivery of the
                    // latest value to a slow collector. A fast reconnect cycle that nets
                    // back to the same value it last saw (Connected -> Connecting ->
                    // Connected) can be invisible to it. We know unambiguously, right here,
                    // that the connect succeeded - the collector remains responsible only
                    // for genuinely later/async transitions (e.g. a backend-reported drop).
                    _state.value = TransportState.Connected
                    true
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

    private fun handleNetworkLost() {
        if (userInitiatedDisconnect) return
        if (_state.value !is TransportState.Connected) return
        diagnostics.updateNetworkType("unavailable")
        reconnectJob = scope.launch { reconnectLoop() }
    }

    private suspend fun reconnectLoop() {
        var attempt = 0
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

            val succeeded = connectMutex.withLock { doConnectAttempt() }
            if (succeeded) {
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
