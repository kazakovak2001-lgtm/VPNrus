package net.pocvpn.client.fieldtest

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.isFreshHandshake

/**
 * The ONE owner of the field test's tunnel lifecycle: deterministic
 * Frankfurt (GERMANY) -> Stockholm fallback, using the EXISTING production
 * [VpnTransport] (AmneziaWG) implementation, never a fake/simulated
 * transport, and never B36 bootstrap semantics (this is a normal,
 * full-tunnel field-test peer - see [buildFieldTestAwgConfig]).
 *
 * "Usable" requires a genuine fresh AWG handshake - the SAME real proof
 * [net.pocvpn.client.bootstrap.BootstrapTunnelController]/
 * [net.pocvpn.client.vpn.VpnController.awaitFreshHandshake] already use for
 * a direct AWG gateway (never merely [net.pocvpn.client.vpn.TransportState
 * .Connected], never fake success based only on transport state - task
 * requirement). "Protected" additionally requires [healthCheck] to pass -
 * this is the field test's own extra data-plane confidence check on top of
 * the handshake proof (defaults to always-true so a handshake alone is
 * already sufficient when no stronger probe is wired, but callers/tests can
 * supply a real post-handshake connectivity probe).
 *
 * **VPN permission is NOT checked here** (PR #61 follow-up - a real-device
 * incident showed this same [connect] previously calling
 * `transport.preparePermissionIntent()` per candidate and marking
 * Frankfurt/Stockholm "failed" within milliseconds whenever Android's VPN
 * permission was merely pending, never actually launching the system
 * dialog). Permission is device/app-level, not gateway-specific - it is
 * [FieldTestViewModel.ensureVpnPermission]'s job to resolve it ONCE,
 * before this controller's [connect] is ever invoked. This controller
 * trusts that precondition and evaluates every candidate as a real
 * transport attempt - it never consumes a gateway candidate for a
 * permission reason.
 */
class FieldTestTunnelController(
    private val transportFactory: (ProductionGatewayId) -> VpnTransport,
    private val candidates: List<ProductionGatewayId> = listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
    private val diagnostics: FieldTestDiagnosticsRecorder? = null,
    private val nowProvider: () -> Long = System::currentTimeMillis,
    private val delayMs: suspend (Long) -> Unit = { delay(it) },
    /** Runs only after a fresh handshake is observed - the extra data-plane confidence check (task's own "health/data-plane proof"). Defaults to always-healthy (handshake alone suffices) when no stronger probe is supplied. */
    private val healthCheck: suspend (VpnTransport) -> Boolean = { true },
    /**
     * B37 - resolves which [ProductionGatewayDescriptor] (host/port/pubkey/
     * AWG profile) each candidate actually connects to. Defaults to
     * [ProductionGatewayCatalog] (the PRE-B37 legacy behavior, on the
     * shared production `awg0` interface) purely so every pre-existing test
     * in this file keeps working unchanged; [FieldTestViewModel] overrides
     * this with [FieldTestAwg31GatewayCatalog]`::byId` for the real B37
     * field-test build, since that is the ONLY thing that actually changes
     * which AWG generation gets exercised - never a second copy of the
     * Frankfurt/Stockholm-first fallback logic below.
     */
    private val gatewayLookup: (ProductionGatewayId) -> ProductionGatewayDescriptor = ProductionGatewayCatalog::byId,
    /** B37 - which AWG generation [gatewayLookup] actually resolves to, purely for diagnostics labeling (see [AwgGeneration]'s own docs) - never affects connection behavior. */
    private val awgGeneration: AwgGeneration = AwgGeneration.AWG_LEGACY,
) {
    private val _state = MutableStateFlow<FieldTestState>(FieldTestState.Idle)
    val state: StateFlow<FieldTestState> = _state.asStateFlow()

    private var activeTransport: VpnTransport? = null

    /**
     * Tries [candidates] in order (Frankfurt then Stockholm), returns the
     * terminal [FieldTestState.Protected]/[FieldTestState.Failed] reached. A
     * call while not [FieldTestState.Idle] is refused (returns the current
     * state unchanged) - never a second concurrent attempt.
     */
    suspend fun connect(): FieldTestState {
        if (_state.value !is FieldTestState.Idle) return _state.value

        val attempted = mutableListOf<ProductionGatewayId>()
        for (candidate in candidates) {
            attempted += candidate
            _state.value = FieldTestState.Connecting(candidate)
            val gateway = gatewayLookup(candidate)
            diagnostics?.recordAttemptStarted(
                candidate,
                TransportKind.AMNEZIA_WG,
                awgGeneration,
                gateway.awg.endpointHost,
                gateway.awg.endpointPort,
                HANDSHAKE_TIMEOUT_MS,
            )

            val transport = transportFactory(candidate)
            val handshakeOk = try {
                transport.connect(TransportConfig.Awg(buildFieldTestAwgConfig(gateway)))
                awaitUsableHandshake(transport)
            } catch (t: Throwable) {
                false
            }
            diagnostics?.recordCandidateResult(candidate, handshakeOk)

            val healthy = if (handshakeOk) {
                val result = try {
                    healthCheck(transport)
                } catch (t: Throwable) {
                    false
                }
                diagnostics?.recordHealthResult(candidate, result)
                result
            } else {
                false
            }

            if (healthy) {
                activeTransport = transport
                _state.value = FieldTestState.Protected(candidate)
                diagnostics?.recordBecameProtected(candidate)
                return _state.value
            }

            runCatching { transport.disconnect() }
        }

        _state.value = FieldTestState.Failed(attempted.toList())
        diagnostics?.recordUnavailable(attempted.toList())
        return _state.value
    }

    /** Tears down whatever candidate is currently active and returns to [FieldTestState.Idle]. Safe to call from any state. */
    suspend fun disconnect() {
        val transport = activeTransport
        if (transport != null) {
            runCatching { transport.disconnect() }
            activeTransport = null
        }
        _state.value = FieldTestState.Idle
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
