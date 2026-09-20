package net.pocvpn.client.vpn.shadowsocks

import android.content.Context
import android.content.Intent
import android.net.VpnService
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.UnderlyingNetworkRecovery
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.TransportConfig

/**
 * B45B-3 - the isolated VpnTransport adapter for Shadowsocks 2022. Follows
 * the SAME shape as VlessTlsTransport (Intent-driven start/stop against its
 * own VpnService, session-id-scoped state collection) - no new transport
 * interface, no new public lifecycle authority (Phase 3/11).
 *
 * DELIBERATELY UNREACHABLE from real selection (Phase 15): TransportRegistry
 * keeps TransportKind.SHADOWSOCKS_2022 at NOT_IMPLEMENTED with no factory -
 * nothing in TransportOrchestrator, Smart Connect, AutoGatewaySelector, or
 * PathCandidateBuilder ever constructs this class. It exists to be
 * instantiated directly by tests (and, later, a slice that explicitly wires
 * it in).
 *
 * [underlyingNetworkRecovery] is [UnderlyingNetworkRecovery.RESTART_SESSION]
 * (Phase 13) - Q7 (seamless handover) is unverified; this transport never
 * claims IN_PLACE recovery.
 */
class ShadowsocksTransport(
    private val context: Context,
    // B45B-4P fix - comfortably longer than ShadowsocksRuntime's own
    // worst-case bounded stop (DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS +
    // DEFAULT_FORCE_STOP_WAIT_MILLIS = 4s), plus margin for Intent
    // dispatch/service-start latency. Injectable (same convention as
    // ShadowsocksRuntime's own tunFdHandoffTimeoutMillis/gracefulStopTimeoutMillis)
    // so a test can use a short bound instead of waiting on the real one.
    private val disconnectConfirmTimeoutMillis: Long = 6_000L,
) : VpnTransport {

    override val name: String = "shadowsocks-2022"
    override val kind: TransportKind = TransportKind.SHADOWSOCKS_2022
    override val capabilities: TransportCapabilities = TransportCapabilities.shadowsocks2022AdapterShell()
    override val underlyingNetworkRecovery: UnderlyingNetworkRecovery = UnderlyingNetworkRecovery.RESTART_SESSION

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.Shadowsocks) { "ShadowsocksTransport only accepts TransportConfig.Shadowsocks" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        val sessionId = nextSessionId.incrementAndGet()
        observerJob?.cancel()
        observerJob = scope.launch {
            ShadowsocksVpnService.status.collect { status ->
                if (status != null && status.sessionId == sessionId) {
                    shadowsocksTransportStateFor(status.phase)?.let { state.value = it }
                }
            }
        }

        state.value = TransportState.Connecting
        try {
            val intent = Intent(context, ShadowsocksVpnService::class.java)
                .setAction(ShadowsocksVpnService.ACTION_START)
                .putExtra(ShadowsocksVpnService.EXTRA_SESSION_ID, sessionId)
                .putExtra(ShadowsocksVpnService.EXTRA_ENDPOINT_ID, config.endpointId.value)
                .putExtra(ShadowsocksVpnService.EXTRA_HOST, config.host)
                .putExtra(ShadowsocksVpnService.EXTRA_PORT, config.port)
                .putExtra(ShadowsocksVpnService.EXTRA_METHOD, config.method)
                .putExtra(ShadowsocksVpnService.EXTRA_ROUTING_MODE, config.routingMode.name)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    /**
     * B45B-4P fix - real ownership/cleanup bug found on a physical device:
     * the previous version returned early (setting [TransportState.Disconnected]
     * directly, never sending [ShadowsocksVpnService.ACTION_STOP]) whenever
     * [state] already reported [TransportState.Error] - wrongly assuming
     * Error always means the service/process/TUN were already torn down.
     * They are not guaranteed to be: never skip the real teardown based on
     * the last-reported state. Idempotent in the one case that IS actually
     * safe to skip - [state] already [TransportState.Disconnected] means the
     * service has already confirmed a real stop (see [shadowsocksTransportStateFor]/
     * [ShadowsocksVpnService.teardown]'s own docs for why STOPPED is the only
     * source of that value now).
     *
     * Deterministic, not fire-and-forget: after asking the service to stop,
     * this call actually waits (bounded) for [state] to reach a genuine
     * terminal value the service's own status reports, rather than returning
     * the instant the async `startService()` call is merely accepted. If the
     * bound is exceeded (the service failed to confirm in time), [state] is
     * forced to [TransportState.Disconnected] anyway - a caller must never be
     * left waiting on [TransportState.Disconnecting] forever.
     */
    override suspend fun disconnect() {
        if (state.value is TransportState.Disconnected) return
        state.value = TransportState.Disconnecting
        try {
            val intent = Intent(context, ShadowsocksVpnService::class.java).setAction(ShadowsocksVpnService.ACTION_STOP)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
            return
        }
        withTimeoutOrNull(disconnectConfirmTimeoutMillis) {
            state.first { it is TransportState.Disconnected || it is TransportState.Error }
        }
        if (state.value !is TransportState.Disconnected && state.value !is TransportState.Error) {
            state.value = TransportState.Disconnected
        }
    }

    override fun observeState(): Flow<TransportState> = state.asStateFlow()

    private companion object {
        val nextSessionId = AtomicLong(0)
    }
}

/** Pure mapping, file-scope for direct unit testing without a Context/Intent double (same convention as VlessTlsTransport's own xrayTransportStateFor). */
internal fun shadowsocksTransportStateFor(phase: ShadowsocksRuntimePhase): TransportState? = when (phase) {
    ShadowsocksRuntimePhase.STOPPED -> TransportState.Disconnected
    ShadowsocksRuntimePhase.STARTING -> TransportState.Connecting
    ShadowsocksRuntimePhase.RUNNING -> TransportState.Connected
    ShadowsocksRuntimePhase.STOPPING -> TransportState.Disconnecting
    ShadowsocksRuntimePhase.FAILED -> TransportState.Error("Shadowsocks runtime failed")
}
