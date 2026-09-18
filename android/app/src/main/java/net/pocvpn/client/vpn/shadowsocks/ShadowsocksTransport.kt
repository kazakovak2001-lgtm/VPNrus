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
import kotlinx.coroutines.launch
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
                .putExtra(ShadowsocksVpnService.EXTRA_ROUTING_MODE, config.routingMode.name)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    override suspend fun disconnect() {
        if (state.value is TransportState.Error) {
            state.value = TransportState.Disconnected
            return
        }
        state.value = TransportState.Disconnecting
        try {
            val intent = Intent(context, ShadowsocksVpnService::class.java).setAction(ShadowsocksVpnService.ACTION_STOP)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
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
