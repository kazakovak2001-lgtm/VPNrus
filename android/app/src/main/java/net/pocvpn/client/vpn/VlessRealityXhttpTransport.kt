package net.pocvpn.client.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
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
import net.pocvpn.client.identity.XrayRealityXhttpProfileRepository
import net.pocvpn.client.identity.XrayRealityXhttpProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.IndependentEgressTargets
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XrayProcessBridge
import net.pocvpn.client.vpn.xray.XrayRealityXhttpRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import net.pocvpn.client.vpn.xray.XrayRuntimeState

/**
 * VLESS over XHTTP secured by REALITY, run by the same [NovaXrayVpnService]
 * and Xray core lifecycle as [VlessRealityTransport]. Same shape as that
 * class: a pre-flight resolve of the endpoint-scoped stored profile, then a
 * START intent naming only the session, kind, endpoint and routing mode -
 * the `:xray` process re-reads the profile itself, so no secret crosses an
 * Intent, Binder or file handoff. Direct only: there is no relay path.
 */
class VlessRealityXhttpTransport(
    private val context: Context,
    private val profileRepositoryFor: (EndpointId) -> XrayRealityXhttpProfileRepository =
        { id -> XrayRealityXhttpProfileRepositoryFactory.create(context, id) },
) : VpnTransport {

    override val name: String = "xray-vless-reality-xhttp"
    override val kind: TransportKind = TransportKind.XRAY_REALITY_XHTTP
    override val capabilities: TransportCapabilities = TransportCapabilities.xrayXhttpAdapterShell()
    override val underlyingNetworkRecovery: UnderlyingNetworkRecovery = UnderlyingNetworkRecovery.RESTART_SESSION

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.XrayRealityXhttp) {
            "VlessRealityXhttpTransport only accepts TransportConfig.XrayRealityXhttp"
        }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        when (val resolution = XrayRuntimeResolver.resolveRealityXhttp(profileRepositoryFor(config.endpointId))) {
            is XrayRealityXhttpRuntimeResolution.Rejected -> {
                state.value = TransportState.Error("Xray REALITY+XHTTP profile not ready: ${resolution.reason}")
                return
            }
            is XrayRealityXhttpRuntimeResolution.Ready -> Unit
        }

        val sessionId = XrayRuntimeState.nextSessionId()
        activeSessionId = sessionId
        activeEndpointId = config.endpointId
        observerJob?.cancel()
        observerJob = scope.launch {
            XrayRuntimeState.events.collect { event ->
                xrayTransportStateFor(event, sessionId)?.let { state.value = it }
            }
        }

        state.value = TransportState.Connecting
        try {
            val intent = Intent(context, NovaXrayVpnService::class.java)
                .setAction(NovaXrayVpnService.ACTION_START)
                .putExtra(NovaXrayVpnService.EXTRA_SESSION_ID, sessionId)
                .putExtra(NovaXrayVpnService.EXTRA_TRANSPORT_KIND, TransportKind.XRAY_REALITY_XHTTP.name)
                .putExtra(NovaXrayVpnService.EXTRA_ENDPOINT_ID, config.endpointId.value)
                .putExtra(NovaXrayVpnService.EXTRA_ROUTING_MODE, config.routingMode.name)
                .putExtra(NovaXrayVpnService.EXTRA_IS_RELAYED, false)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    override suspend fun disconnect() {
        // Same idle/failed/confirm handling as VlessRealityTransport.disconnect.
        if (state.value is TransportState.Disconnected) return
        if (state.value is TransportState.Error) {
            NovaXrayVpnService.sendBestEffortStop(context, activeSessionId)
            state.value = TransportState.Disconnected
            return
        }
        state.value = TransportState.Disconnecting
        try {
            XrayProcessBridge.stopSession(activeSessionId) {
                context.startService(NovaXrayVpnService.stopIntent(context, activeSessionId))
            }
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
            return
        }
        withTimeoutOrNull(DISCONNECT_CONFIRM_TIMEOUT_MS) {
            state.first { it is TransportState.Disconnected || it is TransportState.Error }
        }
        if (state.value is TransportState.Disconnecting) state.value = TransportState.Disconnected
    }

    // B-WL7 - the session whose `:xray` byte totals dataPlaneCounters() may report.
    @Volatile private var activeSessionId: Long? = null

    override suspend fun dataPlaneCounters(): TransportStats = XrayProcessBridge.dataPlaneStats(context, activeSessionId)

    override suspend fun liveTrafficCounters(): TransportStats = XrayProcessBridge.liveTrafficStats(activeSessionId)

    // B-WL7 M1 - the gateway this session exits through, so the egress probe targets a DIFFERENT one.
    @Volatile private var activeEndpointId: EndpointId? = null

    override suspend fun probeIndependentEgress(): IndependentEgressProbeResult =
        XrayProcessBridge.probeIndependentEgress(context, activeSessionId, IndependentEgressTargets.forSession(activeEndpointId))

    override fun observeState(): Flow<TransportState> = state.asStateFlow()

    private companion object {
        const val DISCONNECT_CONFIRM_TIMEOUT_MS = 5_000L
    }
}
