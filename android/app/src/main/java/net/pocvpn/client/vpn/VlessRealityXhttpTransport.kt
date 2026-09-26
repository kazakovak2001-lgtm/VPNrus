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
import kotlinx.coroutines.launch
import net.pocvpn.client.smartconnect.TrafficProgressSnapshot
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.RealityXhttpSessionConfigStore
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import java.util.concurrent.atomic.AtomicLong

/**
 * B-WL-R6 - VLESS + REALITY + XHTTP (Direct only) over the SAME
 * NovaXrayVpnService / XrayCoreController / B33 remote confirmation / session
 * watchdog every other Xray transport uses - no second service, resolver or
 * health path. Connected is only ever reported after B33 confirmation.
 */
class VlessRealityXhttpTransport(
    private val context: Context,
) : VpnTransport {

    override val name: String = "xray-vless-reality-xhttp"
    override val kind: TransportKind = TransportKind.XRAY_REALITY_XHTTP
    override val capabilities: TransportCapabilities = TransportCapabilities.xrayRealityXhttpAdapterShell()
    override val underlyingNetworkRecovery: UnderlyingNetworkRecovery = UnderlyingNetworkRecovery.RESTART_SESSION

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null
    private var pendingConfigSessionId: Long? = null

    @Volatile private var currentSessionId: Long? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.XrayRealityXhttp) { "VlessRealityXhttpTransport only accepts TransportConfig.XrayRealityXhttp" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        val sessionId = nextSessionId.incrementAndGet()
        currentSessionId = sessionId
        pendingConfigSessionId?.let(RealityXhttpSessionConfigStore::remove)

        observerJob?.cancel()
        observerJob = scope.launch {
            XrayRuntimeState.events.collect { event ->
                xrayTransportStateFor(event, sessionId)?.let { state.value = it }
            }
        }

        RealityXhttpSessionConfigStore.put(sessionId, config.config)
        pendingConfigSessionId = sessionId
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
            RealityXhttpSessionConfigStore.remove(sessionId)
            pendingConfigSessionId = null
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    override suspend fun disconnect() {
        pendingConfigSessionId?.let(RealityXhttpSessionConfigStore::remove)
        pendingConfigSessionId = null
        if (state.value is TransportState.Error) {
            state.value = TransportState.Disconnected
            return
        }
        state.value = TransportState.Disconnecting
        try {
            context.startService(Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_STOP))
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
        }
    }

    override fun observeTrafficProgress(): Flow<TrafficProgressSnapshot> = xrayTrafficProgressFor { currentSessionId }

    override fun observeState(): Flow<TransportState> = state.asStateFlow()

    private companion object {
        // Offset id space: the other Xray transports each count from 0 and
        // share XrayRuntimeState, so this transport never reuses their ids.
        val nextSessionId = AtomicLong(1L shl 40)
    }
}
