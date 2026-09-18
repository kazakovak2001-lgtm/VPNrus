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
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XhttpSessionConfigStore
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import java.util.concurrent.atomic.AtomicLong

/**
 * B35 - VLESS/XHTTP CDN-fronted transport using the same NovaXrayVpnService
 * and Xray core lifecycle as REALITY/TLS.
 *
 * Secret-bearing XHTTP runtime config stays process-local in
 * XhttpSessionConfigStore and never crosses Intent/Binder extras.
 */
class VlessXhttpTransport(
    private val context: Context,
) : VpnTransport {

    override val name: String = "xray-vless-xhttp"
    override val kind: TransportKind = TransportKind.XRAY_XHTTP
    override val capabilities: TransportCapabilities =
        TransportCapabilities.xrayXhttpAdapterShell()
    override val underlyingNetworkRecovery: UnderlyingNetworkRecovery =
        UnderlyingNetworkRecovery.RESTART_SESSION

    private val state =
        MutableStateFlow<TransportState>(TransportState.Disconnected)

    private val scope =
        CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private var observerJob: Job? = null
    private var pendingConfigSessionId: Long? = null

    override fun preparePermissionIntent(): Intent? =
        VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.XrayXhttp) {
            "VlessXhttpTransport only accepts TransportConfig.XrayXhttp"
        }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        val sessionId = nextSessionId.incrementAndGet()
        pendingConfigSessionId?.let(XhttpSessionConfigStore::remove)

        observerJob?.cancel()
        observerJob = scope.launch {
            XrayRuntimeState.events.collect { event ->
                xrayTransportStateFor(event, sessionId)?.let {
                    state.value = it
                }
            }
        }

        XhttpSessionConfigStore.put(sessionId, config.config)
        pendingConfigSessionId = sessionId

        state.value = TransportState.Connecting

        try {
            val intent =
                Intent(context, NovaXrayVpnService::class.java)
                    .setAction(NovaXrayVpnService.ACTION_START)
                    .putExtra(
                        NovaXrayVpnService.EXTRA_SESSION_ID,
                        sessionId,
                    )
                    .putExtra(
                        NovaXrayVpnService.EXTRA_TRANSPORT_KIND,
                        TransportKind.XRAY_XHTTP.name,
                    )
                    .putExtra(
                        NovaXrayVpnService.EXTRA_ENDPOINT_ID,
                        config.endpointId.value,
                    )
                    .putExtra(
                        NovaXrayVpnService.EXTRA_ROUTING_MODE,
                        config.routingMode.name,
                    )
                    .putExtra(
                        NovaXrayVpnService.EXTRA_IS_RELAYED,
                        config.isRelayed,
                    )

            config.relayExitProbeHost?.let {
                intent.putExtra(
                    NovaXrayVpnService.EXTRA_RELAY_EXIT_PROBE_HOST,
                    it,
                )
            }

            context.startService(intent)
        } catch (t: Throwable) {
            XhttpSessionConfigStore.remove(sessionId)
            pendingConfigSessionId = null
            state.value =
                TransportState.Error(
                    t.message ?: "connect failed",
                    t,
                )
        }
    }

    override suspend fun disconnect() {
        pendingConfigSessionId?.let(XhttpSessionConfigStore::remove)
        pendingConfigSessionId = null
        if (state.value is TransportState.Error) {
            state.value = TransportState.Disconnected
            return
        }

        state.value = TransportState.Disconnecting

        try {
            val intent =
                Intent(context, NovaXrayVpnService::class.java)
                    .setAction(NovaXrayVpnService.ACTION_STOP)

            context.startService(intent)
        } catch (t: Throwable) {
            state.value =
                TransportState.Error(
                    t.message ?: "disconnect failed",
                    t,
                )
        }
    }

    override fun observeState(): Flow<TransportState> =
        state.asStateFlow()

    private companion object {
        val nextSessionId = AtomicLong(0)
    }
}
