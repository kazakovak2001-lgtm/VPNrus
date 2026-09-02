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
import net.pocvpn.client.identity.XrayQuicProfileRepository
import net.pocvpn.client.identity.XrayQuicProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XrayQuicRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import java.util.concurrent.atomic.AtomicLong

/**
 * B21 - the QUIC counterpart of [VlessTlsTransport]: the SAME isolated
 * adapter shell (SAME [NovaXrayVpnService]/[net.pocvpn.client.vpn.xray.XrayCoreController]
 * runtime shell REALITY/TLS_TCP already use - no second VpnService, no
 * second TUN/socket-protection stack), a DIFFERENT [XrayQuicProfileRepository]
 * and [TransportKind.QUIC]. See docs/B21_QUIC_TRANSPORT_AUDIT.md for why
 * this is real XHTTP/H3 QUIC, not xray-core's removed standalone "quic".
 *
 * Kept at FOUNDATION until physical-device AND production-port verification
 * (see this PR's own PRODUCTION APPROVAL REQUIRED gate): this class exists
 * and is fully wired so it CAN be manually/test-invoked or registered as
 * available (see TransportRegistry/MainViewModel.buildTransportRegistry),
 * but nothing in this slice adds QUIC to any automatic failover path.
 */
class VlessQuicTransport(
    private val context: Context,
    private val profileRepositoryFor: (EndpointId) -> XrayQuicProfileRepository =
        { id -> XrayQuicProfileRepositoryFactory.create(context, id) },
) : VpnTransport {

    override val name: String = "xray-vless-quic"
    override val kind: TransportKind = TransportKind.QUIC
    override val capabilities: TransportCapabilities = TransportCapabilities.xrayQuicAdapterShell()

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.XrayQuic) { "VlessQuicTransport only accepts TransportConfig.XrayQuic" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        val profileRepository = profileRepositoryFor(config.endpointId)
        when (val resolution = XrayRuntimeResolver.resolveQuic(profileRepository)) {
            is XrayQuicRuntimeResolution.Rejected -> {
                state.value = TransportState.Error("Xray QUIC profile not ready: ${resolution.reason}")
                return
            }
            is XrayQuicRuntimeResolution.Ready -> Unit
        }

        val sessionId = nextSessionId.incrementAndGet()
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
                .putExtra(NovaXrayVpnService.EXTRA_TRANSPORT_KIND, TransportKind.QUIC.name)
                .putExtra(NovaXrayVpnService.EXTRA_ENDPOINT_ID, config.endpointId.value)
                .putExtra(NovaXrayVpnService.EXTRA_ROUTING_MODE, config.routingMode.name)
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
            val intent = Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_STOP)
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
