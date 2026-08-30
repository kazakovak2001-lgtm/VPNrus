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
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import net.pocvpn.client.vpn.xray.XrayTlsRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import java.util.concurrent.atomic.AtomicLong

/**
 * B8O2 - the TLS/TCP counterpart of [VlessRealityTransport]: same isolated
 * adapter shell, the SAME [NovaXrayVpnService]/[net.pocvpn.client.vpn.xray.XrayCoreController]
 * runtime shell REALITY already uses (never a second VpnService or TUN/
 * socket-protection stack - see this class's own [connect] for the ONE
 * difference, [NovaXrayVpnService.EXTRA_TRANSPORT_KIND]), a DIFFERENT
 * [XrayTlsProfileRepository] and [TransportKind.TLS_TCP].
 *
 * Kept at FOUNDATION until physical-device verification: this class exists
 * and is fully wired so it CAN be manually/test-invoked or registered as
 * available (see TransportRegistry/MainViewModel.buildTransportRegistry),
 * but nothing in this slice adds TLS_TCP to any automatic failover path
 * (see AwgXrayFailoverPolicy, deliberately untouched) - see
 * docs/ROADMAP.md's own TLS/TCP fallback row for why.
 */
class VlessTlsTransport(
    private val context: Context,
    // B13 (audit item 5 fix) - same "resolved per-attempt, never fixed at
    // construction" contract as VlessRealityTransport.profileRepositoryFor -
    // see that field's own docs.
    private val profileRepositoryFor: (EndpointId) -> XrayTlsProfileRepository =
        { id -> XrayTlsProfileRepositoryFactory.create(context, id) },
) : VpnTransport {

    override val name: String = "xray-vless-tls"
    override val kind: TransportKind = TransportKind.TLS_TCP
    override val capabilities: TransportCapabilities = TransportCapabilities.xrayTlsAdapterShell()

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.XrayTls) { "VlessTlsTransport only accepts TransportConfig.XrayTls" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        // B13 - resolved for THIS attempt's real endpoint, never a fixed instance.
        val profileRepository = profileRepositoryFor(config.endpointId)
        when (val resolution = XrayRuntimeResolver.resolveTls(profileRepository)) {
            is XrayTlsRuntimeResolution.Rejected -> {
                state.value = TransportState.Error("Xray TLS profile not ready: ${resolution.reason}")
                return
            }
            is XrayTlsRuntimeResolution.Ready -> Unit
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
                .putExtra(NovaXrayVpnService.EXTRA_TRANSPORT_KIND, TransportKind.TLS_TCP.name)
                .putExtra(NovaXrayVpnService.EXTRA_ENDPOINT_ID, config.endpointId.value)
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
