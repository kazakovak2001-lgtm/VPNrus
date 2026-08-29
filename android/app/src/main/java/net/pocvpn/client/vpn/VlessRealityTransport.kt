package net.pocvpn.client.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XrayConfigValidationResult
import net.pocvpn.client.vpn.xray.validateXrayVlessRealityConfig

/**
 * B8K1B - VpnTransport wrapper around the isolated NovaXrayVpnService. This
 * class is intentionally NOT registered in TransportRegistry.defaults() -
 * TransportKind.XRAY_REALITY stays TransportStatus.NOT_IMPLEMENTED there, so
 * nothing in VpnController/TransportOrchestrator/Smart Connect can construct
 * or select this transport. It exists only so the debug-only manual test
 * entry point (see the `debug` source set) has a real VpnTransport to drive,
 * proving the service/runtime boundary end to end without touching
 * production selection logic.
 *
 * State fidelity limitation (honest, not a bug to "fix" casually): this
 * shell has no IPC/binder channel back from NovaXrayVpnService reporting
 * real core status, unlike AmneziaWgTransport's Tunnel.onStateChange
 * callback. [observeState] therefore reflects only "start/stop was
 * requested", not a confirmed Xray core handshake/traffic state - do not
 * read TransportState.Connected here as proof the tunnel is actually
 * passing traffic; that requires the physical-device verification described
 * in docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md before END_TO_END_VLESS_READY.
 */
class VlessRealityTransport(private val context: Context) : VpnTransport {

    override val name: String = "xray-vless-reality"
    override val kind: TransportKind = TransportKind.XRAY_REALITY
    override val capabilities: TransportCapabilities = TransportCapabilities.xrayRealityAdapterShell()

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.Xray) { "VlessRealityTransport only accepts TransportConfig.Xray" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        val validation = validateXrayVlessRealityConfig(config.config)
        if (validation is XrayConfigValidationResult.Invalid) {
            state.value = TransportState.Error("invalid Xray config: ${validation.errors.size} error(s)")
            return
        }

        state.value = TransportState.Connecting
        try {
            val intent = Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_START)
            context.startService(intent)
            // See this class's own docs: no confirmation channel yet, so this
            // is "start was requested", not a verified handshake.
            state.value = TransportState.Connected
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    override suspend fun disconnect() {
        state.value = TransportState.Disconnecting
        try {
            val intent = Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_STOP)
            context.startService(intent)
            state.value = TransportState.Disconnected
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
        }
    }

    override fun observeState(): Flow<TransportState> = state.asStateFlow()
}
