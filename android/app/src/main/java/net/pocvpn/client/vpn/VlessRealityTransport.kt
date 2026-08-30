package net.pocvpn.client.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XrayRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver

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
 * B8K4C - the `config` parameter's embedded XrayVlessRealityConfig is
 * deliberately NOT what gets validated or used below (only its TYPE is
 * checked, via the require() call) - NovaXrayVpnService loads its own
 * profile straight from [XrayProfileRepository] on ACTION_START and ignores
 * anything this class might otherwise have sent it, so validating a
 * caller-supplied config object here would prove nothing about what
 * actually starts. Instead this class runs the SAME [XrayRuntimeResolver]
 * against the SAME repository as a genuine pre-flight check - one
 * authoritative configuration source, never Intent extras.
 *
 * State fidelity limitation (honest, not a bug to "fix" casually): this
 * shell has no IPC/binder channel back from NovaXrayVpnService reporting
 * real core status, unlike AmneziaWgTransport's Tunnel.onStateChange
 * callback. [observeState] therefore never reports [TransportState.Connected]
 * for a request that merely returned from startService() - it stays at
 * [TransportState.Connecting] ("request accepted"), not a confirmed Xray core
 * handshake/traffic state - that requires either the physical-device
 * verification described in docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md, or a real
 * service->transport status channel this slice does not add.
 */
class VlessRealityTransport(
    private val context: Context,
    // Additive test seam, defaults to the real authoritative encrypted store -
    // same factory/AndroidKeyStore alias NovaXrayVpnService itself reads
    // from (see XrayProfileRepositoryFactory's own docs), so this class's
    // pre-flight check and NovaXrayVpnService's actual startup decision can
    // never look at two different stores.
    private val profileRepository: XrayProfileRepository = XrayProfileRepositoryFactory.create(context),
) : VpnTransport {

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

        when (val resolution = XrayRuntimeResolver.resolve(profileRepository)) {
            is XrayRuntimeResolution.Rejected -> {
                state.value = TransportState.Error("Xray profile not ready: ${resolution.reason}")
                return
            }
            is XrayRuntimeResolution.Ready -> Unit
        }

        state.value = TransportState.Connecting
        try {
            val intent = Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_START)
            context.startService(intent)
            // See this class's own docs: no confirmation channel yet - stays
            // Connecting (request accepted only), never a fabricated Connected.
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
