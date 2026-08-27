package net.pocvpn.client.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.AwgConfigMapper
import net.pocvpn.client.vpn.config.TransportConfig
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel

/**
 * VpnTransport backed by the official upstream AmneziaWG GoBackend.
 * This is the only class (besides AwgConfigMapper) that touches org.amnezia.awg.* -
 * everything above VpnTransport deals only in TransportConfig/TransportState.
 */
class AmneziaWgTransport(private val context: Context) : VpnTransport {

    override val name: String = "amneziawg"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)

    private val backend by lazy { GoBackend(context.applicationContext) }

    private val tunnel = object : Tunnel {
        override fun getName(): String = TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            state.value = when (newState) {
                Tunnel.State.UP -> TransportState.Connected
                Tunnel.State.DOWN -> TransportState.Disconnected
                Tunnel.State.TOGGLE -> state.value
            }
        }
    }

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.Awg) { "AmneziaWgTransport only accepts TransportConfig.Awg" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        state.value = TransportState.Connecting
        try {
            val backendConfig = AwgConfigMapper.toBackendConfig(config.config)
            withContext(Dispatchers.IO) {
                backend.setState(tunnel, Tunnel.State.UP, backendConfig)
            }
            // tunnel.onStateChange(UP) is invoked by the backend itself on success;
            // if setState returned without throwing but state is still Connecting,
            // reflect the backend's own view directly as a fallback.
            if (state.value == TransportState.Connecting) {
                state.value = TransportState.Connected
            }
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    override suspend fun disconnect() {
        state.value = TransportState.Disconnecting
        try {
            withContext(Dispatchers.IO) {
                backend.setState(tunnel, Tunnel.State.DOWN, null)
            }
            state.value = TransportState.Disconnected
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
        }
    }

    override fun observeState(): Flow<TransportState> = state.asStateFlow()

    private companion object {
        const val TUNNEL_NAME = "pocvpn"
    }
}
