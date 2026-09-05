package net.pocvpn.client.bootstrap

import android.content.Intent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.TransportConfig

/**
 * B36 - the safe fallback used only when
 * [net.pocvpn.client.MainViewModel]'s `bootstrapTransportFactory`
 * constructor param is null (bootstrap not wired - every pre-B36
 * construction/test). [preparePermissionIntent] returns a non-null
 * (dummy) [Intent] so [BootstrapTunnelController.connect] fails THIS
 * candidate immediately, without ever calling [connect]/[disconnect] or
 * burning the real handshake-poll timeout window - a real
 * [BootstrapState.Unavailable] is reached quickly for every known
 * candidate, never a fabricated success and never an 8+ second stall for a
 * transport that was never going to work.
 */
internal object NoOpBootstrapTransport : VpnTransport {
    override val name: String = "bootstrap-unwired"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()

    override fun preparePermissionIntent(): Intent = Intent()
    override suspend fun connect(config: TransportConfig) = Unit
    override suspend fun disconnect() = Unit
    override fun observeState(): Flow<TransportState> = flowOf(TransportState.Disconnected)
}
