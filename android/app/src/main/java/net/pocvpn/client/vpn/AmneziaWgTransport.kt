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
import net.pocvpn.client.transport.TransportStats
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

    // B8B3D - the real handshake-freshness signal VpnController polls to
    // decide Connected vs HandshakeFailed.
    //
    // UNIT FIX: Backend.getLastHandshake(tunnel) returns SECONDS, not
    // milliseconds - verified by decompiling the pinned v3.1.20260814 AAR's
    // GoBackend.class bytecode (not assumed, not taken from documentation
    // alone): it parses the wire line `last_handshake_time_sec=<N>` via a
    // bare `Long.parseLong(...)`, with no *1000 anywhere in that method, and
    // returns the negative sentinels -3 (no active tunnel)/-2 (config-fetch
    // or parse failure) on error. Treating that value directly as millis
    // (the original B8B3D bug) would make every real handshake compare as
    // enormously OLDER than any attempt-start timestamp - awaitFreshHandshake
    // would never observe a fresh handshake at all.
    //
    // Backend.getStatistics(tunnel)'s own Statistics.PeerStats, in contrast,
    // IS already correct milliseconds: the SAME decompiled bytecode shows
    // getStatistics() computing `last_handshake_time_sec * 1000 +
    // last_handshake_time_nsec / 1_000_000` before storing it via
    // Statistics.add(...). So this method uses getStatistics() ONLY -
    // getLastHandshake() is not called here at all, which also means none
    // of its negative sentinels can ever reach lastHandshakeEpochMillis:
    // Statistics has no error-sentinel scheme of its own, it simply has no
    // entry for a peer it couldn't parse, or reports 0 (normalized to null
    // below, same as "no handshake yet") if the field was absent/unparsed.
    override suspend fun stats(): TransportStats {
        return try {
            val statistics = withContext(Dispatchers.IO) { backend.getStatistics(tunnel) }
            val peerKey = statistics.peers().firstOrNull() // exactly one peer (the gateway) in this app
            val peerStats = peerKey?.let { statistics.peer(it) }
            TransportStats.Counters(
                bytesReceived = peerStats?.rxBytes() ?: statistics.totalRx(),
                bytesSent = peerStats?.txBytes() ?: statistics.totalTx(),
                lastHandshakeEpochMillis = peerStats?.latestHandshakeEpochMillis()?.takeIf { it > 0 },
            )
        } catch (t: Throwable) {
            TransportStats.Unavailable
        }
    }

    private companion object {
        const val TUNNEL_NAME = "pocvpn"
    }
}
