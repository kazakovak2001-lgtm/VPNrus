package net.pocvpn.client.vpn.hysteria

import android.content.Context
import android.content.Intent
import android.net.VpnService
import java.util.concurrent.atomic.AtomicLong
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
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.UnderlyingNetworkRecovery
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.TransportConfig

/**
 * B46-4A - the production, isolated `VpnTransport` adapter for Hysteria2.
 * Follows the SAME session-scoped state shape
 * [net.pocvpn.client.vpn.shadowsocks.ShadowsocksTransport] already
 * establishes (Intent-driven start/stop against its own VpnService,
 * session-id-scoped state collection - a stale previous session can never
 * mark a new session Connected) - no new transport interface, no new
 * public lifecycle authority.
 *
 * DELIBERATE PRODUCTION-SECRET CORRECTION (per task instruction, correcting
 * B46-3C's own debug spike): this class sends ONLY non-secret facts through
 * the start [Intent] - session id, endpoint id, host, port, SNI, public
 * obfuscation mode, routing mode. There is NO `EXTRA_AUTH`, NO
 * `EXTRA_OBFS_PASSWORD`, no secret Bundle/Intent extra of any kind.
 * [Hysteria2VpnService] independently loads the endpoint-scoped encrypted
 * credential from `Hysteria2CredentialRepository` itself.
 *
 * NOT registered AVAILABLE in `TransportRegistry` merely by this class
 * existing - see `MainViewModel.isHysteria2AvailableFor`'s own docs for the
 * full eligibility gate (trusted signed binding + credential + ABI/binary).
 *
 * [underlyingNetworkRecovery] is [UnderlyingNetworkRecovery.RESTART_SESSION] -
 * seamless roaming is unverified; this transport never claims IN_PLACE
 * recovery (see [TransportCapabilities.hysteria2AdapterShell]'s own doc).
 */
class Hysteria2Transport(
    private val context: Context,
    private val disconnectConfirmTimeoutMillis: Long = 6_000L,
) : VpnTransport {

    override val name: String = "hysteria2"
    override val kind: TransportKind = TransportKind.HYSTERIA2
    override val capabilities: TransportCapabilities = TransportCapabilities.hysteria2AdapterShell()
    override val underlyingNetworkRecovery: UnderlyingNetworkRecovery = UnderlyingNetworkRecovery.RESTART_SESSION

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.Hysteria2) { "Hysteria2Transport only accepts TransportConfig.Hysteria2" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        val sessionId = nextSessionId.incrementAndGet()
        observerJob?.cancel()
        observerJob = scope.launch {
            Hysteria2VpnService.status.collect { status ->
                if (status != null && status.sessionId == sessionId) {
                    hysteria2TransportStateFor(status.phase)?.let { state.value = it }
                }
            }
        }

        state.value = TransportState.Connecting
        try {
            val intent = Intent(context, Hysteria2VpnService::class.java)
                .setAction(Hysteria2VpnService.ACTION_START)
                .putExtra(Hysteria2VpnService.EXTRA_SESSION_ID, sessionId)
                .putExtra(Hysteria2VpnService.EXTRA_ENDPOINT_ID, config.endpointId.value)
                .putExtra(Hysteria2VpnService.EXTRA_HOST, config.host)
                .putExtra(Hysteria2VpnService.EXTRA_PORT, config.port)
                .putExtra(Hysteria2VpnService.EXTRA_SNI, config.sni)
                .putExtra(Hysteria2VpnService.EXTRA_OBFUSCATION_MODE, config.obfuscationMode)
                .putExtra(Hysteria2VpnService.EXTRA_ROUTING_MODE, config.routingMode.name)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    /** Same deterministic, non-fire-and-forget disconnect discipline as [net.pocvpn.client.vpn.shadowsocks.ShadowsocksTransport.disconnect] - see that method's own doc. */
    override suspend fun disconnect() {
        if (state.value is TransportState.Disconnected) return
        state.value = TransportState.Disconnecting
        try {
            val intent = Intent(context, Hysteria2VpnService::class.java).setAction(Hysteria2VpnService.ACTION_STOP)
            context.startService(intent)
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
            return
        }
        withTimeoutOrNull(disconnectConfirmTimeoutMillis) {
            state.first { it is TransportState.Disconnected || it is TransportState.Error }
        }
        if (state.value !is TransportState.Disconnected && state.value !is TransportState.Error) {
            state.value = TransportState.Disconnected
        }
    }

    override fun observeState(): Flow<TransportState> = state.asStateFlow()

    private companion object {
        val nextSessionId = AtomicLong(0)
    }
}

/**
 * Pure mapping, file-scope for direct unit testing without a Context/Intent
 * double (mirrors [net.pocvpn.client.vpn.shadowsocks.shadowsocksTransportStateFor]'s
 * own convention). [Hysteria2RuntimePhase.RUNNING] is reported by
 * [Hysteria2VpnService] only once BOTH children have confirmed real
 * readiness (Hysteria2 child SOCKS5_LISTENING + successful QUIC connect,
 * AND tun2socks child started) - never merely "TUN established" or
 * "process exists" (see [Hysteria2VpnService]'s own "connected definition"
 * doc).
 */
internal fun hysteria2TransportStateFor(phase: Hysteria2RuntimePhase): TransportState? = when (phase) {
    Hysteria2RuntimePhase.STOPPED -> TransportState.Disconnected
    Hysteria2RuntimePhase.STARTING -> TransportState.Connecting
    Hysteria2RuntimePhase.RUNNING -> TransportState.Connected
    Hysteria2RuntimePhase.STOPPING -> TransportState.Disconnecting
    Hysteria2RuntimePhase.FAILED -> TransportState.Error("Hysteria2 runtime failed")
}
