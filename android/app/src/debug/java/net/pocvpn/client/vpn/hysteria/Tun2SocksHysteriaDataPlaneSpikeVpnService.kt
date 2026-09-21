package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "B46_3C_DataPlaneSpike"
private const val SPIKE_SESSION_NAME = "B46-3C process-isolated Hysteria2 data-plane spike (RESEARCH ONLY - not a real VPN transport)"
private const val TUN_ADDRESS = "10.206.49.1"
private const val TUN_PREFIX_LENGTH = 24
private const val DEFAULT_ROUTE = "0.0.0.0"
private const val DEFAULT_ROUTE_PREFIX = 0
private const val DNS_PRIMARY = "1.1.1.1"
private const val DNS_SECONDARY = "1.0.0.1"
private const val MTU = 1400
private const val TUN2SOCKS_CONTROL_SOCKET_FILENAME = "b46-3c-tun2socks-control.sock"
private const val LOCAL_SOCKS_ADDR = "127.0.0.1:41080"
private const val HYSTERIA_WORKDIR_NAME = "b46-3c-hysteria"

/** Result the spike service reports through [Tun2SocksHysteriaDataPlaneSpikeVpnService.status]. */
sealed interface DataPlaneSpikeStatus {
    object Idle : DataPlaneSpikeStatus
    data class Started(val tun2socksPid: Int, val quicConnected: Boolean) : DataPlaneSpikeStatus
    data class Failed(val reason: String) : DataPlaneSpikeStatus
}

/**
 * B46-3C - RESEARCH ONLY, NOT A PRODUCTION TRANSPORT. Debug-only real
 * [VpnService] proving the COMPLETE process-isolated Hysteria2 data-plane
 * path on a genuine full-tunnel Android TUN - see
 * docs/B46_3C_HYSTERIA_PROCESS_ISOLATED_DATAPLANE.md. Three independent
 * runtime boundaries, exactly as B46-3A's own finding demands: Xray's Go
 * runtime (if loaded) stays in THIS app process; the tun2socks Go runtime
 * runs in its own OS process ([Tun2SocksChildRuntime], unchanged from
 * B46-3B); the minimal Hysteria2 Go runtime runs in a THIRD, separate OS
 * process ([HysteriaChildRuntime]). No process ever contains two
 * independent Go runtimes.
 *
 * TUN config mirrors B46-2P's own real physical validation exactly (same
 * values, re-derived rather than imported since this debug spike has zero
 * dependency on B46-2P's own harness module): `10.206.49.1/24`, MTU 1400,
 * DNS `1.1.1.1`/`1.0.0.1`, `0.0.0.0/0` (full tunnel).
 * `addDisallowedApplication` is deliberately never called, same reasoning
 * B46-2P already established - this app's own in-app probe traffic is
 * captured by the TUN exactly like any other app's traffic; only the
 * Hysteria2 child's own QUIC socket is excluded, and only via the real
 * `protect(fd)` call routed through [HysteriaChildRuntime]'s own protect
 * bridge.
 *
 * FD ownership: unchanged from B46-3B - this service is the SOLE owner of
 * the original TUN [ParcelFileDescriptor]; only a DUPLICATE is ever handed
 * to [Tun2SocksChildRuntime.start].
 *
 * Startup order: the Hysteria2 child is started FIRST (it must report its
 * own `SOCKS5_LISTENING` readiness before tun2socks is told to proxy
 * through it) - see [handleStart]. Either child dying unexpectedly tears
 * down the WHOLE session (both children, the TUN, all artifacts) - a
 * partial session (one child alive, the other dead) is never left
 * standing.
 */
class Tun2SocksHysteriaDataPlaneSpikeVpnService : VpnService() {

    private val tunFdLock = Any()
    private var tunFd: ParcelFileDescriptor? = null
    private val tun2socksRuntime = Tun2SocksChildRuntime()
    private val hysteriaRuntime = HysteriaChildRuntime()

    init {
        tun2socksRuntime.onUnexpectedExit = { code -> handleUnexpectedExit("tun2socks", code) }
        hysteriaRuntime.onUnexpectedExit = { code -> handleUnexpectedExit("hysteria", code) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> handleStart(
                server = intent.getStringExtra(EXTRA_SERVER) ?: "",
                auth = intent.getStringExtra(EXTRA_AUTH) ?: "",
                sni = intent.getStringExtra(EXTRA_SNI) ?: "",
                insecure = intent.getBooleanExtra(EXTRA_INSECURE, false),
            )
            ACTION_STOP -> handleStop()
            else -> Log.w(TAG, "onStartCommand: unrecognized action ${intent?.action}")
        }
        return START_NOT_STICKY
    }

    private fun handleStart(server: String, auth: String, sni: String, insecure: Boolean) {
        val tun2socksBinary = when (val r = Tun2SocksChildBinaryResolver.resolve(applicationInfo.nativeLibraryDir)) {
            is Tun2SocksChildBinaryResolver.Result.Found -> r.file.absolutePath
            is Tun2SocksChildBinaryResolver.Result.Missing -> {
                _status.value = DataPlaneSpikeStatus.Failed("tun2socks-child: ${r.reason}")
                return
            }
        }
        val hysteriaBinary = when (val r = HysteriaChildBinaryResolver.resolve(applicationInfo.nativeLibraryDir)) {
            is HysteriaChildBinaryResolver.Result.Found -> r.file.absolutePath
            is HysteriaChildBinaryResolver.Result.Missing -> {
                _status.value = DataPlaneSpikeStatus.Failed("hysteria-child: ${r.reason}")
                return
            }
        }

        val established = Builder()
            .addAddress(TUN_ADDRESS, TUN_PREFIX_LENGTH)
            .addRoute(DEFAULT_ROUTE, DEFAULT_ROUTE_PREFIX)
            .addDnsServer(DNS_PRIMARY)
            .addDnsServer(DNS_SECONDARY)
            .setMtu(MTU)
            .setSession(SPIKE_SESSION_NAME)
            .setBlocking(false)
            .establish()

        if (established == null) {
            _status.value = DataPlaneSpikeStatus.Failed("Builder.establish() returned null - VPN permission not granted?")
            return
        }
        synchronized(tunFdLock) {
            tunFd = established
            _originalTunFd = established.fileDescriptor
        }

        // Hysteria2 child FIRST - tun2socks needs its SOCKS5 listener ready.
        val hysteriaWorkDir = File(filesDir, HYSTERIA_WORKDIR_NAME)
        val hysteriaResult = hysteriaRuntime.start(
            config = HysteriaChildConfig(server = server, auth = auth, sni = sni, insecure = insecure, socksListen = LOCAL_SOCKS_ADDR),
            binaryPath = hysteriaBinary,
            workingDir = hysteriaWorkDir,
            protector = { fd -> protect(fd) },
        )
        if (hysteriaResult is HysteriaChildResult.Failed) {
            Log.w(TAG, "hysteria child start failed: ${hysteriaResult.reason}")
            _status.value = DataPlaneSpikeStatus.Failed("hysteria: ${hysteriaResult.reason}")
            closeOriginalTunFd()
            return
        }

        val dupFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
        val controlSocketPath = File(filesDir, TUN2SOCKS_CONTROL_SOCKET_FILENAME)
        val tun2socksResult = tun2socksRuntime.start(dupFd, MTU, LOCAL_SOCKS_ADDR, tun2socksBinary, controlSocketPath)
        when (tun2socksResult) {
            is Tun2SocksChildResult.Ok -> {
                _status.value = DataPlaneSpikeStatus.Started(tun2socksResult.pid, hysteriaRuntime.quicConnected)
            }
            is Tun2SocksChildResult.Failed -> {
                Log.w(TAG, "tun2socks child start failed: ${tun2socksResult.reason}")
                _status.value = DataPlaneSpikeStatus.Failed("tun2socks: ${tun2socksResult.reason}")
                hysteriaRuntime.stop()
                closeOriginalTunFd()
            }
        }
    }

    private fun handleStop() {
        tun2socksRuntime.stop()
        hysteriaRuntime.stop()
        closeOriginalTunFd()
        _status.value = DataPlaneSpikeStatus.Idle
        stopSelf()
    }

    /** Either child dying unexpectedly tears down the WHOLE session - never a half-alive state. */
    private fun handleUnexpectedExit(which: String, exitCode: Int) {
        Log.w(TAG, "$which child exited unexpectedly: code=$exitCode - tearing down the whole session")
        tun2socksRuntime.stop()
        hysteriaRuntime.stop()
        closeOriginalTunFd()
        _status.value = DataPlaneSpikeStatus.Failed("$which child exited unexpectedly (code=$exitCode)")
    }

    private fun closeOriginalTunFd() {
        synchronized(tunFdLock) {
            runCatching { tunFd?.close() }
            tunFd = null
            _originalTunFd = null
        }
    }

    override fun onDestroy() {
        handleStop()
        super.onDestroy()
    }

    override fun onRevoke() {
        handleStop()
        super.onRevoke()
    }

    companion object {
        const val ACTION_START = "net.pocvpn.client.vpn.hysteria.DATAPLANE_SPIKE_START"
        const val ACTION_STOP = "net.pocvpn.client.vpn.hysteria.DATAPLANE_SPIKE_STOP"
        const val EXTRA_SERVER = "server"
        const val EXTRA_AUTH = "auth"
        const val EXTRA_SNI = "sni"
        const val EXTRA_INSECURE = "insecure"

        private val _status = MutableStateFlow<DataPlaneSpikeStatus>(DataPlaneSpikeStatus.Idle)
        val status: StateFlow<DataPlaneSpikeStatus> = _status.asStateFlow()

        @Volatile
        private var _originalTunFd: java.io.FileDescriptor? = null

        fun currentOriginalTunFileDescriptor(): java.io.FileDescriptor? = _originalTunFd
    }
}
