package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "Tun2SocksIsolatedSpike"
private const val SPIKE_SESSION_NAME = "B46-3B process-isolated tun2socks spike (SPIKE ONLY - not a real VPN)"
private const val TUN_ADDRESS = "10.205.48.1"
private const val TUN_PREFIX_LENGTH = 24
private const val TUN_ROUTE = "10.205.48.0"
private const val CONTROL_SOCKET_FILENAME = "b46-3b-tun2socks-control.sock"

/** Result the spike service reports back through [Tun2SocksProcessIsolatedSpikeVpnService.status]. */
sealed interface Tun2SocksIsolatedSpikeStatus {
    object Idle : Tun2SocksIsolatedSpikeStatus
    data class Started(val childPid: Int) : Tun2SocksIsolatedSpikeStatus
    data class Failed(val reason: String) : Tun2SocksIsolatedSpikeStatus
}

/**
 * B46-3B - SPIKE ONLY, NOT A PRODUCTION TRANSPORT. Debug-only real
 * [VpnService] proving the PROCESS-ISOLATED native tun2socks bridge's real
 * fd-lifecycle mechanics against a genuine Android TUN interface - see
 * docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md. Same narrow-route,
 * never-carries-real-traffic discipline as B46-3A's own (rejected) spike
 * and B45A's spike before it - never wired into
 * TransportRegistry/VpnController/SmartConnect.
 *
 * Unlike B46-3A's spike, this NEVER loads any tun2socks code into this
 * process at all - [Tun2SocksChildRuntime] spawns a separate OS process
 * for the real tun2socks Go runtime.
 *
 * FD ownership contract (load-bearing, reused verbatim from B46-2C/B46-2P/
 * B46-3A/B46-3B's own [Tun2SocksChildRuntime]): this service is the SOLE
 * owner of the original [ParcelFileDescriptor] Android hands back from
 * `Builder.establish()`. Only a DUPLICATE is ever handed to
 * [Tun2SocksChildRuntime.start] (which itself hands it to the child via
 * SCM_RIGHTS, see that class's own doc); this service never closes that
 * duplicate itself, and closes the ORIGINAL exactly once, on its own
 * [handleStop]/[onDestroy]/[onRevoke].
 */
class Tun2SocksProcessIsolatedSpikeVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    private val runtime = Tun2SocksChildRuntime()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> handleStart(
                socksAddr = intent.getStringExtra(EXTRA_SOCKS_ADDR) ?: DEFAULT_SOCKS_ADDR,
                mtu = intent.getIntExtra(EXTRA_MTU, DEFAULT_MTU),
            )
            ACTION_STOP -> handleStop()
            else -> Log.w(TAG, "onStartCommand: unrecognized action ${intent?.action}")
        }
        return START_NOT_STICKY
    }

    private fun handleStart(socksAddr: String, mtu: Int) {
        val resolution = Tun2SocksChildBinaryResolver.resolve(applicationInfo.nativeLibraryDir)
        val binaryPath = when (resolution) {
            is Tun2SocksChildBinaryResolver.Result.Found -> resolution.file.absolutePath
            is Tun2SocksChildBinaryResolver.Result.Missing -> {
                Log.e(TAG, "tun2socks-child binary resolution failed: ${resolution.reason}")
                _status.value = Tun2SocksIsolatedSpikeStatus.Failed(resolution.reason)
                return
            }
        }

        val established = Builder()
            .addAddress(TUN_ADDRESS, TUN_PREFIX_LENGTH)
            .addRoute(TUN_ROUTE, TUN_PREFIX_LENGTH)
            .setMtu(mtu)
            .setSession(SPIKE_SESSION_NAME)
            .setBlocking(false)
            .establish()

        if (established == null) {
            _status.value = Tun2SocksIsolatedSpikeStatus.Failed("Builder.establish() returned null - VPN permission not granted?")
            return
        }
        tunFd = established
        _originalTunFd = established.fileDescriptor

        val dupFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
        val controlSocketPath = File(filesDir, CONTROL_SOCKET_FILENAME)

        when (val result = runtime.start(dupFd, mtu, socksAddr, binaryPath, controlSocketPath)) {
            is Tun2SocksChildResult.Ok -> _status.value = Tun2SocksIsolatedSpikeStatus.Started(result.pid)
            is Tun2SocksChildResult.Failed -> {
                Log.w(TAG, "child start failed: ${result.reason}")
                _status.value = Tun2SocksIsolatedSpikeStatus.Failed(result.reason)
                runCatching { tunFd?.close() }
                tunFd = null
                _originalTunFd = null
            }
        }
    }

    private fun handleStop() {
        val stopResult = runtime.stop()
        if (stopResult is Tun2SocksChildResult.Failed) {
            Log.w(TAG, "child stop reported: ${stopResult.reason}")
        }
        runCatching { tunFd?.close() }
        tunFd = null
        _originalTunFd = null
        _status.value = Tun2SocksIsolatedSpikeStatus.Idle
        stopSelf()
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
        const val ACTION_START = "net.pocvpn.client.vpn.hysteria.TUN2SOCKS_ISOLATED_SPIKE_START"
        const val ACTION_STOP = "net.pocvpn.client.vpn.hysteria.TUN2SOCKS_ISOLATED_SPIKE_STOP"
        const val EXTRA_SOCKS_ADDR = "socksAddr"
        const val EXTRA_MTU = "mtu"
        const val DEFAULT_SOCKS_ADDR = "127.0.0.1:41999"
        const val DEFAULT_MTU = 1500

        private val _status = MutableStateFlow<Tun2SocksIsolatedSpikeStatus>(Tun2SocksIsolatedSpikeStatus.Idle)

        /** Observed by the instrumentation tests - process-wide, since only one spike instance may exist at a time. */
        val status: StateFlow<Tun2SocksIsolatedSpikeStatus> = _status.asStateFlow()

        @Volatile
        private var _originalTunFd: java.io.FileDescriptor? = null

        /** See `NativeTun2SocksSpikeVpnService.currentOriginalTunFileDescriptor`'s own doc (B46-3A) for why this exists - same stress-test-reuse rationale. */
        fun currentOriginalTunFileDescriptor(): java.io.FileDescriptor? = _originalTunFd
    }
}
