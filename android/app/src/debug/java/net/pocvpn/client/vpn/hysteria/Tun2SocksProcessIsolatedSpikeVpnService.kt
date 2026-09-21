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
/** Public (not private) so instrumentation tests can check the control socket's real cleanup without duplicating this literal. */
const val TUN2SOCKS_CONTROL_SOCKET_FILENAME = "b46-3b-tun2socks-control.sock"

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
 * `Builder.establish()`. The DUPLICATE handed to [Tun2SocksChildRuntime.start]
 * is owned by that call from the instant it is invoked (see its own FD
 * OWNERSHIP CONTRACT doc) - this service never touches that fd number
 * again after the call, on ANY outcome; it only ever closes the ORIGINAL,
 * exactly once, on its own [handleStop]/[onDestroy]/[onRevoke].
 *
 * UNEXPECTED CHILD DEATH (B46-3B lifecycle-hardening pass): registers
 * [Tun2SocksChildRuntime.onUnexpectedExit] once, in [init] - if the child
 * ever exits without this service's own [handleStop] having initiated it,
 * [handleUnexpectedChildExit] runs the SAME real cleanup [handleStop] does
 * (close the original TUN fd, clear ownership, report a terminal
 * [Tun2SocksIsolatedSpikeStatus.Failed]) automatically, without waiting for
 * a caller to notice and issue an explicit `ACTION_STOP`.
 */
class Tun2SocksProcessIsolatedSpikeVpnService : VpnService() {

    // Touched from both this service's own onStartCommand-driven calls and
    // Tun2SocksChildRuntime's background watcher thread (via
    // handleUnexpectedChildExit) - guarded by tunFdLock so a concurrent
    // "explicit stop" and "unexpected child death" never race on closing/
    // nulling the same field (double-close, or one thread's close() lost
    // to a torn/stale read from the other).
    private val tunFdLock = Any()
    private var tunFd: ParcelFileDescriptor? = null
    private val runtime = Tun2SocksChildRuntime()

    init {
        runtime.onUnexpectedExit = { exitCode -> handleUnexpectedChildExit(exitCode) }
    }

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
        synchronized(tunFdLock) {
            tunFd = established
            _originalTunFd = established.fileDescriptor
        }

        val dupFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
        val controlSocketPath = File(filesDir, TUN2SOCKS_CONTROL_SOCKET_FILENAME)

        when (val result = runtime.start(dupFd, mtu, socksAddr, binaryPath, controlSocketPath)) {
            is Tun2SocksChildResult.Ok -> _status.value = Tun2SocksIsolatedSpikeStatus.Started(result.pid)
            is Tun2SocksChildResult.Failed -> {
                Log.w(TAG, "child start failed: ${result.reason}")
                _status.value = Tun2SocksIsolatedSpikeStatus.Failed(result.reason)
                closeOriginalTunFd()
            }
        }
    }

    private fun handleStop() {
        val stopResult = runtime.stop()
        if (stopResult is Tun2SocksChildResult.Failed) {
            Log.w(TAG, "child stop reported: ${stopResult.reason}")
        }
        closeOriginalTunFd()
        _status.value = Tun2SocksIsolatedSpikeStatus.Idle
        stopSelf()
    }

    private fun closeOriginalTunFd() {
        synchronized(tunFdLock) {
            runCatching { tunFd?.close() }
            tunFd = null
            _originalTunFd = null
        }
    }

    /**
     * Runs on [Tun2SocksChildRuntime]'s own background watcher thread (see
     * that class's own doc on [Tun2SocksChildRuntime.onUnexpectedExit]) -
     * never invoked for an expected [handleStop]-initiated exit, only for
     * the child dying on its own. Performs the SAME real cleanup
     * [handleStop] does, but does NOT call `runtime.stop()` again - the
     * runtime has ALREADY cleared its own `process`/`pid` state by the time
     * this callback fires (see [Tun2SocksChildRuntime.handleChildExit]),
     * and calling `stop()` here would just be a harmless no-op that also
     * risks racing with a caller's own concurrent explicit `ACTION_STOP` -
     * simpler and equally correct to leave `runtime.stop()`'s own
     * idempotency to handle that path if it happens.
     */
    private fun handleUnexpectedChildExit(exitCode: Int) {
        Log.w(TAG, "tun2socks child exited unexpectedly: code=$exitCode")
        closeOriginalTunFd()
        _status.value = Tun2SocksIsolatedSpikeStatus.Failed("child exited unexpectedly (code=$exitCode)")
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
