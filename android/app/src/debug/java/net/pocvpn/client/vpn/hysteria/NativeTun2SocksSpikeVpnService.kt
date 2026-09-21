package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "NativeTun2SocksSpike"
private const val SPIKE_SESSION_NAME = "B46-3A tun2socks bridge spike (SPIKE ONLY - not a real VPN)"
private const val TUN_ADDRESS = "10.204.47.1"
private const val TUN_PREFIX_LENGTH = 24
private const val TUN_ROUTE = "10.204.47.0"

/** Result the spike service reports back through [NativeTun2SocksSpikeVpnService.status]. */
sealed interface NativeTun2SocksSpikeStatus {
    object Idle : NativeTun2SocksSpikeStatus
    object Started : NativeTun2SocksSpikeStatus
    data class Failed(val reason: String) : NativeTun2SocksSpikeStatus
}

/**
 * B46-3A - SPIKE ONLY, NOT A PRODUCTION TRANSPORT. Debug-only real
 * [VpnService] whose only purpose is to prove the native tun2socks bridge's
 * real fd-lifecycle mechanics against a genuine Android TUN interface - see
 * docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md Part E. It never carries
 * real application traffic (narrow, non-default route only - same
 * discipline as [net.pocvpn.client.debug.b45a.B45ASpikeVpnService]) and is
 * never wired into TransportRegistry/VpnController/SmartConnect.
 *
 * Calls straight into the real JNI-backed [NativeTun2SocksBridge] singleton
 * (not the Kotlin-side [NativeTun2SocksController] gate, which is already
 * covered by JVM unit tests) - so this service's own "already started"/
 * "idempotent stop" behavior exercises the REAL native/Go engine state
 * machine, not a Kotlin approximation of it.
 *
 * FD ownership contract (load-bearing, reused verbatim from B46-2C/B46-2P -
 * see [NativeTun2SocksBridge]'s own doc): this service is the SOLE owner of
 * the original [ParcelFileDescriptor] Android hands back from
 * `Builder.establish()`. Only a DUPLICATE
 * (`ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`) is ever
 * given to [NativeTun2SocksBridge]; the native engine owns and closes that
 * duplicate on a successful [NativeTun2SocksBridge.stop]. This service never
 * closes the duplicate itself, and closes the ORIGINAL exactly once, on its
 * own [handleStop]/[onDestroy]/[onRevoke].
 */
class NativeTun2SocksSpikeVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null

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
        val established = Builder()
            .addAddress(TUN_ADDRESS, TUN_PREFIX_LENGTH)
            .addRoute(TUN_ROUTE, TUN_PREFIX_LENGTH)
            .setMtu(mtu)
            .setSession(SPIKE_SESSION_NAME)
            .setBlocking(false)
            .establish()

        if (established == null) {
            _status.value = NativeTun2SocksSpikeStatus.Failed("Builder.establish() returned null - VPN permission not granted?")
            return
        }
        tunFd = established
        _originalTunFd = established.fileDescriptor

        // FD ownership contract: the duplicate - never the original - goes
        // to the native bridge.
        val dupFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()

        when (val result = NativeTun2SocksBridge.start(dupFd, mtu, socksAddr)) {
            is NativeBridgeResult.Ok -> _status.value = NativeTun2SocksSpikeStatus.Started
            is NativeBridgeResult.Failed -> {
                Log.w(TAG, "native start failed: ${result.reason}")
                _status.value = NativeTun2SocksSpikeStatus.Failed(result.reason)
                // The native side never took ownership of dupFd on a failed
                // start (Go's own validation returns before engine.Insert -
                // see native/main.go), so only the ORIGINAL tunFd needs
                // closing here; there is nothing else to release.
                runCatching { tunFd?.close() }
                tunFd = null
            }
        }
    }

    private fun handleStop() {
        val stopResult = NativeTun2SocksBridge.stop()
        if (stopResult is NativeBridgeResult.Failed) {
            Log.w(TAG, "native stop reported: ${stopResult.reason}")
        }
        runCatching { tunFd?.close() }
        tunFd = null
        _originalTunFd = null
        _status.value = NativeTun2SocksSpikeStatus.Idle
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
        const val ACTION_START = "net.pocvpn.client.vpn.hysteria.NATIVE_TUN2SOCKS_SPIKE_START"
        const val ACTION_STOP = "net.pocvpn.client.vpn.hysteria.NATIVE_TUN2SOCKS_SPIKE_STOP"
        const val EXTRA_SOCKS_ADDR = "socksAddr"
        const val EXTRA_MTU = "mtu"
        const val DEFAULT_SOCKS_ADDR = "127.0.0.1:41999"
        const val DEFAULT_MTU = 1500

        private val _status = MutableStateFlow<NativeTun2SocksSpikeStatus>(NativeTun2SocksSpikeStatus.Idle)

        /** Observed by the instrumentation tests - process-wide, since only one spike instance may exist at a time. */
        val status: StateFlow<NativeTun2SocksSpikeStatus> = _status.asStateFlow()

        @Volatile
        private var _originalTunFd: FileDescriptor? = null

        /**
         * The CURRENTLY-ESTABLISHED original TUN [FileDescriptor], or `null`
         * if the spike is idle. Read-only - the instrumentation stress test
         * (Part G of docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md) uses
         * this to `ParcelFileDescriptor.dup(...)` a FRESH duplicate for each
         * repeated native start/stop cycle, reusing the SAME real
         * Android-established TUN interface across the whole stress run
         * instead of tearing it down and re-establishing 100+ times. This
         * function never closes or takes ownership of anything - it only
         * lets a caller mint its own duplicate, same as
         * [NativeTun2SocksSpikeVpnService] itself does internally.
         */
        fun currentOriginalTunFileDescriptor(): FileDescriptor? = _originalTunFd
    }
}
