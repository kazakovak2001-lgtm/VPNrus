package net.pocvpn.client.vpn.shadowsocks

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import java.io.IOException

private const val TAG = "ShadowsocksTunFdBridge"
private const val RETRY_INTERVAL_MILLIS = 100L

internal enum class ShadowsocksTunFdBridgeState { WAITING, FD_SENT, FAILED }

/**
 * B45B-3 - production TUN-fd handoff, same upstream `tun_device_fd_from_path`
 * protocol B45A physically proved (Android is the CLIENT: connects, sends
 * the fd via SCM_RIGHTS, sslocal never acks on this path - see
 * B45ATunFdBridge's own docs for the full protocol citation). Not
 * redesigned: same bounded-retry connect loop, same typed terminal states.
 *
 * Hardening over the spike: obtains the ancillary-eligible FileDescriptor via
 * the public [ParcelFileDescriptor.adoptFd] API instead of reflecting into
 * java.io.FileDescriptor's private `descriptor` field (the spike's approach -
 * a real non-SDK-interface risk this production class avoids, mirroring the
 * fix already applied on the protect bridge's receive side).
 */
internal interface ShadowsocksTunFdBridge {
    fun handOff(tunFd: Int, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState
}

internal class RealShadowsocksTunFdBridge : ShadowsocksTunFdBridge {

    override fun handOff(tunFd: Int, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var lastError: Throwable? = null

        // adoptFd does NOT dup - it wraps the existing fd number. The caller
        // (ShadowsocksRuntime) retains its own ParcelFileDescriptor over the
        // same underlying TUN fd for its own lifecycle; closing THIS wrapper
        // must never close the underlying fd out from under that owner, so
        // it is deliberately never close()'d here - only detached.
        val adopted = ParcelFileDescriptor.adoptFd(tunFd)
        try {
            while (System.currentTimeMillis() < deadline) {
                val socket = LocalSocket()
                try {
                    socket.connect(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                    socket.setFileDescriptorsForSend(arrayOf(adopted.fileDescriptor))
                    // Upstream only checks fd_size != 0 - payload bytes unused.
                    socket.outputStream.write(byteArrayOf(1))
                    socket.outputStream.flush()
                    Log.d(TAG, "handed off tun fd to ${socketPath.absolutePath}")
                    return ShadowsocksTunFdBridgeState.FD_SENT
                } catch (err: IOException) {
                    lastError = err
                    Thread.sleep(RETRY_INTERVAL_MILLIS)
                } finally {
                    runCatching { socket.close() }
                }
            }
        } finally {
            // detachFd() releases this wrapper's ownership WITHOUT closing
            // the underlying fd (see ParcelFileDescriptor's own contract) -
            // the real TUN ParcelFileDescriptor the caller already holds
            // remains the sole close authority.
            runCatching { adopted.detachFd() }
        }

        Log.w(TAG, "tun fd handoff timed out after ${timeoutMillis}ms", lastError)
        return ShadowsocksTunFdBridgeState.FAILED
    }
}
