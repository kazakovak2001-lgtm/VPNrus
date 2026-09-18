package net.pocvpn.client.vpn.shadowsocks

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

private const val TAG = "ShadowsocksTunFdBridge"
private const val RETRY_INTERVAL_MILLIS = 100L

internal enum class ShadowsocksTunFdBridgeState { WAITING, FD_SENT, FAILED }

/**
 * B45B-3P - production TUN-fd handoff, same upstream `tun_device_fd_from_path`
 * protocol B45A physically proved (Android is the CLIENT: connects, sends
 * the fd via SCM_RIGHTS, sslocal never acks on this path - see
 * B45ATunFdBridge's own docs for the full protocol citation).
 *
 * **Ownership model (physical-crash-driven correction of B45B-3's own
 * mistake)**: takes the ALREADY-OWNED [FileDescriptor] straight from the real
 * TUN `android.os.ParcelFileDescriptor` `ShadowsocksVpnService` holds
 * (`tunParcelFileDescriptor.fileDescriptor`) and hands it directly to
 * `LocalSocket.setFileDescriptorsForSend` - never a second owner.
 *
 * Verified directly against the AOSP source
 * (`frameworks/base/core/java/android/net/LocalSocketImpl.java`,
 * `setFileDescriptorsForSend`/`SocketOutputStream.write`): the fds are held
 * in a plain field and handed to a native `sendmsg()`-based SCM_RIGHTS write
 * on the next `write()` call - a KERNEL-level fd duplication into the
 * receiving process, never a Java-level `ParcelFileDescriptor`/fdsan
 * operation. `java.io.FileDescriptor` itself carries no fdsan ownership tag
 * (only `ParcelFileDescriptor`'s own constructor does) - so plain
 * `ParcelFileDescriptor.getFileDescriptor()` (a side-effect-free getter) is
 * safe to pass through unmodified: the sender's own fd is never closed,
 * duplicated, or reassigned by this send, and the original
 * `ParcelFileDescriptor` remains the sole owner/close-authority throughout
 * and after this call.
 *
 * B45B-3's own first version called `ParcelFileDescriptor.adoptFd(tunFd)` on
 * the raw fd int, which DOES perform an fdsan ownership-tag exchange
 * expecting an UNTAGGED fd - since the real TUN `ParcelFileDescriptor`
 * already owns/tags that exact fd, this aborted the whole process
 * (`SIGABRT`, "fdsan: failed to exchange ownership...was expected to be
 * unowned") the first time it ran on a real device. This class's
 * [FileDescriptor]-typed contract makes that class of mistake structurally
 * unreachable: `java.io.FileDescriptor` exposes no `close()`/`adopt`-style
 * API for this class to misuse in the first place.
 */
internal interface ShadowsocksTunFdBridge {
    /** [tunFd] is BORROWED, never owned by this call - the caller's own TUN [android.os.ParcelFileDescriptor] remains the sole close authority before, during, and after this returns. */
    fun handOff(tunFd: FileDescriptor, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState
}

internal class RealShadowsocksTunFdBridge : ShadowsocksTunFdBridge {

    override fun handOff(tunFd: FileDescriptor, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var lastError: Throwable? = null

        while (System.currentTimeMillis() < deadline) {
            val socket = LocalSocket()
            try {
                socket.connect(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                // Borrowed, not adopted - see this class's own docs. Never
                // closed here; the caller's TUN ParcelFileDescriptor remains
                // valid and open after this send completes.
                socket.setFileDescriptorsForSend(arrayOf(tunFd))
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

        Log.w(TAG, "tun fd handoff timed out after ${timeoutMillis}ms", lastError)
        return ShadowsocksTunFdBridgeState.FAILED
    }
}
