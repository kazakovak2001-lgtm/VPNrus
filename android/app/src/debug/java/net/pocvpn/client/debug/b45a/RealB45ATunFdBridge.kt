package net.pocvpn.client.debug.b45a

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

private const val TAG = "B45ASpikeTunFd"
private const val RETRY_INTERVAL_MILLIS = 100L

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Real Android implementation of [B45ATunFdBridge]. Unlike the protect
 * bridge's LISTEN side, connecting AS A CLIENT to a filesystem-namespace
 * Unix domain socket is directly supported by the public, documented
 * `android.net.LocalSocket.connect(LocalSocketAddress)` API when the address
 * is constructed with `LocalSocketAddress.Namespace.FILESYSTEM` - no raw
 * `android.system.Os` syscalls are needed for this direction.
 *
 * NOT exercised end to end in this session - requires a real Android
 * runtime. Compiles against the real Android SDK stubs (verified via
 * `assembleDebug`), which is the only verification performed here.
 */
class RealB45ATunFdBridge : B45ATunFdBridge {

    override fun handOff(tunFd: Int, socketPath: File, timeoutMillis: Long): B45ATunFdBridgeState {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var lastError: Throwable? = null

        while (System.currentTimeMillis() < deadline) {
            val socket = LocalSocket()
            try {
                socket.connect(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))

                val fdField = FileDescriptor::class.java.getDeclaredField("descriptor")
                fdField.isAccessible = true
                val fileDescriptor = FileDescriptor()
                fdField.setInt(fileDescriptor, tunFd)

                socket.setFileDescriptorsForSend(arrayOf(fileDescriptor))
                // Upstream only checks that the received buffer is non-empty
                // (fd_size aside) - the payload's actual bytes are unused.
                socket.outputStream.write(byteArrayOf(1))
                socket.outputStream.flush()

                Log.d(TAG, "handed off tun fd=$tunFd to ${socketPath.absolutePath}")
                return B45ATunFdBridgeState.FD_SENT
            } catch (err: IOException) {
                lastError = err
                // sslocal may not have bound its listener yet - bounded retry.
                Thread.sleep(RETRY_INTERVAL_MILLIS)
            } finally {
                runCatching { socket.close() }
            }
        }

        Log.w(TAG, "tun fd handoff timed out after ${timeoutMillis}ms", lastError)
        return B45ATunFdBridgeState.FAILED
    }
}
