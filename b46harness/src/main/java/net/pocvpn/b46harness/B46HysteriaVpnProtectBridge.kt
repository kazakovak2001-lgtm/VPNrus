package net.pocvpn.b46harness

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.io.File
import java.io.IOException
import kotlin.concurrent.thread

private const val TAG = "B46HysteriaProtectBridge"
private const val PROTECT_ANCILLARY_BUFFER_SIZE = 1024
private const val LISTEN_BACKLOG = 4

/**
 * B46-2P - REAL Android VpnService.protect() analog. Never protects the
 * TUN-facing fd - only the Hysteria2 child's outbound QUIC socket fd.
 */
internal fun interface B46HysteriaVpnProtector {
    /** Must return the REAL VpnService.protect(fd) result - never fabricated. */
    fun protect(fd: Int): Boolean
}

internal enum class B46HysteriaProtectBridgeState { WAITING, RUNNING, FAILED, CLOSED }

/**
 * B46-2P - DEBUG/RESEARCH ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Implements the exact same Unix-domain SOCK_STREAM + SCM_RIGHTS protocol
 * already physically proven in production by
 * [net.pocvpn.client.vpn.shadowsocks.RealShadowsocksVpnProtectBridge]
 * (`android/app/src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksVpnProtectBridge.kt`) -
 * NOT a subtly different protocol. Android is the LISTENER/SERVER: the
 * Hysteria2 child (a separate process, per B46-2C Part H - it cannot call
 * `VpnService.protect()` directly) connects once per outbound QUIC socket
 * it wants protected:
 *
 * 1. Child connects to the Unix domain socket at [socketPath].
 * 2. Child sends exactly 1 payload byte plus 1 ancillary fd via `SCM_RIGHTS`
 *    (see `research/b46-2p-android-physical/hysteria-minimal-client/novaminimal_main.go`'s
 *    `protectViaUnixSocket`).
 * 3. We call [protector] (the real `VpnService.protect(fd)`, wired by
 *    [B46HysteriaVpnService]) on our own kernel-duplicated copy of the
 *    received fd (never the raw ancillary fd directly - matches
 *    `RealShadowsocksVpnProtectBridge`'s own `ParcelFileDescriptor.dup()`
 *    discipline, never reflection).
 * 4. We write back exactly 1 byte: `0x00` = success, anything else
 *    (`0xFF` here) = failure. The child fails closed on anything but
 *    `0x00` - see its own `protectViaUnixSocket`.
 */
internal interface B46HysteriaVpnProtectBridge {
    fun start(socketPath: File, protector: B46HysteriaVpnProtector)
    fun stop()
    val state: B46HysteriaProtectBridgeState
    val requestCount: Int
    val failureCount: Int
}

internal class RealB46HysteriaVpnProtectBridge : B46HysteriaVpnProtectBridge {

    @Volatile
    override var state: B46HysteriaProtectBridgeState = B46HysteriaProtectBridgeState.WAITING
        private set

    @Volatile
    override var requestCount: Int = 0
        private set

    @Volatile
    override var failureCount: Int = 0
        private set

    @Volatile
    private var running = false

    private var bindSocket: LocalSocket? = null
    private var serverSocket: LocalServerSocket? = null
    private var acceptThread: Thread? = null
    private var boundPath: File? = null

    override fun start(socketPath: File, protector: B46HysteriaVpnProtector) {
        check(serverSocket == null) { "protect bridge already started - call stop() first" }

        socketPath.delete()

        val bound = LocalSocket()
        try {
            bound.bind(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            Os.listen(bound.fileDescriptor, LISTEN_BACKLOG)
        } catch (err: Exception) {
            runCatching { bound.close() }
            state = B46HysteriaProtectBridgeState.FAILED
            throw IOException("failed to bind/listen protect socket at ${socketPath.absolutePath}", err)
        }

        val server = LocalServerSocket(bound.fileDescriptor)
        bindSocket = bound
        serverSocket = server
        boundPath = socketPath
        running = true
        state = B46HysteriaProtectBridgeState.RUNNING

        acceptThread = thread(name = "b46-hysteria-protect-accept", isDaemon = true) {
            Log.i(TAG, "accept loop started, listening at ${socketPath.absolutePath}")
            acceptLoop(server, protector)
        }
    }

    private fun acceptLoop(server: LocalServerSocket, protector: B46HysteriaVpnProtector) {
        while (running) {
            val peer = try {
                server.accept()
            } catch (err: IOException) {
                if (running) Log.w(TAG, "accept() failed on protect bridge", err)
                break
            }
            handleOneRequest(peer, protector)
        }
    }

    private fun handleOneRequest(peer: LocalSocket, protector: B46HysteriaVpnProtector) {
        requestCount++
        try {
            val buffer = ByteArray(PROTECT_ANCILLARY_BUFFER_SIZE)
            val read = peer.inputStream.read(buffer)
            if (read <= 0) {
                Log.w(TAG, "protect bridge: peer sent no payload")
                failureCount++
                return
            }

            val receivedFd = peer.ancillaryFileDescriptors?.firstOrNull()
            if (receivedFd == null) {
                Log.w(TAG, "protect bridge: peer sent bytes but no ancillary fd")
                failureCount++
                writeResponse(peer, succeeded = false)
                return
            }

            // Our own kernel-duplicated copy (SCM_RIGHTS duplicates on
            // receive) via the public dup() API - never reflection, never
            // /proc/<pid>/fd.
            ParcelFileDescriptor.dup(receivedFd).use { dup ->
                val succeeded = runCatching { protector.protect(dup.fd) }.getOrElse { t ->
                    Log.w(TAG, "protector.protect() threw", t)
                    false
                }
                if (!succeeded) {
                    failureCount++
                    Log.w(TAG, "protect() returned false")
                }
                writeResponse(peer, succeeded)
            }
            runCatching { Os.close(receivedFd) }
        } catch (t: Throwable) {
            failureCount++
            Log.w(TAG, "protect bridge: request handling failed", t)
        } finally {
            runCatching { peer.close() }
        }
    }

    private fun writeResponse(socket: LocalSocket, succeeded: Boolean) {
        val status = if (succeeded) 0x00 else 0xFF
        runCatching { socket.outputStream.write(status) }
            .onFailure { Log.w(TAG, "protect bridge: failed to write response byte", it) }
    }

    override fun stop() {
        running = false
        acceptThread?.interrupt()
        acceptThread = null
        runCatching { serverSocket?.close() }
        runCatching { bindSocket?.close() }
        serverSocket = null
        bindSocket = null
        boundPath?.delete()
        boundPath = null
        state = B46HysteriaProtectBridgeState.CLOSED
    }
}

/**
 * B46-2P CONTROLLED FAILURE TEST ONLY - never used in a normal start.
 * Returns false WITHOUT calling the real `VpnService.protect()`, to prove
 * the child fails closed on a negative ACK (see
 * docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md's controlled-failure
 * cycle). Production `protect()` code is never modified to support this -
 * this is purely a substitute [B46HysteriaVpnProtector] implementation
 * swapped in by the debug harness for exactly one cycle.
 */
internal val FakeAlwaysFailProtector = B46HysteriaVpnProtector { _ -> false }
