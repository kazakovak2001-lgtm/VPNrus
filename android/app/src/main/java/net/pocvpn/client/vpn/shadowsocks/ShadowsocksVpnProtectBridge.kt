package net.pocvpn.client.vpn.shadowsocks

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.io.File
import java.io.IOException
import kotlin.concurrent.thread

private const val TAG = "ShadowsocksProtectBridge"
private const val PROTECT_ANCILLARY_BUFFER_SIZE = 1024
private const val LISTEN_BACKLOG = 4

/** Protects an outbound socket fd from the VPN's own routing. Never protects the TUN-facing fd (Phase 10). */
internal fun interface ShadowsocksVpnProtector {
    fun protect(fd: Int): Boolean
}

internal enum class ShadowsocksProtectBridgeState { WAITING, RUNNING, FAILED, CLOSED }

/**
 * B45B-3 - production protect bridge, same upstream `outbound_vpn_protect_path`
 * protocol B45A physically proved (Android is the LISTENER: sslocal connects
 * once per outbound socket it wants protected, sends 1 byte + 1 ancillary fd,
 * we reply 0x00/0xFF - see B45AVpnProtectBridge's own docs for the full
 * protocol citation, including why sslocal's own 3s RPC timeout is the
 * binding constraint, not a timeout imposed here). Same bind-via-LocalSocket
 * + Os.listen + LocalServerSocket(fd) composition the spike's corrected
 * (non-reflection) real implementation already established - not redesigned.
 */
internal interface ShadowsocksVpnProtectBridge {
    fun start(socketPath: File, protector: ShadowsocksVpnProtector)
    fun stop()
    val state: ShadowsocksProtectBridgeState
}

internal class RealShadowsocksVpnProtectBridge : ShadowsocksVpnProtectBridge {

    @Volatile
    override var state: ShadowsocksProtectBridgeState = ShadowsocksProtectBridgeState.WAITING
        private set

    @Volatile
    private var running = false

    private var bindSocket: LocalSocket? = null
    private var serverSocket: LocalServerSocket? = null
    private var acceptThread: Thread? = null
    private var boundPath: File? = null

    override fun start(socketPath: File, protector: ShadowsocksVpnProtector) {
        check(serverSocket == null) { "protect bridge already started - call stop() first" }

        socketPath.delete()

        val bound = LocalSocket()
        try {
            bound.bind(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            Os.listen(bound.fileDescriptor, LISTEN_BACKLOG)
        } catch (err: Exception) {
            runCatching { bound.close() }
            state = ShadowsocksProtectBridgeState.FAILED
            throw IOException("failed to bind/listen protect socket at ${socketPath.absolutePath}", err)
        }

        val server = LocalServerSocket(bound.fileDescriptor)
        bindSocket = bound
        serverSocket = server
        boundPath = socketPath
        running = true
        state = ShadowsocksProtectBridgeState.RUNNING

        acceptThread = thread(name = "shadowsocks-protect-accept", isDaemon = true) {
            // B45B-4P debug-only diagnostic instrumentation (non-secret: no
            // fd number, no config/key material) - temporary, to determine
            // whether sslocal ever reaches this bridge at all.
            Log.i(TAG, "accept loop started, listening at ${socketPath.absolutePath}")
            acceptLoop(server, protector)
        }
    }

    private fun acceptLoop(server: LocalServerSocket, protector: ShadowsocksVpnProtector) {
        while (running) {
            val peer = try {
                server.accept()
            } catch (err: IOException) {
                if (running) Log.w(TAG, "accept() failed on protect bridge", err)
                break
            }
            Log.i(TAG, "accepted a peer connection")
            handleOneRequest(peer, protector)
        }
    }

    private fun handleOneRequest(peer: LocalSocket, protector: ShadowsocksVpnProtector) {
        try {
            val buffer = ByteArray(PROTECT_ANCILLARY_BUFFER_SIZE)
            val read = peer.inputStream.read(buffer)
            if (read <= 0) {
                Log.w(TAG, "protect bridge: peer sent no payload")
                return
            }

            val receivedFd = peer.ancillaryFileDescriptors?.firstOrNull()
            if (receivedFd == null) {
                Log.w(TAG, "protect bridge: peer sent bytes but no ancillary fd")
                writeResponse(peer, succeeded = false)
                return
            }

            // Our own kernel-duplicated copy (SCM_RIGHTS duplicates on
            // receive) via the public dup() API - never reflection.
            ParcelFileDescriptor.dup(receivedFd).use { dup ->
                val succeeded = runCatching { protector.protect(dup.fd) }.getOrElse { t ->
                    Log.w(TAG, "protector.protect() threw", t)
                    false
                }
                Log.i(TAG, "protect() result=$succeeded")
                writeResponse(peer, succeeded)
            }
            runCatching { Os.close(receivedFd) }
        } catch (t: Throwable) {
            Log.w(TAG, "protect bridge: request handling failed", t)
        } finally {
            runCatching { peer.close() }
        }
    }

    private fun writeResponse(socket: LocalSocket, succeeded: Boolean) {
        // sslocal only checks for the sentinel FAILURE byte 0xFF - any other byte is success.
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
        state = ShadowsocksProtectBridgeState.CLOSED
    }
}
