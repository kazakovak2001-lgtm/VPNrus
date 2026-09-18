package net.pocvpn.client.debug.b45a

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.LocalServerSocket
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.io.File
import java.io.IOException
import kotlin.concurrent.thread

private const val TAG = "B45ASpikeProtect"
private const val PROTECT_ANCILLARY_BUFFER_SIZE = 1024
private const val LISTEN_BACKLOG = 4

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Real Android implementation of [B45AVpnProtectBridge]. `sslocal`'s
 * `outbound_vpn_protect_path` mechanism requires a Unix domain socket bound
 * to a real FILESYSTEM path (never Android's abstract namespace) - the
 * pinned upstream side does `UnixStream::connect(protect_path)` against a
 * plain `PathBuf`.
 *
 * There is no single public Android SDK class that both binds a FILESYSTEM
 * path AND listens/accepts (`LocalServerSocket`'s only two public
 * constructors are an ABSTRACT-namespace-only `String` name, or an
 * ALREADY-bound-and-listening `FileDescriptor` - confirmed by reading
 * `android.net.LocalServerSocket`'s public API surface directly via
 * `javap` against this project's own compileSdk 35 `android.jar`, not
 * assumed from memory). The correct, fully public/documented composition -
 * verified to actually COMPILE against that same `android.jar` - is:
 *
 * 1. `LocalSocket().bind(LocalSocketAddress(path, Namespace.FILESYSTEM))` -
 *    `LocalSocket.bind()` DOES support the FILESYSTEM namespace publicly,
 *    unlike `LocalServerSocket`'s constructor.
 * 2. Extract that now-bound socket's underlying `FileDescriptor` via the
 *    public `LocalSocket.getFileDescriptor()`.
 * 3. Call the public `android.system.Os.listen(fd, backlog)` on that SAME
 *    fd - turning a merely-bound socket into a listening one.
 * 4. Wrap it in `LocalServerSocket(FileDescriptor)` - its own documented
 *    contract is exactly "a bound and listening fd", which is now true.
 * 5. `LocalServerSocket.accept()` returns an ordinary [LocalSocket] per
 *    connection, with its already-public `getAncillaryFileDescriptors()`/
 *    `getInputStream()`/`getOutputStream()` - no non-existent factory
 *    method needed (an earlier draft of this file incorrectly assumed a
 *    `LocalSocket.createConnectedLocalSocket(FileDescriptor)` static
 *    factory existed; it does not, per the same `javap` check).
 *
 * NOT exercised end to end on a real device in this session - only
 * compilation against the real Android SDK stubs was verified
 * (`assembleDebug`).
 */
class RealB45AVpnProtectBridge : B45AVpnProtectBridge {

    @Volatile
    override var state: B45AProtectBridgeState = B45AProtectBridgeState.WAITING
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

    override fun start(socketPath: File, protector: B45AVpnProtector) {
        check(serverSocket == null) { "B45A protect bridge already started - call stop() first" }

        // Phase 6: remove any stale socket entry from a prior run before binding.
        socketPath.delete()

        val bound = LocalSocket()
        try {
            bound.bind(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            Os.listen(bound.fileDescriptor, LISTEN_BACKLOG)
        } catch (err: Exception) {
            runCatching { bound.close() }
            state = B45AProtectBridgeState.FAILED
            throw IOException("failed to bind/listen protect socket at ${socketPath.absolutePath}", err)
        }

        val server = LocalServerSocket(bound.fileDescriptor)
        bindSocket = bound
        serverSocket = server
        boundPath = socketPath
        running = true
        state = B45AProtectBridgeState.WAITING

        acceptThread = thread(name = "b45a-spike-protect-accept", isDaemon = true) {
            acceptLoop(server, protector)
        }
    }

    private fun acceptLoop(server: LocalServerSocket, protector: B45AVpnProtector) {
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

    private fun handleOneRequest(peer: LocalSocket, protector: B45AVpnProtector) {
        state = B45AProtectBridgeState.CONNECTED
        try {
            val buffer = ByteArray(PROTECT_ANCILLARY_BUFFER_SIZE)
            val read = peer.inputStream.read(buffer)
            if (read <= 0) {
                Log.w(TAG, "protect bridge: peer sent no payload")
                recordOutcome(false)
                return
            }

            val ancillaryFds = peer.ancillaryFileDescriptors
            val receivedFd = ancillaryFds?.firstOrNull()
            if (receivedFd == null) {
                Log.w(TAG, "protect bridge: peer sent bytes but no ancillary fd")
                recordOutcome(false)
                writeResponse(peer, succeeded = false)
                return
            }

            // Public, documented way to obtain the raw OS fd number from a
            // java.io.FileDescriptor - java.io.FileDescriptor itself exposes
            // no public accessor, and reflecting into its private
            // `descriptor` field is a real, known Android non-SDK-interface
            // restriction risk at higher targetSdk levels (deliberately
            // avoided here - an earlier draft of this file used exactly that
            // reflection hack; this is the corrected version).
            ParcelFileDescriptor.dup(receivedFd).use { dup ->
                val rawFd = dup.fd
                val succeeded = runCatching { protector.protect(rawFd) }.getOrElse { t ->
                    Log.w(TAG, "protector.protect() threw", t)
                    false
                }
                recordOutcome(succeeded)
                writeResponse(peer, succeeded)
            }

            // Phase 5: the ancillary FileDescriptor Android decoded for us is
            // OUR OWN kernel-duplicated copy (SCM_RIGHTS duplicates on
            // receive) - closing it is required to avoid a leak and does NOT
            // affect sslocal's own original, which it retains independently.
            runCatching { Os.close(receivedFd) }
        } catch (t: Throwable) {
            Log.w(TAG, "protect bridge: request handling failed", t)
            recordOutcome(false)
        } finally {
            runCatching { peer.close() }
        }
    }

    private fun recordOutcome(succeeded: Boolean) {
        requestCount++
        if (!succeeded) failureCount++
        state = if (succeeded) B45AProtectBridgeState.ACKNOWLEDGED else B45AProtectBridgeState.FAILED
    }

    private fun writeResponse(socket: LocalSocket, succeeded: Boolean) {
        // sslocal itself (send_vpn_protect_uds, pinned v1.25.0) only checks
        // for the sentinel FAILURE byte 0xFF; any other byte is success.
        // 0x00 for success matches shadowsocks-android's own convention.
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
        state = B45AProtectBridgeState.CLOSED
    }
}
