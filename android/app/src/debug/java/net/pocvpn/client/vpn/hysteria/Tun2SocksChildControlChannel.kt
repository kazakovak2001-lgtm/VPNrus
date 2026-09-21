package net.pocvpn.client.vpn.hysteria

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.json.JSONObject

private const val TAG = "Tun2SocksChildControl"
private const val LISTEN_BACKLOG = 2
private const val ACK_READ_BUFFER_SIZE = 4096

/** Result of the child's own startup ack - see [Tun2SocksChildControlChannel]'s own protocol doc. */
sealed interface Tun2SocksChildAck {
    /** [pid] is the child's own `os.Getpid()`, reported over the wire (see the Go side's own doc on why). */
    data class Ok(val pid: Int) : Tun2SocksChildAck
    data class Failed(val reason: String) : Tun2SocksChildAck
}

/**
 * B46-3B - abstraction over the real SCM_RIGHTS control channel, so
 * [Tun2SocksChildRuntime]'s orchestration is unit-testable against a fake
 * without a real Unix-domain socket/child process - mirrors this codebase's
 * existing interface/fake split for I/O collaborators (e.g.
 * `B46Tun2SocksBridge`/`FakeB46Tun2SocksBridge`).
 */
interface Tun2SocksChildControlChannel {
    /** Binds and starts listening at [socketPath] (deleted first if stale). */
    fun bind(socketPath: File)

    /**
     * Accepts the child's first connection (bounded by [timeoutMillis]),
     * sends the JSON control header + [fd] via SCM_RIGHTS, then accepts the
     * child's second connection and reads its JSON ack. Never throws - all
     * failure paths return [Tun2SocksChildAck.Failed].
     */
    fun sendStartRequestAndAwaitAck(fd: Int, mtu: Int, socksAddr: String, timeoutMillis: Long): Tun2SocksChildAck

    fun close()
}

/**
 * Real implementation, reusing the EXACT bind-via-LocalSocket +
 * `Os.listen` + `LocalServerSocket(fd)` composition
 * `RealShadowsocksVpnProtectBridge`/`B46HysteriaVpnProtectBridge` already
 * prove physically - not redesigned. Two connections per session (see the
 * Go child's own `main.go` doc for why: a fresh connection per direction
 * keeps both sides' code simple, at the cost of two accept()s instead of
 * one full-duplex exchange).
 */
class RealTun2SocksChildControlChannel : Tun2SocksChildControlChannel {

    private var bindSocket: LocalSocket? = null
    private var serverSocket: LocalServerSocket? = null
    private var boundPath: File? = null

    override fun bind(socketPath: File) {
        check(serverSocket == null) { "control channel already bound - call close() first" }
        socketPath.delete()

        val bound = LocalSocket()
        try {
            bound.bind(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            Os.listen(bound.fileDescriptor, LISTEN_BACKLOG)
        } catch (err: Exception) {
            runCatching { bound.close() }
            throw IOException("failed to bind/listen control socket at ${socketPath.absolutePath}", err)
        }
        bindSocket = bound
        serverSocket = LocalServerSocket(bound.fileDescriptor)
        boundPath = socketPath
    }

    override fun sendStartRequestAndAwaitAck(fd: Int, mtu: Int, socksAddr: String, timeoutMillis: Long): Tun2SocksChildAck {
        val server = serverSocket ?: return Tun2SocksChildAck.Failed("control channel not bound")

        val peer1 = acceptWithTimeout(server, timeoutMillis)
            ?: return Tun2SocksChildAck.Failed("child never connected to send the start request within ${timeoutMillis}ms")
        try {
            val header = JSONObject().apply {
                put("mtu", mtu)
                put("socksAddr", socksAddr)
            }.toString().toByteArray(Charsets.UTF_8)

            // ParcelFileDescriptor.adoptFd takes ownership of exactly this fd
            // number for the duration of this call - the underlying fd is
            // handed off to the child via SCM_RIGHTS (which duplicates it
            // kernel-side onto the receiver), so we close our own copy
            // immediately after sending, same "one owner at a time" contract
            // the debug-only VpnService establishes when it dup()s the
            // original TUN fd in the first place.
            ParcelFileDescriptor.adoptFd(fd).use { pfd ->
                peer1.setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))
                peer1.outputStream.write(header)
                peer1.outputStream.flush()
            }
        } catch (t: Throwable) {
            return Tun2SocksChildAck.Failed("failed to send start request: ${t.javaClass.simpleName}: ${t.message}")
        } finally {
            runCatching { peer1.close() }
        }

        val peer2 = acceptWithTimeout(server, timeoutMillis)
            ?: return Tun2SocksChildAck.Failed("child never sent an ack within ${timeoutMillis}ms")
        val ackJson = try {
            val buf = ByteArray(ACK_READ_BUFFER_SIZE)
            val n = peer2.inputStream.read(buf)
            if (n <= 0) return Tun2SocksChildAck.Failed("child sent an empty ack")
            String(buf, 0, n, Charsets.UTF_8)
        } catch (t: Throwable) {
            return Tun2SocksChildAck.Failed("failed to read ack: ${t.javaClass.simpleName}: ${t.message}")
        } finally {
            runCatching { peer2.close() }
        }

        return parseAck(ackJson)
    }

    private fun parseAck(raw: String): Tun2SocksChildAck {
        return try {
            val obj = JSONObject(raw.trim())
            if (obj.optBoolean("ok", false)) {
                Tun2SocksChildAck.Ok(pid = obj.optInt("pid", -1))
            } else {
                Tun2SocksChildAck.Failed(obj.optString("error", "child reported failure with no reason"))
            }
        } catch (t: Throwable) {
            Tun2SocksChildAck.Failed("malformed ack json ${raw.take(200)}: ${t.message}")
        }
    }

    /**
     * `android.net.LocalServerSocket` has no built-in per-call accept
     * timeout, so this runs `accept()` on a background thread and bounds
     * the WAIT for its result rather than the `accept()` call itself. On a
     * genuine timeout the background thread is deliberately left running
     * (a daemon thread, so it never blocks JVM shutdown) - the server
     * socket itself is NOT closed here because it may still be needed for
     * a second `acceptWithTimeout` call in the same session (the ack
     * connection). Whatever this abandoned `accept()` eventually returns
     * (a real late connection, or an `IOException` once [close] finally
     * runs) is discarded - nothing reads `resultQueue` again after this
     * function has already returned a value once.
     */
    private fun acceptWithTimeout(server: LocalServerSocket, timeoutMillis: Long): LocalSocket? {
        val resultQueue = SynchronousQueue<LocalSocket?>()
        thread(name = "tun2socks-child-control-accept", isDaemon = true) {
            val result = try {
                server.accept()
            } catch (t: IOException) {
                null
            }
            // offer(), not put(): if nobody is polling any more (the caller
            // already timed out and returned), this must not block forever.
            resultQueue.offer(result)
        }
        val accepted = resultQueue.poll(timeoutMillis, TimeUnit.MILLISECONDS)
        if (accepted == null) {
            Log.w(TAG, "acceptWithTimeout: no connection within ${timeoutMillis}ms")
        }
        return accepted
    }

    override fun close() {
        runCatching { serverSocket?.close() }
        runCatching { bindSocket?.close() }
        serverSocket = null
        bindSocket = null
        boundPath?.delete()
        boundPath = null
    }
}
