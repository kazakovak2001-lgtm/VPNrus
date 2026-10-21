package net.pocvpn.client.vpn.hysteria

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.json.JSONObject

private const val TAG = "Hysteria2Tun2SocksControl"
private const val LISTEN_BACKLOG = 2
private const val ACK_READ_BUFFER_SIZE = 4096

/** Result of the child's own startup ack - see [Hysteria2Tun2SocksChildControlChannel]'s own protocol doc. */
/**
 * Parses the child's JSON ack. B46-4A: a successful ack must also carry
 * `"socksAuth": true` - only the hardened tun2socks child (novasocks5) sends
 * it. A pre-hardening child that would talk anonymous SOCKS5 is refused, so a
 * stale child binary can never run silently unauthenticated.
 */
internal fun parseTun2SocksChildAck(raw: String): Hysteria2Tun2SocksChildAck =
    try {
        val obj = JSONObject(raw.trim())
        when {
            !obj.optBoolean("ok", false) ->
                Hysteria2Tun2SocksChildAck.Failed(obj.optString("error", "child reported failure with no reason"))
            !obj.optBoolean("socksAuth", false) ->
                Hysteria2Tun2SocksChildAck.Failed("child does not support authenticated local socks (pre-B46-4A binary)")
            else -> Hysteria2Tun2SocksChildAck.Ok(pid = obj.optInt("pid", -1), streamsStats = obj.optBoolean("stats", false))
        }
    } catch (t: Throwable) {
        Hysteria2Tun2SocksChildAck.Failed("malformed ack json ${raw.take(200)}: ${t.message}")
    }

sealed interface Hysteria2Tun2SocksChildAck {
    /**
     * [pid] is the child's own `os.Getpid()`, reported over the wire (see the Go side's own doc on why).
     * H2-GATE: [streamsStats] is the child's `"stats": true` capability marker - false for an older
     * child, which then provides no data-plane counters (never fabricated ones).
     */
    data class Ok(val pid: Int, val streamsStats: Boolean = false) : Hysteria2Tun2SocksChildAck
    data class Failed(val reason: String) : Hysteria2Tun2SocksChildAck
}

/**
 * B46-3B - abstraction over the real SCM_RIGHTS control channel, so
 * [Hysteria2Tun2SocksChildRuntime]'s orchestration is unit-testable against a fake
 * without a real Unix-domain socket/child process - mirrors this codebase's
 * existing interface/fake split for I/O collaborators (e.g.
 * `B46Tun2SocksBridge`/`FakeB46Tun2SocksBridge`).
 */
interface Hysteria2Tun2SocksChildControlChannel {
    /** Binds and starts listening at [socketPath] (deleted first if stale). */
    fun bind(socketPath: File)

    /**
     * Accepts the child's first connection (bounded by [timeoutMillis]),
     * sends the JSON control header + [fd] via SCM_RIGHTS, then accepts the
     * child's second connection and reads its JSON ack. Never throws - all
     * failure paths return [Hysteria2Tun2SocksChildAck.Failed].
     *
     * B46-4A: [socksUser]/[socksPass] are the per-session local SOCKS
     * credentials. They travel only inside the JSON header over this
     * app-private Unix socket and are never logged.
     */
    fun sendStartRequestAndAwaitAck(
        fd: Int,
        mtu: Int,
        socksAddr: String,
        socksUser: String,
        socksPass: String,
        timeoutMillis: Long,
    ): Hysteria2Tun2SocksChildAck

    /**
     * H2-GATE - accepts the child's THIRD connection (its stats stream) within
     * [timeoutMillis] and feeds each line to [tracker] until the stream ends
     * or [close] runs; [Hysteria2DataPlaneStatsTracker.streamEnded] is called
     * on every exit path, including never connecting. Never blocks the caller.
     * Default: no stream (test doubles), which the tracker never sees as data.
     */
    fun startStatsReader(tracker: Hysteria2DataPlaneStatsTracker, timeoutMillis: Long) {
        tracker.streamEnded()
    }

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
class RealHysteria2Hysteria2Tun2SocksChildControlChannel : Hysteria2Tun2SocksChildControlChannel {

    private var bindSocket: LocalSocket? = null
    private var serverSocket: LocalServerSocket? = null
    private var boundPath: File? = null
    @Volatile private var statsPeer: LocalSocket? = null

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

    override fun sendStartRequestAndAwaitAck(
        fd: Int,
        mtu: Int,
        socksAddr: String,
        socksUser: String,
        socksPass: String,
        timeoutMillis: Long,
    ): Hysteria2Tun2SocksChildAck {
        val server = serverSocket ?: return Hysteria2Tun2SocksChildAck.Failed("control channel not bound")

        val peer1 = acceptWithTimeout(server, timeoutMillis)
            ?: return Hysteria2Tun2SocksChildAck.Failed("child never connected to send the start request within ${timeoutMillis}ms")
        try {
            val header = JSONObject().apply {
                put("mtu", mtu)
                put("socksAddr", socksAddr)
                put("socksUser", socksUser)
                put("socksPass", socksPass)
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
            return Hysteria2Tun2SocksChildAck.Failed("failed to send start request: ${t.javaClass.simpleName}: ${t.message}")
        } finally {
            runCatching { peer1.close() }
        }

        val peer2 = acceptWithTimeout(server, timeoutMillis)
            ?: return Hysteria2Tun2SocksChildAck.Failed("child never sent an ack within ${timeoutMillis}ms")
        val ackJson = try {
            val buf = ByteArray(ACK_READ_BUFFER_SIZE)
            val n = peer2.inputStream.read(buf)
            if (n <= 0) return Hysteria2Tun2SocksChildAck.Failed("child sent an empty ack")
            String(buf, 0, n, Charsets.UTF_8)
        } catch (t: Throwable) {
            return Hysteria2Tun2SocksChildAck.Failed("failed to read ack: ${t.javaClass.simpleName}: ${t.message}")
        } finally {
            runCatching { peer2.close() }
        }

        return parseTun2SocksChildAck(ackJson)
    }

    /**
     * `android.net.LocalServerSocket` has no built-in per-call accept
     * timeout, so this runs `accept()` on a background thread and bounds
     * the WAIT for its result rather than the `accept()` call itself (see
     * [awaitHandoff]). On a genuine timeout the background thread is
     * deliberately left running (a daemon thread, so it never blocks JVM
     * shutdown) - the server socket itself is NOT closed here because it may
     * still be needed for a later `acceptWithTimeout` call in the same
     * session. A connection that this abandoned `accept()` returns late is
     * closed, never leaked.
     */
    private fun acceptWithTimeout(server: LocalServerSocket, timeoutMillis: Long): LocalSocket? {
        val accepted = awaitHandoff(
            timeoutMillis = timeoutMillis,
            threadName = "tun2socks-child-control-accept",
            produce = { server.accept() },
            discardLate = { late -> runCatching { late.close() } },
        )
        if (accepted == null) {
            Log.w(TAG, "acceptWithTimeout: no connection within ${timeoutMillis}ms")
        }
        return accepted
    }

    override fun startStatsReader(tracker: Hysteria2DataPlaneStatsTracker, timeoutMillis: Long) {
        val server = serverSocket ?: return tracker.streamEnded()
        thread(name = "tun2socks-child-stats", isDaemon = true) {
            val peer = acceptWithTimeout(server, timeoutMillis)
            if (peer == null) {
                tracker.streamEnded()
                return@thread
            }
            statsPeer = peer
            try {
                val reader = peer.inputStream.bufferedReader(Charsets.UTF_8)
                while (true) {
                    val line = readBoundedLine(reader, Hysteria2DataPlaneStatsTracker.MAX_LINE_LENGTH) ?: break
                    tracker.accept(line)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "stats stream ended: ${t.javaClass.simpleName}")
            } finally {
                tracker.streamEnded()
                runCatching { peer.close() }
            }
        }
    }

    override fun close() {
        runCatching { statsPeer?.close() }
        statsPeer = null
        runCatching { serverSocket?.close() }
        runCatching { bindSocket?.close() }
        serverSocket = null
        bindSocket = null
        boundPath?.delete()
        boundPath = null
    }
}

private val NO_RESULT = Any()

/**
 * Runs [produce] on a daemon thread and waits at most [timeoutMillis] for its
 * result; null on timeout or when [produce] throws [IOException].
 *
 * The result is handed over through a one-slot queue, so a [produce] that
 * returns before this thread starts waiting is still delivered. (The earlier
 * `SynchronousQueue.offer()` dropped exactly that case: the tun2socks child
 * dials its stats connection right after the ack, `accept()` returned before
 * `poll()` ran, and the gate never received counters. Its `offer(null)` on an
 * `IOException` also threw.) A result that arrives after the timeout goes to
 * [discardLate] exactly once. [beforeWait] is a test seam that runs between
 * starting the thread and waiting.
 */
internal fun <T : Any> awaitHandoff(
    timeoutMillis: Long,
    threadName: String,
    produce: () -> T,
    discardLate: (T) -> Unit,
    beforeWait: () -> Unit = {},
): T? {
    val slot = LinkedBlockingQueue<Any>(1)
    val abandoned = AtomicBoolean(false)
    thread(name = threadName, isDaemon = true) {
        val result: Any = try {
            produce()
        } catch (_: IOException) {
            NO_RESULT
        }
        slot.offer(result)
        // The waiter gave up before or while we offered: whoever removes the
        // value first (here or the waiter's own drain below) discards it.
        if (abandoned.get() && result !== NO_RESULT && slot.remove(result)) {
            @Suppress("UNCHECKED_CAST")
            discardLate(result as T)
        }
    }
    beforeWait()
    val got = slot.poll(timeoutMillis, TimeUnit.MILLISECONDS)
    if (got == null) {
        abandoned.set(true)
        val late = slot.poll()
        if (late != null && late !== NO_RESULT) {
            @Suppress("UNCHECKED_CAST")
            discardLate(late as T)
        }
        return null
    }
    @Suppress("UNCHECKED_CAST")
    return if (got === NO_RESULT) null else got as T
}

/** Reads one '\n'-terminated line of at most [maxLength] chars; null on EOF. A longer line is an error, never truncated into a valid one. */
internal fun readBoundedLine(reader: java.io.Reader, maxLength: Int): String? {
    val line = StringBuilder()
    while (true) {
        val c = reader.read()
        if (c < 0) return if (line.isEmpty()) null else throw IOException("stats stream ended mid-line")
        if (c == '\n'.code) return line.toString()
        if (line.length >= maxLength) throw IOException("stats line too long")
        line.append(c.toChar())
    }
}
