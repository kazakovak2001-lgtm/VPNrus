package net.pocvpn.client.vpn.hysteria

import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

private const val TAG = "Hysteria2Tun2SocksChildProcess"

/** A live child OS process - launcher-side handle only, never the authority on the child's own reported pid (see [Hysteria2Tun2SocksChildAck.Ok.pid]). */
interface Hysteria2Tun2SocksChildProcess {
    fun isAlive(): Boolean
    /** Graceful termination request (SIGTERM on Android/Linux) - the child's own signal handler runs `engine.Stop()` before exiting. */
    fun requestStop()
    /** Forceful termination (SIGKILL) - only for a child that ignored [requestStop] within a bounded grace period. */
    fun forceStop()
    fun waitForExit(timeoutMillis: Long): Int?
    fun onExit(callback: (Int) -> Unit)
}

interface Hysteria2Hysteria2Tun2SocksChildProcessLauncher {
    fun launch(binaryPath: String, args: List<String>): Hysteria2Tun2SocksChildProcess
}

/**
 * B46-3B - real [Hysteria2Hysteria2Tun2SocksChildProcessLauncher] backed by [ProcessBuilder].
 * Mirrors `RealB45AProcessLauncher`'s own shape (this is the ONLY class
 * that touches [java.lang.Process] directly). Note this launcher-side
 * handle deliberately does NOT expose a pid: Android's `java.lang.Process`
 * has no public `pid()` accessor on this project's compileSdk (confirmed
 * via `javap` - see `RealB45AProcessLauncher`'s own doc comment) - the
 * REAL, authoritative pid comes from the child's own `os.Getpid()`,
 * reported over the wire in [Hysteria2Tun2SocksChildAck.Ok.pid].
 */
class RealHysteria2Hysteria2Hysteria2Tun2SocksChildProcessLauncher : Hysteria2Hysteria2Tun2SocksChildProcessLauncher {
    override fun launch(binaryPath: String, args: List<String>): Hysteria2Tun2SocksChildProcess {
        val process = ProcessBuilder(listOf(binaryPath) + args)
            .redirectErrorStream(false)
            .start()
        return RealHysteria2Hysteria2Tun2SocksChildProcess(process, binaryPath)
    }
}

private class RealHysteria2Hysteria2Tun2SocksChildProcess(
    private val process: Process,
    private val binaryPathForLogging: String,
) : Hysteria2Tun2SocksChildProcess {

    private val exitLock = ReentrantLock()
    private val exitCallbackFired = AtomicBoolean(false)
    private var exitCallback: ((Int) -> Unit)? = null

    init {
        drainStreamAsync(process.inputStream, "stdout")
        drainStreamAsync(process.errorStream, "stderr")
        thread(name = "tun2socks-child-watcher", isDaemon = true) {
            val code = try {
                process.waitFor()
            } catch (_: InterruptedException) {
                return@thread
            }
            exitLock.withLock {
                if (exitCallbackFired.compareAndSet(false, true)) {
                    exitCallback?.invoke(code)
                }
            }
        }
    }

    override fun isAlive(): Boolean = process.isAlive

    override fun requestStop() {
        Log.d(TAG, "requestStop() for $binaryPathForLogging")
        process.destroy()
    }

    override fun forceStop() {
        Log.d(TAG, "forceStop() for $binaryPathForLogging")
        process.destroyForcibly()
    }

    override fun waitForExit(timeoutMillis: Long): Int? {
        val exited = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
        return if (exited) process.exitValue() else null
    }

    override fun onExit(callback: (Int) -> Unit) {
        exitLock.withLock {
            if (!isAlive() && exitCallbackFired.compareAndSet(false, true)) {
                callback(process.exitValue())
            } else {
                exitCallback = callback
            }
        }
    }

    private fun drainStreamAsync(stream: java.io.InputStream, label: String) {
        thread(name = "tun2socks-child-$label-drain", isDaemon = true) {
            try {
                stream.bufferedReader().forEachLine { line ->
                    // Non-secret operational log lines only (B46_3B_CHILD_*
                    // prefixes, MTU, socks address, pid) - never config/secret
                    // material, matching the Go child's own logging discipline.
                    Log.d(TAG, "[$label] $line")
                }
            } catch (_: java.io.IOException) {
                // Stream closed because the process exited - expected, not an error.
            }
        }
    }
}

/**
 * Filename the pinned tun2socks-child ELF is packaged under in
 * `src/main/jniLibs/arm64-v8a/` (production packaging - see
 * `third_party/hysteria2-child/README.md` and
 * docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "native binary
 * packaging" section; first physically proven in `src/debug/jniLibs/arm64-v8a/`
 * by B46-3B, see docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md).
 */
const val TUN2SOCKS_CHILD_BINARY_FILENAME = "libnovatun2sockschild.so"

/**
 * B46-3B - the single binary-resolution authority, mirroring
 * `B45ANativeBinaryResolver`'s own "one place resolves the path, one set
 * of checks" discipline and its own AGP `jniLibs`/`useLegacyPackaging`
 * extraction convention (`applicationInfo.nativeLibraryDir`) - not a new
 * packaging design.
 */
object Hysteria2Tun2SocksChildBinaryResolver {
    sealed interface Result {
        data class Found(val file: File) : Result
        data class Missing(val reason: String) : Result
    }

    fun resolve(nativeLibraryDir: String?): Result {
        if (nativeLibraryDir.isNullOrBlank()) {
            return Result.Missing("applicationInfo.nativeLibraryDir is null or blank")
        }
        val file = File(nativeLibraryDir, TUN2SOCKS_CHILD_BINARY_FILENAME)
        return when {
            !file.exists() -> Result.Missing("not found at ${file.absolutePath} - was it packaged into src/debug/jniLibs/arm64-v8a/?")
            !file.isFile -> Result.Missing("not a regular file: ${file.absolutePath}")
            !file.canRead() -> Result.Missing("not readable: ${file.absolutePath}")
            !file.canExecute() -> Result.Missing("not executable: ${file.absolutePath}")
            else -> Result.Found(file)
        }
    }
}
