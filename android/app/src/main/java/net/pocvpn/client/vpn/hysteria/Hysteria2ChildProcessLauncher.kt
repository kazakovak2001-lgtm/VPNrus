package net.pocvpn.client.vpn.hysteria

import android.util.Log
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

private const val TAG = "Hysteria2ChildProcess"

/** A live Hysteria child OS process - mirrors [Hysteria2Tun2SocksChildProcess]'s own shape (deliberately not reused directly - a different child, kept independently reviewable per B46-3C's own scope). */
interface Hysteria2ChildProcess {
    fun isAlive(): Boolean
    fun requestStop()
    fun forceStop()
    fun waitForExit(timeoutMillis: Long): Int?
    fun onExit(callback: (Int) -> Unit)
}

interface Hysteria2ChildProcessLauncher {
    fun launch(binaryPath: String, args: List<String>): Hysteria2ChildProcess
}

/** Real launcher, mirrors `RealHysteria2Hysteria2Hysteria2Tun2SocksChildProcessLauncher`'s own shape - the only class that touches [java.lang.Process] directly for the Hysteria child. */
class RealHysteria2ChildProcessLauncher : Hysteria2ChildProcessLauncher {
    override fun launch(binaryPath: String, args: List<String>): Hysteria2ChildProcess {
        val process = ProcessBuilder(listOf(binaryPath) + args)
            .redirectErrorStream(false)
            .start()
        return RealHysteria2ChildProcess(process, binaryPath)
    }
}

private class RealHysteria2ChildProcess(
    private val process: Process,
    private val binaryPathForLogging: String,
) : Hysteria2ChildProcess, LogLineObservable {

    private val exitLock = ReentrantLock()
    private val exitCallbackFired = AtomicBoolean(false)
    private var exitCallback: ((Int) -> Unit)? = null

    private val logListenersLock = ReentrantLock()
    private val logListeners = mutableListOf<(String) -> Unit>()

    override fun addLogLineListener(listener: (String) -> Unit) {
        logListenersLock.withLock { logListeners.add(listener) }
    }

    private fun notifyLogListeners(line: String) {
        val snapshot = logListenersLock.withLock { logListeners.toList() }
        snapshot.forEach { it(line) }
    }

    init {
        drainStreamAsync(process.inputStream, "stdout")
        drainStreamAsync(process.errorStream, "stderr")
        thread(name = "hysteria-child-watcher", isDaemon = true) {
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
        thread(name = "hysteria-child-$label-drain", isDaemon = true) {
            try {
                stream.bufferedReader().forEachLine { line ->
                    // The Go child's own log lines never carry --auth (see
                    // its own --config-file doc) - only operational status.
                    Log.d(TAG, "[$label] $line")
                    notifyLogListeners(line)
                }
            } catch (_: java.io.IOException) {
                // Stream closed because the process exited - expected.
            }
        }
    }
}

/**
 * Filename the pinned minimal Hysteria2 ELF is packaged under in
 * `src/main/jniLibs/arm64-v8a/` (production packaging - see
 * `third_party/hysteria2-child/README.md` and
 * docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "native binary
 * packaging" section for the exact reproducible build/provenance record;
 * the research spike that first proved this ELF, B46-3C, packaged the SAME
 * artifact under `src/debug/jniLibs/arm64-v8a/` instead).
 */
const val HYSTERIA2_CHILD_BINARY_FILENAME = "libnovahysteriachild.so"

/** Mirrors `Hysteria2Tun2SocksChildBinaryResolver`'s own "one place resolves the path" discipline. */
object Hysteria2ChildBinaryResolver {
    sealed interface Result {
        data class Found(val file: java.io.File) : Result
        data class Missing(val reason: String) : Result
    }

    fun resolve(nativeLibraryDir: String?): Result {
        if (nativeLibraryDir.isNullOrBlank()) {
            return Result.Missing("applicationInfo.nativeLibraryDir is null or blank")
        }
        val file = java.io.File(nativeLibraryDir, HYSTERIA2_CHILD_BINARY_FILENAME)
        return when {
            !file.exists() -> Result.Missing("not found at ${file.absolutePath} - was it packaged into src/debug/jniLibs/arm64-v8a/?")
            !file.isFile -> Result.Missing("not a regular file: ${file.absolutePath}")
            !file.canRead() -> Result.Missing("not readable: ${file.absolutePath}")
            !file.canExecute() -> Result.Missing("not executable: ${file.absolutePath}")
            else -> Result.Found(file)
        }
    }
}
