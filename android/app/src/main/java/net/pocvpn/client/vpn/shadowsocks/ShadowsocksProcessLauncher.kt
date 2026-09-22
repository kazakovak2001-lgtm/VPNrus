package net.pocvpn.client.vpn.shadowsocks

import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

/** A running sslocal process handle - abstracted from java.lang.Process so [ShadowsocksRuntime] is unit-testable against a fake. */
internal interface ShadowsocksSpawnedProcess {
    fun isAlive(): Boolean
    fun requestStop()
    fun forceStop()
    fun waitForExit(timeoutMillis: Long): Int?

    /** Registers a callback invoked exactly once, off the caller's thread, when the process exits on its own. */
    fun onExit(callback: (exitCode: Int) -> Unit)
}

/**
 * Spawns the production sslocal binary. No decision logic of its own - every
 * decision (retry, cleanup, ownership) lives in [ShadowsocksRuntime].
 * [args] must never contain secret material (Phase 7/8) - the caller passes
 * only a config-file path and non-secret flags.
 */
internal interface ShadowsocksProcessLauncher {
    fun launch(binaryPath: String, args: List<String>, workingDir: File): ShadowsocksSpawnedProcess
}

internal class RealShadowsocksProcessLauncher : ShadowsocksProcessLauncher {
    override fun launch(binaryPath: String, args: List<String>, workingDir: File): ShadowsocksSpawnedProcess {
        val process = ProcessBuilder(listOf(binaryPath) + args)
            .directory(workingDir)
            .redirectErrorStream(false)
            .start()
        return RealShadowsocksSpawnedProcess(process)
    }
}

private class RealShadowsocksSpawnedProcess(private val process: Process) : ShadowsocksSpawnedProcess {

    private val exitLock = ReentrantLock()
    private val exitCallbackFired = AtomicBoolean(false)
    private var exitCallback: ((Int) -> Unit)? = null

    init {
        // Drain both pipes so the subprocess cannot block on a full buffer,
        // but deliberately discard their content. A third-party runtime may
        // echo configuration or credential-adjacent detail on an error path;
        // production logcat is not an acceptable sink even at DEBUG level.
        // The debug-only B45A spike owns its separate evidence logger.
        drainStreamAsync(process.inputStream)
        drainStreamAsync(process.errorStream)
        thread(name = "shadowsocks-process-watcher", isDaemon = true) {
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
        process.destroy()
    }

    override fun forceStop() {
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

    private fun drainStreamAsync(stream: java.io.InputStream) {
        thread(name = "shadowsocks-output-drain", isDaemon = true) {
            try {
                stream.bufferedReader().forEachLine { /* drain without logging */ }
            } catch (_: java.io.IOException) {
                // Stream closed because the process exited - expected.
            }
        }
    }
}
