package net.pocvpn.client.debug.b45a

import android.util.Log
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

private const val TAG = "B45ASpikeProcess"

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Real [B45AProcessLauncher] backed by [ProcessBuilder]. This is the ONLY
 * class in the spike that touches [java.lang.Process] directly - everything
 * else goes through [B45ASpawnedProcess]/[B45AProcessLauncher] so ownership
 * and lifecycle DECISIONS (Phase 5/8) stay in [B45ARuntime] and are
 * unit-testable there against a fake, never here.
 *
 * Requires an actual Android runtime to execute correctly - Java's
 * [ProcessBuilder] on this Windows development machine can spawn a process,
 * but the pinned `sslocal` binary is an Android ARM64 ELF and will not run
 * on a Windows/x86_64 JVM. This class has NOT been exercised end to end in
 * this session - see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's own "what could
 * not be verified without a device" section.
 */
class RealB45AProcessLauncher : B45AProcessLauncher {
    override fun launch(binaryPath: String, args: List<String>, workingDir: File): B45ASpawnedProcess {
        val builder = ProcessBuilder(listOf(binaryPath) + args)
            .directory(workingDir)
            .redirectErrorStream(false)
        // Phase 9: never put secrets in argv - the config path is a filesystem
        // reference into app-private storage, never the secret material itself.
        val process = builder.start()
        return RealB45ASpawnedProcess(process, binaryPath)
    }
}

private class RealB45ASpawnedProcess(
    private val process: Process,
    private val binaryPathForLogging: String,
) : B45ASpawnedProcess {

    private val exitLock = ReentrantLock()
    private val exitCallbackFired = AtomicBoolean(false)
    private var exitCallback: ((Int) -> Unit)? = null

    init {
        // Phase 8: capture stdout/stderr locally for debug evidence - never
        // routed into production logcat channels at more than debug
        // visibility, never fed into B29 diagnostics (architecture principle 9).
        drainStreamAsync(process.inputStream, "stdout")
        drainStreamAsync(process.errorStream, "stderr")
        thread(name = "b45a-spike-process-watcher", isDaemon = true) {
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

    // Android's own java.lang.Process (this project's compileSdk 35
    // android.jar, confirmed directly via javap - not assumed) does not
    // expose the JDK 9 Process.pid() API at all, unlike a desktop JVM -
    // there is no reliable public, non-reflective way to read the PID of a
    // plain java.lang.Process on Android. Left honestly null rather than
    // reflecting into an internal field; the debug UI already renders "-"
    // for a null pid (see B45ASpikeActivity.renderStatus).
    override val pid: Int? = null

    override fun isAlive(): Boolean = process.isAlive

    override fun requestStop() {
        // ProcessBuilder has no portable SIGTERM-vs-SIGKILL distinction on
        // every platform; Process.destroy() requests graceful termination
        // where the OS supports it (SIGTERM on Linux/Android), reserving
        // destroyForcibly() (SIGKILL) for forceStop() below.
        Log.d(TAG, "requestStop() for $binaryPathForLogging")
        process.destroy()
    }

    override fun forceStop() {
        Log.d(TAG, "forceStop() for $binaryPathForLogging")
        process.destroyForcibly()
    }

    override fun waitForExit(timeoutMillis: Long): Int? {
        val exited = process.waitFor(timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
        return if (exited) process.exitValue() else null
    }

    override fun onExit(callback: (Int) -> Unit) {
        exitLock.withLock {
            if (!isAlive() && exitCallbackFired.compareAndSet(false, true)) {
                // Already exited before the caller registered - fire synchronously
                // rather than losing the event.
                callback(process.exitValue())
            } else {
                exitCallback = callback
            }
        }
    }

    private fun drainStreamAsync(stream: java.io.InputStream, label: String) {
        thread(name = "b45a-spike-$label-drain", isDaemon = true) {
            try {
                stream.bufferedReader().forEachLine { line ->
                    Log.d(TAG, "[$label] $line")
                }
            } catch (_: java.io.IOException) {
                // Stream closed because the process exited - expected, not an error.
            }
        }
    }
}
