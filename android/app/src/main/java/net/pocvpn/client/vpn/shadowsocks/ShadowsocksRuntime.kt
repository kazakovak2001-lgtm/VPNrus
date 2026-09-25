package net.pocvpn.client.vpn.shadowsocks

import android.util.Log
import java.io.File
import java.io.FileDescriptor
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.pocvpn.client.reachability.GenerationFence

private const val TAG = "ShadowsocksRuntime"
private const val PROTECT_SOCKET_FILENAME = "protect_path"
private const val TUN_FD_SOCKET_FILENAME = "tun_fd_path"
private const val RUNTIME_CONFIG_FILENAME = "runtime_config.json"
private const val DEFAULT_TUN_FD_HANDOFF_TIMEOUT_MILLIS = 5_000L
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L

/** Everything needed to start one sslocal session - never held longer than one [ShadowsocksRuntime.start] call; the key never appears in [toString]. */
internal data class ShadowsocksRuntimeTarget(
    val host: String,
    val port: Int,
    val method: String,
    val keyBase64: String,
) {
    override fun toString(): String = "ShadowsocksRuntimeTarget(host=$host, port=$port, method=$method, key=<redacted>)"
}

/**
 * B45B-3 - production runtime, the isolated-adapter-shell counterpart of the
 * debug-only B45ARuntime it is adapted from (never sharing state or
 * lifecycle with it). Owns the pinned sslocal process, the protect listener,
 * the TUN-fd handoff, and the plaintext runtime config file's full lifetime -
 * the one class that touches all four, so ownership/shutdown ordering lives
 * in exactly one place.
 *
 * This is not, and must never become, a second production connection
 * authority: it is reachable only from [ShadowsocksTransport]/
 * [ShadowsocksVpnService], and SHADOWSOCKS_2022 stays NOT_IMPLEMENTED in
 * TransportRegistry - see this slice's own instructions.
 */
internal class ShadowsocksRuntime(
    private val launcher: ShadowsocksProcessLauncher,
    private val tunFdBridge: ShadowsocksTunFdBridge,
    private val protectBridge: ShadowsocksVpnProtectBridge,
    private val protector: ShadowsocksVpnProtector,
    private val scope: CoroutineScope,
    private val tunFdHandoffTimeoutMillis: Long = DEFAULT_TUN_FD_HANDOFF_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val _status = MutableStateFlow(ShadowsocksRuntimeStatus.IDLE)
    val status: StateFlow<ShadowsocksRuntimeStatus> = _status.asStateFlow()

    /**
     * Lifecycle race fix. Every state transition (start's synchronous
     * part, stop, and the two asynchronous completions registered by start:
     * the tun-fd handoff coroutine and the process-exit callback) runs under
     * [lock], and each asynchronous completion carries the [lifecycle]
     * generation of the start() that registered it. stop() and every new
     * start() begin a new generation. Because a completion checks "still my
     * generation AND still STARTING/RUNNING" in the SAME critical section in
     * which it writes, a completion that arrives after stop() can never
     * publish RUNNING/FAILED over STOPPED, and never touches a later
     * start()'s process or config.
     *
     * Deadlock rules:
     * - Never call [ShadowsocksSpawnedProcess.onExit] while holding [lock]:
     *   the real launcher invokes that callback under its own exit lock, and
     *   the callback takes [lock].
     * - Never run [ShadowsocksTunFdBridge.handOff] under [lock].
     *
     * The only blocking work under [lock] is the bounded process-exit wait
     * that stop() already performed before this fix.
     */
    private val lock = Any()
    private val lifecycle = GenerationFence()

    private var process: ShadowsocksSpawnedProcess? = null
    private var runtimeConfigFile: File? = null

    /**
     * B45B-3P - `tun_fd_path` is bound/listened-on by sslocal itself, never
     * by this class (Android is only the CLIENT in that protocol - see
     * [ShadowsocksTunFdBridge]'s own docs) - so it is only ever safe to
     * unlink AFTER sslocal's process has been confirmed terminated (physical
     * testing found sslocal does not unlink its own bound socket on a plain
     * SIGTERM, so a normal Stop left this file behind until this fix - see
     * [stopSpawnedProcessIfAny]/[cleanupEphemeralFiles], always called in
     * that order). Never deleted while the process might still be alive.
     */
    private var tunSocketFile: File? = null

    /**
     * [binaryPath] must already exist ([ShadowsocksNativeBinaryResolver]).
     * [tunFd] is BORROWED from an already-established VpnService.Builder
     * result's own `ParcelFileDescriptor` - this class (and everything it
     * calls) never closes, adopts, or otherwise takes ownership of it; the
     * caller's `ParcelFileDescriptor` remains the sole close authority
     * before, during, and after this call (see [ShadowsocksTunFdBridge]'s
     * own docs for why a plain [FileDescriptor], not an `Int` or a second
     * `ParcelFileDescriptor`, is the correct type for this boundary). This
     * class never establishes the TUN itself (that stays
     * [ShadowsocksVpnService]'s job). [target] carries the decrypted
     * credential for exactly this call - the caller never retains it beyond
     * calling this. Returns false immediately if already
     * STARTING/RUNNING/STOPPING (never a double-start).
     */
    fun start(
        binaryPath: String,
        tunFd: FileDescriptor,
        workingDir: File,
        tunInterfaceAddressCidr: String,
        target: ShadowsocksRuntimeTarget,
    ): Boolean {
        val generation: Long
        val spawned: ShadowsocksSpawnedProcess
        val tunSocketPath: File
        synchronized(lock) {
            val current = _status.value
            if (current.phase == ShadowsocksRuntimePhase.STARTING ||
                current.phase == ShadowsocksRuntimePhase.RUNNING ||
                current.phase == ShadowsocksRuntimePhase.STOPPING
            ) {
                return false
            }
            generation = lifecycle.begin()
            _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.STARTING)

            if (!File(binaryPath).exists()) {
                fail(ShadowsocksRuntimeError.BinaryMissing("binary not found at $binaryPath"))
                return false
            }

            workingDir.mkdirs()
            val protectSocketPath = File(workingDir, PROTECT_SOCKET_FILENAME)
            tunSocketPath = File(workingDir, TUN_FD_SOCKET_FILENAME)
            val runtimeConfigPath = File(workingDir, RUNTIME_CONFIG_FILENAME)

            // A process-level crash (SIGABRT/SIGKILL) bypasses every Kotlin
            // `finally` block, so a previous abnormal death can leave the
            // plaintext runtime config or a stale UDS behind (physically
            // observed - see this slice's own report). Swept BEFORE writing any
            // new plaintext config, scoped to ONLY this transport's own known
            // ephemeral filenames in [workingDir] - never the encrypted
            // credential repository (a different directory entirely,
            // `noBackupFilesDir`, never touched here) or any other app file.
            // Fails closed (never overwrites stale state and continues) if a
            // stale file cannot actually be removed.
            if (!sweepStaleEphemeralState(protectSocketPath, tunSocketPath, runtimeConfigPath)) {
                fail(ShadowsocksRuntimeError.StaleStateCleanupFailed("could not remove stale ephemeral runtime files"))
                return false
            }

            val configFile = try {
                ShadowsocksRuntimeConfigWriter.write(
                    directory = workingDir,
                    fileName = RUNTIME_CONFIG_FILENAME,
                    host = target.host,
                    port = target.port,
                    method = target.method,
                    keyBase64 = target.keyBase64,
                )
            } catch (t: Throwable) {
                fail(ShadowsocksRuntimeError.RuntimeConfigWriteFailed(t.javaClass.simpleName))
                return false
            }
            runtimeConfigFile = configFile

            // Protect listener MUST bind before sslocal starts - sslocal connects fresh per outbound socket, and a not-yet-bound path would simply fail to connect.
            try {
                protectBridge.start(protectSocketPath, protector)
            } catch (t: Throwable) {
                ShadowsocksRuntimeConfigWriter.delete(configFile)
                runtimeConfigFile = null
                fail(ShadowsocksRuntimeError.ProtectListenerFailed(t.message ?: "unknown"))
                return false
            }

            // Never argv - only the config-file path and non-secret flags (Phase 7/8).
            val args = listOf(
                "-c", configFile.absolutePath,
                "--protocol", "tun",
                "--tun-device-fd-from-path", tunSocketPath.absolutePath,
                "--tun-interface-address", tunInterfaceAddressCidr,
                "--vpn",
                "-U",
            )

            spawned = try {
                launcher.launch(binaryPath, args, workingDir)
            } catch (t: Throwable) {
                protectBridge.stop()
                ShadowsocksRuntimeConfigWriter.delete(configFile)
                runtimeConfigFile = null
                fail(ShadowsocksRuntimeError.SpawnFailed(t.message ?: "unknown"))
                return false
            }
            process = spawned
            tunSocketFile = tunSocketPath
        }

        // Outside [lock] - see [lock]'s docs. A stop() that lands right here
        // has already begun a new generation, so both registrations below
        // become no-ops for this start().
        spawned.onExit { exitCode -> onProcessExitedUnexpectedly(generation, exitCode) }

        scope.launch(ioDispatcher) {
            val bridgeState = tunFdBridge.handOff(tunFd, tunSocketPath, tunFdHandoffTimeoutMillis)
            completeStartup(generation, bridgeState)
        }

        return true
    }

    /** The only place a start() is confirmed or failed after handoff: check and transition are one atomic step (see [lock]). */
    private fun completeStartup(generation: Long, bridgeState: ShadowsocksTunFdBridgeState) {
        synchronized(lock) {
            if (!lifecycle.isCurrent(generation) || _status.value.phase != ShadowsocksRuntimePhase.STARTING) return
            when (bridgeState) {
                ShadowsocksTunFdBridgeState.FD_SENT -> {
                    // Startup confirmed (Phase 7): sslocal already read the
                    // config exactly once at process start (before it could
                    // ever reach the tun-fd-handoff accept() this succeeded
                    // against) - safe to delete the plaintext secret now,
                    // strictly before RUNNING is published.
                    runtimeConfigFile?.let { ShadowsocksRuntimeConfigWriter.delete(it) }
                    runtimeConfigFile = null
                    _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.RUNNING)
                }
                ShadowsocksTunFdBridgeState.FAILED -> {
                    teardownAfterFailure()
                    fail(ShadowsocksRuntimeError.TunFdHandoffTimedOut(tunFdHandoffTimeoutMillis))
                }
                ShadowsocksTunFdBridgeState.WAITING -> Unit
            }
        }
    }

    /**
     * Idempotent - stopping an already-STOPPED runtime is a no-op. Begins a
     * new generation first, so no completion of an earlier start() can
     * change state after this returns (see [lock]).
     */
    fun stop() {
        synchronized(lock) {
            val current = _status.value
            if (current.phase == ShadowsocksRuntimePhase.STOPPED) return
            lifecycle.begin()
            _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.STOPPING)

            stopSpawnedProcessIfAny()
            protectBridge.stop()
            cleanupEphemeralFiles()
            _status.value = ShadowsocksRuntimeStatus.IDLE
        }
    }

    private fun onProcessExitedUnexpectedly(generation: Long, exitCode: Int) {
        synchronized(lock) {
            // A stale generation's process exiting (e.g. the one stop() just
            // terminated) was expected - stop() owned that transition.
            if (!lifecycle.isCurrent(generation)) return
            val phase = _status.value.phase
            if (phase == ShadowsocksRuntimePhase.RUNNING || phase == ShadowsocksRuntimePhase.STARTING) {
                teardownAfterFailure()
                fail(ShadowsocksRuntimeError.ProcessExitedUnexpectedly(exitCode))
            }
            // Already STOPPING/STOPPED - this exit was expected, stop() owns the transition.
        }
    }

    private fun teardownAfterFailure() {
        // Same ordering as stop() - the process (if the failure happened
        // after spawn, e.g. TunFdHandoffTimedOut) must be confirmed
        // terminated before tun_fd_path can be safely unlinked (see
        // [tunSocketFile]'s own docs). Previously this path left a spawned
        // sslocal process running unattended on a handoff timeout - fixed
        // alongside the same physically-found UDS cleanup gap.
        stopSpawnedProcessIfAny()
        protectBridge.stop()
        cleanupEphemeralFiles()
    }

    /** Blocks (bounded) until the spawned process is confirmed dead, or is a no-op if none was ever spawned or it already exited. Always call before [cleanupEphemeralFiles] - see [tunSocketFile]'s own docs. */
    private fun stopSpawnedProcessIfAny() {
        val proc = process
        if (proc != null && proc.isAlive()) {
            proc.requestStop()
            if (proc.waitForExit(gracefulStopTimeoutMillis) == null) {
                proc.forceStop()
                proc.waitForExit(DEFAULT_FORCE_STOP_WAIT_MILLIS)
            }
        }
        process = null
    }

    /**
     * Only the transport's own known ephemeral files - never the encrypted
     * credential repository (a different directory entirely). Idempotent -
     * a missing file is not an error. Best-effort: a failed delete here
     * never blocks the STOPPING->IDLE transition (stop() must always
     * complete), but is logged (path only, never secret material - these
     * files never carry the raw key in their name) so a real leak is
     * observable rather than silent.
     */
    private fun cleanupEphemeralFiles() {
        runtimeConfigFile?.let { ShadowsocksRuntimeConfigWriter.delete(it) }
        runtimeConfigFile = null
        tunSocketFile?.let { file ->
            val deleted = runCatching { file.delete() }.getOrDefault(false)
            if (!deleted && file.exists()) {
                Log.w(TAG, "failed to remove tun-fd UDS at ${file.name}")
            }
        }
        tunSocketFile = null
    }

    private fun fail(error: ShadowsocksRuntimeError) {
        _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.FAILED, error)
    }
}

/**
 * Removes exactly the files listed - this transport's own known ephemeral
 * runtime material (protect UDS, TUN-fd UDS, plaintext runtime config) - and
 * nothing else. Idempotent (a file that does not exist counts as already
 * clean); returns false the moment any listed file still exists after a
 * delete attempt, which the caller treats as fail-closed (never proceeds to
 * write a new plaintext config over state it could not actually clear).
 * File-scope, not a method, specifically so it never has access to anything
 * beyond the paths it is explicitly given - it cannot reach the encrypted
 * credential repository (a different directory entirely) or any other app
 * file even by mistake.
 */
internal fun sweepStaleEphemeralState(vararg ephemeralFiles: File): Boolean =
    ephemeralFiles.all { file ->
        if (!file.exists()) return@all true
        file.delete()
        !file.exists()
    }
