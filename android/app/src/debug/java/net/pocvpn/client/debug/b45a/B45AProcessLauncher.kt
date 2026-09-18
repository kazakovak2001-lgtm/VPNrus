package net.pocvpn.client.debug.b45a

import java.io.File

/**
 * B45A - SPIKE ONLY. A running process handle, abstracted away from
 * [java.lang.Process] so [B45ARuntime]'s ownership/lifecycle rules (Phase 5/8)
 * are unit-testable against a fake without ever spawning a real OS process.
 */
interface B45ASpawnedProcess {
    val pid: Int?
    fun isAlive(): Boolean

    /** Requests graceful termination (SIGTERM-equivalent). Never blocks. */
    fun requestStop()

    /** Forcible termination, used only after a bounded grace period elapses. Never blocks. */
    fun forceStop()

    /** Blocks up to [timeoutMillis] waiting for exit; returns the exit code, or null if still alive after the timeout. */
    fun waitForExit(timeoutMillis: Long): Int?

    /** Non-blocking: registers a callback invoked exactly once, off the caller's thread, when the process exits on its own. */
    fun onExit(callback: (exitCode: Int) -> Unit)
}

/**
 * B45A - SPIKE ONLY. Spawns the pinned sslocal binary. The real
 * implementation is a thin [ProcessBuilder] wrapper - deliberately with NO
 * decision logic of its own, so every decision (single-instance enforcement,
 * shutdown ordering, leak prevention) lives in [B45ARuntime] and is testable
 * against [FakeB45AProcessLauncher] instead.
 */
interface B45AProcessLauncher {
    /**
     * Launches [binaryPath] with [args] and working directory [workingDir].
     * [workingDir] MUST be an app-private directory - the `--vpn` flag's
     * `protect_path` convention resolves relative to it (see
     * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 4/14).
     */
    fun launch(binaryPath: String, args: List<String>, workingDir: File): B45ASpawnedProcess
}
