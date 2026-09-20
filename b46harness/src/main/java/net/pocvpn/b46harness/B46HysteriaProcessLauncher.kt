package net.pocvpn.b46harness

import java.io.File

/**
 * B46-2P - a running child-process handle, abstracted from [java.lang.Process]
 * so [B46HysteriaRuntime]'s lifecycle rules are unit-testable against a fake
 * without spawning a real OS process (mirrors
 * [net.pocvpn.client.debug.b45a.B45ASpawnedProcess]'s own separation).
 */
internal interface B46HysteriaSpawnedProcess {
    /** Real PID from `/proc` cmdline matching, best-effort - see [RealB46HysteriaProcessLauncher]. Never a reflection hack into JVM internals. */
    val pid: Int?
    fun isAlive(): Boolean
    fun requestStop()
    fun forceStop()
    fun waitForExit(timeoutMillis: Long): Int?

    /** Invoked exactly once, off the caller's thread, when the process exits on its own. */
    fun onExit(callback: (exitCode: Int) -> Unit)

    /** Invoked once per line of stdout/stderr, ALREADY redacted (never raw config-file contents/auth). Safe log events only, per the task's own allowlist. */
    fun onLogLine(callback: (line: String) -> Unit)
}

internal interface B46HysteriaProcessLauncher {
    fun launch(binaryPath: String, args: List<String>, workingDir: File): B46HysteriaSpawnedProcess
}
