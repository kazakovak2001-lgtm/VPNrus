package net.pocvpn.client.vpn.hysteria

import android.util.Log
import java.io.File

private const val TAG = "Tun2SocksChildRuntime"
private const val DEFAULT_ACK_TIMEOUT_MILLIS = 5_000L
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L

/** Result of a [Tun2SocksChildRuntime] lifecycle call - never a raw exception/crash. */
sealed interface Tun2SocksChildResult {
    data class Ok(val pid: Int) : Tun2SocksChildResult
    data class Failed(val reason: String) : Tun2SocksChildResult
}

/**
 * B46-3B - orchestrates the process-isolated tun2socks child: resolve the
 * binary, spawn it, hand off the TUN fd duplicate + config over the real
 * SCM_RIGHTS control channel, await its ack, and own its stop/cleanup.
 * This is the direct, structural answer to B46-3A's physical finding
 * (`docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md`): the tun2socks Go
 * runtime never loads into this process at all - it always runs in a
 * separate OS process, with a separate address space, so it cannot corrupt
 * (or be corrupted by) Xray's own Go runtime in the app process.
 *
 * Kotlin-side lifecycle rules (repeated-start rejection, stop idempotency)
 * live HERE, in front of [launcher]/[controlChannel] - both are injectable
 * interfaces specifically so this class is unit-testable with fakes,
 * mirroring `B46HysteriaRuntime`'s own "one class owns lifecycle ordering,
 * testable against fakes" shape.
 *
 * FD ownership contract (load-bearing, reused verbatim from B46-2C/B46-2P/
 * B46-3A): [start]'s `dupTunFd` MUST already be a duplicate of the
 * VpnService's original TUN fd
 * (`ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`). This
 * class hands that duplicate to the child via SCM_RIGHTS (which itself
 * kernel-duplicates it onto the child) and then closes ITS OWN copy of the
 * fd number immediately (see [RealTun2SocksChildControlChannel]'s own
 * `ParcelFileDescriptor.adoptFd` doc) - the child, not this process, is the
 * one live owner of the transferred duplicate from that point on, and the
 * child's own `engine.Stop()` closes it.
 */
class Tun2SocksChildRuntime(
    private val launcher: Tun2SocksChildProcessLauncher = RealTun2SocksChildProcessLauncher(),
    private val controlChannel: Tun2SocksChildControlChannel = RealTun2SocksChildControlChannel(),
    private val ackTimeoutMillis: Long = DEFAULT_ACK_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val forceStopWaitMillis: Long = DEFAULT_FORCE_STOP_WAIT_MILLIS,
) {
    private var process: Tun2SocksChildProcess? = null
    private var childPid: Int? = null

    val pid: Int? get() = childPid

    fun isRunning(): Boolean = process?.isAlive() == true

    /**
     * [dupTunFd] must already be a duplicate of the VpnService's TUN fd -
     * see this class's own doc. [binaryPath] is the resolved
     * `tun2socks-child` executable path (see [Tun2SocksChildBinaryResolver]).
     * [controlSocketPath] is a per-session app-private path this call binds
     * and cleans up on both success and failure.
     */
    fun start(dupTunFd: Int, mtu: Int, socksAddr: String, binaryPath: String, controlSocketPath: File): Tun2SocksChildResult {
        if (isRunning()) {
            return Tun2SocksChildResult.Failed("child already running (pid=$childPid)")
        }
        if (dupTunFd < 0) {
            return Tun2SocksChildResult.Failed("invalid fd")
        }
        if (mtu <= 0) {
            return Tun2SocksChildResult.Failed("invalid mtu")
        }
        if (socksAddr.isEmpty()) {
            return Tun2SocksChildResult.Failed("empty socks address")
        }

        try {
            controlChannel.bind(controlSocketPath)
        } catch (t: Throwable) {
            // We still own dupTunFd here (the control channel never touched
            // it) - the caller is responsible for closing it on a Failed
            // result before this function was ever able to hand it off.
            return Tun2SocksChildResult.Failed("control channel bind failed: ${t.javaClass.simpleName}: ${t.message}")
        }

        val launched = try {
            launcher.launch(binaryPath, listOf(controlSocketPath.absolutePath))
        } catch (t: Throwable) {
            controlChannel.close()
            return Tun2SocksChildResult.Failed("failed to launch child process: ${t.javaClass.simpleName}: ${t.message}")
        }

        val ack = controlChannel.sendStartRequestAndAwaitAck(dupTunFd, mtu, socksAddr, ackTimeoutMillis)
        return when (ack) {
            is Tun2SocksChildAck.Ok -> {
                process = launched
                childPid = ack.pid
                Log.i(TAG, "child started: pid=${ack.pid}")
                Tun2SocksChildResult.Ok(ack.pid)
            }
            is Tun2SocksChildAck.Failed -> {
                Log.w(TAG, "child start failed: ${ack.reason}")
                // The child either never started the engine, or we never
                // heard back - either way it must not be left running
                // headless. Best-effort graceful-then-forceful stop, same
                // as a normal stop() below.
                stopLaunchedProcess(launched)
                controlChannel.close()
                Tun2SocksChildResult.Failed(ack.reason)
            }
        }
    }

    /** Idempotent: safe to call when not started. */
    fun stop(): Tun2SocksChildResult {
        val current = process
        if (current == null) {
            controlChannel.close()
            return Tun2SocksChildResult.Ok(pid = -1)
        }
        val stoppedPid = childPid ?: -1
        stopLaunchedProcess(current)
        controlChannel.close()
        process = null
        childPid = null
        return Tun2SocksChildResult.Ok(pid = stoppedPid)
    }

    private fun stopLaunchedProcess(launched: Tun2SocksChildProcess) {
        if (!launched.isAlive()) return
        launched.requestStop()
        val exited = launched.waitForExit(gracefulStopTimeoutMillis)
        if (exited == null) {
            Log.w(TAG, "child did not exit gracefully within ${gracefulStopTimeoutMillis}ms - forcing")
            launched.forceStop()
            launched.waitForExit(forceStopWaitMillis)
        }
    }
}
