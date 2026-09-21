package net.pocvpn.client.vpn.hysteria

import android.os.ParcelFileDescriptor
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
 * B46-3B lifecycle-hardening pass - closes a real fd number this process
 * still owns. Abstracted behind an interface (rather than calling
 * `ParcelFileDescriptor.adoptFd(fd).close()` directly in
 * [Tun2SocksChildRuntime]) specifically so [Tun2SocksChildRuntime] stays
 * unit-testable on the plain JVM: `ParcelFileDescriptor` is an Android
 * framework class this project's `testOptions.unitTests.isReturnDefaultValues`
 * stubs to return `null`/defaults rather than throw, which would silently
 * NPE inside a real fd-close call in a JVM test - a [FakeTun2SocksDupFdCloser]
 * records calls instead, so tests can assert exactly which fds were closed
 * and how many times, without touching any real OS resource.
 */
fun interface Tun2SocksDupFdCloser {
    fun close(fd: Int)
}

/** Real fd closer - the only place `ParcelFileDescriptor.adoptFd` is called for the runtime's own pre-handoff fd cleanup. */
object RealTun2SocksDupFdCloser : Tun2SocksDupFdCloser {
    override fun close(fd: Int) {
        if (fd < 0) return
        runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
            .onFailure { Log.w(TAG, "failed to close duplicated fd $fd: ${it.javaClass.simpleName}: ${it.message}") }
    }
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
 * FD OWNERSHIP CONTRACT (B46-3B lifecycle-hardening pass - load-bearing,
 * corrected from an earlier version of this class that left a leak on
 * pre-handoff failure paths): [start]'s `dupTunFd` MUST already be a
 * duplicate of the VpnService's original TUN fd
 * (`ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`). **This
 * function takes ownership of that exact fd number the INSTANT it is
 * called** - the caller never needs to guess whether handoff happened or
 * close it themselves on any [Tun2SocksChildResult.Failed]:
 *  - On every validation/bind/launch failure BEFORE
 *    [Tun2SocksChildControlChannel.sendStartRequestAndAwaitAck] is ever
 *    called, this class closes `dupTunFd` itself via [dupFdCloser] before
 *    returning [Tun2SocksChildResult.Failed].
 *  - Once [Tun2SocksChildControlChannel.sendStartRequestAndAwaitAck] is
 *    called, IT owns closing `dupTunFd` from that point on (see
 *    [RealTun2SocksChildControlChannel]'s own `ParcelFileDescriptor
 *    .adoptFd(fd).use { }` - closes exactly once, on success OR failure of
 *    the SCM_RIGHTS send) - this class never touches the fd number again
 *    after that call.
 *  - After a successful handoff, the CHILD process owns its own
 *    kernel-duplicated copy; the real tun2socks engine closes it on
 *    `engine.Stop()`.
 *
 * UNEXPECTED CHILD DEATH (B46-3B lifecycle-hardening pass): a successful
 * [start] registers [Tun2SocksChildProcess.onExit] so this class - not just
 * the app process's own survival - notices when the child exits for ANY
 * reason. [stop] and an unexpected exit both race to claim the SAME
 * terminal transition (`terminalClaimed`, guarded by [stateLock]): whichever
 * one gets there first performs the real state clearing/cleanup exactly
 * once; the other sees the claim already taken and no-ops - see
 * [handleChildExit]/[stop]'s own inline comments for the exact ordering
 * argument. [onUnexpectedExit] is invoked ONLY for a genuine unexpected
 * exit (the child dying on its own, or being killed by something other
 * than this class's own [stop]) - never for an expected [stop]-initiated
 * exit.
 */
class Tun2SocksChildRuntime(
    private val launcher: Tun2SocksChildProcessLauncher = RealTun2SocksChildProcessLauncher(),
    private val controlChannel: Tun2SocksChildControlChannel = RealTun2SocksChildControlChannel(),
    private val dupFdCloser: Tun2SocksDupFdCloser = RealTun2SocksDupFdCloser,
    private val ackTimeoutMillis: Long = DEFAULT_ACK_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val forceStopWaitMillis: Long = DEFAULT_FORCE_STOP_WAIT_MILLIS,
) {
    private val stateLock = Any()
    private var process: Tun2SocksChildProcess? = null
    private var childPid: Int? = null

    /**
     * `true` whenever there is no active session for which a terminal
     * transition (stop-initiated OR unexpected-exit-initiated) is still
     * owed. Set `false` the instant a session is successfully started; set
     * back to `true` by WHICHEVER of [stop]/[handleChildExit] first claims
     * the transition for that session - the other one's check then sees
     * `true` already and no-ops. This is the single source of truth for
     * "exactly one terminal transition per session," including the race
     * where an unexpected death and an explicit [stop] happen close
     * together.
     */
    private var terminalClaimed = true

    /**
     * Invoked exactly once per session, ONLY when the child exits without
     * this class's own [stop] having initiated it (real crash, external
     * `SIGKILL`, parent-death guard not applicable here since THIS is the
     * parent). Never invoked for an expected [stop]. Settable at any time;
     * a `null` listener (the default) means "no one is listening yet" -
     * the internal state clearing/cleanup still happens regardless of
     * whether a listener is registered.
     */
    var onUnexpectedExit: ((exitCode: Int) -> Unit)? = null

    val pid: Int? get() = synchronized(stateLock) { childPid }

    fun isRunning(): Boolean = synchronized(stateLock) { process?.isAlive() == true }

    /**
     * [dupTunFd] must already be a duplicate of the VpnService's TUN fd -
     * see this class's own FD OWNERSHIP CONTRACT doc above; this function
     * takes ownership of it immediately, regardless of outcome.
     * [binaryPath] is the resolved `tun2socks-child` executable path (see
     * [Tun2SocksChildBinaryResolver]). [controlSocketPath] is a per-session
     * app-private path this call binds and cleans up on both success and
     * failure.
     */
    fun start(dupTunFd: Int, mtu: Int, socksAddr: String, binaryPath: String, controlSocketPath: File): Tun2SocksChildResult {
        synchronized(stateLock) {
            if (process != null) {
                dupFdCloser.close(dupTunFd)
                return Tun2SocksChildResult.Failed("child already running (pid=$childPid)")
            }
        }
        if (dupTunFd < 0) {
            // Nothing to close - an already-invalid fd was never ours to own.
            return Tun2SocksChildResult.Failed("invalid fd")
        }
        if (mtu <= 0) {
            dupFdCloser.close(dupTunFd)
            return Tun2SocksChildResult.Failed("invalid mtu")
        }
        if (socksAddr.isEmpty()) {
            dupFdCloser.close(dupTunFd)
            return Tun2SocksChildResult.Failed("empty socks address")
        }

        try {
            controlChannel.bind(controlSocketPath)
        } catch (t: Throwable) {
            dupFdCloser.close(dupTunFd)
            return Tun2SocksChildResult.Failed("control channel bind failed: ${t.javaClass.simpleName}: ${t.message}")
        }

        val launched = try {
            launcher.launch(binaryPath, listOf(controlSocketPath.absolutePath))
        } catch (t: Throwable) {
            controlChannel.close()
            dupFdCloser.close(dupTunFd)
            return Tun2SocksChildResult.Failed("failed to launch child process: ${t.javaClass.simpleName}: ${t.message}")
        }

        // From here on, sendStartRequestAndAwaitAck owns closing dupTunFd -
        // see this class's own FD OWNERSHIP CONTRACT doc.
        val ack = controlChannel.sendStartRequestAndAwaitAck(dupTunFd, mtu, socksAddr, ackTimeoutMillis)
        return when (ack) {
            is Tun2SocksChildAck.Ok -> {
                synchronized(stateLock) {
                    process = launched
                    childPid = ack.pid
                    terminalClaimed = false
                }
                // Registered AFTER the session is visible in `process`/
                // `childPid` - if the child somehow exits between the ack
                // and this line (vanishingly unlikely, but not provably
                // impossible), onExit's own "already exited" branch (see
                // RealTun2SocksChildProcess.onExit) fires the callback
                // synchronously right here rather than losing the event.
                launched.onExit { code -> handleChildExit(code) }
                Log.i(TAG, "child started: pid=${ack.pid}")
                Tun2SocksChildResult.Ok(ack.pid)
            }
            is Tun2SocksChildAck.Failed -> {
                Log.w(TAG, "child start failed: ${ack.reason}")
                // The child either never started the engine, or we never
                // heard back - either way it must not be left running
                // headless. Best-effort graceful-then-forceful stop, same
                // as a normal stop() below. dupTunFd is already closed (or
                // handed off) by sendStartRequestAndAwaitAck at this point
                // regardless of which branch it took internally.
                stopLaunchedProcess(launched)
                controlChannel.close()
                Tun2SocksChildResult.Failed(ack.reason)
            }
        }
    }

    /**
     * Idempotent: safe to call when not started, and safe to call after an
     * unexpected death was already detected and handled (see this class's
     * own doc on [terminalClaimed]).
     */
    fun stop(): Tun2SocksChildResult {
        val current: Tun2SocksChildProcess?
        val stoppedPid: Int
        synchronized(stateLock) {
            current = process
            stoppedPid = childPid ?: -1
            if (current == null) {
                // Either never started, or an unexpected exit already
                // claimed the terminal transition and cleared state -
                // either way, nothing left for us to do.
                controlChannel.close()
                return Tun2SocksChildResult.Ok(pid = -1)
            }
            // Claim the transition NOW, before touching the process at
            // all: if handleChildExit's callback fires concurrently (the
            // child dying at roughly the same moment we decided to stop
            // it), it will see terminalClaimed already true and no-op,
            // guaranteeing exactly one terminal transition either way.
            terminalClaimed = true
            process = null
            childPid = null
        }
        stopLaunchedProcess(current!!)
        controlChannel.close()
        return Tun2SocksChildResult.Ok(pid = stoppedPid)
    }

    /**
     * Runs on [RealTun2SocksChildProcess]'s own background watcher thread
     * (see that class's own doc) whenever the underlying OS process exits,
     * for ANY reason - including a normal [stop] (in which case this is a
     * harmless no-op, see [terminalClaimed]'s own doc) and a genuine
     * unexpected death (crash, external kill, parent-death guard not
     * applicable to this direction).
     */
    private fun handleChildExit(exitCode: Int) {
        val shouldNotify = synchronized(stateLock) {
            if (terminalClaimed) {
                // stop() already claimed this transition (or there was
                // never a session at all) - nothing more to do.
                false
            } else {
                terminalClaimed = true
                process = null
                childPid = null
                true
            }
        }
        if (!shouldNotify) return
        Log.w(TAG, "child exited unexpectedly: code=$exitCode")
        controlChannel.close()
        onUnexpectedExit?.invoke(exitCode)
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
