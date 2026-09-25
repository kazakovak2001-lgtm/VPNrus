package net.pocvpn.client.vpn.shadowsocks

import android.content.Intent
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileDescriptor
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.pocvpn.client.identity.Shadowsocks2022Credential
import net.pocvpn.client.identity.Shadowsocks2022CredentialGetResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialRepository
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidationResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidator
import net.pocvpn.client.reachability.EndpointId
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

private const val METHOD = "2022-blake3-aes-256-gcm"
private val KEY_BASE64 = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })

/**
 * Service-level lifecycle races in [ShadowsocksVpnService]: a teardown (ACTION_STOP, onRevoke,
 * onDestroy) or a newer start must never leave an sslocal process, a TUN, or a plaintext
 * runtime config without a live owner, and a stale attempt/teardown must never touch a newer
 * session.
 *
 * Deterministic: gates decide every interleaving. The start attempt, the runtime's handoff
 * completion and ACTION_STOP's teardown run on executors the test drains (awaitIdle), and
 * "is this call blocked?" is read from the calling thread's own state - never a sleep. Awaits
 * carry a 10 s bound only so a test bug fails instead of hanging.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShadowsocksVpnServiceLifecycleRaceTest {

    private class Gate {
        private val reached = CountDownLatch(1)
        private val released = CountDownLatch(1)
        fun block() {
            reached.countDown()
            check(released.await(10, TimeUnit.SECONDS)) { "gate never released" }
        }
        fun awaitReached() = check(reached.await(10, TimeUnit.SECONDS)) { "gate never reached" }
        fun release() = released.countDown()
    }

    /** Numbered call sites (0, 1, 2 ... in call order); only calls whose number was [gate]d block. */
    private class Gates {
        private val gates = ConcurrentHashMap<Int, Gate>()
        private val calls = AtomicInteger(0)
        fun gate(call: Int): Gate = gates.computeIfAbsent(call) { Gate() }
        fun pass(): Int {
            val call = calls.getAndIncrement()
            gates[call]?.block()
            return call
        }
    }

    /** Runs tasks on a thread pool and can wait until none is running or queued. */
    private class TrackingExecutor : Executor {
        private val pool = Executors.newCachedThreadPool()
        private val pending = AtomicInteger(0)
        private val idle = Object()
        override fun execute(command: Runnable) {
            pending.incrementAndGet()
            pool.execute {
                try {
                    command.run()
                } finally {
                    if (pending.decrementAndGet() == 0) synchronized(idle) { idle.notifyAll() }
                }
            }
        }
        fun awaitIdle() {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            synchronized(idle) {
                while (pending.get() != 0) {
                    val left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
                    check(left > 0) { "executor never went idle" }
                    idle.wait(left)
                }
            }
        }
        fun shutdown() = pool.shutdownNow()
    }

    /** Queues tasks until [runAll] - models a teardown whose dispatch is delayed behind later intents. */
    private class HeldExecutor : Executor {
        private val queue = java.util.concurrent.ConcurrentLinkedQueue<Runnable>()
        override fun execute(command: Runnable) { queue += command }
        fun runAll() {
            val runner = Thread { generateSequence { queue.poll() }.forEach { it.run() } }
            runner.start()
            runner.join(10_000)
            check(!runner.isAlive) { "held tasks did not finish" }
        }
    }

    /** Credential loading is the attempt's pre-commit phase; gating it holds an attempt before it may establish/spawn. */
    private class GatedCredentialRepository(private val gates: Gates, private val credential: Shadowsocks2022Credential) : Shadowsocks2022CredentialRepository {
        override suspend fun getCredential(): Shadowsocks2022CredentialGetResult {
            gates.pass()
            return Shadowsocks2022CredentialGetResult.Present(credential)
        }
        override suspend fun storeCredential(credential: Shadowsocks2022Credential) = Unit
        override suspend fun deleteCredential() = Unit
        override suspend fun credentialExists(): Boolean = true
    }

    private class HandoffBridge(private val gates: Gates) : ShadowsocksTunFdBridge {
        val results = ConcurrentHashMap<Int, ShadowsocksTunFdBridgeState>()
        override fun handOff(tunFd: FileDescriptor, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState =
            results[gates.pass()] ?: ShadowsocksTunFdBridgeState.FD_SENT
    }

    private inner class Harness {
        val service: ShadowsocksVpnService = Robolectric.buildService(ShadowsocksVpnService::class.java).create().get()
        val startExec = TrackingExecutor()
        val ioExec = TrackingExecutor()
        val teardownExec = TrackingExecutor()
        val credentialGates = Gates()
        val beforeStartGates = Gates()
        val launchGates = Gates()
        val handoffGates = Gates()
        val handoff = HandoffBridge(handoffGates)
        val processes: MutableList<FakeShadowsocksSpawnedProcess> = java.util.Collections.synchronizedList(mutableListOf())
        val tuns: MutableList<ParcelFileDescriptor> = java.util.Collections.synchronizedList(mutableListOf())
        val workingDir: File get() = File(service.filesDir, "shadowsocks")
        private val binary = kotlin.io.path.createTempFile("fake-sslocal", "").toFile().apply { deleteOnExit() }

        init {
            service.startDispatcher = startExec.asCoroutineDispatcher()
            service.teardownDispatcher = teardownExec.asCoroutineDispatcher()
            service.credentialRepositoryFactory = { _, _ -> GatedCredentialRepository(credentialGates, credential()) }
            service.binaryResolver = { ShadowsocksNativeBinaryResolver.Result.Found(binary) }
            service.tunEstablisher = {
                val file = kotlin.io.path.createTempFile("tun", "").toFile().apply { deleteOnExit() }
                ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE).also { tuns += it }
            }
            service.beforeRuntimeStart = { beforeStartGates.pass() }
            val launcher = FakeShadowsocksProcessLauncher(processFactory = {
                launchGates.pass()
                FakeShadowsocksSpawnedProcess().also { processes += it }
            })
            service.runtimeFactory = { protector, scope ->
                ShadowsocksRuntime(launcher, handoff, FakeShadowsocksVpnProtectBridge(), protector, scope, ioDispatcher = ioExec.asCoroutineDispatcher())
            }
        }

        fun start(sessionId: Long) {
            service.onStartCommand(
                Intent(ShadowsocksVpnService.ACTION_START)
                    .putExtra(ShadowsocksVpnService.EXTRA_SESSION_ID, sessionId)
                    .putExtra(ShadowsocksVpnService.EXTRA_ENDPOINT_ID, "frankfurt")
                    .putExtra(ShadowsocksVpnService.EXTRA_HOST, "203.0.113.10")
                    .putExtra(ShadowsocksVpnService.EXTRA_PORT, 8388)
                    .putExtra(ShadowsocksVpnService.EXTRA_METHOD, METHOD),
                0, sessionId.toInt(),
            )
        }

        fun actionStop() = service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 0)

        /** Runs [block] on its own thread and returns once it has either finished or is parked on a monitor. */
        fun onOtherThread(block: () -> Unit): Thread {
            val t = Thread(block).apply { start() }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (t.state != Thread.State.TERMINATED && t.state != Thread.State.BLOCKED) {
                check(System.nanoTime() < deadline) { "call neither finished nor blocked" }
                Thread.onSpinWait()
            }
            return t
        }

        fun drain() {
            startExec.awaitIdle()
            ioExec.awaitIdle()
            teardownExec.awaitIdle()
        }

        fun alive() = processes.filter { !it.stopRequested && !it.forceStopped }
        fun openTuns() = tuns.filter { it.fileDescriptor.valid() }
        fun configFiles() = workingDir.listFiles { f -> f.name.endsWith(".json") }.orEmpty().toList()

        /** spawned == owned + intentionally terminated, with exactly [owned] still alive. */
        fun assertOwnership(owned: Int) {
            val terminated = processes.count { it.stopRequested || it.forceStopped }
            assertEquals("owned (alive) processes; spawned=${processes.size}, terminated=$terminated", owned, alive().size)
            assertEquals("spawned == owned + terminated", processes.size, owned + terminated)
            assertEquals("open TUNs must match owned sessions", owned, openTuns().size)
        }

        fun shutdown() {
            listOf(startExec, ioExec, teardownExec).forEach { it.shutdown() }
        }
    }

    private val harnesses = mutableListOf<Harness>()
    private fun harness() = Harness().also { harnesses += it }

    @After fun tearDown() = harnesses.forEach { it.shutdown() }

    private fun credential() = (
        Shadowsocks2022CredentialValidator.validate(EndpointId("frankfurt"), METHOD, KEY_BASE64)
            as Shadowsocks2022CredentialValidationResult.Valid
        ).credential

    private fun awaitStatus(sessionId: Long, phase: ShadowsocksRuntimePhase) = runBlocking {
        withTimeout(10_000) { ShadowsocksVpnService.status.first { it?.sessionId == sessionId && it.phase == phase } }
    }

    private fun session() = nextSession.incrementAndGet()

    // --- reproductions of the original races ------------------------------

    @Test
    fun `teardown after the runtime is published but before it starts leaves no orphan sslocal`() {
        val h = harness()
        val s = session()
        h.beforeStartGates.gate(0)
        h.handoffGates.gate(0)
        h.start(s)
        h.beforeStartGates.gate(0).awaitReached()

        val stopper = h.onOtherThread { h.service.onRevoke() }
        h.beforeStartGates.gate(0).release()
        stopper.join()
        h.startExec.awaitIdle()

        h.assertOwnership(owned = 0)
        assertTrue("no plaintext config may outlive the teardown", h.configFiles().isEmpty())
        h.handoffGates.gate(0).release()
        h.drain()
        h.assertOwnership(owned = 0)
    }

    @Test
    fun `teardown before the attempt commits - the attempt never establishes a TUN nor spawns sslocal`() {
        val h = harness()
        h.credentialGates.gate(0)
        h.start(session())
        h.credentialGates.gate(0).awaitReached()

        h.onOtherThread { h.service.onRevoke() }.join()
        h.credentialGates.gate(0).release()
        h.drain()

        assertEquals("an invalidated start must never spawn sslocal", 0, h.processes.size)
        assertEquals("an invalidated start must never establish a TUN", 0, h.tuns.size)
        h.assertOwnership(owned = 0)
        assertTrue(h.configFiles().isEmpty())
    }

    @Test
    fun `onDestroy during a start attempt leaves no running sslocal and no plaintext config`() {
        val h = harness()
        h.credentialGates.gate(0)
        h.start(session())
        h.credentialGates.gate(0).awaitReached()

        h.onOtherThread { h.service.onDestroy() }.join()
        h.credentialGates.gate(0).release()
        h.drain()

        h.assertOwnership(owned = 0)
        assertTrue("the plaintext config (with the key) must not stay on disk", h.configFiles().isEmpty())
    }

    @Test
    fun `rapid reconnect before the first attempt commits - only the newest attempt owns sslocal`() {
        val h = harness()
        val a = session()
        val b = session()
        h.credentialGates.gate(0)
        h.start(a)
        h.credentialGates.gate(0).awaitReached()
        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.RUNNING)

        h.credentialGates.gate(0).release()
        h.drain()

        assertEquals("the superseded attempt must never spawn", 1, h.processes.size)
        assertEquals("the superseded attempt must never establish a TUN", 1, h.tuns.size)
        h.assertOwnership(owned = 1)
    }

    @Test
    fun `rapid reconnect after the first attempt committed - the superseded runtime is stopped, not orphaned`() {
        val h = harness()
        val a = session()
        val b = session()
        h.handoffGates.gate(0)
        h.start(a)
        h.handoffGates.gate(0).awaitReached() // A committed and spawned; still STARTING

        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.RUNNING)
        assertTrue("A's process must be stopped when B supersedes it", h.processes[0].stopRequested)
        h.assertOwnership(owned = 1)

        // A's late FAILED handoff must not touch B (its TUN, its runtime, or the service).
        h.handoff.results[0] = ShadowsocksTunFdBridgeState.FAILED
        h.handoffGates.gate(0).release()
        h.drain()
        h.assertOwnership(owned = 1)
        assertFalse(h.processes[1].stopRequested)
    }

    @Test
    fun `a stop that is dispatched after a newer start neither cancels nor ignores that start`() {
        val h = harness()
        val held = HeldExecutor()
        h.service.teardownDispatcher = held.asCoroutineDispatcher()
        val a = session()
        val b = session()
        h.start(a)
        awaitStatus(a, ShadowsocksRuntimePhase.RUNNING)

        h.actionStop() // teardown queued behind the next intent
        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.RUNNING)
        held.runAll()
        h.drain()

        assertEquals(2, h.processes.size)
        assertTrue("A must be stopped", h.processes[0].stopRequested)
        h.assertOwnership(owned = 1)
        assertEquals(ShadowsocksServiceStatus(b, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
    }

    @Test
    fun `a stop superseded by a start that then fails early still releases the old session`() {
        val h = harness()
        val held = HeldExecutor()
        h.service.teardownDispatcher = held.asCoroutineDispatcher()
        val a = session()
        val b = session()
        h.start(a)
        awaitStatus(a, ShadowsocksRuntimePhase.RUNNING)

        h.actionStop() // A's teardown is queued; B's request makes it stale
        h.service.credentialRepositoryFactory = { _, _ -> absentCredentialRepository() }
        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.FAILED)
        held.runAll()
        h.drain()

        assertTrue("A must not outlive both the stop and the failed start", h.processes.single().stopRequested)
        h.assertOwnership(owned = 0)
        assertEquals(ShadowsocksServiceStatus(b, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.CredentialAbsent("frankfurt")), ShadowsocksVpnService.status.value)
    }

    @Test
    fun `a committed but still STARTING session is released when the superseding start cannot establish a TUN`() {
        val h = harness()
        val a = session()
        val b = session()
        h.handoffGates.gate(0)
        h.start(a)
        h.handoffGates.gate(0).awaitReached() // A committed and spawned; STARTING

        h.service.tunEstablisher = { null }
        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.FAILED)
        h.handoffGates.gate(0).release()
        h.drain()

        assertTrue(h.processes.single().stopRequested)
        h.assertOwnership(owned = 0)
        assertEquals(ShadowsocksServiceStatus(b, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.TunEstablishFailed("establish() returned null")), ShadowsocksVpnService.status.value)
    }

    private fun absentCredentialRepository() = object : Shadowsocks2022CredentialRepository {
        override suspend fun getCredential(): Shadowsocks2022CredentialGetResult = Shadowsocks2022CredentialGetResult.Absent
        override suspend fun storeCredential(credential: Shadowsocks2022Credential) = Unit
        override suspend fun deleteCredential() = Unit
        override suspend fun credentialExists(): Boolean = false
    }

    // --- lifecycle after the fix ------------------------------------------

    @Test
    fun `normal start reaches RUNNING with one owned sslocal and no config left`() {
        val h = harness()
        val s = session()
        h.start(s)
        awaitStatus(s, ShadowsocksRuntimePhase.RUNNING)
        h.drain()

        h.assertOwnership(owned = 1)
        assertTrue(h.configFiles().isEmpty())
    }

    @Test
    fun `normal teardown after RUNNING stops sslocal, closes the TUN and publishes STOPPED`() {
        val h = harness()
        val s = session()
        h.start(s)
        awaitStatus(s, ShadowsocksRuntimePhase.RUNNING)

        h.actionStop()
        h.drain()

        h.assertOwnership(owned = 0)
        assertEquals(ShadowsocksServiceStatus(s, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
    }

    @Test
    fun `teardown while runtime start is spawning waits for it, then terminates the spawned process`() {
        val h = harness()
        h.launchGates.gate(0)
        h.handoffGates.gate(0)
        h.start(session())
        h.launchGates.gate(0).awaitReached()

        val stopper = h.onOtherThread { h.service.onRevoke() }
        h.launchGates.gate(0).release()
        stopper.join()
        h.handoffGates.gate(0).release()
        h.drain()

        assertEquals(1, h.processes.size)
        h.assertOwnership(owned = 0)
        assertTrue(h.configFiles().isEmpty())
    }

    @Test
    fun `start, teardown, start - the second session runs and the first stays stopped`() {
        val h = harness()
        val a = session()
        val b = session()
        h.start(a)
        awaitStatus(a, ShadowsocksRuntimePhase.RUNNING)
        h.actionStop()
        h.drain()
        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.RUNNING)
        h.drain()

        assertEquals(2, h.processes.size)
        assertTrue(h.processes[0].stopRequested)
        h.assertOwnership(owned = 1)
    }

    @Test
    fun `double teardown is idempotent`() {
        val h = harness()
        val s = session()
        h.start(s)
        awaitStatus(s, ShadowsocksRuntimePhase.RUNNING)

        h.actionStop()
        h.actionStop()
        h.service.onRevoke()
        h.drain()

        h.assertOwnership(owned = 0)
        assertEquals(ShadowsocksServiceStatus(s, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
    }

    @Test
    fun `a stale handoff completion of a stopped start does not affect the next session`() {
        val h = harness()
        val a = session()
        val b = session()
        h.handoffGates.gate(0)
        h.start(a)
        h.handoffGates.gate(0).awaitReached()
        h.actionStop()
        h.teardownExec.awaitIdle()
        h.start(b)
        awaitStatus(b, ShadowsocksRuntimePhase.RUNNING)

        h.handoffGates.gate(0).release() // A's handoff "succeeds" long after A was stopped
        h.drain()

        h.assertOwnership(owned = 1)
        assertTrue(h.processes[0].stopRequested)
        assertEquals(ShadowsocksServiceStatus(b, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
    }

    private companion object {
        val nextSession = AtomicLong(7_000_000L)
    }
}
