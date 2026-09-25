package net.pocvpn.client.vpn.shadowsocks

import android.content.Intent
import android.os.ParcelFileDescriptor
import java.io.File
import java.util.Base64
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import net.pocvpn.client.identity.Shadowsocks2022Credential
import net.pocvpn.client.identity.Shadowsocks2022CredentialGetResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialRepository
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidationResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidator
import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

private const val METHOD = "2022-blake3-aes-256-gcm"
private val KEY_BASE64 = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })
private const val AWAIT_SECONDS = 10L

/**
 * Service -> runtime lifecycle races in [ShadowsocksVpnService]: publication
 * of the runtime/TUN, `start()`, and every teardown entry point (ACTION_STOP,
 * onRevoke, onDestroy), plus superseding START requests.
 *
 * Deterministic: every interleaving is forced with latches/gates at a named
 * point of the start path. Nothing here sleeps, retries, or repeats a
 * scenario hoping to hit a window. Await timeouts only turn a test bug into a
 * failure instead of a hang.
 *
 * The start path runs on [InlineDispatcher] (inline on whichever thread
 * dispatches or resumes it), so the test decides on which thread and at which
 * point it runs.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShadowsocksVpnServiceLifecycleRaceTest {

    // --- 1. runtime published -> teardown -> delayed start (the orphan race) ---

    @Test
    fun `teardown between runtime publication and runtime start never leaves an orphan sslocal process`() {
        teardownEntryPoints.forEach { (name, teardown) ->
            val f = Fixture()
            val published = f.dispatcher.gateNextDispatchAfterRuntimeCreated(f)

            val starter = thread { f.service.onStartCommand(f.startIntent(sessionId = 11), 0, 1) }
            published.awaitReached()
            // The runtime reference is published and start() has not been called yet.
            assertEquals(name, 0, f.launchCount())

            val stopper = thread { teardown(f) }
            awaitFinishedOrBlockedBy(stopper, starter)
            published.release()
            starter.join()
            stopper.join()

            assertEquals(name, 1, f.tuns.size)
            f.processes.forEach { assertTrue("$name: a process spawned by the delayed start must be stopped by teardown, never orphaned", it.stopRequested) }
            assertTrue("$name: TUN must be closed", f.tuns.all { it.isClosed() })
            assertEquals(name, ShadowsocksServiceStatus(11, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
        }
    }

    // --- 2. stop before start ---

    @Test
    fun `stop issued while the credential is still loading prevents any TUN or process`() {
        val f = Fixture(gateCredentials = true)
        f.service.onStartCommand(f.startIntent(sessionId = 21), 0, 1)

        f.service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 2)
        f.credentials.release(0)

        assertEquals("no TUN may be established after teardown", 0, f.tuns.size)
        assertEquals("no sslocal may be spawned after teardown", 0, f.launchCount())
        assertEquals(ShadowsocksServiceStatus(21, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
    }

    // --- 3. teardown during runtime start ---

    @Test
    fun `teardown issued while runtime start is spawning stops the spawned process after start returns`() {
        val f = Fixture()
        val protectGate = Gate()
        f.protectStartGate = protectGate

        val starter = thread { f.service.onStartCommand(f.startIntent(sessionId = 31), 0, 1) }
        protectGate.awaitReached()
        val stopper = thread { f.service.onRevoke() }
        awaitFinishedOrBlockedBy(stopper, starter)
        protectGate.release()
        starter.join()
        stopper.join()

        assertEquals(1, f.launchCount())
        assertTrue("the process spawned by the interrupted start must be stopped", f.processes.single().stopRequested)
        assertTrue(f.tuns.single().isClosed())
        assertEquals(ShadowsocksServiceStatus(31, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
    }

    // --- 4. start -> stop -> start ---

    @Test
    fun `start then stop then start runs the second session on a fresh runtime and fully releases the first`() {
        val f = Fixture()
        f.service.onStartCommand(f.startIntent(sessionId = 41), 0, 1)
        assertEquals(ShadowsocksServiceStatus(41, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)

        f.service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 2)
        assertEquals(ShadowsocksServiceStatus(41, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
        assertTrue(f.processes[0].stopRequested)
        assertTrue(f.tuns[0].isClosed())

        f.service.onStartCommand(f.startIntent(sessionId = 42), 0, 3)
        assertEquals(ShadowsocksServiceStatus(42, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
        assertEquals(2, f.launchCount())
        assertFalse(f.processes[1].stopRequested)
        assertFalse(f.tuns[1].isClosed())
    }

    // --- 5. double teardown ---

    @Test
    fun `repeated teardown from every entry point stops the session exactly once`() {
        val f = Fixture()
        f.service.onStartCommand(f.startIntent(sessionId = 51), 0, 1)
        assertEquals(ShadowsocksRuntimePhase.RUNNING, ShadowsocksVpnService.status.value?.phase)

        f.service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 2)
        f.service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 3)
        f.service.onRevoke()
        f.service.onDestroy()

        assertEquals("the runtime is stopped once, never re-stopped by a later teardown", 1, f.protectBridges.single().stopCalls)
        assertTrue(f.processes.single().stopRequested)
        assertTrue(f.tuns.single().isClosed())
        assertEquals(ShadowsocksServiceStatus(51, ShadowsocksRuntimePhase.STOPPED), ShadowsocksVpnService.status.value)
    }

    // --- 6. rapid reconnect ---

    @Test
    fun `a stop issued before a new start never tears down the new session`() {
        val f = Fixture()
        val deferredTeardown = QueueDispatcher()
        f.service.onStartCommand(f.startIntent(sessionId = 61), 0, 1)
        assertEquals(ShadowsocksRuntimePhase.RUNNING, ShadowsocksVpnService.status.value?.phase)

        // Disconnect's STOP is accepted but its teardown has not run yet when the reconnect's START arrives.
        f.service.teardownDispatcher = deferredTeardown
        f.service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 2)
        f.service.onStartCommand(f.startIntent(sessionId = 62), 0, 3)
        deferredTeardown.runAll()

        assertEquals("the reconnect must actually start, never be ignored as a duplicate", 2, f.launchCount())
        assertTrue("the session the STOP was issued for is stopped", f.processes[0].stopRequested)
        assertTrue(f.tuns[0].isClosed())
        assertFalse("the late teardown must not stop the NEW session", f.processes[1].stopRequested)
        assertFalse(f.tuns[1].isClosed())
        assertFalse("the late teardown must not stop the service the new session lives in", shadowOf(f.service).isStoppedBySelf)
        assertEquals(ShadowsocksServiceStatus(62, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
    }

    // --- 7. stale completion ---

    @Test
    fun `a superseded start whose credential load completes late never establishes a TUN or spawns`() {
        val f = Fixture(gateCredentials = true)
        f.service.onStartCommand(f.startIntent(sessionId = 71), 0, 1)
        f.service.onStartCommand(f.startIntent(sessionId = 72), 0, 2)

        f.credentials.release(1) // the newer start completes first
        assertEquals(ShadowsocksServiceStatus(72, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
        f.credentials.release(0) // the superseded start completes late

        assertEquals("the stale start must not establish a second TUN", 1, f.tuns.size)
        assertEquals("the stale start must not spawn a second sslocal", 1, f.launchCount())
        assertFalse(f.processes.single().stopRequested)
        assertFalse(f.tuns.single().isClosed())
        assertEquals(ShadowsocksServiceStatus(72, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
    }

    // --- 8. stale callback ---

    @Test
    fun `a superseded runtime failing late never stops the service or the newer session`() {
        val f = Fixture(gateCredentials = true)
        f.handoffResults += ShadowsocksTunFdBridgeState.WAITING // first runtime stays STARTING
        f.service.onStartCommand(f.startIntent(sessionId = 81), 0, 1)
        f.credentials.release(0)
        assertEquals(ShadowsocksServiceStatus(81, ShadowsocksRuntimePhase.STARTING), ShadowsocksVpnService.status.value)

        f.service.onStartCommand(f.startIntent(sessionId = 82), 0, 2) // supersedes; its start is still loading
        f.processes[0].simulateUnexpectedExit(1) // the superseded runtime reports FAILED now

        assertFalse("a stale runtime's failure must not stop the service", shadowOf(f.service).isStoppedBySelf)
        f.credentials.release(1)

        assertEquals(ShadowsocksServiceStatus(82, ShadowsocksRuntimePhase.RUNNING), ShadowsocksVpnService.status.value)
        assertFalse(shadowOf(f.service).isStoppedBySelf)
        assertTrue("the superseded session's TUN is released", f.tuns[0].isClosed())
        assertFalse(f.tuns[1].isClosed())
        assertFalse(f.processes[1].stopRequested)
    }

    // --- fixture ---

    private val teardownEntryPoints: List<Pair<String, (Fixture) -> Unit>> = listOf(
        "ACTION_STOP" to { f -> f.service.onStartCommand(Intent(ShadowsocksVpnService.ACTION_STOP), 0, 2) },
        "onRevoke" to { f -> f.service.onRevoke() },
        "onDestroy" to { f -> f.service.onDestroy() },
    )

    private class Fixture(gateCredentials: Boolean = false) {
        val service: ShadowsocksVpnService = Robolectric.buildService(ShadowsocksVpnService::class.java).create().get()
        val dispatcher = InlineDispatcher()
        val credentials = GatedCredentialRepository(credential(), gateCredentials)
        val tuns: MutableList<ParcelFileDescriptor> = Collections.synchronizedList(mutableListOf())
        val processes: MutableList<FakeShadowsocksSpawnedProcess> = Collections.synchronizedList(mutableListOf())
        val protectBridges: MutableList<FakeShadowsocksVpnProtectBridge> = Collections.synchronizedList(mutableListOf())
        val handoffResults = ConcurrentLinkedQueue<ShadowsocksTunFdBridgeState>()
        @Volatile var protectStartGate: Gate? = null
        @Volatile var onRuntimeCreated: () -> Unit = {}
        private val launches = AtomicInteger(0)
        private val runtimeScope = CoroutineScope(SupervisorJob())
        private val binary = kotlin.io.path.createTempFile("fake-sslocal", "").toFile().apply { deleteOnExit() }
        private val tunBacking = kotlin.io.path.createTempFile("fake-tun", "").toFile().apply { deleteOnExit() }

        init {
            service.teardownDispatcher = Dispatchers.Unconfined
            service.workDispatcher = dispatcher
            service.credentialRepositoryFactory = { _, _ -> credentials }
            service.binaryResolver = { ShadowsocksNativeBinaryResolver.Result.Found(binary) }
            service.tunEstablisher = {
                ParcelFileDescriptor.open(tunBacking, ParcelFileDescriptor.MODE_READ_WRITE).also { tuns += it }
            }
            service.runtimeFactory = { protector ->
                val fakeProtect = FakeShadowsocksVpnProtectBridge().also { protectBridges += it }
                val protectBridge = object : ShadowsocksVpnProtectBridge by fakeProtect {
                    override fun start(socketPath: File, protector: ShadowsocksVpnProtector) {
                        protectStartGate?.let { protectStartGate = null; it.block() }
                        fakeProtect.start(socketPath, protector)
                    }
                }
                val launcher = FakeShadowsocksProcessLauncher(processFactory = {
                    launches.incrementAndGet()
                    FakeShadowsocksSpawnedProcess().also { processes += it }
                })
                val handoff = FakeShadowsocksTunFdBridge(handoffResults.poll() ?: ShadowsocksTunFdBridgeState.FD_SENT)
                ShadowsocksRuntime(launcher, handoff, protectBridge, protector, runtimeScope, ioDispatcher = Dispatchers.Unconfined)
                    .also { onRuntimeCreated() }
            }
        }

        fun launchCount(): Int = launches.get()

        fun startIntent(sessionId: Long): Intent =
            Intent(ShadowsocksVpnService.ACTION_START)
                .putExtra(ShadowsocksVpnService.EXTRA_SESSION_ID, sessionId)
                .putExtra(ShadowsocksVpnService.EXTRA_ENDPOINT_ID, "frankfurt")
                .putExtra(ShadowsocksVpnService.EXTRA_HOST, "203.0.113.10")
                .putExtra(ShadowsocksVpnService.EXTRA_PORT, 28388)
                .putExtra(ShadowsocksVpnService.EXTRA_METHOD, METHOD)

        private fun credential(): Shadowsocks2022Credential =
            (Shadowsocks2022CredentialValidator.validate(EndpointId("frankfurt"), METHOD, KEY_BASE64) as Shadowsocks2022CredentialValidationResult.Valid).credential
    }

    /** One-shot rendezvous: the code under test calls [block]; the test awaits [awaitReached] and later calls [release]. */
    private class Gate {
        private val reached = CountDownLatch(1)
        private val released = CountDownLatch(1)

        fun block() {
            reached.countDown()
            check(released.await(AWAIT_SECONDS, TimeUnit.SECONDS)) { "gate was never released" }
        }

        fun awaitReached() = check(reached.await(AWAIT_SECONDS, TimeUnit.SECONDS)) { "gate was never reached" }

        fun release() = released.countDown()
    }

    /** Runs every dispatched block inline on the dispatching thread; can park the first dispatch after an armed trigger on a [Gate]. */
    private class InlineDispatcher : CoroutineDispatcher() {
        @Volatile private var armed: Gate? = null

        /** Parks the first dispatch issued after the service created its runtime - i.e. right after the runtime reference is published, before runtime.start(). */
        fun gateNextDispatchAfterRuntimeCreated(f: Fixture): Gate {
            val gate = Gate()
            f.onRuntimeCreated = { armed = gate }
            return gate
        }

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            armed?.let { armed = null; it.block() }
            block.run()
        }
    }

    /** Holds dispatched blocks until the test runs them. */
    private class QueueDispatcher : CoroutineDispatcher() {
        private val queue = ConcurrentLinkedQueue<Runnable>()
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            queue += block
        }
        fun runAll() {
            while (true) (queue.poll() ?: return).run()
        }
    }

    private class GatedCredentialRepository(
        private val credential: Shadowsocks2022Credential,
        private val gated: Boolean,
    ) : Shadowsocks2022CredentialRepository {
        private val gates = ConcurrentHashMap<Int, CompletableDeferred<Unit>>()
        private val calls = AtomicInteger(0)

        private fun gate(call: Int) = gates.computeIfAbsent(call) { CompletableDeferred() }

        /** Lets the [call]-th (0-based) getCredential return; the waiting start path resumes inline on this thread. */
        fun release(call: Int) {
            gate(call).complete(Unit)
        }

        override suspend fun getCredential(): Shadowsocks2022CredentialGetResult {
            if (gated) gate(calls.getAndIncrement()).await()
            return Shadowsocks2022CredentialGetResult.Present(credential)
        }

        override suspend fun storeCredential(credential: Shadowsocks2022Credential) = Unit
        override suspend fun deleteCredential() = Unit
        override suspend fun credentialExists(): Boolean = true
    }

    /** A worker thread whose failure is rethrown on [join], never silently lost. */
    private class Worker(body: () -> Unit) {
        @Volatile private var failure: Throwable? = null
        val thread: Thread = kotlin.concurrent.thread { runCatching(body).onFailure { failure = it } }

        fun join() {
            thread.join(TimeUnit.SECONDS.toMillis(AWAIT_SECONDS))
            check(!thread.isAlive) { "worker did not finish" }
            failure?.let { throw AssertionError("worker failed", it) }
        }
    }

    private fun thread(body: () -> Unit) = Worker(body)

    /**
     * Deterministic hand-over point, not a timing guess: [waiter] has either
     * run to completion (it did not wait for [holder]) or is parked on a
     * monitor [holder] owns. Both are stable until [holder] is released.
     */
    private fun awaitFinishedOrBlockedBy(waiterWorker: Worker, holderWorker: Worker) {
        val waiter = waiterWorker.thread
        val holder = holderWorker.thread
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(AWAIT_SECONDS)
        while (true) {
            if (waiter.state == Thread.State.TERMINATED) return
            if (waiter.state == Thread.State.BLOCKED && monitorOwnerIdOf(waiter) == holder.id) return
            check(System.nanoTime() < deadline) { "teardown neither finished nor blocked on the start path" }
            Thread.yield()
        }
    }

    /** Id of the thread owning the monitor [thread] is blocked on. java.lang.management is JVM-only (not on the Android compile classpath), hence reflection. */
    private fun monitorOwnerIdOf(thread: Thread): Long {
        val mxBean = Class.forName("java.lang.management.ManagementFactory").getMethod("getThreadMXBean").invoke(null)
        val info = Class.forName("java.lang.management.ThreadMXBean").getMethod("getThreadInfo", Long::class.javaPrimitiveType).invoke(mxBean, thread.id)
            ?: return -1
        return Class.forName("java.lang.management.ThreadInfo").getMethod("getLockOwnerId").invoke(info) as Long
    }

    private fun ParcelFileDescriptor.isClosed(): Boolean = !fileDescriptor.valid()
}
