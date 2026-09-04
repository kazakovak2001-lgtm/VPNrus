package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.FileXrayTlsProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.SecureXrayTlsProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * B8K4C - proves NovaXrayVpnService's actual start/stop sequencing end to
 * end (resolve -> establish -> startLoop / stopLoop -> close), against a
 * fake [XrayCoreRuntime] and a fake tun-establish function - no Android
 * framework dependency (this project has no Robolectric dependency).
 */
class XrayCoreControllerTest {

    private val validProfile = XrayProfile(
        server = "152.70.43.1",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "a1b2c3d4",
    )

    private fun newRepository(): SecureXrayProfileRepository =
        SecureXrayProfileRepository(FileXrayProfileStore(Files.createTempDirectory("xray-controller-test").toFile()), FakeAesGcmKeyEncryptor())

    private class Harness(
        repository: SecureXrayProfileRepository,
        val coreRuntime: FakeXrayCoreRuntime = FakeXrayCoreRuntime(),
        establishedFd: Int? = 42,
        establishThrows: Throwable? = null,
        tlsRepository: SecureXrayTlsProfileRepository? = null,
    ) {
        var ensureCoreEnvCallCount = 0
            private set
        var establishTunCallCount = 0
            private set
        var closeTunCallCount = 0
            private set

        val controller = XrayCoreController(
            repository = repository,
            coreRuntime = coreRuntime,
            novaPackageId = "net.pocvpn.client.test",
            ensureCoreEnvInitialized = { ensureCoreEnvCallCount++ },
            establishTun = {
                establishTunCallCount++
                establishThrows?.let { throw it }
                establishedFd
            },
            closeTun = { closeTunCallCount++ },
            tlsRepository = tlsRepository,
        )
    }

    // --- absent/corrupt/invalid profile never starts Xray ---

    @Test
    fun `absent profile is rejected and never invokes the runtime`() = runBlocking {
        val harness = Harness(newRepository())

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.Rejected("no Xray profile configured"), outcome)
        assertEquals(0, harness.establishTunCallCount)
        assertEquals(0, harness.coreRuntime.startLoopCallCount)
    }

    @Test
    fun `corrupted profile is rejected and never invokes the runtime`() = runBlocking {
        val dir = Files.createTempDirectory("xray-controller-corrupt-test").toFile()
        dir.mkdirs()
        java.io.File(dir, "xray_profile.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
        val repository = SecureXrayProfileRepository(FileXrayProfileStore(dir), FakeAesGcmKeyEncryptor())
        val harness = Harness(repository)

        val outcome = harness.controller.requestStart()

        assertTrue(outcome is XrayCoreStartOutcome.Rejected)
        assertEquals(0, harness.establishTunCallCount)
        assertEquals(0, harness.coreRuntime.startLoopCallCount)
    }

    @Test
    fun `invalid mapped config is rejected and never invokes the runtime`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile.copy(fingerprint = "not-a-real-fingerprint"))
        val harness = Harness(repository)

        val outcome = harness.controller.requestStart()

        assertTrue(outcome is XrayCoreStartOutcome.Rejected)
        assertEquals(0, harness.establishTunCallCount)
        assertEquals(0, harness.coreRuntime.startLoopCallCount)
    }

    // --- valid profile invokes runtime start exactly once ---

    @Test
    fun `a valid profile invokes startLoop exactly once with the exact rendered config and fd`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository, establishedFd = 7)

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(1, harness.establishTunCallCount)
        assertEquals(1, harness.coreRuntime.startLoopCallCount)
        assertEquals(1, harness.ensureCoreEnvCallCount)
        assertEquals(7, harness.coreRuntime.lastStartedTunFd)
        assertEquals(XrayConfigRenderer.render(validProfile.toXrayVlessRealityConfig()), harness.coreRuntime.lastStartedConfigContent)
    }

    // --- repeated start is idempotent / safely rejected ---

    @Test
    fun `a second start while already running is rejected without a second startLoop call`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository)

        val first = harness.controller.requestStart()
        val second = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.Started, first)
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, second)
        assertEquals(1, harness.coreRuntime.startLoopCallCount)
        assertEquals(1, harness.establishTunCallCount)
    }

    // --- establish/core-start failure never leaves a half-started state ---

    @Test
    fun `establish returning null is reported and never invokes startLoop`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository, establishedFd = null)

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.EstablishFailed("establish() returned null"), outcome)
        assertEquals(0, harness.coreRuntime.startLoopCallCount)
    }

    @Test
    fun `startLoop throwing closes the tun and is reported as CoreStartFailed`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository, coreRuntime = FakeXrayCoreRuntime(startLoopThrows = IllegalStateException("boom")))

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.CoreStartFailed("IllegalStateException"), outcome)
        assertEquals(1, harness.closeTunCallCount)
    }

    // --- stop invokes runtime stop and releases resources ---

    @Test
    fun `stop after a successful start invokes stopLoop and closes the tun exactly once`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository)
        harness.controller.requestStart()

        val outcome = harness.controller.requestStop()

        assertEquals(XrayCoreStopOutcome(didTeardown = true), outcome)
        assertEquals(1, harness.coreRuntime.stopLoopCallCount)
        assertEquals(1, harness.closeTunCallCount)
    }

    @Test
    fun `stop when never started is a safe no-op`() = runBlocking {
        val harness = Harness(newRepository())

        val outcome = harness.controller.requestStop()

        assertEquals(XrayCoreStopOutcome(didTeardown = false), outcome)
        assertEquals(0, harness.coreRuntime.stopLoopCallCount)
        assertEquals(0, harness.closeTunCallCount)
    }

    @Test
    fun `a second stop after an already-completed stop is a safe no-op`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository)
        harness.controller.requestStart()
        harness.controller.requestStop()

        val second = harness.controller.requestStop()

        assertEquals(XrayCoreStopOutcome(didTeardown = false), second)
        assertEquals(1, harness.coreRuntime.stopLoopCallCount)
        assertEquals(1, harness.closeTunCallCount)
    }

    // --- no secrets in diagnostic/error strings ---

    @Test
    fun `no outcome ever carries the profile's actual secret field values`() = runBlocking {
        val repository = newRepository()
        val saved = validProfile.copy(uuid = "not-a-uuid")
        repository.saveProfile(saved)
        val harness = Harness(repository)

        val rejected = harness.controller.requestStart() as XrayCoreStartOutcome.Rejected
        assertFalse(rejected.reason.contains(saved.uuid))
        assertFalse(rejected.reason.contains(saved.realityPublicKey))
        assertFalse(rejected.reason.contains(saved.shortId))

        val establishFailureHarness = Harness(newRepository().also { it.saveProfile(validProfile) }, establishedFd = null)
        val establishFailed = establishFailureHarness.controller.requestStart() as XrayCoreStartOutcome.EstablishFailed
        assertFalse(establishFailed.reason.contains(validProfile.uuid))
        assertFalse(establishFailed.reason.contains(validProfile.realityPublicKey))
    }

    // --- B8O2: TLS_TCP branch, and REALITY's own default-arg behavior unaffected by its mere existence ---

    private val validTlsProfile = XrayTlsProfile(
        server = "152.70.43.1",
        serverPort = 2053,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "203.0.113.1",
        fingerprint = "chrome",
    )

    private fun newTlsRepository(): SecureXrayTlsProfileRepository =
        SecureXrayTlsProfileRepository(FileXrayTlsProfileStore(Files.createTempDirectory("xray-tls-controller-test").toFile()), FakeAesGcmKeyEncryptor())

    @Test
    fun `requestStart TLS_TCP with no tlsRepository wired is rejected without touching the runtime`() = runBlocking {
        val harness = Harness(newRepository())

        val outcome = harness.controller.requestStart(TransportKind.TLS_TCP)

        assertEquals(XrayCoreStartOutcome.Rejected("Xray TLS profile repository not wired"), outcome)
        assertEquals(0, harness.establishTunCallCount)
        assertEquals(0, harness.coreRuntime.startLoopCallCount)
    }

    @Test
    fun `requestStart TLS_TCP with an absent TLS profile is rejected without touching the runtime`() = runBlocking {
        val harness = Harness(newRepository(), tlsRepository = newTlsRepository())

        val outcome = harness.controller.requestStart(TransportKind.TLS_TCP)

        assertEquals(XrayCoreStartOutcome.Rejected("no Xray TLS profile configured"), outcome)
        assertEquals(0, harness.establishTunCallCount)
    }

    @Test
    fun `requestStart TLS_TCP with a valid TLS profile invokes startLoop with the TLS rendered config`() = runBlocking {
        val tlsRepository = newTlsRepository()
        tlsRepository.saveProfile(validTlsProfile)
        val harness = Harness(newRepository(), tlsRepository = tlsRepository, establishedFd = 9)

        val outcome = harness.controller.requestStart(TransportKind.TLS_TCP)

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(1, harness.establishTunCallCount)
        assertEquals(1, harness.coreRuntime.startLoopCallCount)
        assertEquals(9, harness.coreRuntime.lastStartedTunFd)
        assertEquals(XrayConfigRenderer.render(validTlsProfile.toXrayVlessTlsConfig()), harness.coreRuntime.lastStartedConfigContent)
    }

    @Test
    fun `requestStart with no argument still resolves REALITY - byte-for-byte unaffected by TLS_TCP's existence`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val tlsRepository = newTlsRepository() // wired but empty - must never be consulted for a plain requestStart()
        val harness = Harness(repository, tlsRepository = tlsRepository)

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(XrayConfigRenderer.render(validProfile.toXrayVlessRealityConfig()), harness.coreRuntime.lastStartedConfigContent)
    }

    // --- B33: local startLoop() success is NOT by itself sufficient - a real, bounded remote confirmation is required ---

    @Test
    fun `startLoop succeeding but the remote confirmation throwing is reported as RemoteUnconfirmed - never Started`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = java.io.IOException("connection refused"))
        val harness = Harness(repository, coreRuntime = runtime)

        val outcome = harness.controller.requestStart()

        assertTrue("expected RemoteUnconfirmed, got $outcome", outcome is XrayCoreStartOutcome.RemoteUnconfirmed)
        assertEquals(1, runtime.startLoopCallCount)
        // The local loop DID start - proving this is genuinely a DIFFERENT,
        // later failure than CoreStartFailed (startLoop itself never threw).
    }

    @Test
    fun `a RemoteUnconfirmed outcome stops the loop and closes the tun - never left half-up`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = java.io.IOException("timeout"))
        val harness = Harness(repository, coreRuntime = runtime)

        harness.controller.requestStart()

        assertEquals(1, runtime.stopLoopCallCount)
        assertEquals(1, harness.closeTunCallCount)
    }

    @Test
    fun `a RemoteUnconfirmed outcome never blocks a subsequent real start - the lifecycle gate was never marked running`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = java.io.IOException("timeout"))
        val harness = Harness(repository, coreRuntime = runtime)
        val first = harness.controller.requestStart()
        assertTrue(first is XrayCoreStartOutcome.RemoteUnconfirmed)

        // A fresh attempt (e.g. the SAME candidate retried, or a different
        // one) must be able to PROCEED - never permanently wedged as
        // AlreadyRunning/StartInFlight by an attempt that never actually
        // confirmed (the lifecycle gate must never have been marked running
        // for the first, unconfirmed attempt).
        val second = harness.controller.requestStart()

        assertTrue("expected a genuine second attempt, got $second", second is XrayCoreStartOutcome.RemoteUnconfirmed)
        assertEquals(2, runtime.startLoopCallCount)
        assertEquals(2, runtime.stopLoopCallCount)
    }

    @Test
    fun `a successful remote confirmation reports Started and dials the exact resolved server host`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = FakeXrayCoreRuntime()
        val harness = Harness(repository, coreRuntime = runtime)

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(1, runtime.measureDelayCallCount)
        assertEquals("https://${validProfile.server}/v1/manifest", runtime.lastMeasureDelayUrl)
    }

    @Test
    fun `TLS_TCP remote confirmation dials the TLS profile's own resolved server host`() = runBlocking {
        val tlsRepository = newTlsRepository()
        tlsRepository.saveProfile(validTlsProfile)
        val runtime = FakeXrayCoreRuntime()
        val harness = Harness(newRepository(), coreRuntime = runtime, tlsRepository = tlsRepository)

        val outcome = harness.controller.requestStart(TransportKind.TLS_TCP)

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals("https://${validTlsProfile.server}/v1/manifest", runtime.lastMeasureDelayUrl)
    }

    // --- B33 review fix (round 2, blocker): the timeout must be REAL wall-clock-bounded, not merely wrapped around the blocking call ---

    /** A real, un-cancellable BLOCKING measureDelay - simulates the exact native-call shape the review's blocker concerned. */
    private class BlockingMeasureDelayRuntime(private val blockMillis: Long) : XrayCoreRuntime {
        var startLoopCallCount = 0
            private set
        var stopLoopCallCount = 0
            private set
        override fun ensureCoreEnvInitialized(context: android.content.Context) {}
        override val isRunning: Boolean get() = startLoopCallCount > stopLoopCallCount
        override fun startLoop(configContent: String, tunFd: Int) { startLoopCallCount++ }
        override fun stopLoop() { stopLoopCallCount++ }
        override fun measureDelay(url: String): Long {
            Thread.sleep(blockMillis)
            return 1L
        }
    }

    private suspend fun blockingHarness(blockMillis: Long, repository: SecureXrayProfileRepository) =
        BlockingMeasureDelayRuntime(blockMillis).let { runtime ->
            runtime to XrayCoreController(
                repository = repository,
                coreRuntime = runtime,
                novaPackageId = "net.pocvpn.client.test",
                ensureCoreEnvInitialized = {},
                establishTun = { 42 },
                closeTun = {},
            )
        }

    @Test
    fun `a measureDelay call blocking far longer than the bound does not delay requestStart past it - the real, previously-broken timeout`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val (runtime, controller) = blockingHarness(blockMillis = 20_000L, repository = repository)

        val startedAt = System.currentTimeMillis()
        val outcome = controller.requestStart()
        val elapsedMillis = System.currentTimeMillis() - startedAt

        assertTrue("expected RemoteUnconfirmed, got $outcome", outcome is XrayCoreStartOutcome.RemoteUnconfirmed)
        // Generous slack above the real 6s bound, but nowhere near the 20s
        // the (fixed) blocking call actually takes - proves requestStart
        // genuinely did not wait for it.
        assertTrue("requestStart must return within the bound, took ${elapsedMillis}ms", elapsedMillis < 10_000L)
        assertEquals(1, runtime.stopLoopCallCount)
    }

    @Test
    fun `late completion of an abandoned probe after timeout never affects a subsequent fresh attempt`() = runBlocking {
        // Blocks just past the bound (not the full 20s above) so the test
        // can also afford to wait for it to actually finish below.
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val (runtime, controller) = blockingHarness(blockMillis = 6_500L, repository = repository)

        val first = controller.requestStart()
        assertTrue(first is XrayCoreStartOutcome.RemoteUnconfirmed)

        // Let the abandoned first probe actually complete in the background -
        // its late "success" must be inert: nothing reads it, nothing it
        // could mutate is shared with a fresh attempt (see
        // confirmRemoteConnectivity's own docs).
        kotlinx.coroutines.delay(1_000)

        // A genuinely FRESH attempt (the lifecycle gate was never marked
        // running by the first, unconfirmed one) must proceed independently
        // and correctly - never silently "completed" by the stale probe.
        val second = controller.requestStart()

        assertTrue("expected a genuine second RemoteUnconfirmed attempt, got $second", second is XrayCoreStartOutcome.RemoteUnconfirmed)
        assertEquals(2, runtime.startLoopCallCount)
        assertEquals(2, runtime.stopLoopCallCount)
    }

    @Test
    fun `RemoteUnconfirmed reason never carries the profile's secret field values`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = IllegalStateException("boom"))
        val harness = Harness(repository, coreRuntime = runtime)

        val outcome = harness.controller.requestStart() as XrayCoreStartOutcome.RemoteUnconfirmed

        assertFalse(outcome.reason.contains(validProfile.uuid))
        assertFalse(outcome.reason.contains(validProfile.realityPublicKey))
        assertFalse(outcome.reason.contains(validProfile.shortId))
    }

    @Test
    fun `TLS_TCP and REALITY share the same lifecycle gate - a second start while one is running is rejected`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val tlsRepository = newTlsRepository()
        tlsRepository.saveProfile(validTlsProfile)
        val harness = Harness(repository, tlsRepository = tlsRepository)

        val first = harness.controller.requestStart(TransportKind.XRAY_REALITY)
        val second = harness.controller.requestStart(TransportKind.TLS_TCP)

        assertEquals(XrayCoreStartOutcome.Started, first)
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, second)
        assertEquals(1, harness.coreRuntime.startLoopCallCount)
    }
}
