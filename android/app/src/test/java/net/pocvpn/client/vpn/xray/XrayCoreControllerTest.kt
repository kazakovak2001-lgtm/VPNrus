package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.FileXrayQuicProfileStore
import net.pocvpn.client.identity.FileXrayTlsProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.SecureXrayQuicProfileRepository
import net.pocvpn.client.identity.SecureXrayTlsProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayQuicProfile
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
        quicRepository: SecureXrayQuicProfileRepository? = null,
        dataPlaneReadinessTimeoutMs: Long = 1_000L,
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
            quicRepository = quicRepository,
            dataPlaneReadinessTimeoutMs = dataPlaneReadinessTimeoutMs,
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

    // --- B21-fix: startLoop not throwing is not enough - readiness must also succeed ---

    @Test
    fun `startLoop succeeding but the data plane never becoming ready is reported, not Started`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(
            repository,
            coreRuntime = FakeXrayCoreRuntime(measureDelayThrows = IllegalStateException("failed to dial")),
        )

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.DataPlaneNotReady("IllegalStateException"), outcome)
        assertEquals(1, harness.coreRuntime.startLoopCallCount)
        assertEquals(1, harness.coreRuntime.stopLoopCallCount)
        assertEquals(1, harness.closeTunCallCount)
    }

    @Test
    fun `readiness exceeding the bounded timeout is reported as a timeout, not Started`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(
            repository,
            coreRuntime = FakeXrayCoreRuntime(measureDelayDelayMs = 200L),
            dataPlaneReadinessTimeoutMs = 20L,
        )

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.DataPlaneNotReady("timeout"), outcome)
        assertEquals(1, harness.coreRuntime.stopLoopCallCount)
        assertEquals(1, harness.closeTunCallCount)
    }

    @Test
    fun `readiness success reports Started exactly once readiness is confirmed`() = runBlocking {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val harness = Harness(repository, coreRuntime = FakeXrayCoreRuntime(measureDelayResult = 55L))

        val outcome = harness.controller.requestStart()

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(1, harness.coreRuntime.measureDelayCallCount)
        assertEquals(0, harness.closeTunCallCount)
    }

    // --- B21: QUIC branch - same readiness gate applies, no transport-specific bypass ---

    private val validQuicProfile = XrayQuicProfile(
        server = "152.70.43.1",
        serverPort = 2087,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "203.0.113.1",
        fingerprint = "chrome",
        path = "/nova-xhttp",
    )

    private fun newQuicRepository(): SecureXrayQuicProfileRepository =
        SecureXrayQuicProfileRepository(FileXrayQuicProfileStore(Files.createTempDirectory("xray-quic-controller-test").toFile()), FakeAesGcmKeyEncryptor())

    @Test
    fun `requestStart QUIC with no quicRepository wired is rejected without touching the runtime`() = runBlocking {
        val harness = Harness(newRepository())

        val outcome = harness.controller.requestStart(TransportKind.QUIC)

        assertEquals(XrayCoreStartOutcome.Rejected("Xray QUIC profile repository not wired"), outcome)
        assertEquals(0, harness.coreRuntime.startLoopCallCount)
    }

    @Test
    fun `requestStart QUIC with a valid profile but zero real data plane is reported, never Connected`() = runBlocking {
        val quicRepository = newQuicRepository()
        quicRepository.saveProfile(validQuicProfile)
        val harness = Harness(
            newRepository(),
            coreRuntime = FakeXrayCoreRuntime(measureDelayThrows = java.io.IOException("no packets reached the server")),
            quicRepository = quicRepository,
        )

        val outcome = harness.controller.requestStart(TransportKind.QUIC)

        assertEquals(XrayCoreStartOutcome.DataPlaneNotReady("IOException"), outcome)
        assertEquals(1, harness.coreRuntime.startLoopCallCount)
        assertEquals(1, harness.coreRuntime.stopLoopCallCount)
        assertEquals(1, harness.closeTunCallCount)
    }

    @Test
    fun `requestStart QUIC with a valid profile and a real data plane reports Started`() = runBlocking {
        val quicRepository = newQuicRepository()
        quicRepository.saveProfile(validQuicProfile)
        val harness = Harness(
            newRepository(),
            coreRuntime = FakeXrayCoreRuntime(measureDelayResult = 80L),
            quicRepository = quicRepository,
        )

        val outcome = harness.controller.requestStart(TransportKind.QUIC)

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(XrayConfigRenderer.render(validQuicProfile.toXrayVlessQuicConfig()), harness.coreRuntime.lastStartedConfigContent)
    }
}
