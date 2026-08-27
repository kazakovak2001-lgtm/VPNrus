package net.pocvpn.client.network

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.pocvpn.client.smartconnect.SmartConnectDecisionEngine
import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.vpn.AmneziaWgTransport
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 2A / T12: exercises NetworkProfiler against the REAL ConnectivityManager
 * on-device, driving transitions via `adb shell svc wifi/data` (same approach
 * validated in B7I's AndroidReconnectManager test). NetworkProfiler is not
 * wired into any Activity/ViewModel yet in this phase, so "no callback leak
 * across recreation" is proven directly at the class level: start() is
 * idempotent (unregisters any previous registration first, mirroring
 * AndroidReconnectManager), and stop() leaves no stale callback able to emit.
 */
@RunWith(AndroidJUnit4::class)
class NetworkProfilerInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String) {
        instrumentation.uiAutomation.executeShellCommand(cmd).close()
    }

    private fun setNetworkUp(up: Boolean) {
        val state = if (up) "enable" else "disable"
        shell("svc wifi $state")
        shell("svc data $state")
    }

    @Before
    fun ensureNetworkUpBeforeTest() {
        setNetworkUp(true)
        Thread.sleep(1_000)
    }

    @After
    fun restoreNetwork() {
        setNetworkUp(true)
        Thread.sleep(1_000)
    }

    private fun waitUntil(timeoutMs: Long = 15_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(100)
        }
        throw AssertionError("condition not met within ${timeoutMs}ms")
    }

    @Test
    fun profiler_observesCurrentRealNetworkAsUsable() {
        val profiler = NetworkProfiler(context)
        try {
            profiler.start()
            waitUntil { profiler.profile.value.isUsable }
            val profile = profiler.profile.value
            assertTrue(profile.type != NetworkType.NONE)
            assertTrue(profile.validatedInternet)
        } finally {
            profiler.stop()
        }
    }

    @Test
    fun disablingNetwork_yieldsUnavailableProfile_restoringRecovers_noCrash() {
        val profiler = NetworkProfiler(context)
        try {
            profiler.start()
            waitUntil { profiler.profile.value.isUsable }

            setNetworkUp(false)
            waitUntil { !profiler.profile.value.isUsable }
            assertEquals(NetworkType.NONE, profiler.profile.value.type)

            setNetworkUp(true)
            waitUntil(timeoutMs = 20_000) { profiler.profile.value.isUsable }
        } finally {
            profiler.stop()
        }
    }

    @Test
    fun repeatedStart_isIdempotent_doesNotAccumulateCallbacks() {
        val profiler = NetworkProfiler(context)
        try {
            repeat(5) { profiler.start() }
            waitUntil { profiler.profile.value.isUsable }

            // If start() accumulated N registrations, a single stop() below would
            // leave (N-1) still active and further network events would still
            // reach this profiler after "shutdown". It must not.
            profiler.stop()
            val afterStop = profiler.profile.value

            setNetworkUp(false)
            Thread.sleep(5_000)
            setNetworkUp(true)
            Thread.sleep(2_000)

            assertEquals("no emission should reach a stopped profiler", afterStop, profiler.profile.value)
        } finally {
            profiler.stop()
        }
    }

    @Test
    fun stop_leavesNoStaleCallback() {
        val profiler = NetworkProfiler(context)
        profiler.start()
        waitUntil { profiler.profile.value.isUsable }
        profiler.stop()
        val snapshot = profiler.profile.value

        setNetworkUp(false)
        Thread.sleep(3_000)

        assertEquals(snapshot, profiler.profile.value)
    }

    @Test
    fun wifiCellularTransitions_doNotCrash() {
        val profiler = NetworkProfiler(context)
        try {
            profiler.start()
            waitUntil { profiler.profile.value.isUsable }

            // Toggle a few times - real ConnectivityManager churn, must not throw/crash.
            repeat(3) {
                setNetworkUp(false)
                Thread.sleep(1_500)
                setNetworkUp(true)
                Thread.sleep(2_500)
            }
            waitUntil(timeoutMs = 20_000) { profiler.profile.value.isUsable }
        } finally {
            profiler.stop()
        }
    }

    /**
     * Composes the real on-device NetworkProfile with SmartConnectDecisionEngine -
     * no tunnel is connected, AmneziaWgTransport is only referenced via the
     * registry's factory (never invoked: connect() is never called here).
     */
    @Test
    fun smartConnect_selectsOnlyAwg_onARealDeviceNetworkProfile() {
        val profiler = NetworkProfiler(context)
        val registry = TransportRegistry.defaults { AmneziaWgTransport(context) }
        try {
            profiler.start()
            waitUntil { profiler.profile.value.isUsable }

            val decision = SmartConnectDecisionEngine.decide(profiler.profile.value, registry)
            assertEquals(TransportSelectionDecision.SelectTransport(TransportKind.AMNEZIA_WG), decision)
        } finally {
            profiler.stop()
        }
    }
}
