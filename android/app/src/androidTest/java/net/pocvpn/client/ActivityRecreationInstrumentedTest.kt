package net.pocvpn.client

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B7I: proves Activity recreation (rotation / config change) does not lose or
 * duplicate MainViewModel/controller state. The real safeguard is architectural
 * (ViewModelStore survives recreation; VpnController.init - which wires the
 * reconnect manager - runs exactly once per ViewModel instance, see
 * MainViewModelTest for the JVM-level proof of that). This test proves the
 * Android-side half of that guarantee: the same ViewModel instance survives
 * a real Activity recreation on-device.
 */
@RunWith(AndroidJUnit4::class)
class ActivityRecreationInstrumentedTest {

    private fun currentViewModel(activity: MainActivity): MainViewModel =
        MainActivity.sessionViewModel(activity.application as androidx.lifecycle.ViewModelStoreOwner, activity.applicationContext)

    @Test
    fun recreate_preservesSameViewModelInstance_andPublicKey() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitForPublicKey(scenario)

            val (viewModelBefore, keyBefore) = scenario.withActivity {
                val vm = currentViewModel(it)
                vm to vm.publicKey.value
            }
            assertNotNull("public key must be loaded before recreate", keyBefore)

            scenario.recreate()
            waitForPublicKey(scenario)

            val (viewModelAfter, keyAfter) = scenario.withActivity {
                val vm = currentViewModel(it)
                vm to vm.publicKey.value
            }

            assertSame(
                "MainViewModel must survive Activity recreation, not be rebuilt",
                viewModelBefore,
                viewModelAfter,
            )
            assertEquals("client public key must not change across recreation", keyBefore, keyAfter)
        }
    }

    @Test
    fun recreate_afterGatewayConfigurationMissingError_reRendersSameErrorWithoutCrash() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitForPublicKey(scenario)

            scenario.withActivity { currentViewModel(it).connect() }
            waitForState(scenario) { it is TransportState.Error }

            val stateBefore = scenario.withActivity { currentViewModel(it).transportState.value }
            assertTrue(stateBefore is TransportState.Error)

            // Recreation itself must not throw; ActivityScenario.recreate() would
            // propagate any crash during onCreate/onDestroy as a test failure.
            scenario.recreate()
            waitForState(scenario) { it is TransportState.Error }

            val stateAfter = scenario.withActivity { currentViewModel(it).transportState.value }
            assertTrue("gateway-missing error must survive recreation, not silently clear", stateAfter is TransportState.Error)
            assertEquals(
                (stateBefore as TransportState.Error).message,
                (stateAfter as TransportState.Error).message,
            )
        }
    }

    @Test
    fun recreate_doesNotDuplicateVpnPermissionState() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitForPublicKey(scenario)

            val grantedBefore = scenario.withActivity { currentViewModel(it).diagnostics.value.permissionGranted }

            scenario.recreate()
            waitForPublicKey(scenario)

            val grantedAfter = scenario.withActivity { currentViewModel(it).diagnostics.value.permissionGranted }
            assertEquals(
                "VPN permission state must be represented consistently across recreation",
                grantedBefore,
                grantedAfter,
            )
        }
    }

    /** A second MainActivity (explicit intent) must read the session's ViewModel, not build its own. */
    @Test
    fun secondActivityInstance_sharesTheSameViewModel() {
        ActivityScenario.launch(MainActivity::class.java).use { first ->
            waitForPublicKey(first)
            val (firstActivity, firstViewModel) = first.withActivity { it to currentViewModel(it) }
            // The field case (`am start -n …/.MainActivity`): an explicit
            // NEW_TASK intent stacks a second instance on top of the first.
            // ActivityScenario.launch and Instrumentation.startActivitySync
            // both clear the first one instead (CLEAR_TOP), so start it as
            // adb does and find it among the resumed activities.
            val instrumentation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
            instrumentation.targetContext.startActivity(
                android.content.Intent(instrumentation.targetContext, MainActivity::class.java)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            val secondActivity = awaitResumedMainActivityOtherThan(firstActivity)
            try {
                assertTrue("a second MainActivity object", firstActivity !== secondActivity)
                assertTrue("the first MainActivity is still alive", !firstActivity.isDestroyed)
                val secondViewModel = currentViewModel(secondActivity)
                assertSame(firstViewModel, secondViewModel)
                assertSame(firstViewModel.transportState, secondViewModel.transportState)
            } finally {
                instrumentation.runOnMainSync { secondActivity.finish() }
            }
        }
    }

    /** Finishing MainActivity (Back) no longer drops the session owner while the process lives. */
    @Test
    fun finishedThenRelaunchedActivity_sharesTheSameViewModel() {
        val before = ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitForPublicKey(scenario)
            scenario.withActivity { currentViewModel(it) }
        }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            assertSame(before, scenario.withActivity { currentViewModel(it) })
        }
    }

    private fun awaitResumedMainActivityOtherThan(existing: MainActivity, timeoutMs: Long = 10_000): MainActivity {
        val instrumentation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            var found: MainActivity? = null
            instrumentation.runOnMainSync {
                found = androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(androidx.test.runner.lifecycle.Stage.RESUMED)
                    .filterIsInstance<MainActivity>()
                    .firstOrNull { it !== existing }
            }
            found?.let { return it }
            Thread.sleep(50)
        }
        throw AssertionError("timed out waiting for a second MainActivity")
    }

    private fun waitForPublicKey(scenario: ActivityScenario<MainActivity>, timeoutMs: Long = 5_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val key = scenario.withActivity { currentViewModel(it).publicKey.value }
            if (key != null) return
            Thread.sleep(50)
        }
        throw AssertionError("timed out waiting for public key to load")
    }

    private fun waitForState(
        scenario: ActivityScenario<MainActivity>,
        timeoutMs: Long = 5_000,
        predicate: (TransportState) -> Boolean,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val state = scenario.withActivity { currentViewModel(it).transportState.value }
            if (predicate(state)) return
            Thread.sleep(50)
        }
        throw AssertionError("timed out waiting for expected transport state")
    }

    private fun <T> ActivityScenario<MainActivity>.withActivity(block: (MainActivity) -> T): T {
        var result: T? = null
        onActivity { result = block(it) }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }
}
