package net.pocvpn.client.vpn.xray

import java.util.concurrent.atomic.AtomicBoolean

enum class XrayServiceStartDecision {
    /** No start/core/tun exists yet for this attempt - caller must proceed and call [XrayServiceLifecycleGate.endStart]. */
    PROCEED,

    /** A previous start already completed and is running - this call is a no-op. */
    IGNORE_ALREADY_RUNNING,

    /** Another start is currently in flight (establish()/startLoop() not yet finished) - this call is a no-op. */
    IGNORE_START_IN_FLIGHT,
}

/**
 * Pure start/stop state machine for [NovaXrayVpnService], factored out so its
 * "duplicate start creates no duplicate core", "stop before start is a
 * no-op", and "a second teardown after an explicit stop is a no-op" (so
 * stopLoop()/tun-close only ever happen once per successful start)
 * invariants are unit-testable without a real Android VpnService/Context
 * (this project has no Robolectric dependency - see build.gradle.kts).
 *
 * Thread-safety: [tryBeginStart] is the only method that races another
 * caller of itself (the AtomicBoolean CAS resolves that); [isRunning] is
 * only ever flipped by [endStart]/[tryBeginTeardown], which the service
 * calls from its own single coroutine/lifecycle callbacks, never concurrently
 * with each other.
 */
class XrayServiceLifecycleGate {

    private val startingLock = AtomicBoolean(false)

    @Volatile
    var isRunning: Boolean = false
        private set

    fun tryBeginStart(): XrayServiceStartDecision {
        if (isRunning) return XrayServiceStartDecision.IGNORE_ALREADY_RUNNING
        if (!startingLock.compareAndSet(false, true)) return XrayServiceStartDecision.IGNORE_START_IN_FLIGHT
        return XrayServiceStartDecision.PROCEED
    }

    /** Must be called exactly once after every [tryBeginStart] that returned PROCEED, regardless of outcome. */
    fun endStart(success: Boolean) {
        if (success) isRunning = true
        startingLock.set(false)
    }

    /** False (no-op, caller must not touch core/tun) if not currently running; true exactly once per successful start. */
    fun tryBeginTeardown(): Boolean {
        if (!isRunning) return false
        isRunning = false
        return true
    }
}
