package net.pocvpn.client.identity

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Phase B step 1 - the ONE lifecycle lock (L) serializing every managed AWG
 * identity mutation, activation-commit binding update and managed AWG
 * eligibility/config build. Deliberately a plain class, not an `object`: the
 * factory constructs exactly one instance and injects that same instance into
 * every consumer (MainViewModel and VpnController in a later step), so tests
 * can construct isolated instances and there is no global mutable state.
 *
 * Lock order (acquire left to right only, never the reverse):
 *
 *     connectMutex -> L -> binding-store lock -> managed key repository mutex
 *
 * - L is a [Mutex] and is NOT reentrant: code already holding L must not call
 *   [withLock] again on the same instance.
 * - Code holding L must never acquire VpnController's connectMutex.
 * - The PRIVATE gateway identity never takes L.
 *
 * Not yet wired into any runtime path (Phase B step 1 is the primitive only).
 */
class ManagedIdentityLifecycle {
    private val mutex = Mutex()

    /** Runs [block] holding L; released on return, exception and cancellation alike. */
    suspend fun <T> withLock(block: suspend () -> T): T = mutex.withLock { block() }

    /** Diagnostic/test visibility only - never use it to decide whether to take L. */
    val isLocked: Boolean get() = mutex.isLocked
}
