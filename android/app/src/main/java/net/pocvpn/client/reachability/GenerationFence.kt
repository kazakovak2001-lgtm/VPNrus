package net.pocvpn.client.reachability

import java.util.concurrent.atomic.AtomicLong

/** Monotonic ownership boundary for asynchronous bootstrap work. */
class GenerationFence {
    private val current = AtomicLong(0L)

    fun begin(): Long = current.incrementAndGet()

    fun isCurrent(generation: Long): Boolean = current.get() == generation
}
