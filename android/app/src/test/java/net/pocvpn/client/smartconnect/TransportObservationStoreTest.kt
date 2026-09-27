package net.pocvpn.client.smartconnect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportObservationStoreTest {

    private fun observation(key: String = "ep1", at: Long = 0L) = TransportAttemptObservation(
        destinationKey = key,
        protocol = TransportAttemptProtocol.TCP,
        connect = AttemptStageOutcome.SUCCEEDED,
        handshake = AttemptStageOutcome.SUCCEEDED,
        bytesSent = 0L,
        bytesReceived = 0L,
        progress = TrafficProgressOutcome.NOT_OBSERVED,
        termination = AttemptTermination.NONE_OBSERVED,
        observedAtEpochMillis = at,
    )

    @Test
    fun `recent for an unknown network key returns empty, never another network's evidence`() {
        val store = TransportObservationStore()
        store.record("wifi-a", observation())
        assertTrue(store.recent("wifi-b").isEmpty())
    }

    @Test
    fun `observations from one network never leak into a read for a different network`() {
        val store = TransportObservationStore()
        store.record("wifi-a", observation("ep1"))
        store.record("cellular-b", observation("ep2"))
        assertEquals(listOf("ep1"), store.recent("wifi-a").map { it.destinationKey })
        assertEquals(listOf("ep2"), store.recent("cellular-b").map { it.destinationKey })
    }

    @Test
    fun `recent returns oldest first for one network`() {
        val store = TransportObservationStore()
        store.record("wifi-a", observation("first", at = 1L))
        store.record("wifi-a", observation("second", at = 2L))
        assertEquals(listOf("first", "second"), store.recent("wifi-a").map { it.destinationKey })
    }

    @Test
    fun `capacity bounds the whole store across every network combined - oldest evicted first`() {
        val store = TransportObservationStore(capacity = 2)
        store.record("wifi-a", observation("first"))
        store.record("wifi-a", observation("second"))
        store.record("wifi-b", observation("third"))
        // "first" (oldest overall) was evicted; wifi-a keeps only "second", wifi-b keeps "third".
        assertEquals(listOf("second"), store.recent("wifi-a").map { it.destinationKey })
        assertEquals(listOf("third"), store.recent("wifi-b").map { it.destinationKey })
    }

    @Test
    fun `clear empties every network's evidence`() {
        val store = TransportObservationStore()
        store.record("wifi-a", observation())
        store.clear()
        assertTrue(store.recent("wifi-a").isEmpty())
    }

    @Test
    fun `constructing a store with a non-positive capacity is rejected`() {
        var threw = false
        try {
            TransportObservationStore(capacity = 0)
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }
}
