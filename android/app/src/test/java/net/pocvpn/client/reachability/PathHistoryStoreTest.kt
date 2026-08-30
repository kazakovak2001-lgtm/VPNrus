package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class PathHistoryStoreTest {

    @get:Rule val tempFolder = TemporaryFolder()

    @Test
    fun `recording success then reading back returns the aggregated entry`() {
        val store = FilePathHistoryStore(tempFolder.newFolder())
        store.record("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 100L)
        store.record("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = false, nowEpochMillis = 200L)
        val entry = store.get("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG)
        assertEquals(1, entry!!.successCount)
        assertEquals(1, entry.failureCount)
        assertEquals(false, entry.lastOutcomeSuccess)
    }

    @Test
    fun `different networkFingerprint x endpointId x transportKind keys never collide`() {
        val store = FilePathHistoryStore(tempFolder.newFolder())
        store.record("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 1L)
        store.record("fp-2", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = false, nowEpochMillis = 1L)
        store.record("fp-1", EndpointId("gw2"), TransportKind.AMNEZIA_WG, success = false, nowEpochMillis = 1L)
        store.record("fp-1", EndpointId("gw"), TransportKind.TLS_TCP, success = false, nowEpochMillis = 1L)

        assertEquals(true, store.get("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG)!!.lastOutcomeSuccess)
        assertEquals(false, store.get("fp-2", EndpointId("gw"), TransportKind.AMNEZIA_WG)!!.lastOutcomeSuccess)
        assertEquals(false, store.get("fp-1", EndpointId("gw2"), TransportKind.AMNEZIA_WG)!!.lastOutcomeSuccess)
        assertEquals(false, store.get("fp-1", EndpointId("gw"), TransportKind.TLS_TCP)!!.lastOutcomeSuccess)
    }

    @Test
    fun `history is bounded - recording beyond maxEntries evicts the least-recently-updated key`() {
        val store = FilePathHistoryStore(tempFolder.newFolder(), maxEntries = 3)
        store.record("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 1L)
        store.record("fp-2", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 2L)
        store.record("fp-3", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 3L)
        store.record("fp-4", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 4L)

        assertNull(store.get("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG))
        assertTrue(store.get("fp-4", EndpointId("gw"), TransportKind.AMNEZIA_WG) != null)
    }

    @Test
    fun `persists across a simulated restart`() {
        val dir = tempFolder.newFolder()
        FilePathHistoryStore(dir).record("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 1L)
        val reopened = FilePathHistoryStore(dir)
        assertEquals(1, reopened.get("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG)!!.successCount)
    }

    @Test
    fun `a corrupted store file is treated as empty, not a crash`() {
        val dir = tempFolder.newFolder()
        java.io.File(dir, "path_history.bin").writeBytes(byteArrayOf(9, 9, 9))
        val store = FilePathHistoryStore(dir)
        assertNull(store.get("fp-1", EndpointId("gw"), TransportKind.AMNEZIA_WG))
    }

    @Test
    fun `concurrent record() and get() calls never throw or corrupt the store (PR #23 second audit - copy-on-write fix)`() {
        val store = FilePathHistoryStore(tempFolder.newFolder(), maxEntries = 50)
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val writers = (0 until 8).map { t ->
            Thread {
                try {
                    repeat(200) { i ->
                        store.record("fp-$t", EndpointId("gw-$i"), TransportKind.AMNEZIA_WG, success = i % 2 == 0, nowEpochMillis = i.toLong())
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
        }
        val readers = (0 until 8).map { t ->
            Thread {
                try {
                    repeat(500) { i ->
                        store.get("fp-$t", EndpointId("gw-${i % 200}"), TransportKind.AMNEZIA_WG)
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
        }
        (writers + readers).forEach { it.start() }
        (writers + readers).forEach { it.join(10_000) }

        assertTrue("concurrent access must never throw: $errors", errors.isEmpty())
    }

    @Test
    fun `PathHistoryEntry's field set structurally cannot hold raw identifying network data`() {
        val fields = PathHistoryEntry::class.java.declaredFields.map { it.name }.toSet()
        val forbidden = setOf("ssid", "bssid", "imsi", "phoneNumber", "dnsServerAddresses", "dns", "networkType")
        assertTrue(fields.intersect(forbidden).isEmpty())
    }
}
