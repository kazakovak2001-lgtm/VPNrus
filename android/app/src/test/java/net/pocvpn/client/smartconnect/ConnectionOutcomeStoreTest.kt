package net.pocvpn.client.smartconnect

import java.nio.file.Files
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8I - narrow tests for FileConnectionOutcomeStore: this feature's own
 * required cases 9 (bounded history) and 10 (no sensitive fields), plus
 * basic persistence/round-trip coverage.
 */
class ConnectionOutcomeStoreTest {

    private fun outcome(index: Int, result: ConnectionOutcomeResult = ConnectionOutcomeResult.SUCCESS) = ConnectionOutcome(
        transport = TransportKind.AMNEZIA_WG,
        gatewayId = ProductionGateway.ID,
        result = result,
        handshakeDurationMs = 1000L + index,
        errorCategory = if (result == ConnectionOutcomeResult.SUCCESS) ConnectionErrorCategory.NONE else ConnectionErrorCategory.HANDSHAKE_TIMEOUT,
        timestampEpochMillis = index.toLong(),
    )

    @Test
    fun `bounded connection history cannot grow past maxRecords, oldest is dropped first`() {
        val dir = Files.createTempDirectory("connection-outcome-test").toFile()
        val store = FileConnectionOutcomeStore(dir, maxRecords = 5)

        repeat(20) { i -> store.record(outcome(i)) }

        val recent = store.recent()
        assertEquals(5, recent.size)
        // FIFO: the last 5 of 20 (indices 15..19) survive, oldest dropped.
        assertEquals((15..19).toList(), recent.map { it.timestampEpochMillis.toInt() })
    }

    @Test
    fun `persisted history survives a fresh store instance against the same directory`() {
        val dir = Files.createTempDirectory("connection-outcome-test").toFile()
        FileConnectionOutcomeStore(dir, maxRecords = 10).apply {
            record(outcome(1, ConnectionOutcomeResult.SUCCESS))
            record(outcome(2, ConnectionOutcomeResult.FAILURE))
        }

        val restored = FileConnectionOutcomeStore(dir, maxRecords = 10).recent()

        assertEquals(2, restored.size)
        assertEquals(ConnectionOutcomeResult.SUCCESS, restored[0].result)
        assertEquals(ConnectionOutcomeResult.FAILURE, restored[1].result)
    }

    @Test
    fun `no saved history yields an empty list, never a crash`() {
        val dir = Files.createTempDirectory("connection-outcome-test").toFile()
        assertTrue(FileConnectionOutcomeStore(dir).recent().isEmpty())
    }

    @Test
    fun `no sensitive fields exist anywhere in the persisted ConnectionOutcome model`() {
        // The exact, closed set of fields this format can ever represent -
        // not a weak substring check, but an exhaustive list: an IP
        // address, destination, DNS query, credential, or key field simply
        // has nowhere to go in this type. Compiler-synthetic fields (e.g.
        // the Compose plugin's "$stable" stability marker, added to every
        // class in this module regardless of whether it's a Composable)
        // are filtered out - they hold no data, only a constant int.
        val fieldNames = ConnectionOutcome::class.java.declaredFields
            .map { it.name }
            .filterNot { it.contains('$') }
            .toSet()
        val expected = setOf("transport", "gatewayId", "result", "handshakeDurationMs", "errorCategory", "timestampEpochMillis")
        assertEquals(expected, fieldNames)

        val forbidden = listOf("ip", "address", "dns", "destination", "credential", "key", "packet", "ssid", "history", "url")
        fieldNames.forEach { name ->
            forbidden.forEach { bad ->
                assertTrue("field '$name' looks sensitive (matches '$bad')", !name.lowercase().contains(bad))
            }
        }
    }
}
