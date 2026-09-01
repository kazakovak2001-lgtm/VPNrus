package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.file.Files

class GatewaySelectionModeStoreTest {

    private fun newStore(): FileGatewaySelectionModeStore =
        FileGatewaySelectionModeStore(Files.createTempDirectory("gateway-selection-mode-test").toFile())

    @Test
    fun `never written defaults to MANUAL_MANAGED - preserves pre-B22 behavior`() {
        assertEquals(GatewaySelectionMode.MANUAL_MANAGED, newStore().read())
    }

    @Test
    fun `write then read round-trips each mode`() {
        val store = newStore()
        for (mode in GatewaySelectionMode.entries) {
            store.write(mode)
            assertEquals(mode, store.read())
        }
    }

    @Test
    fun `a corrupted file falls back to MANUAL_MANAGED, never throws`() {
        val dir = Files.createTempDirectory("gateway-selection-mode-corrupt-test").toFile()
        val store = FileGatewaySelectionModeStore(dir)
        java.io.File(dir, "gateway_selection_mode.txt").writeText("NOT_A_REAL_MODE", Charsets.UTF_8)

        assertEquals(GatewaySelectionMode.MANUAL_MANAGED, store.read())
    }

    @Test
    fun `managedOnly() always reads MANUAL_MANAGED and ignores writes`() {
        val store = GatewaySelectionModeStore.managedOnly()

        store.write(GatewaySelectionMode.PRIVATE)

        assertEquals(GatewaySelectionMode.MANUAL_MANAGED, store.read())
    }
}
