package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** B13 - proves gateway selection persistence: survives a fresh store instance (simulating an app restart), fails safe to Germany. */
class SelectedGatewayStoreTest {

    @get:Rule val tempFolder = TemporaryFolder()

    @Test
    fun `no saved selection defaults to Germany`() {
        val store = FileSelectedGatewayStore(tempFolder.newFolder())
        assertEquals(ProductionGatewayId.GERMANY, store.read())
    }

    @Test
    fun `a written selection survives a fresh store instance - simulates app restart`() {
        val dir = tempFolder.newFolder()
        FileSelectedGatewayStore(dir).write(ProductionGatewayId.STOCKHOLM)

        val freshStore = FileSelectedGatewayStore(dir)
        assertEquals(ProductionGatewayId.STOCKHOLM, freshStore.read())
    }

    @Test
    fun `writing Germany after Stockholm correctly overwrites the persisted selection`() {
        val dir = tempFolder.newFolder()
        val store = FileSelectedGatewayStore(dir)
        store.write(ProductionGatewayId.STOCKHOLM)
        store.write(ProductionGatewayId.GERMANY)

        assertEquals(ProductionGatewayId.GERMANY, FileSelectedGatewayStore(dir).read())
    }

    @Test
    fun `a corrupted selection file fails safe to Germany`() {
        val dir = tempFolder.newFolder()
        java.io.File(dir, "selected_gateway.txt").writeText("NOT_A_REAL_GATEWAY_ID")

        assertEquals(ProductionGatewayId.GERMANY, FileSelectedGatewayStore(dir).read())
    }

    @Test
    fun `germanyOnly always reads Germany and ignores writes`() {
        val store = SelectedGatewayStore.germanyOnly()
        store.write(ProductionGatewayId.STOCKHOLM)
        assertEquals(ProductionGatewayId.GERMANY, store.read())
    }
}
