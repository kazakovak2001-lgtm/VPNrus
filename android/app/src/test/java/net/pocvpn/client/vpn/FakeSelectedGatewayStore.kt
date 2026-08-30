package net.pocvpn.client.vpn

import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.SelectedGatewayStore

/** In-memory JVM test double for [SelectedGatewayStore] - tracks write() calls so tests can assert reconciliation persisted (or didn't). */
class FakeSelectedGatewayStore(initial: ProductionGatewayId = ProductionGatewayId.GERMANY) : SelectedGatewayStore {
    var current: ProductionGatewayId = initial
        private set
    var writeCallCount = 0
        private set

    override fun read(): ProductionGatewayId = current
    override fun write(id: ProductionGatewayId) {
        writeCallCount++
        current = id
    }
}
