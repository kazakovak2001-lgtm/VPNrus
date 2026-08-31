package net.pocvpn.client.vpn

import net.pocvpn.client.vpn.config.ClientTunnelIdentityStore
import net.pocvpn.client.vpn.config.ProductionGatewayId

/** In-memory JVM test double for [ClientTunnelIdentityStore] - mirrors FileClientTunnelIdentityStore's own read()-returns-null-when-unset contract. */
class FakeClientTunnelIdentityStore(
    initial: Map<ProductionGatewayId, String> = emptyMap(),
) : ClientTunnelIdentityStore {
    private val entries = initial.toMutableMap()
    override fun read(id: ProductionGatewayId): String? = entries[id]
    override fun write(id: ProductionGatewayId, clientTunnelIp: String) {
        entries[id] = clientTunnelIp
    }
}
