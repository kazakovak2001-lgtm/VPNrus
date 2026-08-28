package net.pocvpn.client.vpn.config

import java.util.concurrent.atomic.AtomicReference

/**
 * B8B3B - the smallest GatewayConfigSource that can be updated at runtime
 * from a validated provisioning response. Every field delegates to an
 * underlying source (BuildConfigGatewaySource in production, so the
 * existing gateway-dev.properties dev flow is byte-for-byte unchanged)
 * until apply() has been called at least once.
 *
 * apply() performs NO validation of its own - it is only ever called from
 * MainViewModel's provisioning success handler, which by construction only
 * reaches that branch for a net.pocvpn.client.provisioning.
 * ProvisioningResult.Success - i.e. a value that has already passed
 * ProvisioningClient's own structural validation (valid IPv4s, a
 * well-formed AmneziaWG/WireGuard public key, a sane port). This class
 * trusts that boundary rather than re-implementing it.
 *
 * `allowedIps()` is deliberately NOT overridable here - the provisioning
 * response carries no AllowedIPs value, so this always delegates,
 * preserving whatever existing behavior (full-tunnel default, or a
 * gateway-dev.properties override) was already in effect.
 *
 * DefaultGatewayConfigurationRepository.get() re-reads every field on
 * every call (no caching there) - see VpnController.gatewayStatus()/
 * connect() - so a call to apply() here is picked up by the existing
 * Connect flow with no VpnController change needed.
 */
class MutableGatewayConfigSource(
    private val delegate: GatewayConfigSource,
) : GatewayConfigSource {

    private data class Override(
        val endpointHost: String,
        val endpointPort: String,
        val serverPublicKey: String,
        val clientTunnelIp: String,
        val gatewayTunnelIp: String,
    )

    private val override = AtomicReference<Override?>(null)

    fun apply(
        endpointHost: String,
        endpointPort: Int,
        serverPublicKey: String,
        clientTunnelIp: String,
        gatewayTunnelIp: String,
    ) {
        override.set(
            Override(
                endpointHost = endpointHost,
                endpointPort = endpointPort.toString(),
                serverPublicKey = serverPublicKey,
                clientTunnelIp = clientTunnelIp,
                gatewayTunnelIp = gatewayTunnelIp,
            )
        )
    }

    override fun endpointHost(): String = override.get()?.endpointHost ?: delegate.endpointHost()
    override fun endpointPort(): String = override.get()?.endpointPort ?: delegate.endpointPort()
    override fun serverPublicKey(): String = override.get()?.serverPublicKey ?: delegate.serverPublicKey()
    override fun clientTunnelIp(): String = override.get()?.clientTunnelIp ?: delegate.clientTunnelIp()
    override fun gatewayTunnelIp(): String = override.get()?.gatewayTunnelIp ?: delegate.gatewayTunnelIp()
    override fun allowedIps(): String = delegate.allowedIps()
}
