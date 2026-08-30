package net.pocvpn.client.vpn.config

/**
 * B13 - the product's real gateway-selection mechanism: resolves EVERY
 * [GatewayConfigSource] field (including [profile], the AWG-profile
 * endpoint-awareness fix) from [ProductionGatewayCatalog], keyed by
 * whatever [selectedGatewayId] currently returns. Deliberately a supplier
 * function, not a captured value, so this reads the CURRENT selection fresh
 * on every call - the same "no caching" discipline
 * DefaultGatewayConfigurationRepository.get() already documents for itself,
 * and exactly what makes a runtime gateway switch (no app restart required)
 * take effect on the very next connect() attempt.
 *
 * This is the replacement for wiring `android/app/gateway-dev.properties`
 * (via BuildConfigGatewaySource) into the real, production
 * GatewayConfigurationRepository - that file remains a genuinely local dev
 * convenience (see its own docs), never the product's own selector.
 */
class SelectedProductionGatewaySource(
    private val selectedGatewayId: () -> ProductionGatewayId,
) : GatewayConfigSource {

    private val descriptor: ProductionGatewayDescriptor get() = ProductionGatewayCatalog.byId(selectedGatewayId())

    override fun endpointHost(): String = descriptor.awg.endpointHost
    override fun endpointPort(): String = descriptor.awg.endpointPort.toString()
    override fun serverPublicKey(): String = descriptor.awg.serverPublicKeyBase64
    override fun clientTunnelIp(): String = descriptor.awg.clientTunnelIp
    override fun gatewayTunnelIp(): String = descriptor.awg.gatewayTunnelIp
    override fun profile(): AwgProfile = descriptor.awgProfile
}
