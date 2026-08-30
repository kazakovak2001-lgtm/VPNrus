package net.pocvpn.client.vpn.config

/**
 * B13 - the product's real gateway-selection mechanism: resolves every
 * gateway-infrastructure [GatewayConfigSource] field (including [profile],
 * the AWG-profile endpoint-awareness fix) from [ProductionGatewayCatalog],
 * keyed by whatever [selectedGatewayId] currently returns. Deliberately a
 * supplier function, not a captured value, so this reads the CURRENT
 * selection fresh on every call - the same "no caching" discipline
 * DefaultGatewayConfigurationRepository.get() already documents for itself,
 * and exactly what makes a runtime gateway switch (no app restart required)
 * take effect on the very next connect() attempt.
 *
 * [clientTunnelIp] is a SEPARATE resolver, deliberately never sourced from
 * ProductionGatewayCatalog - a B13 review found the tunnel IP hardcoded
 * there, but it is THIS DEVICE'S provisioned peer address on the selected
 * gateway, not a gateway infrastructure fact (see ClientTunnelIdentityStore's
 * own docs). No stored value for the selected endpoint resolves to "" here,
 * NEVER another endpoint's IP and NEVER a hardcoded fallback -
 * DefaultGatewayConfigurationRepository.get() already fails a blank
 * clientTunnelIp() closed to GatewayConfiguration.Invalid (see its own
 * validation), so this deliberately does not duplicate that check.
 *
 * This is the replacement for wiring `android/app/gateway-dev.properties`
 * (via BuildConfigGatewaySource) into the real, production
 * GatewayConfigurationRepository - that file remains a genuinely local dev
 * convenience (see its own docs), never the product's own selector.
 */
class SelectedProductionGatewaySource(
    private val selectedGatewayId: () -> ProductionGatewayId,
    private val clientTunnelIp: (ProductionGatewayId) -> String?,
) : GatewayConfigSource {

    private val descriptor: ProductionGatewayDescriptor get() = ProductionGatewayCatalog.byId(selectedGatewayId())

    override fun endpointHost(): String = descriptor.awg.endpointHost
    override fun endpointPort(): String = descriptor.awg.endpointPort.toString()
    override fun serverPublicKey(): String = descriptor.awg.serverPublicKeyBase64
    override fun clientTunnelIp(): String = clientTunnelIp(selectedGatewayId()) ?: ""
    override fun gatewayTunnelIp(): String = descriptor.awg.gatewayTunnelIp
    override fun profile(): AwgProfile = descriptor.awgProfile
}
