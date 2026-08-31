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
 *
 * B13 THIRD consolidated review fix (finding 6) - [selectedGatewayId] can
 * change concurrently with a resolution in progress (MainViewModel.
 * selectGateway() runs on a different coroutine/thread than whatever is
 * mid-`DefaultGatewayConfigurationRepository.get()`). The individual
 * getters below still each independently call [selectedGatewayId] (kept
 * for GatewayConfigSource interface compatibility/direct unit testing, and
 * genuinely harmless in isolation - a single field read is never
 * internally torn), but [snapshot] is OVERRIDDEN to resolve
 * [selectedGatewayId] and the matching descriptor/clientTunnelIp EXACTLY
 * ONCE and derive every field from that SAME resolved snapshot -
 * DefaultGatewayConfigurationRepository.get() calls ONLY [snapshot], never
 * the six individual getters, so a real config build can never combine one
 * gateway's host with a DIFFERENT gateway's key/clientTunnelIp/profile
 * even if selection changes the instant after [selectedGatewayId] is read.
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

    override fun snapshot(): GatewayConfigSnapshot {
        // THE one place selectedGatewayId() is read for a real config
        // build - everything below derives from this SAME resolved id/
        // descriptor, never a second independent read of either.
        val id = selectedGatewayId()
        val resolved = ProductionGatewayCatalog.byId(id)
        return GatewayConfigSnapshot(
            endpointHost = resolved.awg.endpointHost,
            endpointPort = resolved.awg.endpointPort.toString(),
            serverPublicKey = resolved.awg.serverPublicKeyBase64,
            clientTunnelIp = clientTunnelIp(id) ?: "",
            gatewayTunnelIp = resolved.awg.gatewayTunnelIp,
            allowedIps = allowedIps(),
            profile = resolved.awgProfile,
        )
    }
}
