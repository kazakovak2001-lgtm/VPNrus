package net.pocvpn.client.vpn.config

/**
 * The non-secret gateway-side facts needed to build a tunnel config: where
 * the gateway is, its public key, and this client's assigned tunnel address.
 * Nothing here is a secret - the client's own private key is fetched
 * separately, at connect time, from ClientKeyRepository.
 */
sealed class GatewayConfiguration {

    /** No gateway configured yet. Real VPS required (see B6). CONNECT must fail early and clearly. */
    object Missing : GatewayConfiguration()

    /** Configuration is present but structurally invalid - distinct from Missing so the UI/diagnostics can say why. */
    data class Invalid(val reason: String) : GatewayConfiguration()

    data class Configured(
        val endpointHost: String,
        val endpointPort: Int,
        val serverPublicKeyBase64: String,
        val clientTunnelIp: String,
        val gatewayTunnelIp: String,
        val allowedIps: List<String>,
        /** Placeholder for B10 - not consumed by anything yet. */
        val dnsServers: List<String> = emptyList(),
        val persistentKeepaliveSeconds: Int? = 25,
        val profile: AwgProfile,
    ) : GatewayConfiguration()
}
