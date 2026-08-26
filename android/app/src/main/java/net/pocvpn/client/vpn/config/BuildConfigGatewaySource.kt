package net.pocvpn.client.vpn.config

import net.pocvpn.client.BuildConfig

/**
 * Reads gateway config baked in at build time from the gitignored
 * android/app/gateway-dev.properties (see app/build.gradle.kts). All fields
 * default to "" when that file or a given key is absent, which
 * DefaultGatewayConfigurationRepository interprets as GatewayConfiguration.Missing.
 */
object BuildConfigGatewaySource : GatewayConfigSource {
    override fun endpointHost(): String = BuildConfig.GATEWAY_ENDPOINT_HOST
    override fun endpointPort(): String = BuildConfig.GATEWAY_ENDPOINT_PORT
    override fun serverPublicKey(): String = BuildConfig.GATEWAY_SERVER_PUBLIC_KEY
    override fun clientTunnelIp(): String = BuildConfig.GATEWAY_CLIENT_TUNNEL_IP
    override fun gatewayTunnelIp(): String = BuildConfig.GATEWAY_TUNNEL_IP
    override fun allowedIps(): String = BuildConfig.GATEWAY_ALLOWED_IPS
}
