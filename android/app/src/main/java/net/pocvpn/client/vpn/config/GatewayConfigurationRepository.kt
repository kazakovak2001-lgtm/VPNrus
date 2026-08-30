package net.pocvpn.client.vpn.config

/** Raw, unvalidated strings for gateway config - lets tests supply values without touching Android's BuildConfig. */
interface GatewayConfigSource {
    fun endpointHost(): String
    fun endpointPort(): String
    fun serverPublicKey(): String
    fun clientTunnelIp(): String
    fun gatewayTunnelIp(): String

    /**
     * Comma-separated AllowedIPs override (e.g. "10.77.0.0/24" for a narrow
     * local-test route, instead of the full-tunnel default). Blank means
     * "not specified" - DefaultGatewayConfigurationRepository falls back to
     * the full-tunnel default in that case.
     */
    fun allowedIps(): String = ""

    /**
     * B13 - the AWG obfuscation/timing profile for THIS source's gateway.
     * Defaults to [PocAwgProfile.value] (Germany's own values, historically
     * the only ones that existed) so every pre-B13 implementation
     * ([BuildConfigGatewaySource], every test fake) is byte-for-byte
     * unaffected. [SelectedProductionGatewaySource] is the one real
     * implementation that overrides this per-gateway - see its own docs for
     * why a single global profile was a real bug, not a simplification.
     */
    fun profile(): AwgProfile = PocAwgProfile.value
}

interface GatewayConfigurationRepository {
    fun get(): GatewayConfiguration
}

/**
 * Validates raw config strings into a GatewayConfiguration. All fields blank
 * -> Missing (no gateway configured at all - the expected POC-01 state until
 * B6 exists). Any field present but structurally wrong -> Invalid(reason),
 * never silently ignored and never a crash.
 */
class DefaultGatewayConfigurationRepository(
    private val source: GatewayConfigSource,
) : GatewayConfigurationRepository {

    override fun get(): GatewayConfiguration {
        val host = source.endpointHost().trim()
        val portRaw = source.endpointPort().trim()
        val serverPublicKey = source.serverPublicKey().trim()
        val clientTunnelIp = source.clientTunnelIp().trim()
        val gatewayTunnelIp = source.gatewayTunnelIp().trim()

        if (host.isEmpty() && portRaw.isEmpty() && serverPublicKey.isEmpty() &&
            clientTunnelIp.isEmpty() && gatewayTunnelIp.isEmpty()
        ) {
            return GatewayConfiguration.Missing
        }

        if (host.isEmpty()) return GatewayConfiguration.Invalid("endpoint host is blank")

        val port = portRaw.toIntOrNull()
            ?: return GatewayConfiguration.Invalid("endpoint port is not a number: '$portRaw'")
        if (port !in 1..65535) return GatewayConfiguration.Invalid("endpoint port out of range: $port")

        if (!WgKeyFormat.isValid(serverPublicKey)) {
            return GatewayConfiguration.Invalid("server public key is not a valid AmneziaWG/WireGuard key")
        }
        if (!isValidIpv4(clientTunnelIp)) {
            return GatewayConfiguration.Invalid("client tunnel IP is not a valid IPv4 address: '$clientTunnelIp'")
        }
        if (!isValidIpv4(gatewayTunnelIp)) {
            return GatewayConfiguration.Invalid("gateway tunnel IP is not a valid IPv4 address: '$gatewayTunnelIp'")
        }

        return GatewayConfiguration.Configured(
            endpointHost = host,
            endpointPort = port,
            serverPublicKeyBase64 = serverPublicKey,
            clientTunnelIp = clientTunnelIp,
            gatewayTunnelIp = gatewayTunnelIp,
            allowedIps = resolveAllowedIps(),
            // B8F - a local client policy, not a server-issued/persisted
            // fact (see VpnDnsPolicy's own docs) - applied here so every
            // profile source converges on the same DNS servers.
            dnsServers = VpnDnsPolicy.servers,
            // B13 - read fresh from the source on every get() call (same
            // "no caching" discipline as every other field here), never the
            // constructor-level default this used to be - see
            // GatewayConfigSource.profile()'s own docs.
            profile = source.profile(),
        )
    }

    /** Full-tunnel default, unless the source overrides it (e.g. a narrow route for local testing). */
    private fun resolveAllowedIps(): List<String> {
        val override = source.allowedIps().split(",").map { it.trim() }.filter { it.isNotEmpty() }
        return override.ifEmpty { listOf("0.0.0.0/0", "::/0") }
    }

    private fun isValidIpv4(ip: String): Boolean {
        val match = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$").matchEntire(ip) ?: return false
        return match.groupValues.drop(1).all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
    }
}
