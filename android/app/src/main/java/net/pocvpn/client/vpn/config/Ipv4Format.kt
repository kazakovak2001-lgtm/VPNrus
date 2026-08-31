package net.pocvpn.client.vpn.config

/**
 * B13 consolidated review fix - THE one strict IPv4 validity check, shared
 * by every place that used to have its own looser regex-only copy
 * (`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, which happily accepts "999.999.999.999").
 * DefaultGatewayConfigurationRepository, ClientTunnelIdentityStore, and
 * ProvisionedProfileStore all defer to this now - a corrupted/out-of-range
 * stored value is rejected the SAME way everywhere, never treated as valid
 * in a store's own read path while GatewayConfigurationRepository would
 * have rejected the identical string at connect time (see
 * ClientTunnelIdentityStore's own docs on why a corrupted stored IP must
 * never make a gateway appear provisioned).
 */
object Ipv4Format {
    private val SHAPE = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")

    fun isValid(ip: String): Boolean {
        val match = SHAPE.matchEntire(ip) ?: return false
        return match.groupValues.drop(1).all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
    }
}
